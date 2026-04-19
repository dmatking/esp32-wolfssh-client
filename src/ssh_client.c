#include "esp_wolfssh_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "sdkconfig.h"
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>

#include <wolfssh/ssh.h>

static const char *TAG = "ssh_client";

// ---------------------------------------------------------------------------
// Module-level session state (single session supported)
// ---------------------------------------------------------------------------

static struct {
    ssh_client_config_t  cfg;           // copy of caller's config
    QueueHandle_t        tx_queue;      // keystrokes → writer sub-task
    TaskHandle_t         session_task;
    TaskHandle_t         writer_task;
    volatile bool        connected;     // shell is open and usable
    volatile bool        stop_requested;
    WOLFSSH             *ssh;           // valid only while session_task runs
} s_session;

// ---------------------------------------------------------------------------
// Auth callback
// ---------------------------------------------------------------------------

typedef struct {
    const uint8_t *priv_key;
    word32         priv_key_sz;
    const uint8_t *pub_key;
    word32         pub_key_sz;
    const char    *password;
    bool           pubkey_tried;
} auth_ctx_t;

static int userauth_cb(byte authType, WS_UserAuthData *authData, void *ctx)
{
    auth_ctx_t *ac = (auth_ctx_t *)ctx;

    if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
        if (ac->pubkey_tried || ac->priv_key == NULL)
            return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
        ac->pubkey_tried = true;
        authData->sf.publicKey.publicKeyType   = (const byte *)"ssh-ed25519";
        authData->sf.publicKey.publicKeyTypeSz = 11;
        authData->sf.publicKey.privateKey      = ac->priv_key;
        authData->sf.publicKey.privateKeySz    = ac->priv_key_sz;
        authData->sf.publicKey.publicKey       = ac->pub_key;
        authData->sf.publicKey.publicKeySz     = ac->pub_key_sz;
        return WOLFSSH_USERAUTH_SUCCESS;
    }
    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        if (ac->password && ac->password[0] != '\0') {
            authData->sf.password.password   = (const byte *)ac->password;
            authData->sf.password.passwordSz = (word32)strlen(ac->password);
            return WOLFSSH_USERAUTH_SUCCESS;
        }
    }
    return WOLFSSH_USERAUTH_FAILURE;
}

// ---------------------------------------------------------------------------
// TCP connect helper
// ---------------------------------------------------------------------------

static int tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms)
{
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        ESP_LOGE(TAG, "DNS lookup failed for %s", host);
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    // Apply connect timeout via SO_RCVTIMEO / send a non-blocking connect
    if (timeout_ms > 0) {
        struct timeval tv = {
            .tv_sec  = timeout_ms / 1000,
            .tv_usec = (timeout_ms % 1000) * 1000,
        };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        ESP_LOGE(TAG, "TCP connect to %s:%u failed", host, port);
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return fd;
}

// ---------------------------------------------------------------------------
// Writer sub-task: drains tx_queue → wolfSSH_stream_send
// ---------------------------------------------------------------------------

static void writer_task(void *arg)
{
    WOLFSSH *ssh = (WOLFSSH *)arg;
    char ch;
    while (s_session.connected && !s_session.stop_requested) {
        if (xQueueReceive(s_session.tx_queue, &ch, pdMS_TO_TICKS(100)) == pdTRUE) {
            if (ch == '\0') break;  // sentinel: session is ending
            if (s_session.connected)
                wolfSSH_stream_send(ssh, (byte *)&ch, 1);
        }
    }
    s_session.writer_task = NULL;
    vTaskDelete(NULL);
}

// ---------------------------------------------------------------------------
// Session task: full connect → PTY → read loop → cleanup
// ---------------------------------------------------------------------------

static void session_task(void *arg)
{
    (void)arg;
    ssh_client_config_t *cfg = &s_session.cfg;
    int reason = 0;

    uint32_t timeout_ms = cfg->connect_timeout_ms
                        ? cfg->connect_timeout_ms
                        : CONFIG_SSH_CLIENT_CONNECT_TIMEOUT;
    uint16_t cols = cfg->term_cols ? cfg->term_cols : CONFIG_SSH_CLIENT_TERM_COLS;
    uint16_t rows = cfg->term_rows ? cfg->term_rows : CONFIG_SSH_CLIENT_TERM_ROWS;

    // ---- Parse key material -------------------------------------------------

    auth_ctx_t auth = {
        .password    = cfg->password,
        .pubkey_tried = false,
    };

    WOLFSSH_CTX *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (!ctx) {
        ESP_LOGE(TAG, "wolfSSH_CTX_new failed");
        reason = -1;
        goto done;
    }
    wolfSSH_SetUserAuth(ctx, userauth_cb);

    if (cfg->privkey_pem && cfg->privkey_pem_len > 0) {
        byte  *parsedKey   = NULL;
        word32 parsedKeySz = 0;
        const byte *keyType   = NULL;
        word32      keyTypeSz = 0;

        int ret = wolfSSH_ReadKey_buffer(cfg->privkey_pem, (word32)cfg->privkey_pem_len,
                                         WOLFSSH_FORMAT_OPENSSH,
                                         &parsedKey, &parsedKeySz,
                                         &keyType, &keyTypeSz, NULL);
        if (ret == WS_SUCCESS) {
            wolfSSH_CTX_UsePrivateKey_buffer(ctx, cfg->privkey_pem,
                                              (word32)cfg->privkey_pem_len,
                                              WOLFSSH_FORMAT_OPENSSH);
            auth.priv_key    = parsedKey;
            auth.priv_key_sz = parsedKeySz;
            ESP_LOGI(TAG, "private key parsed (%lu bytes)", (unsigned long)parsedKeySz);
        } else {
            ESP_LOGW(TAG, "failed to parse private key: %d", ret);
        }
    }

    if (cfg->pubkey_pem && cfg->pubkey_pem_len > 0) {
        byte  *parsedPub   = NULL;
        word32 parsedPubSz = 0;
        const byte *pubType   = NULL;
        word32      pubTypeSz = 0;

        int ret = wolfSSH_ReadKey_buffer(cfg->pubkey_pem, (word32)cfg->pubkey_pem_len,
                                         WOLFSSH_FORMAT_SSH,
                                         &parsedPub, &parsedPubSz,
                                         &pubType, &pubTypeSz, NULL);
        if (ret == WS_SUCCESS) {
            auth.pub_key    = parsedPub;
            auth.pub_key_sz = parsedPubSz;
            ESP_LOGI(TAG, "public key parsed (%lu bytes)", (unsigned long)parsedPubSz);
        } else {
            ESP_LOGW(TAG, "failed to parse public key: %d", ret);
        }
    }

    // ---- TCP connect --------------------------------------------------------

    ESP_LOGI(TAG, "connecting to %s:%u as %s", cfg->host, cfg->port, cfg->user);
    int fd = tcp_connect(cfg->host, cfg->port, timeout_ms);
    if (fd < 0 || s_session.stop_requested) {
        reason = -1;
        goto cleanup_ctx;
    }

    // ---- wolfSSH session setup ----------------------------------------------

    WOLFSSH *ssh = wolfSSH_new(ctx);
    if (!ssh) {
        ESP_LOGE(TAG, "wolfSSH_new failed");
        close(fd);
        reason = -1;
        goto cleanup_ctx;
    }
    s_session.ssh = ssh;

    wolfSSH_SetUserAuthCtx(ssh, &auth);
    wolfSSH_SetUsername(ssh, cfg->user);
    wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_TERMINAL, NULL, 0);
    wolfSSH_set_fd(ssh, fd);

    if (wolfSSH_connect(ssh) != WS_SUCCESS) {
        ESP_LOGE(TAG, "SSH handshake failed: %d", wolfSSH_get_error(ssh));
        close(fd);
        reason = wolfSSH_get_error(ssh);
        goto cleanup_ssh;
    }
    ESP_LOGI(TAG, "connected");

    // The connect timeout was needed for handshake only — clear it so the
    // session read loop blocks indefinitely (matches old inline ssh_term.c
    // behaviour; leaving SO_RCVTIMEO active causes spurious disconnects when
    // the server goes quiet for > timeout_ms).
    {
        struct timeval tv_zero = {0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_zero, sizeof(tv_zero));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv_zero, sizeof(tv_zero));
    }

    // Set PTY dimensions (window-change request immediately after connect).
    // wolfSSH_ChangeTerminalSize requires WOLFSSH_TERM && !NO_FILESYSTEM.
#if defined(WOLFSSH_TERM) && !defined(NO_FILESYSTEM)
    wolfSSH_ChangeTerminalSize(ssh, cols, rows, 0, 0);
#endif

    // ---- Drain any queued bytes, fire on_connected --------------------------

    {
        char discard;
        while (xQueueReceive(s_session.tx_queue, &discard, 0) == pdTRUE)
            ;
    }

    s_session.connected = true;
    if (cfg->callbacks.on_connected)
        cfg->callbacks.on_connected(cfg->callbacks.ctx);

    // ---- Start writer sub-task ---------------------------------------------

    uint32_t stack = cfg->task_stack_size ? cfg->task_stack_size
                                          : CONFIG_SSH_CLIENT_TASK_STACK_SIZE;
    uint8_t  prio  = cfg->task_priority   ? cfg->task_priority
                                          : CONFIG_SSH_CLIENT_TASK_PRIORITY;

    xTaskCreate(writer_task, "ssh_writer", stack / 4, ssh, prio,
                &s_session.writer_task);

    // ---- Read loop ----------------------------------------------------------

    uint8_t buf[512];
    while (!s_session.stop_requested) {
        int n = wolfSSH_stream_read(ssh, buf, sizeof(buf));
        if (n > 0) {
            if (cfg->callbacks.on_data)
                cfg->callbacks.on_data(buf, (size_t)n, cfg->callbacks.ctx);
        } else if (n == WS_CHANNEL_CLOSED || n == WS_EOF) {
            ESP_LOGI(TAG, "connection closed by server");
            break;
        } else if (n < 0 && n != WS_WANT_READ) {
            ESP_LOGE(TAG, "stream_read error: %d", n);
            reason = n;
            break;
        } else {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }

    // ---- Teardown -----------------------------------------------------------

    s_session.connected = false;

    // Signal writer task to exit and wait for it
    {
        char sentinel = '\0';
        xQueueSend(s_session.tx_queue, &sentinel, 0);
        for (int i = 0; i < 20 && s_session.writer_task != NULL; i++)
            vTaskDelay(pdMS_TO_TICKS(50));
    }

    close(fd);

cleanup_ssh:
    s_session.ssh = NULL;
    wolfSSH_free(ssh);

    // Free parsed key blobs allocated by wolfSSH_ReadKey_buffer
    if (auth.priv_key) free((void *)auth.priv_key);
    if (auth.pub_key)  free((void *)auth.pub_key);

cleanup_ctx:
    wolfSSH_CTX_free(ctx);

done:
    s_session.connected    = false;
    s_session.stop_requested = false;

    if (cfg->callbacks.on_disconnected)
        cfg->callbacks.on_disconnected(reason, cfg->callbacks.ctx);

    s_session.session_task = NULL;
    vTaskDelete(NULL);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

esp_err_t ssh_client_connect(const ssh_client_config_t *cfg)
{
    if (s_session.session_task != NULL)
        return ESP_ERR_INVALID_STATE;

    // Deep-copy config so caller's pointer need not remain valid
    s_session.cfg = *cfg;

    s_session.connected      = false;
    s_session.stop_requested = false;
    s_session.ssh            = NULL;
    s_session.writer_task    = NULL;

    if (!s_session.tx_queue) {
        s_session.tx_queue = xQueueCreate(CONFIG_SSH_CLIENT_TX_QUEUE_DEPTH,
                                          sizeof(char));
        if (!s_session.tx_queue)
            return ESP_ERR_NO_MEM;
    }

    uint32_t stack = cfg->task_stack_size ? cfg->task_stack_size
                                          : CONFIG_SSH_CLIENT_TASK_STACK_SIZE;
    uint8_t  prio  = cfg->task_priority   ? cfg->task_priority
                                          : CONFIG_SSH_CLIENT_TASK_PRIORITY;

    BaseType_t ret = xTaskCreate(session_task, "ssh_session", stack, NULL,
                                 prio, &s_session.session_task);
    return (ret == pdPASS) ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t ssh_client_send(const uint8_t *data, size_t len)
{
    if (!s_session.connected || !s_session.tx_queue)
        return ESP_ERR_INVALID_STATE;

    for (size_t i = 0; i < len; i++) {
        char ch = (char)data[i];
        if (xQueueSend(s_session.tx_queue, &ch, pdMS_TO_TICKS(10)) != pdTRUE)
            return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

esp_err_t ssh_client_resize(uint16_t cols, uint16_t rows)
{
    if (!s_session.connected || !s_session.ssh)
        return ESP_ERR_INVALID_STATE;

#if defined(WOLFSSH_TERM) && !defined(NO_FILESYSTEM)
    wolfSSH_ChangeTerminalSize(s_session.ssh, cols, rows, 0, 0);
    return ESP_OK;
#else
    (void)cols; (void)rows;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

void ssh_client_disconnect(void)
{
    s_session.stop_requested = true;
    // Poke the writer task in case it is blocked on the queue
    if (s_session.tx_queue) {
        char sentinel = '\0';
        xQueueSend(s_session.tx_queue, &sentinel, 0);
    }
}

bool ssh_client_is_connected(void)
{
    return s_session.connected;
}
