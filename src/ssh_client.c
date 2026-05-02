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
    ssh_client_config_t  cfg;           // deep copy of caller's config
    QueueHandle_t        tx_queue;      // keystrokes posted from any task
    TaskHandle_t         session_task;
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
    byte           key_type[64];   // key algorithm (e.g. "ssh-ed25519", "rsa-sha2-256")
    word32         key_type_sz;
} auth_ctx_t;

static int userauth_cb(byte authType, WS_UserAuthData *authData, void *ctx)
{
    auth_ctx_t *ac = (auth_ctx_t *)ctx;

    if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
        if (ac->pubkey_tried || ac->priv_key == NULL || ac->key_type_sz == 0)
            return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
        ac->pubkey_tried = true;
        authData->sf.publicKey.publicKeyType   = ac->key_type;
        authData->sf.publicKey.publicKeyTypeSz = ac->key_type_sz;
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
// Host-key check callback (wired to wolfSSH_CTX_SetPublicKeyCheck)
// ---------------------------------------------------------------------------

static int hostkey_check_cb(const byte *key, word32 keySz, void *ctx)
{
    ssh_client_config_t *cfg = (ssh_client_config_t *)ctx;
    if (cfg->callbacks.on_host_key == NULL)
        return 0;   // no application check registered → accept
    return cfg->callbacks.on_host_key(key, keySz, cfg->callbacks.ctx) ? 0 : -1;
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

    // Apply connect timeout via SO_RCVTIMEO / SO_SNDTIMEO
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
// Session task: connect → PTY → combined read/send loop → cleanup
//
// All wolfSSH I/O runs in this single task, eliminating concurrent access to
// the same WOLFSSH* from multiple tasks (wolfSSH has no per-session locking).
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
    wolfSSH_CTX_SetPublicKeyCheck(ctx, hostkey_check_cb);

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
            if (keyType && keyTypeSz > 0 && keyTypeSz < sizeof(auth.key_type)) {
                memcpy(auth.key_type, keyType, keyTypeSz);
                auth.key_type_sz = keyTypeSz;
            }
            ESP_LOGI(TAG, "private key parsed (%lu bytes, type %.*s)",
                     (unsigned long)parsedKeySz, (int)keyTypeSz,
                     keyType ? (const char *)keyType : "");
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
            // Fall back to pub key type if private key type wasn't captured
            if (auth.key_type_sz == 0 && pubType && pubTypeSz > 0 &&
                pubTypeSz < sizeof(auth.key_type)) {
                memcpy(auth.key_type, pubType, pubTypeSz);
                auth.key_type_sz = pubTypeSz;
            }
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
    wolfSSH_SetPublicKeyCheckCtx(ssh, cfg);  // ctx arg for hostkey_check_cb

    if (wolfSSH_connect(ssh) != WS_SUCCESS) {
        ESP_LOGE(TAG, "SSH handshake failed: %d", wolfSSH_get_error(ssh));
        close(fd);
        reason = wolfSSH_get_error(ssh);
        goto cleanup_ssh;
    }
    ESP_LOGI(TAG, "connected");

    // Replace the handshake timeout with a short read timeout so the loop can
    // service the TX queue between reads.  wolfSSH translates EAGAIN to
    // WS_WANT_READ (io.c), which the loop treats as "no data — keep going".
    {
        struct timeval tv_read = { .tv_sec = 0, .tv_usec = 10000 };  // 10 ms
        struct timeval tv_zero = {0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_read, sizeof(tv_read));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv_zero, sizeof(tv_zero));
    }

    // Set PTY dimensions (window-change request immediately after connect).
#if defined(WOLFSSH_TERM) && !defined(NO_FILESYSTEM)
    wolfSSH_ChangeTerminalSize(ssh, cols, rows, 0, 0);
#endif

    // Drain any queued bytes that arrived before the session was ready
    {
        char discard;
        while (xQueueReceive(s_session.tx_queue, &discard, 0) == pdTRUE)
            ;
    }

    s_session.connected = true;
    if (cfg->callbacks.on_connected)
        cfg->callbacks.on_connected(cfg->callbacks.ctx);

    // ---- Combined read + TX-drain loop --------------------------------------
    //
    // All wolfSSH calls are serialised in this single task.  The 10 ms
    // SO_RCVTIMEO ensures wolfSSH_stream_read returns promptly (WS_WANT_READ)
    // when the server is quiet, giving the TX drain a chance to run.

    uint8_t buf[512];
    while (!s_session.stop_requested) {
        // Drain TX queue into a batch, then send
        {
            char   tx[64];
            int    tx_len = 0;
            char   ch;
            while (tx_len < (int)sizeof(tx) &&
                   xQueueReceive(s_session.tx_queue, &ch, 0) == pdTRUE) {
                if (ch == '\0') { s_session.stop_requested = true; break; }
                tx[tx_len++] = ch;
            }
            if (tx_len > 0)
                wolfSSH_stream_send(ssh, (byte *)tx, tx_len);
        }
        if (s_session.stop_requested) break;

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
        }
    }

    // ---- Teardown -----------------------------------------------------------

    s_session.connected = false;
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
    s_session.connected     = false;
    s_session.stop_requested = false;

    // Free deep-copied strings/buffers allocated in ssh_client_connect
    free((void *)cfg->host);
    free((void *)cfg->user);
    free((void *)cfg->password);
    free((void *)cfg->privkey_pem);
    free((void *)cfg->pubkey_pem);

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

    // Copy scalars first, then deep-copy every string/buffer pointer so the
    // caller's allocations can be freed as soon as this function returns.
    s_session.cfg             = *cfg;
    s_session.cfg.host        = NULL;
    s_session.cfg.user        = NULL;
    s_session.cfg.password    = NULL;
    s_session.cfg.privkey_pem = NULL;
    s_session.cfg.pubkey_pem  = NULL;

    if (cfg->host     && !(s_session.cfg.host     = strdup(cfg->host)))     goto oom;
    if (cfg->user     && !(s_session.cfg.user     = strdup(cfg->user)))     goto oom;
    if (cfg->password && !(s_session.cfg.password = strdup(cfg->password))) goto oom;
    if (cfg->privkey_pem && cfg->privkey_pem_len > 0) {
        uint8_t *p = malloc(cfg->privkey_pem_len);
        if (!p) goto oom;
        memcpy(p, cfg->privkey_pem, cfg->privkey_pem_len);
        s_session.cfg.privkey_pem = p;
    }
    if (cfg->pubkey_pem && cfg->pubkey_pem_len > 0) {
        uint8_t *p = malloc(cfg->pubkey_pem_len);
        if (!p) goto oom;
        memcpy(p, cfg->pubkey_pem, cfg->pubkey_pem_len);
        s_session.cfg.pubkey_pem = p;
    }

    s_session.connected      = false;
    s_session.stop_requested = false;
    s_session.ssh            = NULL;

    if (!s_session.tx_queue) {
        s_session.tx_queue = xQueueCreate(CONFIG_SSH_CLIENT_TX_QUEUE_DEPTH,
                                          sizeof(char));
        if (!s_session.tx_queue) goto oom;
    }

    uint32_t stack = cfg->task_stack_size ? cfg->task_stack_size
                                          : CONFIG_SSH_CLIENT_TASK_STACK_SIZE;
    uint8_t  prio  = cfg->task_priority   ? cfg->task_priority
                                          : CONFIG_SSH_CLIENT_TASK_PRIORITY;

    BaseType_t ret = xTaskCreate(session_task, "ssh_session", stack, NULL,
                                 prio, &s_session.session_task);
    if (ret != pdPASS) goto oom;
    return ESP_OK;

oom:
    free((void *)s_session.cfg.host);
    free((void *)s_session.cfg.user);
    free((void *)s_session.cfg.password);
    free((void *)s_session.cfg.privkey_pem);
    free((void *)s_session.cfg.pubkey_pem);
    return ESP_ERR_NO_MEM;
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
}

bool ssh_client_is_connected(void)
{
    return s_session.connected;
}
