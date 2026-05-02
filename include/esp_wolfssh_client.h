#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Callbacks delivered by the SSH client task.
 *
 * All callbacks are invoked from the SSH client FreeRTOS task.
 * Keep them short; do not call ssh_client_send() from inside on_data
 * (it posts to a queue and is safe, but unnecessary).
 */
typedef struct {
    /** Raw terminal bytes from the remote shell. Feed into a VT100 parser. */
    void (*on_data)(const uint8_t *data, size_t len, void *ctx);
    /** Called once the SSH session is established and the shell is open. */
    void (*on_connected)(void *ctx);
    /**
     * Called when the session ends for any reason.
     * @param reason  0 = normal close, negative = wolfSSH error code
     */
    void (*on_disconnected)(int reason, void *ctx);
    /**
     * Called once during the SSH handshake with the server's raw host key.
     * Return true to accept the key and continue, false to abort.
     * If NULL, all server host keys are accepted without verification —
     * the connection is vulnerable to MITM on untrusted networks.
     */
    bool (*on_host_key)(const uint8_t *key, size_t len, void *ctx);
    /** Passed as the last argument to every callback. */
    void *ctx;
} ssh_client_callbacks_t;

/**
 * @brief Configuration for an SSH connection.
 *
 * Authentication: supply either (privkey_pem + pubkey_pem) for public-key
 * auth, or password for password auth.  If both are provided, public-key
 * is tried first.
 *
 * Zero values for numeric fields use the Kconfig defaults.
 */
typedef struct {
    const char    *host;              /**< Hostname or IP string */
    uint16_t       port;              /**< TCP port (typically 22) */
    const char    *user;              /**< SSH username */

    /** OpenSSH-format private key PEM bytes (including header/footer).
     *  NULL → skip public-key auth. */
    const uint8_t *privkey_pem;
    size_t         privkey_pem_len;

    /** SSH public key bytes (the "ssh-ed25519 AAAA..." wire format).
     *  NULL → skip public-key auth. */
    const uint8_t *pubkey_pem;
    size_t         pubkey_pem_len;

    /** Password string. NULL → skip password auth. */
    const char    *password;

    uint16_t term_cols;           /**< PTY columns  (0 = Kconfig default) */
    uint16_t term_rows;           /**< PTY rows     (0 = Kconfig default) */

    ssh_client_callbacks_t callbacks;

    /** Override stack size for the SSH session task. 0 = Kconfig default. */
    uint32_t task_stack_size;
    /** Override task priority. 0 = Kconfig default. */
    uint8_t  task_priority;
    /** TCP connect + SSH handshake timeout in ms. 0 = Kconfig default. */
    uint32_t connect_timeout_ms;
} ssh_client_config_t;

/**
 * @brief Start an SSH session.
 *
 * Spawns a FreeRTOS task that performs the TCP connect, SSH handshake, PTY
 * request, and shell setup, then enters the read loop.  Returns immediately
 * after the task is created.
 *
 * Only one session is supported at a time.  If a session is already active,
 * returns ESP_ERR_INVALID_STATE.
 *
 * @param cfg  Connection configuration.  The pointer need not remain valid
 *             after this call returns — the config is copied internally.
 * @return ESP_OK on task creation success, or an error code.
 */
esp_err_t ssh_client_connect(const ssh_client_config_t *cfg);

/**
 * @brief Send bytes to the remote shell.
 *
 * Posts bytes to an internal queue consumed by the SSH writer task.
 * Safe to call from any FreeRTOS task.
 *
 * @param data  Bytes to send (e.g. keystrokes).
 * @param len   Number of bytes.
 * @return ESP_OK, or ESP_ERR_INVALID_STATE if not connected.
 */
esp_err_t ssh_client_send(const uint8_t *data, size_t len);

/**
 * @brief Notify the remote shell of a terminal resize.
 *
 * Sends an SSH window-change request.  Safe to call from any task.
 *
 * @param cols  New column count.
 * @param rows  New row count.
 * @return ESP_OK, or ESP_ERR_INVALID_STATE if not connected.
 */
esp_err_t ssh_client_resize(uint16_t cols, uint16_t rows);

/**
 * @brief Request disconnection.
 *
 * Signals the session task to close the connection and exit.  The
 * on_disconnected callback fires once cleanup is complete.  Non-blocking.
 */
void ssh_client_disconnect(void);

/** @return true if a session task is running and the shell is open. */
bool ssh_client_is_connected(void);

#ifdef __cplusplus
}
#endif
