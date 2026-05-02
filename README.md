# esp32-wolfssh-client

An ESP-IDF component that wraps [wolfSSH](https://www.wolfssl.com/products/wolfssh/) as a
FreeRTOS task with a clean callback API.  The hard part — getting wolfSSH to compile and
run correctly on ESP32 targets — is done for you.

## What this solves

Getting wolfSSH working on ESP32/FreeRTOS requires:

- A carefully tuned `user_settings.h` for wolfSSL (wrong settings → compile errors or
  silent runtime failures).
- A non-obvious threading model: wolfSSH blocks; keystrokes need a thread-safe queue.
- A specific session setup sequence: connect → channel open → PTY request → shell request
  → read/write loop.

None of this is in wolfSSH's ESP32 examples.  This component encodes all of it.

## What the component does NOT do

- VT100/ANSI parsing — use libvterm or similar; wire the `on_data` callback.
- Display anything — render callbacks are the application's job.
- Keyboard input wiring — call `ssh_client_send()` from whatever source you have.
- Store SSH targets — NVS schema is application-specific.

## Quick start

### 1. Add the component

In your project's `main/idf_component.yml`:

```yaml
dependencies:
  dmatking/esp32-wolfssh-client: ">=0.1.0"
```

For local development, use a path dependency instead:

```yaml
dependencies:
  esp32-wolfssh-client:
    path: /path/to/esp32-wolfssh-client
```

### 2. Initialize wolfSSH once at startup

```c
#include "esp_wolfssh_client.h"
#include <wolfssh/ssh.h>

wolfSSH_Init();  // call once, before ssh_client_connect()
```

### 3. Connect

```c
static void on_data(const uint8_t *data, size_t len, void *ctx) {
    // feed into your VT100 parser / terminal renderer
}

static void on_disconnected(int reason, void *ctx) {
    // schedule a reconnect if desired
}

ssh_client_config_t cfg = {
    .host     = "192.168.1.1",
    .port     = 22,
    .user     = "myuser",
    .password = "mypassword",   // or set privkey_pem/pubkey_pem for key auth
    .term_cols = 80,
    .term_rows = 24,
    .callbacks = {
        .on_data         = on_data,
        .on_disconnected = on_disconnected,
    },
};
ssh_client_connect(&cfg);
```

### 4. Send keystrokes

```c
// From any FreeRTOS task (e.g. BLE keyboard callback)
ssh_client_send(key_bytes, len);
```

### 5. Resize the terminal

```c
ssh_client_resize(new_cols, new_rows);
```

## Public API

```c
esp_err_t ssh_client_connect(const ssh_client_config_t *cfg);
esp_err_t ssh_client_send(const uint8_t *data, size_t len);
esp_err_t ssh_client_resize(uint16_t cols, uint16_t rows);
void      ssh_client_disconnect(void);
bool      ssh_client_is_connected(void);
```

See `include/esp_wolfssh_client.h` for full documentation.

## Security

### Host-key verification

By default, the component accepts any server host key.  This is convenient for
LAN-only embedded terminals connecting to a known device, but it means a
man-in-the-middle on the network path can silently intercept the session —
credentials, keystrokes, and output — without any indication to the application.

To verify the server's identity, implement `on_host_key` in your callbacks:

```c
static bool my_host_key_check(const uint8_t *key, size_t len, void *ctx)
{
    // Compare key/len against a pinned fingerprint or a stored known-hosts entry.
    // Return true to accept, false to abort the connection.
    return check_known_host(key, len);
}

ssh_client_config_t cfg = {
    ...
    .callbacks = {
        .on_host_key = my_host_key_check,
        ...
    },
};
```

The raw key bytes are passed as-is from wolfSSH's host-key exchange.  The
application is responsible for pinning, TOFU (trust-on-first-use), or
known-hosts comparison — the component deliberately avoids NVS host-key storage
since that schema is application-specific.

If `on_host_key` is NULL (the default), all host keys are accepted.

## Multi-session note

Only one SSH session is active at a time.  `ssh_client_connect()` returns
`ESP_ERR_INVALID_STATE` if called while a session is running.  Call
`ssh_client_disconnect()` and wait for `on_disconnected` before reconnecting.

## Bundled wolfssh

A copy of [wolfSSH](https://github.com/wolfSSL/wolfssh) v1.4.20 is bundled in `wolfssh/`
(BSD-3 license).  wolfSSL itself is declared as a registry dependency and pulled in
automatically.

## License

Component code: Apache-2.0.
Bundled wolfSSH: BSD-3 (see `wolfssh/LICENSE.txt`).
wolfSSL (registry dependency): GPL-2.0 or commercial — see wolfSSL's terms.
