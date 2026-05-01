# TODO

Polish items from the 2026-04-30 review.  Substantive issues (🔴/🟡) are tracked
on GitHub:

- [#1](https://github.com/dmatking/esp32-wolfssh-client/issues/1) — deep-copy strings/key buffers in `ssh_client_config_t`
- [#2](https://github.com/dmatking/esp32-wolfssh-client/issues/2) — host-key verification
- [#3](https://github.com/dmatking/esp32-wolfssh-client/issues/3) — verify wolfSSH thread-safety for concurrent read+send
- [#4](https://github.com/dmatking/esp32-wolfssh-client/issues/4) — honour parsed key type instead of hardcoding `ssh-ed25519`

The items below are nice-to-have follow-ups; not blockers for 0.1.0.

---

## Batch keystrokes through the TX queue

**Where:** `src/ssh_client.c` — queue created with `sizeof(char)` slots
(line 349); writer dequeues one byte and calls `wolfSSH_stream_send(ssh, &ch, 1)`
(line 124).

**Problem:** every keystroke is a separate queue op + a separate
`wolfSSH_stream_send` call.  Fine for human typing, wasteful for paste / key
repeat / programmatic input.  Each `stream_send` may also generate its own SSH
packet depending on Nagle / wolfSSH internal buffering.

**Fix:** queue elements of e.g. `struct { uint8_t buf[16]; uint8_t len; }`,
have `ssh_client_send` coalesce contiguous bytes into a single queue entry, and
the writer call `wolfSSH_stream_send(ssh, e.buf, e.len)`.

---

## Replace `WS_WANT_READ` polling with `select()`

**Where:** `src/ssh_client.c:289-291` —

```c
} else {
    vTaskDelay(pdMS_TO_TICKS(10));
}
```

**Problem:** up to 10 ms of latency added to every server-driven byte when the
read loop happens to land on `WS_WANT_READ`.  Visible during slow interactive
output; invisible during steady streaming.

**Fix:** call `select(fd+1, &rfds, NULL, NULL, &tv)` (or `poll`) before the
`wolfSSH_stream_read` call so the task wakes the moment the fd is readable.
Keep a short timeout so `stop_requested` is still honoured promptly.

---

## Add a `ssh_client_deinit()` symmetric with `wolfSSH_Init()`

**Where:** README tells callers to call `wolfSSH_Init()` once.  No counterpart.

**Problem:** wolfSSH exports `wolfSSH_Cleanup()`.  Component should either
call it from a `ssh_client_deinit()` for callers that tear down at runtime, or
the README should note that init is one-shot for the process lifetime.

**Fix:** trivial — add `ssh_client_deinit()` that calls `wolfSSH_Cleanup()`
and frees `s_session.tx_queue`.  Or just document the omission.

---

## Document `writer_task` stack sizing

**Where:** `src/ssh_client.c:271` — `xTaskCreate(writer_task, ..., stack / 4, ...)`.

**Problem:** the `/4` is a magic number.  Writer only does
`xQueueReceive` + `wolfSSH_stream_send`, but `stream_send` can dive into
wolfSSL crypto post-handshake (rekey).  4 KB on a 16 KB session-task default
is probably fine; should be either a separate Kconfig (`WRITER_TASK_STACK`) or
a comment justifying the ratio.

**Fix:** add a Kconfig entry or a one-line comment.

---

## Out of scope

- Multi-session support.  Single session is documented and the `s_session`
  static is fine for the embedded use case.  Don't refactor speculatively.
- Migrating off wolfSSH.  The component exists *because* wolfSSH+wolfSSL is the
  right pick for the IDF crypto stack.
