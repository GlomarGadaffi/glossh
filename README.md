# glossh

minimal SSH 2.0 server for ESP-IDF on PSA Crypto (curve25519 / aes256-gcm / ecdsa-p256). single-threaded, one client at a time, callback-driven. intended for device configuration consoles, not bulk transfer — no SFTP, no port forwarding, no agent forwarding.

fixed algorithm suite (modern, single path):
- **KEX**: curve25519-sha256 (+ kex-strict-s-v00@openssh.com)
- **Host key**: ecdsa-sha2-nistp256
- **Cipher**: aes256-gcm@openssh.com (AEAD; no separate MAC)
- **Auth**: password and/or publickey (ecdsa-sha2-nistp256)

## integration

```c
#include "littlessh.h"

lssh_config_t cfg = {
    .port = 22,
    .host_key = my_p256_private_scalar,  /* 32 bytes, big-endian; NULL = ephemeral */
    .auth_max_tries = 5,
    .auth_timeout_ms = 60000,            /* whole login budget; 0 = 60 s */
    .password_auth = my_password_check,  /* and/or .pubkey_auth */
    .on_open = my_shell_or_exec,
    .on_data = my_keystrokes,
    .on_pty = my_resize,                 /* optional */
    .on_tick = my_animation,             /* optional: periodic, between packets */
    .tick_ms = 66,
};
lssh_server_run(&cfg);   /* blocking accept loop, one connection at a time */
```

transport parameters:
- max packet: 4 KB (LSSH_MAX_PACKET) — negotiable at compile time
- channel window: 64 KB (LSSH_WINDOW)
- ephemeral host key if none provided: generated once per `lssh_server_run()`, so it changes per boot
- login deadline: a client gets `auth_timeout_ms` (default 60 s) from connect to successful auth, so a silent or trickling peer can't hold the single slot
- callbacks never nest: events that arrive while `lssh_write()` waits for window are queued and delivered after the current callback returns; `on_data`'s buffer stays valid across writes
- inbound channel packets capped at 1 KB (LSSH_MAX_PACKET / 4); one session, one shell/exec per channel
- `on_tick` runs every `tick_ms` while a channel is open (select() between packets); `recv_timeout_ms` still measures inbound silence, so ticks don't keep an idle client alive

## glotui

16-color ANSI-art terminal UI over any byte stream (`glotui/`). draw CP437 glyphs into a cell buffer; `gt_flush()` diffs against what the terminal shows and sends only the changes (a static screen costs ~1–4 KB/s with a clock and marquee running). palette defaults to the Apple IIgs 16; output as exact 24-bit, nearest xterm-256, ANSI-16, or raw CP437 for ANSI-BBS terminals (SyncTERM). BBS pipe codes (`|00`–`|31`), boxes, shadows, a key decoder for arrows/F-keys/Alt. no deps beyond libc.

## examples

both examples log in as `admin` / `changeme` � demo credentials, change them before the board goes on a network you don't own. the host key is generated once and kept in NVS, so pin it on first connect rather than disabling host key checking.

- `examples/esp32_shell` — line-oriented config shell over W5500 Ethernet (LilyGO T-ETH-ELITE S3).
- `examples/esp32_bbs` — **GLOSSH BBS**: an ANSI-art bulletin board in the IIgs palette on the same board. terminal check, dial-up with modem LEDs, C-Net-style block logo with GeoCities hit counter, KEEP-style main menu with an animated radio tower, bulletins, last callers, live system status (heap, CPU history), a Telix-style FreeRTOS task monitor, a persistent guestbook (NVS), fire/plasma/greetz art gallery, page-the-sysop, NO CARRIER. `ssh -t admin@<board-ip>` (password `changeme`). needs 80x24; uses up to 132x50.

run the BBS on a desktop first:

```sh
cd test/host && make
./bbs_host 2323          # then: ssh -p 2323 caller@127.0.0.1   (password: bbs)
```

## tests

`test/host`: `bash run_tests.sh` (littlessh vs OpenSSH: auth, pty, >4 KB lines, writes that outrun the window, client rekey, pre-auth deadline, ephemeral key stability; `rawssh.py` probes for what OpenSSH never sends: odd messages in KEX, unknown messages, re-auth, password change, env, oversized pty), `./glotui_test` (renderer, CP437, keys), `./wire32_test` (wire bounds with peer-sized lengths; also `make wire32_test_m32` for a 32-bit `size_t`, where `off + n` can wrap), `bash bbs_smoke.sh` (BBS end to end vs OpenSSH, incl. idle timeout under ticks). needs libmbedtls-dev, openssh-client, sshpass, python3-cryptography.

`bash tools/lint.sh` is the Power-of-10 gate for every `.c`/`.h` under littlessh/, run in a host and an `ESP_PLATFORM` configuration: cppcheck, clang-tidy (`.clang-tidy`: functions <= 60 lines and 60 statements, no recursion, every switch has a default, every result of a `LSSH_MUST_CHECK`/`psa_*`/`rd_*`/listed POSIX call used or cast to `(void)`, no comma operator) and `tools/p10_check.py` (no goto/setjmp after preprocessing, `LSSH_MUST_CHECK` on every non-void function, `LSSH_ASSERT` in every function and >= 2 per function on average, no constant asserts, no `#if 0`, no block macros, no calls in `?:` arms, no NOLINT/cppcheck-suppress/diagnostic pragmas). The header of `tools/lint.sh` maps each rule to its mechanism and lists the known limits. `bash tools/lint.sh --selftest` runs the real gate on a clean fixture (`tools/lint-fixture/`, must pass) and on one injected violation or negative control per rule, and fails unless each violation is reported at the injected line and each control passes.

## coding rules

littlessh/ follows Holzmann's Power of 10. `tools/lint.sh` checks what a tool can; the rest is review.

| # | rule | littlessh | enforced by |
|---|------|-----------|-------------|
| 1 | no goto, setjmp/longjmp, recursion | yes | p10-goto (source and preprocessed), misc-no-recursion |
| 2 | fixed loop bounds | yes, but for two event loops (below) | review; each bound is a buffer size or a named `LSSH_*` constant |
| 3 | no heap after init | yes: one `calloc` in `lssh_server_run()`, before the first `accept()` | review |
| 4 | functions <= 60 lines | yes | readability-function-size (60 lines, 60 statements), p10-function-lines |
| 5 | >= 2 asserts per function | yes: at least one in every function, 2.47 on average | p10-assert-missing, -density, -constant |
| 6 | smallest data scope | yes: file scope holds only const tables and the log tag | review |
| 7 | check every result, validate arguments | yes | `LSSH_MUST_CHECK` + clang-diagnostic-unused-result, bugprone-unused-return-value, cert-err33-c |
| 8 | limited preprocessor | yes, but for variadics (below) | p10-macro-braces, p10-config-probe, p10-if-constant, p10-macro-comma |
| 9 | one dereference level, no function pointers | no (below) | none |
| 10 | zero warnings, analysers on every change | analysers yes; compiler warnings (`-Wall -Wextra`) are not gated | cppcheck + clang-tidy, any diagnostic fails |

`LSSH_ASSERT` guards internal invariants and app misuse of the API only. anything the peer controls stays a disconnect: on ESP-IDF a failed assert reboots the board.

exceptions:
- rule 9: the API is callbacks, i.e. function pointers in `lssh_config_t`; their results are not checked by the gate either.
- rule 3 holds for littlessh's own code, not inside PSA: on ESP-IDF 6 every SHA-256 `psa_hash_setup` allocates (`heap_caps_malloc` in the hardware SHA driver), so each key exchange and publickey login touches the heap there.
- rule 8: `lssh_printf` uses stdarg, and the `LOGI`/`LOGW` macros are variadic.
- rule 2: the accept loop (`lssh_server_run`) and the per-connection loop (`serve_connection`) are event loops, bounded by `cfg->stop`, the auth deadline and the idle timeout rather than a count.
- glotui/ and examples/ are not under the gate: glotui allocates on terminal resize, the BBS reallocs its fire buffer.
- the gate has known limits (constructs it cannot see, holes left open from review); the header of `tools/lint.sh` lists them.

## protocol conformance

deviations kept on purpose:
- RFC 4253 §6.1 says implementations MUST accept 32768-byte payloads; littlessh caps packets at `LSSH_MAX_PACKET` (4 KB). clients send channel data within the 1 KB max packet we advertise and an OpenSSH KEXINIT is ~1.5 KB, while raising the cap costs RAM: six per-session buffers are sized by it.
- littlessh never initiates a rekey (RFC 4253 §9 RECOMMENDED after 1 GB or an hour). it answers client-initiated ones, and OpenSSH rekeys on its own.
- received padding is not checked (minimum length, random content): after key exchange AES-GCM authenticates the whole packet.

## why

bring remote console to microcontrollers without the overhead of OpenSSH or dropbear. justifiable in homelabs, field setups, and scenarios where the alternate (serial console over RF) requires human intervention. based on PSA Crypto for compatibility across ESP-IDF versions (mbedTLS 2.28/3.x/4.x).
