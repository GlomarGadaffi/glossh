# glossh

an SSH console for microcontrollers. `ssh admin@<board>` and you're on the device: a config shell, a status screen, or a full ANSI-art BBS.

- **littlessh**: a minimal SSH 2.0 server for ESP-IDF, built on PSA Crypto. one modern algorithm suite, one client at a time, callback-driven.
- **glotui**: a 16-color ANSI-art terminal UI that draws into a cell buffer and sends only what changed.
- **examples**: a config shell and **GLOSSH BBS**, both on a LilyGO T-ETH-ELITE S3 (ESP32-S3 + W5500 Ethernet).

it is meant for device consoles, not bulk transfer: no SFTP, no port forwarding, no agent forwarding.

status: v0.3.1. host-tested against OpenSSH 10 in CI; the examples build warning-free with ESP-IDF 6.0.2. **not yet tested on hardware.**

## try it on a desktop

the BBS runs on Linux with the same littlessh and glotui code:

```sh
sudo apt install build-essential libmbedtls-dev openssh-client
cd test/host && make bbs_host
./bbs_host 2323
ssh -p 2323 caller@127.0.0.1        # password: bbs
```

it needs an 80x24 terminal and uses up to 132x50.

## littlessh

fixed algorithm suite:

| | |
|---|---|
| key exchange | curve25519-sha256, with strict KEX (kex-strict-s-v00@openssh.com) |
| host key | ecdsa-sha2-nistp256 |
| cipher | aes256-gcm@openssh.com |
| user auth | password and/or publickey (ecdsa-sha2-nistp256) |

PSA Crypto keeps it portable across ESP-IDF 5.x and 6.x (mbedTLS 2.28, 3.x, 4.x). the same file builds on POSIX for testing.

### use

```c
#include "littlessh.h"

static bool check_pw(void *u, const char *user, const char *pass){ ... }
static void on_open(void *u, lssh_session_t *s, const char *exec_cmd){ ... }   /* shell or exec */
static void on_data(void *u, lssh_session_t *s, const uint8_t *d, size_t n){ ... }

lssh_config_t cfg = {
    .port            = 22,
    .host_key        = key,          /* 32-byte P-256 scalar; keep it in NVS */
    .password_auth   = check_pw,     /* and/or .pubkey_auth */
    .on_open         = on_open,
    .on_data         = on_data,
    .recv_timeout_ms = 15 * 60 * 1000,
};
int rc = lssh_server_run(&cfg);      /* blocking accept loop; give it its own task, >= 8 KB stack */
```

`lssh_hostkey_generate()` makes a key to store, and `lssh_hostkey_fingerprint()` gives its `SHA256:...` fingerprint for the boot log, so you can pin it on first connect. with `host_key = NULL` the server makes an ephemeral key once per run, which is fine for bring-up and wrong for production.

in callbacks, `lssh_write()`, `lssh_printf()` and `lssh_exit()` talk to the client, and `lssh_username()`, `lssh_has_pty()`, `lssh_term()` and `lssh_client_version()` describe it. `littlessh.h` documents every field and return code.

### what it guarantees

- **one client at a time**, and an unauthenticated one can't hold the slot: the whole login has to finish within `auth_timeout_ms` (default 60 s).
- **callbacks never nest.** if a write has to wait for the client's window, input that arrives meanwhile is queued and delivered after the current callback returns. the buffer `on_data` gets stays valid for the whole call.
- **`on_tick`** (optional, every `tick_ms`) drives animation and live screens between packets. `recv_timeout_ms` still measures input silence, so ticks don't keep an idle client alive.
- **bounded everything.** packets up to 4 KB (`LSSH_MAX_PACKET`), a 64 KB channel window (`LSSH_WINDOW`), 1 KB inbound channel packets, one session channel, one shell or exec per channel, and a cap on every loop.
- **no heap after start.** one allocation in `lssh_server_run()` before the first `accept()`. (PSA's SHA driver on ESP-IDF 6 still allocates inside its own calls.)
- **secrets are wiped:** key-exchange material after every exchange, the session (password included) at the end of every connection.

## glotui

a terminal UI over any byte stream (`glotui/`). draw CP437 glyphs into a cell buffer; `gt_flush()` diffs it against what the terminal shows and sends only the changes, so a static screen with a clock and marquee costs about 1-4 KB/s.

- palette: the Apple IIgs 16 by default, sent as exact 24-bit color, nearest xterm-256, ANSI-16, or raw CP437 for ANSI-BBS terminals like SyncTERM
- BBS pipe codes (`|00`-`|31`), boxes, shadows, views with clipping
- a key decoder for arrows, F-keys and Alt
- no dependencies beyond libc

## examples

both log in as `admin` / `changeme`. these are demo credentials: change them before the board goes on a network you don't own. the host key is generated on first boot and kept in NVS.

| | |
|---|---|
| `examples/esp32_shell` | a line-oriented config shell |
| `examples/esp32_bbs` | **GLOSSH BBS**: terminal check, dial-up with modem LEDs, a main menu with an animated radio tower, bulletins, last callers, live system status, a FreeRTOS task monitor, a guestbook kept in NVS, a fire/plasma/greetz art gallery, page-the-sysop, NO CARRIER |

build and flash (ESP-IDF 5.x or 6.x):

```sh
cd examples/esp32_bbs
idf.py set-target esp32s3
idf.py build flash monitor
```

then `ssh -t admin@<board-ip>`. the IP and host key fingerprint are in the boot log.

## tests

`test/host`, on Linux, needs `libmbedtls-dev openssh-client sshpass python3-cryptography`:

| | |
|---|---|
| `bash run_tests.sh` | littlessh against OpenSSH: auth, pty, long lines, writes that outrun the window, client rekey, the login deadline. `rawssh.py`, a small encrypted probe client, sends what OpenSSH never does: stray messages mid-KEX, unknown messages, re-auth, password change, oversized pty sizes |
| `./wire32_test` | wire bounds with peer-sized lengths. `make wire32_test_m32` builds it with a 32-bit `size_t`, as on the ESP32, where `off + n` can wrap |
| `./glotui_test` | renderer, CP437, key decoding |
| `bash bbs_smoke.sh` | the BBS end to end against OpenSSH |

CI runs all of it on every push, plus the lint gate below.

## coding rules

littlessh/ follows Holzmann's Power of 10, checked by `bash tools/lint.sh`: cppcheck, clang-tidy and `tools/p10_check.py`, each run in a host and an `ESP_PLATFORM` configuration. any diagnostic fails the gate. `bash tools/lint.sh --selftest` proves the gate itself catches each rule by injecting violations into a clean fixture.

| # | rule | littlessh | enforced by |
|---|------|-----------|-------------|
| 1 | no goto, setjmp/longjmp, recursion | yes | p10-goto (source and preprocessed), misc-no-recursion |
| 2 | fixed loop bounds | yes, except two event loops | review; each bound is a buffer size or a named `LSSH_*` constant |
| 3 | no heap after init | yes | review |
| 4 | functions <= 60 lines | yes, and <= 60 statements | readability-function-size, p10-function-lines |
| 5 | >= 2 asserts per function | at least one in every function, 2.47 on average | p10-assert-missing, -density, -constant |
| 6 | smallest data scope | yes | review |
| 7 | check every result | yes | `LSSH_MUST_CHECK`, bugprone-unused-return-value, cert-err33-c |
| 8 | limited preprocessor | yes, except variadics | p10-macro-braces, p10-config-probe, p10-if-constant, p10-macro-comma |
| 9 | one dereference level, no function pointers | no: the API is callbacks | none |
| 10 | zero warnings, analysers on every change | analysers yes; compiler warnings are not gated | cppcheck, clang-tidy |

`LSSH_ASSERT` checks internal invariants and API misuse by the app, never anything the peer controls: on ESP-IDF a failed assert reboots the board, so peer input that breaks a rule gets a disconnect instead.

exceptions:
- rule 2: the accept loop and the per-connection loop are event loops, bounded by `cfg->stop`, the login deadline and the idle timeout rather than a count.
- rule 8: `lssh_printf` uses stdarg and the log macros are variadic.
- glotui/ and examples/ are not under the gate: glotui allocates on terminal resize, the BBS reallocs its fire buffer.
- the gate's known limits are listed in the header of `tools/lint.sh`.

## protocol conformance

littlessh follows RFC 4252, 4253 and 4254, with these deviations kept on purpose:

- **packet size.** RFC 4253 §6.1 asks servers to accept 32 KB payloads. littlessh caps packets at 4 KB because six per-session buffers scale with the cap. clients send channel data within the 1 KB max packet littlessh advertises, and an OpenSSH KEXINIT is about 1.5 KB.
- **rekeying.** littlessh never starts a rekey (RFC 4253 §9 recommends one after 1 GB or an hour). it answers the client's, and OpenSSH rekeys on its own.
- **padding.** received padding isn't checked, because AES-GCM authenticates the whole packet.

## why

a remote console on a microcontroller without the weight of OpenSSH or dropbear: for homelabs, field installs, and anywhere the alternative is a serial cable or a site visit.

## license

Apache-2.0.
