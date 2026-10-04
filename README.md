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

`test/host`: `bash run_tests.sh` (littlessh vs OpenSSH: auth, pty, >4 KB lines, writes that outrun the window, client rekey, pre-auth deadline, ephemeral key stability), `./glotui_test` (renderer, CP437, keys), `bash bbs_smoke.sh` (BBS end to end vs OpenSSH, incl. idle timeout under ticks). needs libmbedtls-dev, openssh-client, sshpass.

## why

bring remote console to microcontrollers without the overhead of OpenSSH or dropbear. justifiable in homelabs, field setups, and scenarios where the alternate (serial console over RF) requires human intervention. based on PSA Crypto for compatibility across ESP-IDF versions (mbedTLS 2.28/3.x/4.x).
