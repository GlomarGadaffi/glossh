/* GLOSSH BBS on a desktop: the ESP example's BBS over littlessh on POSIX.
 *   ./bbs_host [port] [idle_s]   then: ssh -p 2323 caller@127.0.0.1   (password: bbs)
 * SPDX-License-Identifier: MIT */
#include "littlessh.h"
#include "bbs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool pw_auth(void *u, const char *user, const char *pass){
    (void)u; (void)user;
    return strcmp(pass, "bbs") == 0;
}

int main(int argc, char **argv){
    uint16_t port = argc > 1 ? (uint16_t)atoi(argv[1]) : 2323;
    uint32_t idle_s = argc > 2 ? (uint32_t)atoi(argv[2]) : 15 * 60;
    static uint8_t hostkey[32];
    static char fp[64];
    if (lssh_hostkey_generate(hostkey)){ fprintf(stderr, "hostkey gen failed\n"); return 1; }
    lssh_hostkey_fingerprint(hostkey, fp, sizeof fp);
    fprintf(stderr, "bbs_host: port %u, host key %s, any user / password 'bbs'\n", port, fp);

    bbs_config_t bc = { .hostkey_fp = fp };
    bbs_init(&bc);
    lssh_config_t cfg = {
        .port = port,
        .listen_fd = -1,
        .host_key = hostkey,
        .recv_timeout_ms = idle_s * 1000,
        .banner = "GLOSSH BBS -- one line, one caller. Password: bbs\r\n",
        .password_auth = pw_auth,
        .on_open = bbs_on_open,
        .on_data = bbs_on_data,
        .on_pty = bbs_on_pty,
        .on_close = bbs_on_close,
        .on_tick = bbs_on_tick,
        .tick_ms = BBS_TICK_MS,
    };
    return lssh_server_run(&cfg);
}
