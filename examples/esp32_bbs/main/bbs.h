/* GLOSSH BBS: an ANSI-art bulletin board in the Apple IIgs palette, served
 * over littlessh and drawn with glotui. One caller at a time, like a
 * single-line board.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef BBS_H
#define BBS_H

#include "littlessh.h"

#define BBS_TICK_MS   66       /* ~15 fps */
#define BBS_MAX_COLS  132      /* canvas cap: 2 x 4 bytes per cell */
#define BBS_MAX_ROWS  50
/* Art Gallery effects repaint most of the screen every frame; frames are
 * paced so their output stays under this many bytes per second. */
#define BBS_ART_BYTES_PER_S (96 * 1024)

typedef struct {
    const char *hostkey_fp;    /* "SHA256:..." shown on System Status */
} bbs_config_t;

/* Loads persisted state (caller count, last callers, guestbook). */
void bbs_init(const bbs_config_t *cfg);

/* littlessh callbacks: set on_tick = bbs_on_tick, tick_ms = BBS_TICK_MS. */
void bbs_on_open(void *user, lssh_session_t *s, const char *exec_cmd);
void bbs_on_data(void *user, lssh_session_t *s, const uint8_t *data, size_t len);
void bbs_on_pty(void *user, lssh_session_t *s, uint16_t cols, uint16_t rows);
void bbs_on_tick(void *user, lssh_session_t *s);
void bbs_on_close(void *user, lssh_session_t *s);

#endif /* BBS_H */
