/* GLOSSH BBS: screens, input and littlessh session glue.
 *
 * Every tick (and after every keystroke) the current screen is redrawn in
 * full into glotui's back buffer; gt_flush() sends only what changed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "bbs.h"
#include "bbs_art.h"
#include "bbs_plat.h"
#include "glotui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_W 80
#define PAGE_H 22

enum { S_EMU, S_DIAL, S_MENU, S_BULLETINS, S_CALLERS, S_SYSTEM, S_TASKS, S_GUESTBOOK, S_ART, S_BYE };
enum { O_NONE, O_SIGN, O_PAGE, O_LOGOFF };

/* ------------------------------------------------------ persisted state */

#define STATS_MAGIC 0x474C4F01u
#define GB_MAGIC    0x474C4201u
#define CALLERS_MAX 8
#define GB_MAX      12

typedef struct { char user[16]; char client[24]; uint32_t when, num; } caller_t;
typedef struct {
    uint32_t magic, calls;
    uint8_t  n, head, pad[2];
    caller_t last[CALLERS_MAX];
} stats_t;

typedef struct { char name[20], from[20], msg[64]; uint32_t when, num; } gb_entry_t;
typedef struct {
    uint32_t   magic, total;
    uint8_t    n, head, pad[2];
    gb_entry_t e[GB_MAX];
} guestbook_t;

static bbs_config_t s_cfg;
static stats_t      s_stats;
static guestbook_t  s_gb;
static uint16_t     s_pty_cols = 80, s_pty_rows = 24;

/* newest-first index into a ring */
static int ring_idx(int head, int i, int cap){ return (head - 1 - i + cap * 2) % cap; }

/* ------------------------------------------------------- session state */

typedef struct { char buf[64]; uint8_t len, max; } field_t;

static struct {
    lssh_session_t *s;
    gt_t      *t;
    gt_keys_t  keys;
    bool       active, leaving, emu_done;
    uint32_t   tick, caller_no;
    uint64_t   t_login, t_screen, t_overlay;
    int        bells;
    int        screen, overlay, sel, scroll;

    int        emu_sel;
    size_t     reveal;          /* dial: glyphs of the logo revealed so far */
    bool       reveal_all;

    uint64_t   t_sample;
    bbs_sys_t  sys;
    bbs_task_t tasks[BBS_MAX_TASKS];
    int        ntasks, task_sort;
    int16_t    busy, hist[36];
    int        nhist;

    int        gb_page, f_sel;
    field_t    f[3];
    const char *gb_err;

    int        art_fx;
    art_fire_t fire;
    size_t     fire_cap;
    uint64_t   art_next;        /* earliest time for the next effect frame */

    /* lssh_write() may pump inbound packets while a frame is going out, so
     * callbacks can arrive mid-render: queue their input, defer teardown */
    bool       in_render, closed;
    uint8_t    pending[64];
    size_t     npending;
} B;

/* ------------------------------------------------------------- helpers */

static void fmt_dur(uint64_t ms, char *out, size_t n){
    unsigned s = (unsigned)(ms / 1000);
    snprintf(out, n, "%02u:%02u:%02u", s / 3600, (s / 60) % 60, s % 60);
}

static void fmt_bytes(uint32_t b, char *out, size_t n){
    if (b >= 10u * 1024 * 1024) snprintf(out, n, "%u MB", (unsigned)(b >> 20));
    else if (b >= 1024 * 1024) snprintf(out, n, "%u.%u MB", (unsigned)(b >> 20), (unsigned)((b & 0xFFFFF) * 10 >> 20));
    else if (b >= 10 * 1024) snprintf(out, n, "%u KB", (unsigned)(b >> 10));
    else snprintf(out, n, "%u B", (unsigned)b);
}

static void fmt_when(uint32_t when, char *out, size_t n){
    if (!when){ snprintf(out, n, "--"); return; }
    time_t tt = (time_t)when;
    struct tm tm;
    localtime_r(&tt, &tm);
    strftime(out, n, "%a %d %b %H:%M", &tm);
}

/* stored guestbook/caller text is CP437 bytes, not UTF-8 */
static int put_cp437(gt_t *t, int x, int y, uint8_t fg, uint8_t bg, const char *s, int maxw){
    int i = 0;
    for (; s[i] && i < maxw; i++) gt_put(t, x + i, y, (uint8_t)s[i], fg, bg);
    return i;
}

static void copy_ascii(char *dst, size_t n, const char *src){
    size_t i = 0;
    for (; src[i] && i + 1 < n; i++) dst[i] = (src[i] >= 0x20 && src[i] < 0x7F) ? src[i] : '?';
    dst[i] = 0;
}

static const char *mode_name(gt_mode_t m){
    switch (m){
    case GT_MODE_TRUECOLOR: return "IIgs 24-bit";
    case GT_MODE_256:       return "xterm-256";
    case GT_MODE_16:        return "ANSI-16";
    default:                return "ANSI-BBS";
    }
}

static gt_mode_t detect_mode(const char *term){
    if (strstr(term, "sync") || strstr(term, "bbs") || !strcmp(term, "ansi")) return GT_MODE_ANSIBBS;
    if (!strncmp(term, "linux", 5) || !strncmp(term, "vt", 2)) return GT_MODE_16;
    if (!strncmp(term, "screen", 6) || !strncmp(term, "tmux", 4)) return GT_MODE_256;
    return GT_MODE_TRUECOLOR;
}

static void go(int screen){
    B.screen = screen;
    B.t_screen = bbs_plat_ms();
    B.sel = B.scroll = 0;
    B.overlay = O_NONE;
    if (screen == S_DIAL){ B.reveal = 0; B.reveal_all = false; }
}

static void window(gt_t *t, int x, int y, int w, int h, uint8_t frame, uint8_t bg, const char *title){
    gt_fill(t, x, y, w, h, ' ', GT_LIGHT_GRAY, bg);
    gt_box(t, x, y, w, h, GT_BOX_DOUBLE, frame, bg);
    gt_shadow(t, x, y, w, h);
    if (title){
        int tw = gt_strwidth(title) + 2;
        gt_put(t, x + (w - tw) / 2, y, ' ', GT_WHITE, bg);
        gt_text(t, x + (w - tw) / 2 + 1, y, GT_WHITE, bg, title);
        gt_put(t, x + (w - tw) / 2 + tw - 1, y, ' ', GT_WHITE, bg);
    }
}

static void bar(gt_t *t, int x, int y, int w, int permille){
    int fill = (permille * w + 500) / 1000;
    uint8_t c = permille < 600 ? GT_LIGHT_GREEN : permille < 850 ? GT_YELLOW : GT_DEEP_RED;
    for (int i = 0; i < w; i++)
        gt_put(t, x + i, y, i < fill ? 0xDB : 0xB0, i < fill ? c : GT_DARK_GRAY, GT_BLACK);
}

static void sample(bool force){
    uint64_t now = bbs_plat_ms();
    if (!force && now - B.t_sample < 1000) return;
    B.t_sample = now;
    bbs_plat_sys(&B.sys);
    B.ntasks = bbs_plat_tasks(B.tasks, BBS_MAX_TASKS, &B.busy);
    if (B.nhist == (int)(sizeof B.hist / sizeof B.hist[0])){
        memmove(B.hist, B.hist + 1, sizeof B.hist - sizeof B.hist[0]);
        B.nhist--;
    }
    B.hist[B.nhist++] = B.busy;
}

/* ------------------------------------------------------ chrome: bars */

static const char MARQUEE[] =
    "Callers have more fun!  \xfa  Sign the guestbook today!  \xfa  "
    "Now in 24-bit Apple IIgs color  \xfa  No modems were harmed in the making of this BBS  \xfa  "
    "Served by littlessh: curve25519 + AES-256-GCM + ECDSA P-256  \xfa  ";

static void top_bar(gt_t *t){
    int w = gt_view_w(t);
    for (int i = 0; i < 6; i++) gt_put(t, i, 0, 0xDB, ART_STRIPES[i], GT_BLACK);
    char when[40];
    time_t now;
    if (bbs_plat_time(&now)){
        struct tm tm; localtime_r(&now, &tm);
        strftime(when, sizeof when, " %a %d %b %Y  %H:%M:%S ", &tm);
    } else {
        char d[16]; fmt_dur(bbs_plat_ms(), d, sizeof d);
        snprintf(when, sizeof when, " Board uptime %s ", d);
    }
    int x = 6 + gt_text(t, 6, 0, GT_BLACK, GT_LIGHT_BLUE, when);
    int end = w - 8;
    size_t mlen = strlen(MARQUEE);
    for (int i = x; i < end; i++){
        uint8_t ch = (uint8_t)MARQUEE[(B.tick / 2 + (uint32_t)(i - x)) % mlen];
        gt_put(t, i, 0, ch, GT_YELLOW, GT_DEEP_RED);
    }
    gt_text(t, end, 0, GT_WHITE, GT_PURPLE, " Node 1 ");
}

static const char *hint(void){
    if (B.overlay == O_SIGN) return "Tab move \xfa Enter sign \xfa Esc cancel";
    switch (B.screen){
    case S_MENU:      return "\x18\x19 Enter \xfa hotkeys \xfa G bye";
    case S_TASKS:     return "\x18\x19 move \xfa S sort \xfa Esc back";
    case S_GUESTBOOK: return "S sign \xfa N/P page \xfa Esc back";
    case S_BULLETINS: case S_CALLERS: case S_SYSTEM: return "Esc back";
    default:          return "";
    }
}

static void status_bar(gt_t *t){
    int w = gt_view_w(t), y = gt_view_h(t) - 1;
    gt_hline(t, 0, y, w, ' ', GT_LIGHT_GRAY, GT_DARK_BLUE);
    char seg[4][32], d[16];
    fmt_dur(bbs_plat_ms() - B.t_login, d, sizeof d);
    snprintf(seg[0], sizeof seg[0], "%ux%u", gt_cols(t), gt_rows(t));
    snprintf(seg[1], sizeof seg[1], "Online %s", d);
    snprintf(seg[2], sizeof seg[2], "%s", mode_name(gt_mode(t)));
    copy_ascii(seg[3], sizeof seg[3], lssh_username(B.s));
    int x = gt_text(t, 0, y, GT_WHITE, GT_MEDIUM_BLUE, " GLOSSH BBS ");
    for (int i = 0; i < 4; i++){
        gt_put(t, x++, y, 0xB3, GT_MEDIUM_BLUE, GT_DARK_BLUE);
        x += gt_textf(t, x, y, i == 3 ? GT_YELLOW : GT_AQUAMARINE, GT_DARK_BLUE, " %s ", seg[i]);
    }
    /* hint strings are CP437 bytes */
    const char *h = hint();
    int hw = (int)strlen(h);
    if (hw && x + hw + 3 < w){
        gt_put(t, w - hw - 3, y, 0xB3, GT_MEDIUM_BLUE, GT_DARK_BLUE);
        put_cp437(t, w - hw - 1, y, GT_LIGHT_GRAY, GT_DARK_BLUE, h, hw);
    }
}

/* ---------------------------------------------------- terminal check */

static const struct { gt_mode_t m; const char *name, *note; } EMU[] = {
    {GT_MODE_TRUECOLOR, "Apple IIgs 24-bit", "exact palette"},
    {GT_MODE_256,       "xterm 256-color",   "close match"},
    {GT_MODE_16,        "ANSI 16-color",     "any color terminal"},
    {GT_MODE_ANSIBBS,   "ANSI-BBS / CP437",  "SyncTERM & friends"},
};

static void draw_emu(gt_t *t){
    art_plaque(t, 16, 0, 48, GT_WHITE, GT_MEDIUM_BLUE, "T E R M I N A L   C H E C K");
    char client[48], term[40];
    const char *v = lssh_client_version(B.s);
    copy_ascii(client, 27, strncmp(v, "SSH-2.0-", 8) ? v : v + 8);
    copy_ascii(term, 21, lssh_term(B.s));
    gt_text(t, 6, 4, GT_LIGHT_GRAY, GT_BLACK, "Client");
    gt_text(t, 13, 4, GT_YELLOW, GT_BLACK, client);
    gt_text(t, 42, 4, GT_LIGHT_GRAY, GT_BLACK, "TERM");
    gt_textf(t, 47, 4, GT_YELLOW, GT_BLACK, "%s  %ux%u", term[0] ? term : "?", s_pty_cols, s_pty_rows);
    gt_text(t, 6, 6, GT_WHITE, GT_BLACK, "Which row shows sixteen crisp, different colors?");

    for (int i = 0; i < 4; i++){
        int y = 8 + i * 2;
        bool sel = i == B.emu_sel;
        uint8_t bg = sel ? GT_DARK_BLUE : GT_BLACK;
        gt_hline(t, 4, y, 72, ' ', GT_WHITE, bg);
        gt_put(t, 4, y, sel ? 0x10 : ' ', GT_YELLOW, bg);
        gt_textf(t, 6, y, GT_WHITE, bg, "%d", i + 1);
        gt_text(t, 8, y, sel ? GT_WHITE : GT_LIGHT_GRAY, bg, EMU[i].name);
        for (int c = 0; c < 16; c++)
            for (int k = 0; k < 2; k++){
                gt_cell_t *cell = gt_at(t, 27 + c * 2 + k, y);
                if (cell) *cell = (gt_cell_t){0xDB, (uint8_t)c, GT_BLACK, GT_MODE_AS(EMU[i].m)};
            }
        gt_text(t, 60, y, sel ? GT_AQUAMARINE : GT_DARK_GRAY, bg, EMU[i].note);
    }
    gt_pipe(t, 6, 17, "|10Press |131-4|10, or |13↑↓|10 and |13Enter|10.");
    gt_pipe(t, 6, 18, "|10Row 4 blank or garbled? It is for CP437 terminals like SyncTERM.");
    gt_text(t, 6, 20, GT_DARK_GRAY, GT_BLACK, "You can change this later from the main menu (8).");
}

static void key_emu(int k){
    if (k == GT_KEY_UP) B.emu_sel = (B.emu_sel + 3) % 4;
    else if (k == GT_KEY_DOWN || k == GT_KEY_TAB) B.emu_sel = (B.emu_sel + 1) % 4;
    else if (k >= '1' && k <= '4') B.emu_sel = k - '1';
    if (k == GT_KEY_ENTER || (k >= '1' && k <= '4')){
        gt_set_mode(B.t, EMU[B.emu_sel].m);
        B.keys.cp437 = EMU[B.emu_sel].m == GT_MODE_ANSIBBS;
        if (B.emu_done) go(S_MENU);
        else { B.emu_done = true; go(S_DIAL); }
    }
}

/* ------------------------------------------------ dial-up and logo */

static const struct { int wait_ms; const char *text; bool typed; uint8_t color; } DIAL[] = {
    {300, "ATZ",                        true,  GT_LIGHT_GRAY},
    {250, "OK",                         false, GT_LIGHT_GRAY},
    {300, "ATDT 1-555-GLO-SSH",         true,  GT_LIGHT_GRAY},
    {900, "RING",                       false, GT_YELLOW},
    {1100,"RING",                       false, GT_YELLOW},
    {900, "CONNECT 14400/ARQ/V42BIS",   false, GT_LIGHT_GREEN},
};
#define DIAL_CHAR_MS 45
#define DIAL_END_MS  700

/* returns true once the script has finished */
static bool draw_modem(gt_t *t, uint64_t e){
    uint64_t at = 0;
    int y = 2;
    bool carrier = false, offhook = false, data = false;
    for (size_t i = 0; i < sizeof DIAL / sizeof DIAL[0]; i++){
        at += (uint64_t)DIAL[i].wait_ms;
        if (e < at) break;
        size_t len = strlen(DIAL[i].text), shown = len;
        if (DIAL[i].typed){
            shown = (size_t)((e - at) / DIAL_CHAR_MS);
            if (shown > len) shown = len;
            at += len * DIAL_CHAR_MS;
            data = data || shown < len;
        } else if (e - at < 120) data = true;
        char buf[40];
        memcpy(buf, DIAL[i].text, shown); buf[shown] = 0;
        int n = gt_text(t, 2, y, DIAL[i].color, GT_BLACK, buf);
        if (shown < len || (i == sizeof DIAL / sizeof DIAL[0] - 1 && (B.tick / 4) % 2))
            gt_put(t, 2 + n, y, 0xDB, GT_LIGHT_GRAY, GT_BLACK);
        if (!strncmp(DIAL[i].text, "ATDT", 4)) offhook = true;
        if (!strncmp(DIAL[i].text, "CONNECT", 7)) carrier = true;
        y += 1 + (i == 2);
    }

    /* modem front panel */
    static const char *LED[] = {"HS", "AA", "CD", "OH", "RD", "SD", "TR", "MR"};
    bool on[8] = {carrier, true, carrier, offhook, data && (B.tick & 1), data && !(B.tick & 1), true, true};
    int px = 20, py = 14;
    gt_fill(t, px, py, 40, 5, ' ', GT_LIGHT_GRAY, GT_DARK_GRAY);
    gt_box(t, px, py, 40, 5, GT_BOX_SINGLE, GT_LIGHT_GRAY, GT_DARK_GRAY);
    gt_text(t, px + 2, py, GT_WHITE, GT_DARK_GRAY, " GLOSSH SPORTSTER 14,400 ");
    for (int i = 0; i < 8; i++){
        gt_put(t, px + 4 + i * 4, py + 2, 0xFE, on[i] ? (i == 2 || i == 0 ? GT_LIGHT_GREEN : GT_DEEP_RED) : GT_BLACK, GT_DARK_GRAY);
        gt_text(t, px + 3 + i * 4, py + 3, GT_LIGHT_GRAY, GT_DARK_GRAY, LED[i]);
    }
    return e >= at + DIAL_END_MS && carrier;
}

static void draw_logo(gt_t *t){
    int gleam = (int)(B.tick % 110) - 12;
    art_bigword(t, 15, 1, "GLOSSH", gleam <= 60 ? gleam : -1);
    gt_text(t, 19, 8, GT_LIGHT_BLUE, GT_BLACK, "B U L L E T I N   B O A R D   S Y S T E M");
    char ver[64], date[16];
    snprintf(date, sizeof date, "%s", __DATE__);
    for (char *p = date; *p; p++) if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 32);
    snprintf(ver, sizeof ver, "VERSION 0.2  \xc2\xb7  BUILT %s  \xc2\xb7  LITTLESSH %s", date, LSSH_VERSION_STR);
    gt_text(t, (PAGE_W - gt_strwidth(ver)) / 2, 10, GT_WHITE, GT_BLACK, ver);
    const char *c = "(C) 2026 THE GLOSSH PROJECT  \xc2\xb7  APACHE-2.0";
    gt_text(t, (PAGE_W - gt_strwidth(c)) / 2, 11, GT_LIGHT_GRAY, GT_BLACK, c);

    char chip[32], avail[80];
    snprintf(chip, sizeof chip, "%s", B.sys.chip);
    char *sp = strchr(chip, ' ');
    if (sp) *sp = 0;
    gt_text(t, 23, 13, GT_YELLOW, GT_BLACK, "THE ULTIMATE BULLETIN BOARD SYSTEM");
    snprintf(avail, sizeof avail, "AVAILABLE FOR THE %s MICROCONTROLLER", chip);
    gt_text(t, (PAGE_W - (int)strlen(avail)) / 2, 14, GT_YELLOW, GT_BLACK, avail);

    gt_text(t, 17, 17, GT_PINK, GT_BLACK, "You are caller");
    art_odometer(t, 32, 16, B.caller_no, 7);
    gt_text(t, 49, 17, GT_PINK, GT_BLACK, "~*~ welcome! ~*~");
    art_hazard(t, 15, 19, 50, "UNDER CONSTRUCTION", B.tick);
}

static void draw_dial(gt_t *t){
    uint64_t e = bbs_plat_ms() - B.t_screen;
    if (B.reveal == 0 && !B.reveal_all){
        if (!draw_modem(t, e)) return;
        B.reveal = 1;                   /* carrier: start painting the logo */
    }
    draw_logo(t);
    /* reveal the logo at 14,400 bps: ~1,440 visible glyphs a second */
    if (!B.reveal_all){
        B.reveal += 1440 * BBS_TICK_MS / 1000;
        size_t n = 0;
        bool done = true;
        for (int y = 0; y < PAGE_H; y++)
            for (int x = 0; x < PAGE_W; x++){
                gt_cell_t *c = gt_at(t, x, y);
                if (!c || (c->ch == ' ' && c->bg == GT_BLACK) || c->ch == 0xFA || c->ch == 0xF9) continue;
                if (++n > B.reveal){ *c = (gt_cell_t){' ', GT_LIGHT_GRAY, GT_BLACK, 0}; done = false; }
            }
        if (done) B.reveal_all = true;
    }
    if (B.reveal_all && (B.tick / 8) % 2 == 0)
        gt_text(t, 26, 21, GT_WHITE, GT_BLACK, "\xc2\xbb Press any key to enter \xc2\xab");
}

static void key_dial(int k){
    (void)k;
    if (!B.reveal_all){ B.reveal = 1; B.reveal_all = true; }
    else go(S_MENU);
}

/* ----------------------------------------------------------- menu */

static const struct { char key; const char *label; uint8_t color; } MENU[] = {
    {'1', "Bulletins & News",  GT_LIGHT_GREEN},
    {'2', "Last Callers",      GT_YELLOW},
    {'3', "System Status",     GT_ORANGE},
    {'4', "Task Monitor",      GT_PINK},
    {'5', "Guestbook",         GT_PURPLE},
    {'6', "Art Gallery",       GT_LIGHT_BLUE},
    {'7', "Page the Sysop",    GT_AQUAMARINE},
    {'8', "Terminal Settings", GT_LIGHT_GRAY},
    {'G', "Goodbye",           GT_DEEP_RED},
};
#define MENU_N ((int)(sizeof MENU / sizeof MENU[0]))

static void draw_menu(gt_t *t){
    art_tower(t, 0, 1, B.tick);
    art_plaque(t, 42, 0, 37, GT_YELLOW, GT_DARK_GREEN, "M a i n   M e n u");
    for (int i = 0; i < MENU_N; i++){
        int y = 4 + i + (i == MENU_N - 1);
        bool sel = i == B.sel;
        uint8_t bg = sel ? GT_DARK_BLUE : GT_BLACK;
        gt_text(t, 43, y, MENU[i].color, GT_BLACK, "██");
        gt_hline(t, 46, y, 33, ' ', GT_WHITE, bg);
        gt_put(t, 46, y, sel ? 0x10 : ' ', GT_YELLOW, bg);
        gt_put(t, 48, y, (uint8_t)MENU[i].key, sel ? GT_YELLOW : GT_WHITE, bg);
        gt_put(t, 49, y, ')', GT_DARK_GRAY, bg);
        int n = gt_text(t, 51, y, sel ? GT_WHITE : MENU[i].color, bg, MENU[i].label);
        if (MENU[i].key == '5' && (B.tick / 6) % 2)
            gt_text(t, 52 + n, y, GT_YELLOW, GT_DEEP_RED, "NEW!");
    }
    uint64_t on = bbs_plat_ms() - B.t_login;
    int left = 60 - (int)(on / 60000);
    char line[80];
    snprintf(line, sizeof line, "|10Caller |15#%u |05· |10Node |151 |05· |10Time left |15%dm",
             (unsigned)B.caller_no, left > 0 ? left : 0);
    gt_pipe(t, 43, 16, line);
    if (s_stats.n > 1){
        const caller_t *c = &s_stats.last[ring_idx(s_stats.head, 1, CALLERS_MAX)];
        char when[24]; fmt_when(c->when, when, sizeof when);
        gt_text(t, 43, 17, GT_LIGHT_GRAY, GT_BLACK, "Last on");
        int n = put_cp437(t, 51, 17, GT_AQUAMARINE, GT_BLACK, c->user, 12);
        gt_textf(t, 52 + n, 17, GT_DARK_GRAY, GT_BLACK, "%s", when);
    }
    int x = 43 + gt_pipe(t, 43, 19, "|11Enter your choice |15[|131-8,G|15] |14\xc2\xbb ");
    gt_cursor(t, x, 19);
}

static void activate(int i);

static void key_menu(int k){
    if (k == GT_KEY_UP) B.sel = (B.sel + MENU_N - 1) % MENU_N;
    else if (k == GT_KEY_DOWN || k == GT_KEY_TAB) B.sel = (B.sel + 1) % MENU_N;
    else if (k == GT_KEY_HOME) B.sel = 0;
    else if (k == GT_KEY_END) B.sel = MENU_N - 1;
    else if (k == GT_KEY_ENTER) activate(B.sel);
    else if (k == GT_KEY_ESC) activate(MENU_N - 1);
    else if (k < 0x80){
        char c = (char)(k >= 'a' && k <= 'z' ? k - 32 : k);
        for (int i = 0; i < MENU_N; i++) if (MENU[i].key == c){ B.sel = i; activate(i); }
    }
}

static void activate(int i){
    switch (MENU[i].key){
    case '1': go(S_BULLETINS); break;
    case '2': go(S_CALLERS); break;
    case '3': sample(true); go(S_SYSTEM); break;
    case '4': sample(true); go(S_TASKS); break;
    case '5': B.gb_page = 0; go(S_GUESTBOOK); break;
    case '6': go(S_ART); B.art_fx = 0; break;
    case '7': B.overlay = O_PAGE; B.t_overlay = bbs_plat_ms(); B.bells = 0; break;
    case '8': go(S_EMU); break;
    case 'G': B.overlay = O_LOGOFF; break;
    }
    if (MENU[i].key != 'G' && MENU[i].key != '7') B.sel = 0;
    else B.sel = i;
}

/* ----------------------------------------------------- bulletins */

static void draw_bulletins(gt_t *t){
    art_plaque(t, 20, 0, 40, GT_WHITE, GT_DEEP_RED, "B U L L E T I N S");
    char hw[128], mhz[16] = "", flash[24] = "";
    if (B.sys.mhz) snprintf(mhz, sizeof mhz, " at %u MHz", B.sys.mhz);
    if (B.sys.flash_bytes) snprintf(flash, sizeof flash, ", %u MB flash", (unsigned)(B.sys.flash_bytes >> 20));
    snprintf(hw, sizeof hw, "%.31s, %u core%s%s%s. Everything you see",
             B.sys.chip, B.sys.cores, B.sys.cores == 1 ? "" : "s", mhz, flash);
    const struct { uint8_t c; const char *title, *l1, *l2; } BUL[] = {
        {GT_LIGHT_GREEN, "#1  Welcome, caller!",
         "This board is an ESP32 with an Ethernet jack, speaking SSH-2 via littlessh.",
         "One line, one caller at a time, just like 1989. Please wipe your feet."},
        {GT_PURPLE, "#2  The guestbook is open",
         "GeoCities called and they want their guestbook back. We said no.",
         "Sign it from the main menu (5). Entries survive a power cycle."},
        {GT_ORANGE, "#3  Hardware",
         hw, "is drawn in the 16 colors of the Apple IIgs."},
        {GT_LIGHT_BLUE, "#4  House rules",
         "1. Be excellent.  2. No warez.  3. The sysop is always right,",
         "   especially when wrong.  4. Do not climb the radio tower."},
    };
    for (int i = 0; i < 4; i++){
        int y = 3 + i * 5;
        gt_fill(t, 1, y, 78, 4, ' ', GT_LIGHT_GRAY, GT_BLACK);
        gt_hline(t, 1, y, 78, ' ', GT_BLACK, BUL[i].c);
        gt_text(t, 2, y, GT_BLACK, BUL[i].c, BUL[i].title);
        gt_vline(t, 1, y + 1, 3, 0xDD, BUL[i].c, GT_BLACK);
        gt_text(t, 3, y + 1, GT_WHITE, GT_BLACK, BUL[i].l1);
        gt_text(t, 3, y + 2, GT_LIGHT_GRAY, GT_BLACK, BUL[i].l2);
    }
}

/* ---------------------------------------------------- last callers */

static void draw_callers(gt_t *t){
    art_plaque(t, 20, 0, 40, GT_BLACK, GT_YELLOW, "L A S T   C A L L E R S");
    gt_fill(t, 6, 4, 68, 13, ' ', GT_LIGHT_GRAY, GT_BLACK);
    gt_box(t, 6, 4, 68, 13, GT_BOX_DOUBLE_H, GT_YELLOW, GT_BLACK);
    gt_text(t, 8, 5, GT_AQUAMARINE, GT_BLACK, "Caller");
    gt_text(t, 17, 5, GT_AQUAMARINE, GT_BLACK, "Handle");
    gt_text(t, 33, 5, GT_AQUAMARINE, GT_BLACK, "Terminal");
    gt_text(t, 57, 5, GT_AQUAMARINE, GT_BLACK, "When");
    gt_hline(t, 7, 6, 66, 0xCD, GT_YELLOW, GT_BLACK);
    gt_put(t, 6, 6, 0xC6, GT_YELLOW, GT_BLACK);
    gt_put(t, 73, 6, 0xB5, GT_YELLOW, GT_BLACK);
    static const uint8_t rowc[4] = {GT_WHITE, GT_LIGHT_GREEN, GT_PINK, GT_LIGHT_BLUE};
    for (int i = 0; i < s_stats.n; i++){
        const caller_t *c = &s_stats.last[ring_idx(s_stats.head, i, CALLERS_MAX)];
        uint8_t fg = rowc[i % 4];
        char when[24]; fmt_when(c->when, when, sizeof when);
        gt_textf(t, 8, 7 + i, fg, GT_BLACK, "#%u", (unsigned)c->num);
        put_cp437(t, 17, 7 + i, fg, GT_BLACK, c->user, 15);
        put_cp437(t, 33, 7 + i, GT_LIGHT_GRAY, GT_BLACK, c->client, 23);
        gt_text(t, 57, 7 + i, GT_DARK_GRAY, GT_BLACK, when);
    }
    gt_pipe(t, 17, 18, "|10Total calls |15");
    gt_textf(t, 29, 18, GT_WHITE, GT_BLACK, "%u", (unsigned)s_stats.calls);
    gt_pipe(t, 38, 18, "|10·  Board open since the last flash erase");
}

/* --------------------------------------------------- system status */

static void panel(gt_t *t, int x, int y, int w, int h, uint8_t c, const char *title){
    gt_fill(t, x, y, w, h, ' ', GT_LIGHT_GRAY, GT_BLACK);
    gt_box(t, x, y, w, h, GT_BOX_SINGLE, c, GT_BLACK);
    gt_put(t, x + 2, y, ' ', c, GT_BLACK);
    int n = gt_text(t, x + 3, y, GT_BLACK, c, title);
    gt_put(t, x + 3 + n, y, ' ', c, GT_BLACK);
}

static void kv(gt_t *t, int x, int y, const char *k, const char *v){
    gt_text(t, x, y, GT_LIGHT_GRAY, GT_BLACK, k);
    gt_text(t, x + 11, y, GT_WHITE, GT_BLACK, v);
}

static void draw_system(gt_t *t){
    sample(false);
    char a[48], b[24], c[96];

    panel(t, 0, 0, 39, 11, GT_ORANGE, " CPU ");
    if (B.busy >= 0) snprintf(a, sizeof a, "%d.%d%%", B.busy / 10, B.busy % 10);
    else snprintf(a, sizeof a, "n/a");
    gt_text(t, 2, 1, GT_LIGHT_GRAY, GT_BLACK, "Load");
    gt_text(t, 7, 1, GT_WHITE, GT_BLACK, a);
    gt_textf(t, 18, 1, GT_DARK_GRAY, GT_BLACK, "%d tasks · last 36 s", B.ntasks);
    static const uint8_t rowc[4] = {GT_DEEP_RED, GT_ORANGE, GT_YELLOW, GT_LIGHT_GREEN};
    for (int col = 0; col < 36; col++){
        int i = B.nhist - 36 + col;
        int v = i >= 0 && B.hist[i] > 0 ? B.hist[i] : 0;
        int h = (v * 16 + 999) / 1000;               /* 0-16 half-cells over 8 rows */
        for (int r = 0; r < 8; r++){
            int lvl = (7 - r) * 2;
            uint8_t ch = h >= lvl + 2 ? 0xDB : h == lvl + 1 ? 0xDC : ' ';
            gt_put(t, 1 + col, 2 + r, ch == ' ' && r == 7 ? 0xC4 : ch, ch == ' ' ? GT_DARK_GRAY : rowc[r / 2], GT_BLACK);
        }
    }

    panel(t, 41, 0, 39, 11, GT_PINK, " MEMORY ");
    uint32_t used = B.sys.heap_total - B.sys.heap_free;
    fmt_bytes(B.sys.heap_free, a, sizeof a); fmt_bytes(B.sys.heap_total, b, sizeof b);
    gt_text(t, 43, 2, GT_LIGHT_GRAY, GT_BLACK, "Heap");
    snprintf(c, sizeof c, "%s free of %s", a, b);
    gt_text(t, 78 - gt_strwidth(c), 2, GT_WHITE, GT_BLACK, c);
    bar(t, 43, 3, 35, B.sys.heap_total ? (int)((uint64_t)used * 1000 / B.sys.heap_total) : 0);
    fmt_bytes(B.sys.heap_min, a, sizeof a); fmt_bytes(B.sys.heap_largest, b, sizeof b);
    kv(t, 43, 5, "Low water", a);
    kv(t, 43, 6, "Largest", b);
    if (B.sys.psram_total){
        fmt_bytes(B.sys.psram_free, a, sizeof a); fmt_bytes(B.sys.psram_total, b, sizeof b);
        gt_text(t, 43, 8, GT_LIGHT_GRAY, GT_BLACK, "PSRAM");
        snprintf(c, sizeof c, "%s free of %s", a, b);
        gt_text(t, 78 - gt_strwidth(c), 8, GT_WHITE, GT_BLACK, c);
        bar(t, 43, 9, 35, (int)((uint64_t)(B.sys.psram_total - B.sys.psram_free) * 1000 / B.sys.psram_total));
    } else gt_text(t, 43, 8, GT_DARK_GRAY, GT_BLACK, "No PSRAM on this board");

    panel(t, 0, 12, 39, 10, GT_LIGHT_BLUE, " SYSTEM ");
    kv(t, 2, 13, "Chip", B.sys.chip);
    if (B.sys.mhz) snprintf(a, sizeof a, "%u @ %u MHz", B.sys.cores, B.sys.mhz);
    else snprintf(a, sizeof a, "%u", B.sys.cores);
    kv(t, 2, 14, "Cores", a);
    if (B.sys.flash_bytes) fmt_bytes(B.sys.flash_bytes, a, sizeof a);
    else snprintf(a, sizeof a, "--");
    kv(t, 2, 15, "Flash", a);
    kv(t, 2, 16, "SDK", B.sys.sdk);
    kv(t, 2, 17, "Reset", B.sys.reset);
    fmt_dur(B.sys.uptime_ms, a, sizeof a);
    kv(t, 2, 18, "Uptime", a);
    fmt_dur(bbs_plat_ms() - B.t_login, c, sizeof c);
    kv(t, 2, 19, "You", c);

    panel(t, 41, 12, 39, 10, GT_LIGHT_GREEN, " NETWORK & SSH ");
    kv(t, 43, 13, "Address", B.sys.ip);
    kv(t, 43, 14, "MAC", B.sys.mac);
    kv(t, 43, 15, "Kex", "curve25519-sha256");
    kv(t, 43, 16, "Cipher", "aes256-gcm@openssh");
    kv(t, 43, 17, "Host key", "ecdsa-sha2-nistp256");
    const char *fp = s_cfg.hostkey_fp ? s_cfg.hostkey_fp : "";
    gt_text(t, 43, 18, GT_LIGHT_GRAY, GT_BLACK, "Fingerprint");
    snprintf(a, sizeof a, "%.35s", fp);
    gt_text(t, 43, 19, GT_AQUAMARINE, GT_BLACK, a);
    if (strlen(fp) > 35) gt_text(t, 43, 20, GT_AQUAMARINE, GT_BLACK, fp + 35);
}

/* ---------------------------------------------------- task monitor */

static int cmp_cpu(const void *a, const void *b){
    return ((const bbs_task_t*)b)->cpu_x10 - ((const bbs_task_t*)a)->cpu_x10;
}
static int cmp_name(const void *a, const void *b){
    return strcmp(((const bbs_task_t*)a)->name, ((const bbs_task_t*)b)->name);
}
static int cmp_prio(const void *a, const void *b){
    return ((const bbs_task_t*)b)->prio - ((const bbs_task_t*)a)->prio;
}

static void draw_tasks(gt_t *t){
    static const char *sort_name[3] = {"cpu", "name", "prio"};
    sample(false);
    bbs_task_t v[BBS_MAX_TASKS];
    int n = B.ntasks;
    memcpy(v, B.tasks, sizeof v[0] * (size_t)n);
    qsort(v, (size_t)n, sizeof v[0], B.task_sort == 0 ? cmp_cpu : B.task_sort == 1 ? cmp_name : cmp_prio);

    gt_fill(t, 0, 0, PAGE_W, PAGE_H, ' ', GT_LIGHT_GRAY, GT_DARK_BLUE);
    gt_box(t, 0, 0, PAGE_W, PAGE_H, GT_BOX_DOUBLE, GT_LIGHT_BLUE, GT_DARK_BLUE);
    gt_text(t, 3, 0, GT_YELLOW, GT_DARK_BLUE, " Task Monitor ");
    char head[48];
    if (B.busy >= 0) snprintf(head, sizeof head, " %d tasks \xc2\xb7 CPU %d.%d%% ", n, B.busy / 10, B.busy % 10);
    else snprintf(head, sizeof head, " %d tasks ", n);
    gt_text(t, PAGE_W - 3 - gt_strwidth(head), 0, GT_AQUAMARINE, GT_DARK_BLUE, head);

    gt_text(t, 3, 2, GT_YELLOW, GT_DARK_BLUE, "Name              State       Prio   Stack free   CPU");
    gt_hline(t, 1, 3, PAGE_W - 2, 0xC4, GT_MEDIUM_BLUE, GT_DARK_BLUE);
    const int rows = 15;
    if (B.sel >= n) B.sel = n ? n - 1 : 0;
    if (B.sel < B.scroll) B.scroll = B.sel;
    if (B.sel >= B.scroll + rows) B.scroll = B.sel - rows + 1;
    for (int r = 0; r < rows && B.scroll + r < n; r++){
        const bbs_task_t *k = &v[B.scroll + r];
        int y = 4 + r;
        bool sel = B.scroll + r == B.sel;
        uint8_t bg = sel ? GT_DEEP_RED : GT_DARK_BLUE;
        gt_hline(t, 1, y, PAGE_W - 2, ' ', GT_WHITE, bg);
        gt_text(t, 3, y, GT_WHITE, bg, k->name);
        const char *st = "?"; uint8_t sc = GT_LIGHT_GRAY;
        switch (k->state){
        case 'R': st = "running";   sc = GT_LIGHT_GREEN; break;
        case 'r': st = "ready";     sc = GT_AQUAMARINE; break;
        case 'B': st = "blocked";   sc = GT_LIGHT_GRAY; break;
        case 'S': st = "suspended"; sc = GT_ORANGE; break;
        case 'D': st = "deleted";   sc = GT_DARK_GRAY; break;
        }
        gt_text(t, 21, y, sel ? GT_WHITE : sc, bg, st);
        gt_textf(t, 33, y, GT_WHITE, bg, "%4u", k->prio);
        gt_textf(t, 40, y, k->stack_free < 768 ? GT_PINK : GT_WHITE, bg, "%8u B", (unsigned)k->stack_free);
        if (k->cpu_x10 >= 0){
            int fill = (k->cpu_x10 * 12 + 999) / 1000;
            for (int i = 0; i < 12; i++)
                gt_put(t, 54 + i, y, i < fill ? 0xDB : 0xB0,
                       i < fill ? (k->cpu_x10 < 300 ? GT_LIGHT_GREEN : k->cpu_x10 < 700 ? GT_YELLOW : GT_ORANGE) : GT_MEDIUM_BLUE, bg);
            gt_textf(t, 67, y, GT_WHITE, bg, "%3d.%d%%", k->cpu_x10 / 10, k->cpu_x10 % 10);
        } else gt_text(t, 54, y, GT_LIGHT_GRAY, bg, "n/a");
    }
    gt_hline(t, 1, 19, PAGE_W - 2, 0xC4, GT_MEDIUM_BLUE, GT_DARK_BLUE);
    gt_pipe(t, 3, 20, "|18|13↑↓|10 Move   |13S|10 Sort   |13Esc|10 Back");
    gt_textf(t, 50, 20, GT_LIGHT_GRAY, GT_DARK_BLUE, "sorted by %-4s · live, 1 s", sort_name[B.task_sort]);
}

static void key_tasks(int k){
    if (k == GT_KEY_UP && B.sel > 0) B.sel--;
    else if (k == GT_KEY_DOWN && B.sel + 1 < B.ntasks) B.sel++;
    else if (k == GT_KEY_PGUP) B.sel = B.sel > 15 ? B.sel - 15 : 0;
    else if (k == GT_KEY_PGDN) B.sel = B.sel + 15 < B.ntasks ? B.sel + 15 : B.ntasks - 1;
    else if (k == 's' || k == 'S') B.task_sort = (B.task_sort + 1) % 3;
    else if (k == GT_KEY_ESC || k == 'q' || k == 'Q') go(S_MENU);
}

/* ------------------------------------------------------- guestbook */

#define GB_PER_PAGE 3

static void draw_guestbook(gt_t *t){
    art_rainbow(t, 21, 0, "☼ ~*~ Welcome to my Guestbook!! ~*~ ☼", B.tick);
    for (int i = 0; i < 78; i++)
        gt_put(t, 1 + i, 1, i % 13 == 6 ? 0x0F : 0xCD, i % 13 == 6 ? GT_YELLOW : (i / 13) % 2 ? GT_AQUAMARINE : GT_PURPLE, GT_BLACK);
    gt_text(t, 14, 2, GT_WHITE, GT_BLACK, "Thanks for visiting my corner of the web! Please sign below");
    if ((B.tick / 5) % 2) gt_text(t, 6, 2, GT_YELLOW, GT_DEEP_RED, "NEW!");

    int pages = s_gb.n ? (s_gb.n + GB_PER_PAGE - 1) / GB_PER_PAGE : 1;
    if (B.gb_page >= pages) B.gb_page = pages - 1;
    if (!s_gb.n){
        window(t, 15, 6, 50, 7, GT_PINK, GT_BLACK, "It's empty in here!");
        gt_text(t, 23, 8, GT_WHITE, GT_BLACK, "Nobody has signed the guestbook.");
        gt_text(t, 24, 10, GT_LIGHT_GRAY, GT_BLACK, "Press");
        gt_text(t, 30, 10, GT_YELLOW, GT_BLACK, "S");
        gt_text(t, 32, 10, GT_LIGHT_GRAY, GT_BLACK, "to be the very first!");
    }
    static const uint8_t frame[3] = {GT_PINK, GT_LIGHT_BLUE, GT_LIGHT_GREEN};
    for (int i = 0; i < GB_PER_PAGE; i++){
        int idx = B.gb_page * GB_PER_PAGE + i;
        if (idx >= s_gb.n) break;
        const gb_entry_t *e = &s_gb.e[ring_idx(s_gb.head, idx, GB_MAX)];
        int y = 4 + i * 4;
        uint8_t fc = frame[idx % 3];
        gt_box(t, 4, y, 72, 4, GT_BOX_SINGLE, fc, GT_BLACK);
        gt_fill(t, 5, y + 1, 70, 2, ' ', GT_LIGHT_GRAY, GT_BLACK);
        gt_textf(t, 6, y, fc, GT_BLACK, " #%u ", (unsigned)e->num);
        gt_text(t, 6, y + 1, GT_LIGHT_GRAY, GT_BLACK, "Name");
        put_cp437(t, 11, y + 1, GT_YELLOW, GT_BLACK, e->name, 19);
        gt_text(t, 32, y + 1, GT_LIGHT_GRAY, GT_BLACK, "From");
        put_cp437(t, 37, y + 1, GT_AQUAMARINE, GT_BLACK, e->from, 19);
        char when[24]; fmt_when(e->when, when, sizeof when);
        gt_text(t, 74 - gt_strwidth(when), y + 1, GT_DARK_GRAY, GT_BLACK, when);
        gt_put(t, 6, y + 2, '"', GT_PINK, GT_BLACK);
        int n = put_cp437(t, 7, y + 2, GT_WHITE, GT_BLACK, e->msg, 66);
        gt_put(t, 7 + n, y + 2, '"', GT_PINK, GT_BLACK);
    }
    gt_pipe(t, 4, 16, "|15[|13S|15]|10ign it   |15[|13N|15]|10ext   |15[|13P|15]|10rev   |15[|13Esc|15]|10 Back");
    gt_textf(t, 64, 16, GT_DARK_GRAY, GT_BLACK, "page %d of %d", B.gb_page + 1, pages);
    art_hazard(t, 4, 18, 30, "UNDER CONSTRUCTION", B.tick);
    gt_text(t, 44, 18, GT_LIGHT_GRAY, GT_BLACK, "Visitors");
    art_odometer(t, 53, 17, s_stats.calls, 6);
    gt_pipe(t, 4, 20, "|15[|07<< Prev|15] |10The |11ESP32 BBS Webring|10 is |12ONLINE |15[|07Random|15] [|07Next >>|15]");
    gt_text(t, 4, 21, GT_DARK_GRAY, GT_BLACK, "Best viewed with Netscape Navigator 3.0 at 800x600 \xc2\xb7 Made with Notepad");
}

static void sign_open(void){
    memset(B.f, 0, sizeof B.f);
    B.f[0].max = 18; B.f[1].max = 18; B.f[2].max = 58;
    copy_ascii(B.f[0].buf, sizeof B.f[0].buf, lssh_username(B.s));
    B.f[0].len = (uint8_t)strlen(B.f[0].buf);
    if (B.f[0].len > B.f[0].max){ B.f[0].len = B.f[0].max; B.f[0].buf[B.f[0].max] = 0; }
    B.f_sel = 1;
    B.gb_err = NULL;
    B.overlay = O_SIGN;
}

static void sign_submit(void){
    for (int i = 0; i < 3; i++)
        while (B.f[i].len && B.f[i].buf[B.f[i].len - 1] == ' ') B.f[i].buf[--B.f[i].len] = 0;
    if (!B.f[0].len){ B.gb_err = "Everybody has a name!"; B.f_sel = 0; return; }
    if (!B.f[2].len){ B.gb_err = "Say something nice :)"; B.f_sel = 2; return; }
    gb_entry_t *e = &s_gb.e[s_gb.head];
    memset(e, 0, sizeof *e);
    memcpy(e->name, B.f[0].buf, B.f[0].len);
    memcpy(e->from, B.f[1].len ? B.f[1].buf : "the Information Superhighway",
           B.f[1].len ? B.f[1].len : sizeof e->from - 1);
    memcpy(e->msg, B.f[2].buf, B.f[2].len);
    time_t now;
    e->when = bbs_plat_time(&now) ? (uint32_t)now : 0;
    e->num = ++s_gb.total;
    s_gb.head = (uint8_t)((s_gb.head + 1) % GB_MAX);
    if (s_gb.n < GB_MAX) s_gb.n++;
    s_gb.magic = GB_MAGIC;
    bbs_plat_save("gbook", &s_gb, sizeof s_gb);
    B.gb_page = 0;
    B.overlay = O_NONE;
}

static void draw_sign(gt_t *t){
    static const char *label[3] = {"Your name", "Hometown", "Message"};
    window(t, 2, 5, 76, 12, GT_PINK, GT_DARK_BLUE, "~*~ Sign My Guestbook! ~*~");
    for (int i = 0; i < 3; i++){
        int y = 7 + i * 2;
        bool sel = i == B.f_sel;
        gt_text(t, 5, y, sel ? GT_YELLOW : GT_LIGHT_GRAY, GT_DARK_BLUE, label[i]);
        gt_hline(t, 16, y, B.f[i].max + 1, ' ', GT_WHITE, sel ? GT_MEDIUM_BLUE : GT_BLACK);
        put_cp437(t, 16, y, GT_WHITE, sel ? GT_MEDIUM_BLUE : GT_BLACK, B.f[i].buf, B.f[i].max);
        if (sel) gt_cursor(t, 16 + B.f[i].len, y);
    }
    if (B.gb_err) gt_text(t, 5, 13, GT_YELLOW, GT_DEEP_RED, B.gb_err);
    gt_text(t, 5, 14, GT_LIGHT_BLUE, GT_DARK_BLUE, "Tab/↑↓ next field · Enter on Message signs · Esc cancels");
}

static void key_sign(int k){
    field_t *f = &B.f[B.f_sel];
    if (k == GT_KEY_ESC){ B.overlay = O_NONE; return; }
    if (k == GT_KEY_TAB || k == GT_KEY_DOWN){ B.f_sel = (B.f_sel + 1) % 3; return; }
    if (k == GT_KEY_BACKTAB || k == GT_KEY_UP){ B.f_sel = (B.f_sel + 2) % 3; return; }
    if (k == GT_KEY_ENTER){ if (B.f_sel < 2) B.f_sel++; else sign_submit(); return; }
    if (k == GT_KEY_BACKSPACE){ if (f->len) f->buf[--f->len] = 0; return; }
    if (GT_KEY_PRINTABLE(k) && f->len < f->max){ f->buf[f->len++] = (char)k; f->buf[f->len] = 0; B.gb_err = NULL; }
}

static void key_guestbook(int k){
    int pages = s_gb.n ? (s_gb.n + GB_PER_PAGE - 1) / GB_PER_PAGE : 1;
    if (k == 's' || k == 'S') sign_open();
    else if ((k == 'n' || k == 'N' || k == GT_KEY_RIGHT || k == GT_KEY_PGDN) && B.gb_page + 1 < pages) B.gb_page++;
    else if ((k == 'p' || k == 'P' || k == GT_KEY_LEFT || k == GT_KEY_PGUP) && B.gb_page > 0) B.gb_page--;
    else if (k == GT_KEY_ESC || k == 'q' || k == 'Q') go(S_MENU);
}

/* ----------------------------------------------------- art gallery */

static const char *ART_NAME[3] = {"FIRE", "PLASMA", "GREETZ"};
static const char GREETZ[] =
    "     GREETZ FLY OUT TO ... EVERY SYSOP WHO LEFT A NODE RUNNING OVERNIGHT ... "
    "THE APPLE IIGS ... ANSI ARTISTS OF ACiD AND iCE ... GEOCITIES NEIGHBORHOODS ... "
    "ESPRESSIF ... OPENSSH ... AND YOU, CALLER, FOR DIALING IN!     ";

static void draw_art(gt_t *t){
    int w = gt_view_w(t), h = gt_view_h(t);
    if (B.art_fx == 0){
        size_t need = (size_t)w * (size_t)h;
        if (need > B.fire_cap){
            uint8_t *p = realloc(B.fire.heat, need);
            if (!p){ B.art_fx = 1; return; }
            B.fire.heat = p; B.fire_cap = need;
        }
        if (B.fire.w != w || B.fire.h != h){
            memset(B.fire.heat, 0, need);
            B.fire.w = w; B.fire.h = h;
        }
        art_fire_step(t, &B.fire);
        int bw = art_bigword_width("GLOSSH");
        art_bigword(t, (w - bw) / 2, h / 2 - 5, "GLOSSH", -1);
    } else if (B.art_fx == 1){
        art_plasma(t, B.tick);
    } else {
        art_starfield(t, B.tick * 3);
        int bw = art_bigword_width("GLOSSH");
        static const int8_t bounce[16] = {0, 1, 2, 3, 3, 4, 4, 4, 4, 4, 4, 3, 3, 2, 1, 0};
        int y = h / 2 - 7 + (4 - bounce[(B.tick / 2) % 16]);
        art_bigword(t, (w - bw) / 2, y, "GLOSSH", (int)(B.tick % 70) - 10);
        /* text-mode sine scrollers staircase into mush; scroll straight and
         * let the color do the waving */
        size_t gl = strlen(GREETZ);
        gt_hline(t, 0, h - 5, w, 0xDF, GT_DARK_BLUE, GT_BLACK);
        gt_hline(t, 0, h - 3, w, 0xDC, GT_DARK_BLUE, GT_BLACK);
        for (int x = 0; x < w; x++){
            char ch = GREETZ[(B.tick + (uint32_t)x) % gl];
            gt_put(t, x, h - 4, (uint8_t)ch, ART_STRIPES[((uint32_t)x / 3 + B.tick / 2) % 6], GT_BLACK);
        }
    }
    char cap[64];
    snprintf(cap, sizeof cap, " ART GALLERY %d/3 \xc2\xb7 %s \xc2\xb7 Space next \xc2\xb7 Esc back ", B.art_fx + 1, ART_NAME[B.art_fx]);
    int cw = gt_strwidth(cap);
    gt_text(t, (w - cw) / 2, h - 1, GT_BLACK, GT_LIGHT_GRAY, cap);
}

static void key_art(int k){
    B.art_next = 0;
    if (k == ' ' || k == GT_KEY_RIGHT || k == GT_KEY_ENTER) B.art_fx = (B.art_fx + 1) % 3;
    else if (k == GT_KEY_LEFT) B.art_fx = (B.art_fx + 2) % 3;
    else if (k == GT_KEY_ESC || k == 'q' || k == 'Q') go(S_MENU);
}

/* -------------------------------------------------------- overlays */

static void draw_page(gt_t *t){
    uint64_t e = bbs_plat_ms() - B.t_overlay;
    window(t, 13, 6, 54, 9, GT_AQUAMARINE, GT_DARK_BLUE, "Page the Sysop");
    if (e < 4500){
        static const char *notes = "\x0d\x0e";
        int dots = (int)(e / 400) % 4;
        gt_textf(t, 17, 8, GT_WHITE, GT_DARK_BLUE, "Paging the sysop%.*s", dots, "...");
        for (int i = 0; i < 5; i++){
            int x = 17 + (int)((e / 90 + (uint64_t)i * 7) % 44);
            gt_put(t, x, 10 + (i % 3), (uint8_t)notes[i % 2], ART_STRIPES[i], GT_DARK_BLUE);
        }
        int want = (int)(e / 1500) + 1;
        while (B.bells < want && B.bells < 3){ gt_bell(t); B.bells++; }
    } else {
        gt_text(t, 17, 8, GT_YELLOW, GT_DARK_BLUE, "No answer.");
        gt_text(t, 17, 9, GT_WHITE, GT_DARK_BLUE, "The sysop is up the radio tower adjusting");
        gt_text(t, 17, 10, GT_WHITE, GT_DARK_BLUE, "the antenna. Leave a note in the guestbook!");
        gt_text(t, 17, 12, GT_LIGHT_BLUE, GT_DARK_BLUE, "Press any key");
    }
}

static void draw_logoff(gt_t *t){
    window(t, 22, 8, 36, 5, GT_DEEP_RED, GT_BLACK, "Log off");
    gt_pipe(t, 26, 10, "|15Hang up now? |15[|13Y|15/|13n|15]");
}

/* ------------------------------------------------------------- bye */

static void draw_bye(gt_t *t){
    int bw = art_bigword_width("BYE!");
    art_bigword(t, (PAGE_W - bw) / 2, 2, "BYE!", (int)(B.tick % 40) - 6);
    char who[24], line[96], d[16];
    copy_ascii(who, sizeof who, lssh_username(B.s));
    snprintf(line, sizeof line, "Thanks for calling GLOSSH BBS, %s!", who);
    art_rainbow(t, (PAGE_W - gt_strwidth(line)) / 2, 10, line, B.tick);
    fmt_dur(bbs_plat_ms() - B.t_login, d, sizeof d);
    snprintf(line, sizeof line, "You were online %s  \xc2\xb7  caller #%u", d, (unsigned)B.caller_no);
    gt_text(t, (PAGE_W - gt_strwidth(line)) / 2, 12, GT_LIGHT_GRAY, GT_BLACK, line);
    gt_text(t, 22, 14, GT_PINK, GT_BLACK, "~*~ Don't forget to sign the guestbook ~*~");
}

static void hang_up(void){
    B.leaving = true;
    gt_end(B.t);
    (void)!lssh_printf(B.s, "\r\n\x1b[0mNO CARRIER\r\n");
    (void)!lssh_exit(B.s, 0);
}

/* ---------------------------------------------------------- render */

static void session_free(void);
static void on_key(void *ctx, int k);

static void render_frame(void){
    gt_t *t = B.t;
    int W = gt_cols(t), H = gt_rows(t);
    gt_view_full(t);
    gt_cursor(t, -1, -1);

    if (W < PAGE_W || H < PAGE_H + 2){
        gt_clear(t, GT_BLACK);
        gt_textf(t, 0, 0, GT_YELLOW, GT_BLACK, "GLOSSH BBS needs 80x24.");
        gt_textf(t, 0, 1, GT_LIGHT_GRAY, GT_BLACK, "This window is %dx%d.", W, H);
        gt_textf(t, 0, 2, GT_LIGHT_GRAY, GT_BLACK, "Resize, or press G to hang up.");
        gt_flush(t);
        return;
    }

    if (B.screen == S_ART){
        uint64_t now = bbs_plat_ms();
        if (now < B.art_next) return;           /* keep the previous frame */
        size_t before = gt_bytes_out(t);
        draw_art(t);
        gt_flush(t);
        B.art_next = now + (uint64_t)(gt_bytes_out(t) - before) * 1000u / BBS_ART_BYTES_PER_S;
        return;
    }

    bool modem = B.screen == S_DIAL && !B.reveal;
    bool chrome = !modem && !(B.screen == S_DIAL && !B.reveal_all) && B.screen != S_BYE;
    art_starfield(t, B.tick);
    if (modem) gt_clear(t, GT_BLACK);
    if (chrome){ top_bar(t); status_bar(t); }

    gt_view(t, (W - PAGE_W) / 2, 1 + (H - 2 - PAGE_H) / 2, PAGE_W, PAGE_H);
    switch (B.screen){
    case S_EMU:       draw_emu(t); break;
    case S_DIAL:      draw_dial(t); break;
    case S_MENU:      draw_menu(t); break;
    case S_BULLETINS: draw_bulletins(t); break;
    case S_CALLERS:   draw_callers(t); break;
    case S_SYSTEM:    draw_system(t); break;
    case S_TASKS:     draw_tasks(t); break;
    case S_GUESTBOOK: draw_guestbook(t); break;
    case S_BYE:       draw_bye(t); break;
    }
    if (B.overlay != O_NONE) gt_cursor(t, -1, -1);
    switch (B.overlay){
    case O_SIGN:   draw_sign(t); break;
    case O_PAGE:   draw_page(t); break;
    case O_LOGOFF: draw_logoff(t); break;
    }
    gt_view_full(t);
    gt_flush(t);
}

static void render(void){
    if (!B.active || B.leaving || !B.t || B.in_render) return;
    B.in_render = true;
    render_frame();
    B.in_render = false;
    if (B.closed){ session_free(); return; }
    if (B.npending && !B.leaving){
        uint8_t q[sizeof B.pending];
        size_t n = B.npending;
        memcpy(q, B.pending, n);
        B.npending = 0;
        gt_keys_feed(&B.keys, q, n, on_key, NULL);
        render();
    }
}

/* ----------------------------------------------------------- input */

static void on_key(void *ctx, int k){
    (void)ctx;
    if (B.leaving) return;
    if (gt_cols(B.t) < PAGE_W || gt_rows(B.t) < PAGE_H + 2){
        if (k == 'g' || k == 'G' || k == 3) hang_up();
        return;
    }
    if (k == 3 || k == 4){                      /* Ctrl-C / Ctrl-D */
        if (B.screen == S_BYE) return;
        go(S_MENU); B.overlay = O_LOGOFF;
        return;
    }
    switch (B.overlay){
    case O_SIGN: key_sign(k); return;
    case O_PAGE:
        if (bbs_plat_ms() - B.t_overlay >= 4500 || k == GT_KEY_ESC) B.overlay = O_NONE;
        return;
    case O_LOGOFF:
        if (k == 'y' || k == 'Y' || k == GT_KEY_ENTER || k == 'g' || k == 'G'){ B.overlay = O_NONE; go(S_BYE); }
        else B.overlay = O_NONE;
        return;
    }
    switch (B.screen){
    case S_EMU:       key_emu(k); break;
    case S_DIAL:      key_dial(k); break;
    case S_MENU:      key_menu(k); break;
    case S_TASKS:     key_tasks(k); break;
    case S_GUESTBOOK: key_guestbook(k); break;
    case S_ART:       key_art(k); break;
    case S_BULLETINS: case S_CALLERS: case S_SYSTEM:
        if (k == GT_KEY_ESC || k == 'q' || k == 'Q' || k == GT_KEY_ENTER || k == ' ') go(S_MENU);
        break;
    }
}

/* ------------------------------------------------ littlessh glue */

static void wr(void *ctx, const void *d, size_t n){
    if (lssh_write((lssh_session_t*)ctx, d, n) < 0) B.leaving = true;
}

void bbs_init(const bbs_config_t *cfg){
    if (cfg) s_cfg = *cfg;
    if (!bbs_plat_load("stats", &s_stats, sizeof s_stats) || s_stats.magic != STATS_MAGIC){
        memset(&s_stats, 0, sizeof s_stats);
        s_stats.magic = STATS_MAGIC;
    }
    if (!bbs_plat_load("gbook", &s_gb, sizeof s_gb) || s_gb.magic != GB_MAGIC){
        memset(&s_gb, 0, sizeof s_gb);
        s_gb.magic = GB_MAGIC;
    }
    if (s_stats.n > CALLERS_MAX || s_stats.head >= CALLERS_MAX) s_stats.n = s_stats.head = 0;
    if (s_gb.n > GB_MAX || s_gb.head >= GB_MAX) s_gb.n = s_gb.head = 0;
}

static void log_caller(lssh_session_t *s){
    s_stats.calls++;
    caller_t *c = &s_stats.last[s_stats.head];
    memset(c, 0, sizeof *c);
    copy_ascii(c->user, sizeof c->user, lssh_username(s));
    const char *v = lssh_client_version(s);
    copy_ascii(c->client, sizeof c->client, strncmp(v, "SSH-2.0-", 8) ? v : v + 8);
    time_t now;
    c->when = bbs_plat_time(&now) ? (uint32_t)now : 0;
    c->num = s_stats.calls;
    s_stats.head = (uint8_t)((s_stats.head + 1) % CALLERS_MAX);
    if (s_stats.n < CALLERS_MAX) s_stats.n++;
    bbs_plat_save("stats", &s_stats, sizeof s_stats);
}

void bbs_on_pty(void *user, lssh_session_t *s, uint16_t cols, uint16_t rows){
    (void)user; (void)s;
    s_pty_cols = cols; s_pty_rows = rows;
    if (B.active && B.t && !B.in_render){
        gt_resize(B.t, cols, rows);
        B.art_next = 0;
        render();
    }
}

void bbs_on_open(void *user, lssh_session_t *s, const char *exec_cmd){
    (void)user;
    if (exec_cmd || !lssh_has_pty(s)){
        (void)!lssh_printf(s, "GLOSSH BBS is an interactive board. Call in with a terminal:\r\n"
                              "  ssh -t <user>@<board>\r\n");
        (void)!lssh_exit(s, exec_cmd ? 1 : 0);
        return;
    }
    free(B.fire.heat);
    memset(&B, 0, sizeof B);
    B.s = s;
    B.t = gt_new(wr, s, BBS_MAX_COLS, BBS_MAX_ROWS);
    if (!B.t) B.t = gt_new(wr, s, PAGE_W, PAGE_H + 2);
    if (!B.t){
        (void)!lssh_printf(s, "GLOSSH BBS: out of memory, call back later.\r\n");
        (void)!lssh_exit(s, 1);
        return;
    }
    gt_resize(B.t, s_pty_cols, s_pty_rows);
    gt_mode_t m = detect_mode(lssh_term(s));
    for (int i = 0; i < 4; i++) if (EMU[i].m == m) B.emu_sel = i;
    gt_set_mode(B.t, m);
    gt_keys_init(&B.keys);
    B.keys.cp437 = m == GT_MODE_ANSIBBS;
    log_caller(s);
    B.caller_no = s_stats.calls;
    B.t_login = bbs_plat_ms();
    B.busy = -1;
    sample(true);
    B.active = true;
    gt_begin(B.t);
    gt_title(B.t, "GLOSSH BBS \xc2\xb7 Node 1");
    go(S_EMU);
    render();
}

void bbs_on_data(void *user, lssh_session_t *s, const uint8_t *d, size_t n){
    (void)user; (void)s;
    if (!B.active || B.leaving) return;
    if (B.in_render){
        size_t room = sizeof B.pending - B.npending;
        if (n > room) n = room;
        memcpy(B.pending + B.npending, d, n);
        B.npending += n;
        return;
    }
    gt_keys_feed(&B.keys, d, n, on_key, NULL);
    render();
}

void bbs_on_tick(void *user, lssh_session_t *s){
    (void)user; (void)s;
    if (!B.active || B.leaving || B.in_render) return;
    B.tick++;
    gt_keys_tick(&B.keys, on_key, NULL);
    sample(false);
    if (B.screen == S_BYE && bbs_plat_ms() - B.t_screen > 2800){ hang_up(); return; }
    render();
}

static void session_free(void){
    gt_free(B.t);
    free(B.fire.heat);
    memset(&B, 0, sizeof B);
}

void bbs_on_close(void *user, lssh_session_t *s){
    (void)user; (void)s;
    if (B.in_render){ B.closed = true; B.leaving = true; return; }
    session_free();
}
