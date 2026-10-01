/*
 * glotui — 16-color ANSI-art terminal UI over any byte stream.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "glotui.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef GT_OUTBUF
#define GT_OUTBUF 3072      /* one write per ~SSH packet; keep < LSSH_MAX_PACKET */
#endif

/* Apple IIgs Hardware Reference, standard 16 colors ($0RGB -> 0xRRGGBB). */
const uint32_t GT_PALETTE_IIGS[16] = {
    0x000000, 0xDD0033, 0x000099, 0xDD22DD,
    0x007722, 0x555555, 0x2222FF, 0x66AAFF,
    0x885500, 0xFF6600, 0xAAAAAA, 0xFF9988,
    0x11DD00, 0xFFFF00, 0x44FF99, 0xFFFFFF,
};

/* IIgs -> ANSI 16, hand-picked as a bijection so all 16 stay distinct
 * (nearest-color would fold both light blues and both greens together). */
static const uint8_t IIGS_TO_ANSI16[16] = {
    0, 1, 4, 5,  2, 8, 12, 6,  3, 9, 7, 13,  10, 11, 14, 15,
};

/* CGA/VGA text palette: the reference for nearest-color on custom palettes. */
static const uint32_t CGA[16] = {
    0x000000, 0xAA0000, 0x00AA00, 0xAA5500, 0x0000AA, 0xAA00AA, 0x00AAAA, 0xAAAAAA,
    0x555555, 0xFF5555, 0x55FF55, 0xFFFF55, 0x5555FF, 0xFF55FF, 0x55FFFF, 0xFFFFFF,
};

/* ------------------------------------------------------------- CP437 */

static const uint16_t CP437[256] = {
    0x0020,0x263A,0x263B,0x2665,0x2666,0x2663,0x2660,0x2022,
    0x25D8,0x25CB,0x25D9,0x2642,0x2640,0x266A,0x266B,0x263C,
    0x25BA,0x25C4,0x2195,0x203C,0x00B6,0x00A7,0x25AC,0x21A8,
    0x2191,0x2193,0x2192,0x2190,0x221F,0x2194,0x25B2,0x25BC,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,
    0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,
    0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,
    0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,0x7B,0x7C,0x7D,0x7E,0x2302,
    0x00C7,0x00FC,0x00E9,0x00E2,0x00E4,0x00E0,0x00E5,0x00E7,
    0x00EA,0x00EB,0x00E8,0x00EF,0x00EE,0x00EC,0x00C4,0x00C5,
    0x00C9,0x00E6,0x00C6,0x00F4,0x00F6,0x00F2,0x00FB,0x00F9,
    0x00FF,0x00D6,0x00DC,0x00A2,0x00A3,0x00A5,0x20A7,0x0192,
    0x00E1,0x00ED,0x00F3,0x00FA,0x00F1,0x00D1,0x00AA,0x00BA,
    0x00BF,0x2310,0x00AC,0x00BD,0x00BC,0x00A1,0x00AB,0x00BB,
    0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,
    0x2555,0x2563,0x2551,0x2557,0x255D,0x255C,0x255B,0x2510,
    0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x255E,0x255F,
    0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x2567,
    0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256B,
    0x256A,0x2518,0x250C,0x2588,0x2584,0x258C,0x2590,0x2580,
    0x03B1,0x00DF,0x0393,0x03C0,0x03A3,0x03C3,0x00B5,0x03C4,
    0x03A6,0x0398,0x03A9,0x03B4,0x221E,0x03C6,0x03B5,0x2229,
    0x2261,0x00B1,0x2265,0x2264,0x2320,0x2321,0x00F7,0x2248,
    0x00B0,0x2219,0x00B7,0x221A,0x207F,0x00B2,0x25A0,0x00A0,
};

/* Extra spellings that fold onto CP437 glyphs. */
static const struct { uint16_t u; uint8_t c; } CP437_ALIAS[] = {
    {0x2018,'\''}, {0x2019,'\''}, {0x201C,'"'}, {0x201D,'"'},
    {0x2013,'-'},  {0x2014,'-'},  {0x2026,0xFA}, {0x2713,0xFB},
    {0x25CF,0x07}, {0x2605,0x0F}, {0x2606,0x0F}, {0x00A6,'|'},
};

typedef struct { uint16_t u; uint8_t c; } rev_t;
static rev_t s_rev[128 + 33 + sizeof CP437_ALIAS / sizeof CP437_ALIAS[0]];
static size_t s_rev_n;

static int rev_cmp(const void *a, const void *b){
    return (int)((const rev_t*)a)->u - (int)((const rev_t*)b)->u;
}

static void rev_init(void){
    if (s_rev_n) return;
    size_t n = 0;
    for (int c = 1; c < 256; c++)
        if (c < 0x20 || c >= 0x7F) s_rev[n++] = (rev_t){CP437[c], (uint8_t)c};
    for (size_t i = 0; i < sizeof CP437_ALIAS / sizeof CP437_ALIAS[0]; i++)
        s_rev[n++] = (rev_t){CP437_ALIAS[i].u, CP437_ALIAS[i].c};
    qsort(s_rev, n, sizeof s_rev[0], rev_cmp);
    s_rev_n = n;
}

uint8_t gt_cp437(uint32_t u){
    if (u >= 0x20 && u < 0x7F) return (uint8_t)u;
    rev_init();
    size_t lo = 0, hi = s_rev_n;
    while (lo < hi){
        size_t mid = (lo + hi) / 2;
        if (s_rev[mid].u == u) return s_rev[mid].c;
        if (s_rev[mid].u < u) lo = mid + 1; else hi = mid;
    }
    return '?';
}

uint16_t gt_unicode(uint8_t c){ return CP437[c]; }

/* Decode one UTF-8 sequence; invalid input yields U+FFFD and advances. */
static uint32_t utf8_next(const char **ps){
    const uint8_t *s = (const uint8_t*)*ps;
    uint32_t cp; int need;
    if (s[0] < 0x80){ *ps += 1; return s[0]; }
    if ((s[0] & 0xE0) == 0xC0){ cp = s[0] & 0x1F; need = 1; }
    else if ((s[0] & 0xF0) == 0xE0){ cp = s[0] & 0x0F; need = 2; }
    else if ((s[0] & 0xF8) == 0xF0){ cp = s[0] & 0x07; need = 3; }
    else { *ps += 1; return 0xFFFD; }
    for (int i = 1; i <= need; i++){
        if ((s[i] & 0xC0) != 0x80){ *ps += i; return 0xFFFD; }
        cp = (cp << 6) | (s[i] & 0x3F);
    }
    *ps += need + 1;
    return cp;
}

int gt_strwidth(const char *s){
    int n = 0;
    while (*s){ utf8_next(&s); n++; }
    return n;
}

/* ------------------------------------------------------------ state */

#define POISON 0x40         /* attr bit never set on a back cell */

struct gt {
    gt_write_fn wr; void *ctx;
    uint16_t max_cols, max_rows;
    uint16_t term_cols, term_rows;
    uint16_t cols, rows, ox, oy;
    size_t   cap;
    gt_cell_t *back, *front;

    int vx, vy, vw, vh;

    gt_mode_t mode;
    uint32_t pal[16];
    uint8_t  pal256[16], pal16[16];

    int  cx, cy;                        /* terminal cursor, -1 unknown */
    int  pen_fg, pen_bg, pen_fgm, pen_bgm, pen_attr;
    bool pen_bold;
    int  want_x, want_y;                /* canvas coords, -1 hidden */
    bool cur_shown;
    bool full;

    size_t outn, total;
    char out[GT_OUTBUF];
};

static void out_flush(gt_t *t){
    if (t->outn){ t->wr(t->ctx, t->out, t->outn); t->total += t->outn; t->outn = 0; }
}
static void out_raw(gt_t *t, const void *d, size_t n){
    if (t->outn + n > sizeof t->out) out_flush(t);
    if (n > sizeof t->out){ t->wr(t->ctx, d, n); t->total += n; return; }
    memcpy(t->out + t->outn, d, n); t->outn += n;
}
static void out_str(gt_t *t, const char *s){ out_raw(t, s, strlen(s)); }

static int redmean(uint32_t a, uint32_t b){
    int r1 = (a >> 16) & 255, g1 = (a >> 8) & 255, b1 = a & 255;
    int r2 = (b >> 16) & 255, g2 = (b >> 8) & 255, b2 = b & 255;
    int rm = (r1 + r2) / 2, dr = r1 - r2, dg = g1 - g2, db = b1 - b2;
    return (((512 + rm) * dr * dr) >> 8) + 4 * dg * dg + (((767 - rm) * db * db) >> 8);
}

static uint32_t xterm256_rgb(int i){
    static const uint8_t lv[6] = {0, 95, 135, 175, 215, 255};
    if (i >= 232){ uint32_t g = (uint32_t)(8 + 10 * (i - 232)); return g << 16 | g << 8 | g; }
    i -= 16;
    return (uint32_t)lv[i / 36] << 16 | (uint32_t)lv[(i / 6) % 6] << 8 | lv[i % 6];
}

void gt_set_palette(gt_t *t, const uint32_t rgb[16]){
    memcpy(t->pal, rgb, sizeof t->pal);
    bool iigs = memcmp(rgb, GT_PALETTE_IIGS, sizeof t->pal) == 0;
    for (int c = 0; c < 16; c++){
        int best = 16, bd = 0x7FFFFFFF;
        for (int i = 16; i < 256; i++){            /* 0-15 are theme-dependent */
            int d = redmean(rgb[c], xterm256_rgb(i));
            if (d < bd){ bd = d; best = i; }
        }
        t->pal256[c] = (uint8_t)best;
        if (iigs){ t->pal16[c] = IIGS_TO_ANSI16[c]; continue; }
        best = 0; bd = 0x7FFFFFFF;
        for (int i = 0; i < 16; i++){
            int d = redmean(rgb[c], CGA[i]);
            if (d < bd){ bd = d; best = i; }
        }
        t->pal16[c] = (uint8_t)best;
    }
    gt_invalidate(t);
}

gt_t *gt_new(gt_write_fn wr, void *ctx, uint16_t max_cols, uint16_t max_rows){
    gt_t *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->wr = wr; t->ctx = ctx;
    t->max_cols = max_cols ? max_cols : 80;
    t->max_rows = max_rows ? max_rows : 24;
    t->want_x = t->want_y = -1;
    gt_set_palette(t, GT_PALETTE_IIGS);
    if (!gt_resize(t, 80, 24)){ free(t); return NULL; }
    return t;
}

void gt_free(gt_t *t){
    if (!t) return;
    free(t->back); free(t->front); free(t);
}

bool gt_resize(gt_t *t, uint16_t tc, uint16_t tr){
    if (!tc) tc = 80;
    if (!tr) tr = 24;
    uint16_t c = tc < t->max_cols ? tc : t->max_cols;
    uint16_t r = tr < t->max_rows ? tr : t->max_rows;
    size_t need = (size_t)c * r;
    if (need > t->cap){
        gt_cell_t *b = malloc(need * sizeof *b), *f = malloc(need * sizeof *f);
        if (!b || !f){ free(b); free(f); return false; }
        free(t->back); free(t->front);
        t->back = b; t->front = f; t->cap = need;
    }
    t->term_cols = tc; t->term_rows = tr;
    t->cols = c; t->rows = r;
    t->ox = (uint16_t)((tc - c) / 2);
    t->oy = (uint16_t)((tr - r) / 2);
    gt_view_full(t);
    gt_clear(t, GT_BLACK);
    gt_invalidate(t);
    return true;
}

uint16_t gt_cols(const gt_t *t){ return t->cols; }
uint16_t gt_rows(const gt_t *t){ return t->rows; }
gt_mode_t gt_mode(const gt_t *t){ return t->mode; }
size_t gt_bytes_out(const gt_t *t){ return t->total + t->outn; }

void gt_set_mode(gt_t *t, gt_mode_t m){
    if (m == t->mode) return;
    t->mode = m;
    gt_invalidate(t);
}

void gt_invalidate(gt_t *t){ t->full = true; }

void gt_begin(gt_t *t){
    out_str(t, "\x1b[?1049h\x1b[?25l\x1b[?7l");
    t->cur_shown = false;
    gt_invalidate(t);
}

void gt_end(gt_t *t){
    out_str(t, "\x1b[0m\x1b[?7h\x1b[?25h\x1b[?1049l");
    out_flush(t);
}

void gt_title(gt_t *t, const char *s){
    if (t->mode == GT_MODE_ANSIBBS) return;     /* not every BBS terminal parses OSC */
    out_str(t, "\x1b]0;");
    out_str(t, s);
    out_str(t, "\x07");
}

void gt_bell(gt_t *t){ out_str(t, "\x07"); }

/* ------------------------------------------------------------- views */

void gt_view(gt_t *t, int x, int y, int w, int h){
    if (x < 0){ w += x; x = 0; }
    if (y < 0){ h += y; y = 0; }
    if (x + w > t->cols) w = t->cols - x;
    if (y + h > t->rows) h = t->rows - y;
    t->vx = x; t->vy = y;
    t->vw = w > 0 ? w : 0; t->vh = h > 0 ? h : 0;
}
void gt_view_full(gt_t *t){ gt_view(t, 0, 0, t->cols, t->rows); }
int  gt_view_w(const gt_t *t){ return t->vw; }
int  gt_view_h(const gt_t *t){ return t->vh; }

/* ----------------------------------------------------------- drawing */

gt_cell_t *gt_at(gt_t *t, int x, int y){
    if (x < 0 || y < 0 || x >= t->vw || y >= t->vh) return NULL;
    return &t->back[(size_t)(t->vy + y) * t->cols + (size_t)(t->vx + x)];
}

void gt_put(gt_t *t, int x, int y, uint8_t ch, uint8_t fg, uint8_t bg){
    gt_cell_t *c = gt_at(t, x, y);
    if (c){ c->ch = ch; c->fg = fg & 15; c->bg = bg & 15; c->attr = 0; }
}

void gt_fill(gt_t *t, int x, int y, int w, int h, uint8_t ch, uint8_t fg, uint8_t bg){
    for (int j = 0; j < h; j++)
        for (int i = 0; i < w; i++) gt_put(t, x + i, y + j, ch, fg, bg);
}

void gt_clear(gt_t *t, uint8_t bg){ gt_fill(t, 0, 0, t->vw, t->vh, ' ', GT_LIGHT_GRAY, bg); }

void gt_hline(gt_t *t, int x, int y, int w, uint8_t ch, uint8_t fg, uint8_t bg){
    gt_fill(t, x, y, w, 1, ch, fg, bg);
}
void gt_vline(gt_t *t, int x, int y, int h, uint8_t ch, uint8_t fg, uint8_t bg){
    gt_fill(t, x, y, 1, h, ch, fg, bg);
}

int gt_text(gt_t *t, int x, int y, uint8_t fg, uint8_t bg, const char *s){
    int n = 0;
    while (*s) gt_put(t, x + n++, y, gt_cp437(utf8_next(&s)), fg, bg);
    return n;
}

int gt_textf(gt_t *t, int x, int y, uint8_t fg, uint8_t bg, const char *fmt, ...){
    char buf[256];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    return gt_text(t, x, y, fg, bg, buf);
}

static int pipe_code(const char *s){
    if (s[0] != '|' || s[1] < '0' || s[1] > '3' || s[2] < '0' || s[2] > '9') return -1;
    int v = (s[1] - '0') * 10 + (s[2] - '0');
    return v < 32 ? v : -1;
}

static int pipe_walk(gt_t *t, int x, int y, const char *s){
    uint8_t fg = GT_LIGHT_GRAY, bg = GT_BLACK;
    int n = 0;
    while (*s){
        int v = pipe_code(s);
        if (v >= 0){
            if (v < 16) fg = (uint8_t)v; else bg = (uint8_t)(v - 16);
            s += 3; continue;
        }
        if (s[0] == '|' && s[1] == '|') s++;
        uint8_t ch = gt_cp437(utf8_next(&s));
        if (t) gt_put(t, x + n, y, ch, fg, bg);
        n++;
    }
    return n;
}

int gt_pipe(gt_t *t, int x, int y, const char *s){ return pipe_walk(t, x, y, s); }
int gt_pipe_width(const char *s){ return pipe_walk(NULL, 0, 0, s); }

void gt_box(gt_t *t, int x, int y, int w, int h, int style, uint8_t fg, uint8_t bg){
    /* tl tr bl br horiz vert; BLOCK uses distinct top/bottom edges */
    static const uint8_t G[4][6] = {
        {0xDA, 0xBF, 0xC0, 0xD9, 0xC4, 0xB3},
        {0xC9, 0xBB, 0xC8, 0xBC, 0xCD, 0xBA},
        {0xD5, 0xB8, 0xD4, 0xBE, 0xCD, 0xB3},
        {0xDC, 0xDC, 0xDF, 0xDF, 0xDC, 0xDB},
    };
    if (w < 2 || h < 2 || style < 0 || style > 3) return;
    const uint8_t *g = G[style];
    uint8_t bottom = style == GT_BOX_BLOCK ? 0xDF : g[4];
    gt_hline(t, x + 1, y, w - 2, g[4], fg, bg);
    gt_hline(t, x + 1, y + h - 1, w - 2, bottom, fg, bg);
    gt_vline(t, x, y + 1, h - 2, g[5], fg, bg);
    gt_vline(t, x + w - 1, y + 1, h - 2, g[5], fg, bg);
    gt_put(t, x, y, g[0], fg, bg);
    gt_put(t, x + w - 1, y, g[1], fg, bg);
    gt_put(t, x, y + h - 1, g[2], fg, bg);
    gt_put(t, x + w - 1, y + h - 1, g[3], fg, bg);
}

static void shade(gt_cell_t *c){
    if (!c) return;
    if (c->fg != GT_BLACK) c->fg = GT_DARK_GRAY;
    c->bg = GT_BLACK;
    if (c->ch == 0xDB) c->ch = ' ';     /* a full block would stay solid */
}

void gt_shadow(gt_t *t, int x, int y, int w, int h){
    for (int j = 1; j <= h; j++){ shade(gt_at(t, x + w, y + j)); shade(gt_at(t, x + w + 1, y + j)); }
    for (int i = 2; i < w; i++) shade(gt_at(t, x + i, y + h));
}

void gt_cursor(gt_t *t, int x, int y){
    if (x < 0 || y < 0 || x >= t->vw || y >= t->vh){ t->want_x = t->want_y = -1; return; }
    t->want_x = t->vx + x; t->want_y = t->vy + y;
}

/* ---------------------------------------------------------- renderer */

static int cell_mode(const gt_t *t, const gt_cell_t *c){
    return (c->attr & 0x80) ? (c->attr >> 4) & 3 : (int)t->mode;
}

static int put_color(char *p, const gt_t *t, int idx, int m, bool bg){
    uint32_t rgb = t->pal[idx];
    int a = t->pal16[idx];
    switch (m){
    case GT_MODE_TRUECOLOR:
        return sprintf(p, ";%d;2;%u;%u;%u", bg ? 48 : 38,
                       (unsigned)(rgb >> 16) & 255, (unsigned)(rgb >> 8) & 255, (unsigned)rgb & 255);
    case GT_MODE_256:
        return sprintf(p, ";%d;5;%u", bg ? 48 : 38, t->pal256[idx]);
    case GT_MODE_16:
        return sprintf(p, ";%d", (bg ? 40 : 30) + (a & 7) + (a >= 8 ? 60 : 0));
    default:    /* ANSI-BBS: brightness is bold (fg) and unavailable (bg) */
        return sprintf(p, ";%d", (bg ? 40 : 30) + (a & 7));
    }
}

static void pen(gt_t *t, const gt_cell_t *c){
    int m = cell_mode(t, c);
    int attr = c->attr & (GT_BLINK | GT_UNDERLINE);
    bool fg_matters = !(c->ch == ' ' || c->ch == 0 || c->ch == 0xFF) || (attr & GT_UNDERLINE);
    bool bg_matters = c->ch != 0xDB;
    bool bold = m == GT_MODE_ANSIBBS && t->pal16[c->fg] >= 8 && fg_matters;
    bool fg_ok = !fg_matters || (t->pen_fg == c->fg && t->pen_fgm == m);
    bool bg_ok = !bg_matters || (t->pen_bg == c->bg && t->pen_bgm == m);
    /* ANSI-BBS pens stay bold for spaces rather than resetting to unbold */
    if (!fg_matters && t->pen_bold) bold = true;
    bool reset = t->pen_attr < 0 || (t->pen_attr & ~attr) || (t->pen_bold && !bold);
    if (fg_ok && bg_ok && !reset && t->pen_attr == attr && t->pen_bold == bold) return;

    char b[96]; int n = 0;
    b[n++] = 0x1b; b[n++] = '[';
    if (reset){
        n += sprintf(b + n, "0");
        t->pen_attr = 0; t->pen_bold = false;
        fg_ok = bg_ok = false;
    }
    if ((attr & GT_BLINK) && !(t->pen_attr & GT_BLINK)) n += sprintf(b + n, ";5");
    if ((attr & GT_UNDERLINE) && !(t->pen_attr & GT_UNDERLINE)) n += sprintf(b + n, ";4");
    if (bold && !t->pen_bold) n += sprintf(b + n, ";1");
    if (!fg_ok){ n += put_color(b + n, t, c->fg, m, false); t->pen_fg = c->fg; t->pen_fgm = m; }
    if (!bg_ok){ n += put_color(b + n, t, c->bg, m, true);  t->pen_bg = c->bg; t->pen_bgm = m; }
    b[n++] = 'm';
    /* drop the leading ';' left by the first parameter */
    if (b[2] == ';'){ memmove(b + 2, b + 3, (size_t)n - 3); n--; }
    out_raw(t, b, (size_t)n);
    t->pen_attr = attr; t->pen_bold = bold;
}

static void move_to(gt_t *t, int x, int y){
    if (t->cy == y && t->cx == x) return;
    char b[32];
    int n;
    if (t->cy == y && t->cx >= 0 && x > t->cx)
        n = x - t->cx == 1 ? snprintf(b, sizeof b, "\x1b[C") : snprintf(b, sizeof b, "\x1b[%dC", x - t->cx);
    else
        n = snprintf(b, sizeof b, "\x1b[%d;%dH", y + 1, x + 1);
    out_raw(t, b, (size_t)n);
    t->cx = x; t->cy = y;
}

/* ANSI-BBS terminals treat 0x00-0x1F and 0x7F as controls: substitute. */
static uint8_t bbs_safe(uint8_t c){
    static const char SUB[] = " @@*****ooo*****><|!PS-|^v><L-^v";   /* index = CP437 code */
    if (c == 0x7F) return '^';
    if (c < 0x20) return c == 0x07 ? 0xF9 : (uint8_t)SUB[c];
    return c;
}

static void glyph(gt_t *t, uint8_t ch, int m){
    if (m == GT_MODE_ANSIBBS){ uint8_t b = bbs_safe(ch); out_raw(t, &b, 1); return; }
    uint16_t u = CP437[ch];
    char b[3];
    if (u < 0x80){ b[0] = (char)u; out_raw(t, b, 1); }
    else if (u < 0x800){ b[0] = (char)(0xC0 | (u >> 6)); b[1] = (char)(0x80 | (u & 0x3F)); out_raw(t, b, 2); }
    else {
        b[0] = (char)(0xE0 | (u >> 12)); b[1] = (char)(0x80 | ((u >> 6) & 0x3F));
        b[2] = (char)(0x80 | (u & 0x3F)); out_raw(t, b, 3);
    }
}

void gt_flush(gt_t *t){
    size_t n = (size_t)t->cols * t->rows;
    if (t->full){
        t->pen_attr = -1;
        gt_cell_t blank = {' ', GT_LIGHT_GRAY, GT_BLACK, 0};
        pen(t, &blank);
        out_str(t, "\x1b[2J");          /* background-color erase paints it black */
        memset(t->front, 0, n * sizeof *t->front);
        for (size_t i = 0; i < n; i++) t->front[i].attr = POISON;
        t->cx = t->cy = -1;
        t->full = false;
    }
    if (t->cur_shown){ out_str(t, "\x1b[?25l"); t->cur_shown = false; }

    for (uint16_t y = 0; y < t->rows; y++){
        gt_cell_t *b = &t->back[(size_t)y * t->cols], *f = &t->front[(size_t)y * t->cols];
        for (uint16_t x = 0; x < t->cols; x++){
            if (!memcmp(&b[x], &f[x], sizeof b[x])) continue;
            int tx = t->ox + x, ty = t->oy + y;
            move_to(t, tx, ty);
            pen(t, &b[x]);
            glyph(t, b[x].ch, cell_mode(t, &b[x]));
            f[x] = b[x];
            t->cx = tx + 1 < t->term_cols ? tx + 1 : -1;   /* last column: position unknown */
        }
    }
    if (t->want_x >= 0){
        move_to(t, t->ox + t->want_x, t->oy + t->want_y);
        out_str(t, "\x1b[?25h");
        t->cur_shown = true;
    }
    out_flush(t);
}

/* ---------------------------------------------------------- keyboard */

void gt_keys_init(gt_keys_t *k){ memset(k, 0, sizeof *k); }

/* 1 complete (*key may be 0: recognised but ignored), 0 need more, -1 not a
 * sequence we understand. */
static int parse_esc(const uint8_t *b, size_t n, int *key){
    *key = 0;
    if (n < 2) return 0;
    if (b[1] == 'O'){
        if (n < 3) return 0;
        switch (b[2]){
        case 'A': *key = GT_KEY_UP; break;    case 'B': *key = GT_KEY_DOWN; break;
        case 'C': *key = GT_KEY_RIGHT; break; case 'D': *key = GT_KEY_LEFT; break;
        case 'H': *key = GT_KEY_HOME; break;  case 'F': *key = GT_KEY_END; break;
        case 'M': *key = GT_KEY_ENTER; break;
        case 'P': case 'Q': case 'R': case 'S': *key = GT_KEY_F1 + (b[2] - 'P'); break;
        }
        return 1;
    }
    if (b[1] != '[') return -1;
    if (n < 3) return 0;
    if (b[2] == '['){                                /* Linux console F1-F5 */
        if (n < 4) return 0;
        if (b[3] >= 'A' && b[3] <= 'E') *key = GT_KEY_F1 + (b[3] - 'A');
        return 1;
    }
    uint8_t fin = b[n - 1];
    if (fin >= 0x20 && fin <= 0x3F) return 0;       /* params / intermediates */
    if (fin < 0x40 || fin > 0x7E) return -1;
    int p1 = 0;
    for (size_t i = 2; i < n - 1 && b[i] >= '0' && b[i] <= '9'; i++) p1 = p1 * 10 + (b[i] - '0');
    switch (fin){
    case 'A': *key = GT_KEY_UP; break;    case 'B': *key = GT_KEY_DOWN; break;
    case 'C': *key = GT_KEY_RIGHT; break; case 'D': *key = GT_KEY_LEFT; break;
    case 'H': *key = GT_KEY_HOME; break;  case 'F': *key = GT_KEY_END; break;
    case 'Z': *key = GT_KEY_BACKTAB; break;
    case 'P': case 'Q': case 'R': case 'S': *key = GT_KEY_F1 + (fin - 'P'); break;
    case '~':
        switch (p1){
        case 1: case 7: *key = GT_KEY_HOME; break;
        case 4: case 8: *key = GT_KEY_END; break;
        case 2: *key = GT_KEY_INSERT; break;  case 3: *key = GT_KEY_DELETE; break;
        case 5: *key = GT_KEY_PGUP; break;    case 6: *key = GT_KEY_PGDN; break;
        default:
            if (p1 >= 11 && p1 <= 15) *key = GT_KEY_F1 + (p1 - 11);
            else if (p1 >= 17 && p1 <= 21) *key = GT_KEY_F6 + (p1 - 17);
            else if (p1 == 23 || p1 == 24) *key = GT_KEY_F11 + (p1 - 23);
        }
        break;
    }
    return 1;
}

static void plain(gt_keys_t *k, uint8_t b, gt_key_fn cb, void *ctx){
    if (k->u8_need){
        if ((b & 0xC0) == 0x80){
            k->u8_cp = (k->u8_cp << 6) | (b & 0x3F);
            if (--k->u8_need == 0){
                uint8_t c = gt_cp437(k->u8_cp);
                if (c != '?' && c >= 0x80) cb(ctx, c);
            }
            return;
        }
        k->u8_need = 0;
    }
    bool was_cr = k->cr;
    k->cr = false;
    if (b == '\r'){ k->cr = true; cb(ctx, GT_KEY_ENTER); return; }
    if (b == '\n' || b == 0){ if (!was_cr && b == '\n') cb(ctx, GT_KEY_ENTER); return; }
    if (b == 0x7F || b == 0x08){ cb(ctx, GT_KEY_BACKSPACE); return; }
    if (b < 0x80 || k->cp437){ cb(ctx, b); return; }
    if ((b & 0xE0) == 0xC0){ k->u8_cp = b & 0x1F; k->u8_need = 1; }
    else if ((b & 0xF0) == 0xE0){ k->u8_cp = b & 0x0F; k->u8_need = 2; }
    else if ((b & 0xF8) == 0xF0){ k->u8_cp = b & 0x07; k->u8_need = 3; }
}

void gt_keys_feed(gt_keys_t *k, const uint8_t *d, size_t n, gt_key_fn cb, void *ctx){
    for (size_t i = 0; i < n; i++){
        uint8_t b = d[i];
        if (!k->n){
            if (b == 0x1B){ k->buf[0] = b; k->n = 1; k->age = 0; k->cr = false; }
            else plain(k, b, cb, ctx);
            continue;
        }
        k->buf[k->n++] = b;
        int key, r = parse_esc(k->buf, k->n, &key);
        if (r == 0 && k->n < sizeof k->buf) continue;
        if (r > 0){ if (key) cb(ctx, key); k->n = 0; continue; }
        /* not a sequence: ESC was a key of its own (Alt-x, ESC ESC ...);
         * replay what followed it */
        uint8_t rest[sizeof k->buf];
        size_t rn = k->n - 1;
        memcpy(rest, k->buf + 1, rn);
        k->n = 0;
        cb(ctx, GT_KEY_ESC);
        gt_keys_feed(k, rest, rn, cb, ctx);
    }
}

void gt_keys_tick(gt_keys_t *k, gt_key_fn cb, void *ctx){
    if (k->n && ++k->age >= 2){
        k->n = 0;
        cb(ctx, GT_KEY_ESC);
    }
}
