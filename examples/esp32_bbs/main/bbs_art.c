/* ANSI art and effects for GLOSSH BBS.
 * SPDX-License-Identifier: Apache-2.0 */
#include "bbs_art.h"

#include <math.h>
#include <string.h>

const uint8_t ART_STRIPES[6] = {
    GT_LIGHT_GREEN, GT_YELLOW, GT_ORANGE, GT_DEEP_RED, GT_PURPLE, GT_LIGHT_BLUE,
};

/* ------------------------------------------------ ANSI Shadow figlet */

typedef struct { char c; const char *row[6]; } glyph_t;

static const glyph_t FONT[] = {
    {'G', {" ██████╗ ", "██╔════╝ ", "██║  ███╗", "██║   ██║", "╚██████╔╝", " ╚═════╝ "}},
    {'L', {"██╗     ",  "██║     ",  "██║     ",  "██║     ",  "███████╗",  "╚══════╝"}},
    {'O', {" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "}},
    {'S', {"███████╗",  "██╔════╝",  "███████╗",  "╚════██║",  "███████║",  "╚══════╝"}},
    {'H', {"██╗  ██╗",  "██║  ██║",  "███████║",  "██╔══██║",  "██║  ██║",  "╚═╝  ╚═╝"}},
    {'B', {"██████╗ ",  "██╔══██╗",  "██████╔╝",  "██╔══██╗",  "██████╔╝",  "╚═════╝ "}},
    {'Y', {"██╗   ██╗", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚██╔╝  ", "   ██║   ", "   ╚═╝   "}},
    {'E', {"███████╗",  "██╔════╝",  "█████╗  ",  "██╔══╝  ",  "███████╗",  "╚══════╝"}},
    {'!', {"██╗",       "██║",       "██║",       "╚═╝",       "██╗",       "╚═╝"}},
    {' ', {"   ",       "   ",       "   ",       "   ",       "   ",       "   "}},
};

static const glyph_t *font_glyph(char c){
    for (size_t i = 0; i < sizeof FONT / sizeof FONT[0]; i++)
        if (FONT[i].c == c) return &FONT[i];
    return &FONT[sizeof FONT / sizeof FONT[0] - 1];
}

int art_bigword_width(const char *w){
    int n = 0;
    for (; *w; w++) n += gt_strwidth(font_glyph(*w)->row[0]);
    return n;
}

void art_bigword(gt_t *t, int x, int y, const char *w, int gleam){
    int gx = x;
    for (; *w; w++){
        const glyph_t *g = font_glyph(*w);
        for (int r = 0; r < 6; r++){
            /* decode the row into CP437 cells; spaces stay transparent */
            const char *s = g->row[r];
            int col = 0;
            char one[5];
            while (*s){
                int len = (*s & 0x80) ? ((*s & 0xE0) == 0xC0 ? 2 : 3) : 1;
                memcpy(one, s, (size_t)len); one[len] = 0; s += len;
                int cx = gx + col++;
                if (one[0] == ' ') continue;
                gt_cell_t *c = gt_at(t, cx, y + r);
                if (!c) continue;
                gt_text(t, cx, y + r, GT_BLACK, GT_BLACK, one);
                bool solid = c->ch == 0xDB;
                int d = cx - x - gleam + r;          /* slanted gleam band */
                if (solid) c->fg = (gleam >= 0 && d >= -1 && d <= 1) ? GT_WHITE : ART_STRIPES[r];
                else       c->fg = GT_DARK_GRAY;
            }
        }
        gx += gt_strwidth(g->row[0]);
    }
}

/* --------------------------------------------------------- backdrops */

static uint32_t hash2(int x, int y){
    uint32_t h = (uint32_t)x * 73856093u ^ (uint32_t)y * 19349663u ^ 0x9E3779B9u;
    h ^= h >> 15; h *= 0x2C1B3C6Du; h ^= h >> 12; h *= 0x297A2D39u; h ^= h >> 15;
    return h;
}

void art_starfield(gt_t *t, uint32_t tick){
    static const uint8_t accent[4] = {GT_LIGHT_BLUE, GT_PINK, GT_AQUAMARINE, GT_YELLOW};
    int w = gt_view_w(t), h = gt_view_h(t);
    gt_clear(t, GT_BLACK);
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++){
            uint32_t v = hash2(x, y);
            if (v % 47) continue;
            uint32_t phase = ((tick >> 1) + (v >> 7)) % 40;
            uint8_t ch = 0xFA, fg = GT_DARK_GRAY;           /* · */
            if (phase >= 34){ ch = '*'; fg = GT_WHITE; }
            else if (phase >= 28){ ch = 0xF9; fg = GT_LIGHT_GRAY; }   /* ∙ */
            if ((v >> 20) % 11 == 0) fg = accent[(v >> 24) & 3];
            if ((v >> 12) % 29 == 0 && phase >= 34) ch = 0x0F;        /* ☼ */
            gt_put(t, x, y, ch, fg, GT_BLACK);
        }
}

/* ------------------------------------------------------- tower scene */

static const struct { int y, x; const char *s; } TOWER[] = {
    { 3, 12, "|"},
    { 4, 11, "/|\\"},             { 5, 11, "\\|/"},
    { 6, 11, "/|\\"},             { 7, 10, "/\\|/\\"},
    { 8, 10, "\\/|\\/"},          { 9,  9, "/\\/|\\/\\"},
    {10,  9, "\\/\\|/\\/"},       {11,  8, "/\\/\\|/\\/\\"},
    {12,  8, "\\/\\/|\\/\\/"},    {13,  7, "/\\/\\/|\\/\\/\\"},
    {14,  7, "\\/\\/\\|/\\/\\/"}, {15,  6, "/\\/\\/\\|/\\/\\/\\"},
    {16,  5, "/_/\\/\\/|\\/\\/\\_\\"},
};

void art_tower(gt_t *t, int x, int y, uint32_t tick){
    /* moon */
    gt_text(t, x + 31, y + 1, GT_WHITE, GT_BLACK, "▄███▄");
    gt_text(t, x + 30, y + 2, GT_WHITE, GT_BLACK, "███████");
    gt_text(t, x + 30, y + 3, GT_WHITE, GT_BLACK, "███████");
    gt_text(t, x + 31, y + 4, GT_WHITE, GT_BLACK, "▀███▀");
    gt_put(t, x + 32, y + 2, 0xB2, GT_LIGHT_GRAY, GT_WHITE);
    gt_put(t, x + 34, y + 3, 0xB1, GT_LIGHT_GRAY, GT_WHITE);
    gt_put(t, x + 31, y + 3, 0xB0, GT_LIGHT_GRAY, GT_WHITE);

    /* shooting star every ~10 s */
    uint32_t sp = tick % 150;
    if (sp < 14){
        int hx = x + 38 - (int)sp * 2, hy = y + (int)sp / 2;
        gt_put(t, hx, hy, '*', GT_WHITE, GT_BLACK);
        for (int i = 1; i <= 3; i++)
            gt_put(t, hx + i * 2, hy - (i + (int)(sp & 1)) / 2, 0xFA,
                   i == 1 ? GT_LIGHT_GRAY : GT_DARK_GRAY, GT_BLACK);
    }

    /* rolling hills behind everything else on the ground */
    gt_text(t, x, y + 17, GT_DARK_GREEN, GT_BLACK, "▄▄▄▄▄▄          ▄▄▄▄▄▄▄▄▄           ▄▄▄▄▄");
    gt_text(t, x, y + 18, GT_DARK_GREEN, GT_BLACK, "██████▄▄▄▄▄▄▄▄▄▄█████████▄▄▄▄▄▄▄▄▄▄▄█████");
    gt_fill(t, x, y + 19, 40, 1, 0xDB, GT_DARK_GREEN, GT_BLACK);
    gt_fill(t, x, y + 20, 40, 1, 0xB2, GT_DARK_GREEN, GT_BLACK);
    gt_put(t, x + 2, y + 16, 0x1E, GT_DARK_GREEN, GT_BLACK);     /* ▲ pines */
    gt_put(t, x + 3, y + 16, 0x1E, GT_DARK_GREEN, GT_BLACK);
    gt_put(t, x + 37, y + 16, 0x1E, GT_DARK_GREEN, GT_BLACK);

    /* the radio shack, windows flicker now and then */
    gt_text(t, x + 26, y + 14, GT_DEEP_RED, GT_BLACK, " ▄▄▄▄▄▄▄▄ ");
    gt_text(t, x + 26, y + 15, GT_DEEP_RED, GT_BLACK, "▐████████▌");
    gt_text(t, x + 26, y + 16, GT_LIGHT_GRAY, GT_BLACK, "▐████████▌");
    gt_text(t, x + 26, y + 17, GT_LIGHT_GRAY, GT_BLACK, "▐███▐▌███▌");
    bool dim = (tick / 7) % 23 == 0;
    gt_put(t, x + 28, y + 16, 0xFE, dim ? GT_BROWN : GT_YELLOW, GT_LIGHT_GRAY);
    gt_put(t, x + 33, y + 16, 0xFE, GT_YELLOW, GT_LIGHT_GRAY);
    gt_put(t, x + 30, y + 17, 0xDD, GT_BROWN, GT_LIGHT_GRAY);
    gt_text(t, x + 27, y + 15, GT_WHITE, GT_DEEP_RED, " WGLO ");
    /* feedline from the tower to the shack */
    gt_hline(t, x + 17, y + 13, 10, 0xC4, GT_DARK_GRAY, GT_BLACK);
    gt_put(t, x + 27, y + 13, 0xBF, GT_DARK_GRAY, GT_BLACK);
    gt_put(t, x + 27, y + 14, 0xB3, GT_DARK_GRAY, GT_BLACK);

    /* lattice tower in international orange and white bands */
    for (size_t i = 0; i < sizeof TOWER / sizeof TOWER[0]; i++){
        int ty = TOWER[i].y;
        uint8_t fg = ty == 3 || ty == 16 ? GT_LIGHT_GRAY : ((ty - 4) / 2) % 2 ? GT_WHITE : GT_ORANGE;
        gt_text(t, x + TOWER[i].x, y + ty, fg, GT_BLACK, TOWER[i].s);
    }

    /* beacon: on 6 ticks of 18 */
    bool on = tick % 18 < 6;
    gt_put(t, x + 12, y + 2, on ? 0x0F : 0x07, on ? GT_DEEP_RED : GT_DARK_GRAY, GT_BLACK);
    if (on){
        gt_put(t, x + 11, y + 2, 0xFA, GT_DEEP_RED, GT_BLACK);
        gt_put(t, x + 13, y + 2, 0xFA, GT_DEEP_RED, GT_BLACK);
    }

    /* radio waves rolling outward */
    static const uint8_t fade[6] = {GT_WHITE, GT_AQUAMARINE, GT_LIGHT_BLUE, GT_MEDIUM_BLUE, GT_DARK_BLUE, 0};
    uint32_t p = (tick / 3) % 6;
    for (int i = 0; i < 3; i++){
        uint8_t c = fade[(p + 6 - (uint32_t)i) % 6];
        if (!c) continue;
        int d = 3 + i * 3;
        gt_put(t, x + 12 - d,     y + 3, '(', c, GT_BLACK);
        gt_put(t, x + 12 - d - 1, y + 4, '(', c, GT_BLACK);
        gt_put(t, x + 12 - d,     y + 5, '(', c, GT_BLACK);
        gt_put(t, x + 12 + d,     y + 3, ')', c, GT_BLACK);
        gt_put(t, x + 12 + d + 1, y + 4, ')', c, GT_BLACK);
        gt_put(t, x + 12 + d,     y + 5, ')', c, GT_BLACK);
    }
}

/* ------------------------------------------------------ decorations */

void art_hazard(gt_t *t, int x, int y, int w, const char *label, uint32_t tick){
    for (int i = 0; i < w; i++){
        bool on = ((i + (int)(tick / 2)) / 3) % 2;
        gt_put(t, x + i, y, on ? 0xDB : ' ', GT_YELLOW, GT_BLACK);
    }
    int lw = gt_strwidth(label) + 2;
    int lx = x + (w - lw) / 2;
    gt_put(t, lx, y, ' ', GT_BLACK, GT_YELLOW);
    gt_text(t, lx + 1, y, GT_BLACK, GT_YELLOW, label);
    gt_put(t, lx + lw - 1, y, ' ', GT_BLACK, GT_YELLOW);
}

int art_odometer(gt_t *t, int x, int y, uint32_t v, int digits){
    char d[12];
    if (digits > 10) digits = 10;
    for (int i = digits - 1; i >= 0; i--){ d[i] = (char)('0' + v % 10); v /= 10; }
    int w = digits * 2 + 1;
    for (int i = 0; i < w; i++){
        bool sep = i % 2 == 0;
        uint8_t top = i == 0 ? 0xDA : i == w - 1 ? 0xBF : sep ? 0xC2 : 0xC4;
        uint8_t bot = i == 0 ? 0xC0 : i == w - 1 ? 0xD9 : sep ? 0xC1 : 0xC4;
        gt_put(t, x + i, y, top, GT_LIGHT_GRAY, GT_BLACK);
        gt_put(t, x + i, y + 2, bot, GT_LIGHT_GRAY, GT_BLACK);
        if (sep) gt_put(t, x + i, y + 1, 0xB3, GT_LIGHT_GRAY, GT_BLACK);
        else     gt_put(t, x + i, y + 1, (uint8_t)d[i / 2], GT_WHITE, GT_DARK_GRAY);
    }
    return w;
}

void art_plaque(gt_t *t, int x, int y, int w, uint8_t fg, uint8_t bg, const char *text){
    gt_hline(t, x + 1, y, w - 2, 0xDC, bg, GT_BLACK);
    gt_hline(t, x + 1, y + 2, w - 2, 0xDF, bg, GT_BLACK);
    gt_put(t, x, y + 1, 0xDE, bg, GT_BLACK);
    gt_put(t, x + w - 1, y + 1, 0xDD, bg, GT_BLACK);
    gt_hline(t, x + 1, y + 1, w - 2, ' ', fg, bg);
    int tw = gt_strwidth(text);
    gt_text(t, x + (w - tw) / 2, y + 1, fg, bg, text);
}

void art_rainbow(gt_t *t, int x, int y, const char *s, uint32_t tick){
    char one[5];
    int i = 0;
    while (*s){
        int len = (*s & 0x80) ? ((*s & 0xE0) == 0xC0 ? 2 : (*s & 0xF0) == 0xE0 ? 3 : 4) : 1;
        memcpy(one, s, (size_t)len); one[len] = 0; s += len;
        gt_text(t, x + i, y, ART_STRIPES[(i + (int)(tick / 2)) % 6], GT_BLACK, one);
        i++;
    }
}

/* ------------------------------------------------------------ effects */

/* 17 heat levels: black -> deep red -> orange -> yellow -> white, dithered
 * with the CP437 shade blocks between neighbouring palette colors. */
static void heat_cell(gt_cell_t *c, int level){
    static const uint8_t ramp[5] = {GT_BLACK, GT_DEEP_RED, GT_ORANGE, GT_YELLOW, GT_WHITE};
    static const uint8_t shade[4] = {' ', 0xB0, 0xB1, 0xB2};
    if (level > 16) level = 16;
    int band = level / 4, step = level % 4;
    c->bg = ramp[band];
    c->fg = band < 4 ? ramp[band + 1] : GT_WHITE;
    c->ch = band < 4 ? shade[step] : ' ';
    c->attr = 0;
}

static uint32_t xorshift(uint32_t *s){
    uint32_t x = *s ? *s : 0x1234567u;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return *s = x;
}

void art_fire_step(gt_t *t, art_fire_t *f){
    int w = f->w, h = f->h;
    uint8_t *H = f->heat;
    for (int x = 0; x < w; x++){
        uint32_t r = xorshift(&f->rng);
        H[(h - 1) * w + x] = (r % 100) < 55 ? 255 : (uint8_t)(r >> 8) % 140;
    }
    int decay = 3 + 190 / (h > 0 ? h : 1);
    for (int y = 0; y < h - 1; y++){
        for (int x = 0; x < w; x++){
            int below = (y + 1) * w;
            int l = H[below + (x > 0 ? x - 1 : x)];
            int m = H[below + x];
            int rr = H[below + (x < w - 1 ? x + 1 : x)];
            int b2 = y + 2 < h ? H[(y + 2) * w + x] : m;
            int v = (l + m + rr + b2) / 4 - decay - (int)(xorshift(&f->rng) & 3);
            H[y * w + x] = (uint8_t)(v < 0 ? 0 : v);
        }
    }
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++){
            gt_cell_t *c = gt_at(t, x, y);
            if (c) heat_cell(c, H[y * w + x] * 17 / 256);
        }
}

void art_plasma(gt_t *t, uint32_t tick){
    static uint8_t S[256];
    static bool init;
    static const uint8_t seq[8] = {
        GT_DARK_BLUE, GT_MEDIUM_BLUE, GT_PURPLE, GT_PINK,
        GT_ORANGE, GT_YELLOW, GT_AQUAMARINE, GT_LIGHT_BLUE,
    };
    static const uint8_t shade[4] = {' ', 0xB0, 0xB1, 0xB2};
    if (!init){
        for (int i = 0; i < 256; i++) S[i] = (uint8_t)(127.5f + 127.5f * sinf((float)i * 6.2831853f / 256.0f));
        init = true;
    }
    int w = gt_view_w(t), h = gt_view_h(t);
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++){
            int v = S[(x * 5 + (int)tick * 3) & 255] + S[(y * 11 + (int)tick * 2) & 255] +
                    S[((x + y) * 4 + (int)tick) & 255] + S[((x - y * 2) * 3 - (int)tick * 2) & 255];
            int pos = (v / 8 + (int)tick) % 32;
            gt_cell_t *c = gt_at(t, x, y);
            if (!c) continue;
            c->bg = seq[pos / 4];
            c->fg = seq[(pos / 4 + 1) % 8];
            c->ch = shade[pos % 4];
            c->attr = 0;
        }
}
