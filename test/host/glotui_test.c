/* glotui unit tests: renderer output, diffing, CP437, key decoding.
 * SPDX-License-Identifier: MIT */
#include "glotui.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(c) do { if (!(c)){ printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static char out[65536];
static size_t outn;
static void wr(void *ctx, const void *d, size_t n){
    (void)ctx;
    if (outn + n < sizeof out){ memcpy(out + outn, d, n); outn += n; out[outn] = 0; }
}
static void reset(void){ outn = 0; out[0] = 0; }

static int keys[64], nkeys;
static void on_key(void *ctx, int k){ (void)ctx; if (nkeys < 64) keys[nkeys++] = k; }
static void feed(gt_keys_t *k, const char *s){ nkeys = 0; gt_keys_feed(k, (const uint8_t*)s, strlen(s), on_key, NULL); }

static void test_cp437(void){
    CHECK(gt_cp437('A') == 'A');
    CHECK(gt_cp437(0x2588) == 0xDB);    /* █ */
    CHECK(gt_cp437(0x2550) == 0xCD);    /* ═ */
    CHECK(gt_cp437(0x263C) == 0x0F);    /* ☼ */
    CHECK(gt_cp437(0x00E9) == 0x82);    /* é */
    CHECK(gt_cp437(0x1F600) == '?');
    for (int c = 1; c < 256; c++)
        if (c != 0xFF) CHECK(gt_cp437(gt_unicode((uint8_t)c)) == c);
    CHECK(gt_strwidth("█▓▒░ ok") == 7);
    CHECK(gt_pipe_width("|14Hi |04there||") == 9);
}

static void test_render(void){
    gt_t *t = gt_new(wr, NULL, 132, 50);
    CHECK(t);
    gt_resize(t, 80, 24);
    gt_flush(t);                       /* initial full clear */
    reset();
    gt_flush(t);
    CHECK(outn == 0);                  /* nothing changed: nothing sent */

    gt_text(t, 10, 5, GT_YELLOW, GT_DARK_BLUE, "Hi");
    reset(); gt_flush(t);
    CHECK(strstr(out, "\x1b[6;11H") != NULL);                     /* 1-based CUP */
    CHECK(strstr(out, "38;2;255;255;0") && strstr(out, "48;2;0;0;153"));
    CHECK(strstr(out, "Hi") != NULL);
    size_t first = outn;
    reset(); gt_flush(t);
    CHECK(outn == 0);

    /* one changed cell costs a move + glyph, and the pen is reused */
    gt_put(t, 11, 5, 'o', GT_YELLOW, GT_DARK_BLUE);
    reset(); gt_flush(t);
    CHECK(outn < first && strstr(out, "38;2") == NULL && out[outn - 1] == 'o');

    /* UTF-8 box glyphs */
    gt_put(t, 0, 0, 0xDB, GT_PINK, GT_BLACK);
    reset(); gt_flush(t);
    CHECK(strstr(out, "\xe2\x96\x88") != NULL);

    /* 256 / 16 / ANSI-BBS modes repaint with their own color forms */
    gt_set_mode(t, GT_MODE_256);
    reset(); gt_flush(t);
    CHECK(strstr(out, "\x1b[2J") && strstr(out, "38;5;") && !strstr(out, "38;2;"));
    gt_set_mode(t, GT_MODE_16);
    reset(); gt_flush(t);
    CHECK(strstr(out, "93") && !strstr(out, "38;5;"));          /* yellow -> bright yellow */
    gt_set_mode(t, GT_MODE_ANSIBBS);
    reset(); gt_flush(t);
    CHECK(strchr(out, (char)0xDB) != NULL);                       /* raw CP437 byte */
    CHECK(strstr(out, "\xe2\x96\x88") == NULL);
    CHECK(strstr(out, ";1") || strstr(out, "[1"));                /* bright via bold */
    gt_put(t, 2, 2, 0x10, GT_WHITE, GT_BLACK);                    /* ► is a C0 control in CP437 */
    gt_put(t, 3, 2, 0x11, GT_WHITE, GT_BLACK);
    reset(); gt_flush(t);
    CHECK(strstr(out, "><") != NULL);

    /* per-cell mode override */
    gt_set_mode(t, GT_MODE_TRUECOLOR);
    gt_flush(t);
    gt_cell_t *c = gt_at(t, 5, 5);
    *c = (gt_cell_t){0xDB, GT_ORANGE, GT_BLACK, GT_MODE_AS(GT_MODE_256)};
    reset(); gt_flush(t);
    CHECK(strstr(out, "38;5;") != NULL);

    /* clipping and views */
    gt_view(t, 70, 20, 20, 20);
    CHECK(gt_view_w(t) == 10 && gt_view_h(t) == 4);
    CHECK(gt_at(t, 10, 0) == NULL && gt_at(t, 9, 3) != NULL);
    gt_view_full(t);

    /* terminal larger than max: canvas is centered */
    gt_resize(t, 200, 60);
    CHECK(gt_cols(t) == 132 && gt_rows(t) == 50);
    gt_flush(t);
    gt_put(t, 0, 0, 'X', GT_WHITE, GT_BLACK);
    reset(); gt_flush(t);
    CHECK(strstr(out, "\x1b[6;35H") != NULL);                     /* (200-132)/2+1, (60-50)/2+1 */

    /* cursor */
    gt_cursor(t, 3, 2);
    reset(); gt_flush(t);
    CHECK(strstr(out, "\x1b[?25h") != NULL);
    gt_cursor(t, -1, -1);
    reset(); gt_flush(t);
    CHECK(strstr(out, "\x1b[?25l") != NULL);

    gt_free(t);
}

static void test_keys(void){
    gt_keys_t k; gt_keys_init(&k);
    feed(&k, "a\r");
    CHECK(nkeys == 2 && keys[0] == 'a' && keys[1] == GT_KEY_ENTER);
    feed(&k, "\r\n");                   /* CR LF is one Enter */
    CHECK(nkeys == 1 && keys[0] == GT_KEY_ENTER);
    feed(&k, "\x1b[A\x1b[B\x1bOP\x1b[15~\x1b[24~\x1b[3~\x7f");
    CHECK(nkeys == 7 && keys[0] == GT_KEY_UP && keys[1] == GT_KEY_DOWN &&
          keys[2] == GT_KEY_F1 && keys[3] == GT_KEY_F5 && keys[4] == GT_KEY_F12 &&
          keys[5] == GT_KEY_DELETE && keys[6] == GT_KEY_BACKSPACE);
    feed(&k, "\x1b[1;5C");              /* modified arrow */
    CHECK(nkeys == 1 && keys[0] == GT_KEY_RIGHT);
    feed(&k, "\x1bx");                  /* Alt-x = ESC then x */
    CHECK(nkeys == 2 && keys[0] == GT_KEY_ESC && keys[1] == 'x');
    feed(&k, "\x1b");                   /* lone ESC resolves on the second tick */
    CHECK(nkeys == 0);
    gt_keys_tick(&k, on_key, NULL);
    CHECK(nkeys == 0);
    gt_keys_tick(&k, on_key, NULL);
    CHECK(nkeys == 1 && keys[0] == GT_KEY_ESC);
    feed(&k, "\x1b[");                  /* split sequence */
    feed(&k, "D");
    CHECK(nkeys == 1 && keys[0] == GT_KEY_LEFT);
    feed(&k, "caf\xc3\xa9");            /* UTF-8 é -> CP437 0x82 */
    CHECK(nkeys == 4 && keys[3] == 0x82);
    k.cp437 = true;
    feed(&k, "\x82");
    CHECK(nkeys == 1 && keys[0] == 0x82);
}

/* gt_end parks the cursor on the last row before leaving the alternate
 * screen, so text printed after it lands at the bottom even on terminals
 * that ignore 1049l (SyncTERM, the Linux console) */
static void test_end(void){
    gt_t *t = gt_new(wr, NULL, 80, 24);
    CHECK(t);
    gt_begin(t);
    gt_flush(t);
    reset();
    gt_end(t);
    const char *park = strstr(out, "\x1b[24;1H"), *leave = strstr(out, "\x1b[?1049l");
    CHECK(park != NULL && leave != NULL && park < leave);
    gt_free(t);
}

int main(void){
    test_cp437();
    test_render();
    test_end();
    test_keys();
    printf(fails ? "glotui: %d FAILED\n" : "glotui: all tests passed\n", fails);
    return fails != 0;
}
