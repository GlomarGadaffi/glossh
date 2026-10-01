/*
 * glotui — 16-color ANSI-art terminal UI over any byte stream.
 *
 * Draw into a back buffer of CP437 glyphs and a 16-entry palette (the Apple
 * IIgs standard colors by default); gt_flush() diffs it against what the
 * terminal already shows and writes only the escape sequences needed. Output
 * goes through a caller-supplied write function, so the same code drives an
 * SSH channel (littlessh), a UART or a telnet socket.
 *
 * Output modes: exact palette over 24-bit SGR, nearest xterm-256, nearest of
 * the 16 ANSI colors, or raw CP437 bytes for ANSI-BBS terminals (SyncTERM).
 * Not thread-safe; drive one gt_t from one task.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef GLOTUI_H
#define GLOTUI_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Apple IIgs standard palette order (lo-res / border colors). */
enum {
    GT_BLACK,       GT_DEEP_RED,    GT_DARK_BLUE,   GT_PURPLE,
    GT_DARK_GREEN,  GT_DARK_GRAY,   GT_MEDIUM_BLUE, GT_LIGHT_BLUE,
    GT_BROWN,       GT_ORANGE,      GT_LIGHT_GRAY,  GT_PINK,
    GT_LIGHT_GREEN, GT_YELLOW,      GT_AQUAMARINE,  GT_WHITE,
};
extern const uint32_t GT_PALETTE_IIGS[16];   /* 0xRRGGBB */

typedef enum {
    GT_MODE_TRUECOLOR,  /* UTF-8, exact palette via 24-bit SGR */
    GT_MODE_256,        /* UTF-8, nearest xterm-256 color */
    GT_MODE_16,         /* UTF-8, one of the 16 ANSI colors (aixterm brights) */
    GT_MODE_ANSIBBS,    /* raw CP437 bytes; bold = bright fg, dark bg only */
} gt_mode_t;

/* cell attributes */
#define GT_BLINK        0x01
#define GT_UNDERLINE    0x02
/* Per-cell mode override: render this one cell as if the session were in
 * mode m (palette test swatches). */
#define GT_MODE_AS(m)   ((uint8_t)(0x80 | ((m) << 4)))

typedef struct { uint8_t ch, fg, bg, attr; } gt_cell_t;

typedef struct gt gt_t;
typedef void (*gt_write_fn)(void *ctx, const void *data, size_t len);

/* The canvas is the terminal clipped to max_cols x max_rows, centered. */
gt_t *gt_new(gt_write_fn wr, void *ctx, uint16_t max_cols, uint16_t max_rows);
void  gt_free(gt_t *t);
/* Terminal size changed (pty-req / window-change). Clears the canvas and
 * forces a full repaint. False if the buffers could not grow (the canvas
 * keeps its previous size). */
bool     gt_resize(gt_t *t, uint16_t term_cols, uint16_t term_rows);
uint16_t gt_cols(const gt_t *t);
uint16_t gt_rows(const gt_t *t);

void      gt_set_mode(gt_t *t, gt_mode_t m);
gt_mode_t gt_mode(const gt_t *t);
void      gt_set_palette(gt_t *t, const uint32_t rgb[16]);

/* Session framing: gt_begin switches to the alternate screen with the
 * cursor hidden and autowrap off; gt_end restores all of that. */
void gt_begin(gt_t *t);
void gt_end(gt_t *t);
void gt_title(gt_t *t, const char *utf8);
void gt_bell(gt_t *t);

/* Frames. gt_cursor takes view coordinates and shows the text cursor there
 * after the next flush; x < 0 hides it. */
void   gt_invalidate(gt_t *t);
void   gt_cursor(gt_t *t, int x, int y);
void   gt_flush(gt_t *t);
size_t gt_bytes_out(const gt_t *t);

/* Views: drawing coordinates are relative to the current view and clip to
 * it. gt_view takes canvas coordinates. */
void gt_view(gt_t *t, int x, int y, int w, int h);
void gt_view_full(gt_t *t);
int  gt_view_w(const gt_t *t);
int  gt_view_h(const gt_t *t);

/* Drawing. Text is UTF-8, mapped to CP437 ('?' where CP437 has no glyph);
 * every CP437 glyph is one column wide. */
gt_cell_t *gt_at(gt_t *t, int x, int y);            /* NULL if clipped */
void gt_put(gt_t *t, int x, int y, uint8_t ch, uint8_t fg, uint8_t bg);
void gt_fill(gt_t *t, int x, int y, int w, int h, uint8_t ch, uint8_t fg, uint8_t bg);
void gt_clear(gt_t *t, uint8_t bg);
void gt_hline(gt_t *t, int x, int y, int w, uint8_t ch, uint8_t fg, uint8_t bg);
void gt_vline(gt_t *t, int x, int y, int h, uint8_t ch, uint8_t fg, uint8_t bg);
int  gt_text(gt_t *t, int x, int y, uint8_t fg, uint8_t bg, const char *utf8);
int  gt_textf(gt_t *t, int x, int y, uint8_t fg, uint8_t bg, const char *fmt, ...)
    __attribute__((format(printf, 6, 7)));
/* BBS pipe codes: |00-|15 set fg, |16-|31 set bg 0-15, "||" is a literal |.
 * Starts light gray on black. Returns columns drawn. */
int  gt_pipe(gt_t *t, int x, int y, const char *s);
int  gt_pipe_width(const char *s);

enum { GT_BOX_SINGLE, GT_BOX_DOUBLE, GT_BOX_DOUBLE_H, GT_BOX_BLOCK };
void gt_box(gt_t *t, int x, int y, int w, int h, int style, uint8_t fg, uint8_t bg);
/* Drop shadow right of and below a window at (x,y,w,h). */
void gt_shadow(gt_t *t, int x, int y, int w, int h);

uint8_t  gt_cp437(uint32_t codepoint);
uint16_t gt_unicode(uint8_t cp437);
int      gt_strwidth(const char *utf8);

/* ---- keyboard ----
 * Key values < 0x100 are CP437 bytes: printable 0x20-0x7E / 0x80-0xFF, or
 * control codes (Ctrl-A = 1 ...). Named keys follow. */
enum {
    GT_KEY_BACKSPACE = 0x08, GT_KEY_TAB = 0x09, GT_KEY_ENTER = 0x0D, GT_KEY_ESC = 0x1B,
    GT_KEY_UP = 0x100, GT_KEY_DOWN, GT_KEY_RIGHT, GT_KEY_LEFT,
    GT_KEY_HOME, GT_KEY_END, GT_KEY_PGUP, GT_KEY_PGDN,
    GT_KEY_INSERT, GT_KEY_DELETE, GT_KEY_BACKTAB,
    GT_KEY_F1, GT_KEY_F2, GT_KEY_F3, GT_KEY_F4, GT_KEY_F5, GT_KEY_F6,
    GT_KEY_F7, GT_KEY_F8, GT_KEY_F9, GT_KEY_F10, GT_KEY_F11, GT_KEY_F12,
};
#define GT_KEY_PRINTABLE(k) ((k) >= 0x20 && (k) < 0x100 && (k) != 0x7F)

typedef void (*gt_key_fn)(void *ctx, int key);
typedef struct {
    uint8_t  buf[16];      /* pending escape sequence */
    uint8_t  n, age;
    bool     cr;           /* swallow the LF/NUL some clients send after CR */
    bool     cp437;        /* input bytes are CP437, not UTF-8 (ANSI-BBS) */
    uint8_t  u8_need;
    uint32_t u8_cp;
} gt_keys_t;

void gt_keys_init(gt_keys_t *k);
void gt_keys_feed(gt_keys_t *k, const uint8_t *d, size_t n, gt_key_fn cb, void *ctx);
/* Call periodically: a lone ESC still pending after two ticks is the Esc key. */
void gt_keys_tick(gt_keys_t *k, gt_key_fn cb, void *ctx);

#ifdef __cplusplus
}
#endif
#endif /* GLOTUI_H */
