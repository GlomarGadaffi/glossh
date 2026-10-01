/* ANSI art and effects for GLOSSH BBS.
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef BBS_ART_H
#define BBS_ART_H

#include "glotui.h"

/* The six Apple logo stripes, top to bottom. */
extern const uint8_t ART_STRIPES[6];

/* Big block-letter word ("GLOSSH", "BYE!") in the ANSI Shadow figlet font,
 * one stripe color per row; a white gleam sweeps across when gleam >= 0. */
int  art_bigword_width(const char *word);
void art_bigword(gt_t *t, int x, int y, const char *word, int gleam);

/* Twinkling starfield over the whole view (deterministic per cell). */
void art_starfield(gt_t *t, uint32_t tick);
/* Night scene with a lattice radio tower, beacon and radio waves; 40x21. */
void art_tower(gt_t *t, int x, int y, uint32_t tick);
/* Yellow/black hazard stripe with a label, scrolling with tick. */
void art_hazard(gt_t *t, int x, int y, int w, const char *label, uint32_t tick);
/* GeoCities odometer hit counter (3 rows); returns width. */
int  art_odometer(gt_t *t, int x, int y, uint32_t value, int digits);
/* Pill-shaped title plaque (3 rows) centered in width w. */
void art_plaque(gt_t *t, int x, int y, int w, uint8_t fg, uint8_t bg, const char *text);
/* Text with each glyph in the next stripe color, cycling with tick. */
void art_rainbow(gt_t *t, int x, int y, const char *utf8, uint32_t tick);

/* Full-view demo effects; state lives in caller-provided buffers. */
typedef struct { uint8_t *heat; int w, h; uint32_t rng; } art_fire_t;
void art_fire_step(gt_t *t, art_fire_t *f);
void art_plasma(gt_t *t, uint32_t tick);

#endif /* BBS_ART_H */
