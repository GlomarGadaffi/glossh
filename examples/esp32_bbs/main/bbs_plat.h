/* What the BBS needs from the board: clocks, task stats, system info and a
 * small blob store. bbs_plat_esp.c implements it on ESP-IDF;
 * test/host/bbs_plat_posix.c on a desktop.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef BBS_PLAT_H
#define BBS_PLAT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#define BBS_MAX_TASKS 32

typedef struct {
    char     name[16];
    char     state;        /* R running, r ready, B blocked, S suspended, D deleted */
    uint8_t  prio;
    uint32_t stack_free;   /* bytes, high-water mark */
    int16_t  cpu_x10;      /* 0.1 % of all cores since the previous call; -1 unknown */
} bbs_task_t;

typedef struct {
    char     chip[32];     /* "ESP32-S3 rev 0.2" */
    char     sdk[32];      /* "ESP-IDF v6.0.1" */
    char     reset[20];    /* last reset reason */
    char     ip[16], mac[18];
    uint16_t mhz;
    uint8_t  cores;
    uint32_t flash_bytes;
    uint32_t heap_free, heap_total, heap_min, heap_largest;
    uint32_t psram_free, psram_total;
    uint64_t uptime_ms;
} bbs_sys_t;

uint64_t bbs_plat_ms(void);                    /* monotonic */
bool     bbs_plat_time(time_t *now);           /* false while the wall clock is unset */
/* Fills up to max tasks; *busy_x10 is total CPU load (0.1 %), -1 if unknown. */
int      bbs_plat_tasks(bbs_task_t *out, int max, int16_t *busy_x10);
void     bbs_plat_sys(bbs_sys_t *out);
/* Fixed-size blobs; load fails unless exactly len bytes are stored. */
bool     bbs_plat_load(const char *key, void *buf, size_t len);
bool     bbs_plat_save(const char *key, const void *buf, size_t len);

#endif /* BBS_PLAT_H */
