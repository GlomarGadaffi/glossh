/* Desktop stand-in for bbs_plat.h so the BBS runs against a real OpenSSH
 * client on a laptop. System info comes from the host; the task list is a
 * simulated ESP32-S3 task set (a host process has no FreeRTOS tasks), and
 * the blob store lives in memory for the life of the process.
 * SPDX-License-Identifier: MIT */
#include "bbs_plat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

static uint64_t s_boot;

uint64_t bbs_plat_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

bool bbs_plat_time(time_t *now){ *now = time(NULL); return true; }

int bbs_plat_tasks(bbs_task_t *out, int max, int16_t *busy){
    static const struct { const char *name; char st; uint8_t prio; uint32_t stack; int load; } SIM[] = {
        {"IDLE0",      'R',  0, 1320, 0},  {"IDLE1",     'r',  0, 1316, 0},
        {"littlessh",  'R',  5, 3140, 90}, {"tiT",       'B', 18, 2204, 25},
        {"w5500_tsk",  'B', 15, 1788, 30}, {"esp_timer", 'B', 22, 2860, 8},
        {"sys_evt",    'B', 20, 1432, 2},  {"ipc0",      'S', 24,  520, 0},
        {"ipc1",       'S', 24,  536, 0},  {"sntp",      'B',  5, 1604, 1},
        {"main",       'D',  1,  964, 0},
    };
    static uint32_t rng = 0xC0FFEE;
    int n = (int)(sizeof SIM / sizeof SIM[0]);
    if (n > max) n = max;
    int total = 0;
    for (int i = 0; i < n; i++){
        rng = rng * 1103515245u + 12345u;
        int jitter = (int)((rng >> 16) % 7) - 3;
        int load = SIM[i].load ? SIM[i].load + jitter * (SIM[i].load / 10 + 1) : 0;
        if (load < 0) load = 0;
        snprintf(out[i].name, sizeof out[i].name, "%s", SIM[i].name);
        out[i].state = SIM[i].st;
        out[i].prio = SIM[i].prio;
        out[i].stack_free = SIM[i].stack;
        out[i].cpu_x10 = (int16_t)load;
        total += load;
    }
    /* the two idle tasks split whatever the others left */
    out[0].cpu_x10 = (int16_t)((1000 - total) / 2);
    out[1].cpu_x10 = (int16_t)(1000 - total - out[0].cpu_x10);
    *busy = (int16_t)total;
    return n;
}

void bbs_plat_sys(bbs_sys_t *o){
    memset(o, 0, sizeof *o);
    if (!s_boot) s_boot = bbs_plat_ms();
    struct utsname u;
    if (uname(&u) == 0){
        snprintf(o->chip, sizeof o->chip, "%.24s host", u.machine);
        snprintf(o->sdk, sizeof o->sdk, "%.12s %.18s", u.sysname, u.release);
    }
    snprintf(o->reset, sizeof o->reset, "process start");
    snprintf(o->ip, sizeof o->ip, "127.0.0.1");
    snprintf(o->mac, sizeof o->mac, "--");
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    o->cores = (uint8_t)(cores > 0 && cores < 255 ? cores : 1);
    struct sysinfo si;
    if (sysinfo(&si) == 0){
        uint64_t unit = si.mem_unit ? si.mem_unit : 1;
        uint64_t total = si.totalram * unit, free_ = si.freeram * unit;
        o->heap_total = total > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)total;
        o->heap_free = free_ > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)free_;
        o->heap_min = o->heap_free;
        o->heap_largest = o->heap_free;
    }
    o->uptime_ms = bbs_plat_ms() - s_boot;
}

static struct { char key[16]; void *data; size_t len; } s_kv[8];

bool bbs_plat_load(const char *key, void *buf, size_t len){
    for (size_t i = 0; i < sizeof s_kv / sizeof s_kv[0]; i++)
        if (s_kv[i].data && !strcmp(s_kv[i].key, key)){
            if (s_kv[i].len != len) return false;
            memcpy(buf, s_kv[i].data, len);
            return true;
        }
    return false;
}

bool bbs_plat_save(const char *key, const void *buf, size_t len){
    size_t slot = sizeof s_kv / sizeof s_kv[0];
    for (size_t i = 0; i < sizeof s_kv / sizeof s_kv[0]; i++){
        if (s_kv[i].data && !strcmp(s_kv[i].key, key)){ slot = i; break; }
        if (!s_kv[i].data && slot == sizeof s_kv / sizeof s_kv[0]) slot = i;
    }
    if (slot == sizeof s_kv / sizeof s_kv[0]) return false;
    void *p = realloc(s_kv[slot].data, len);
    if (!p) return false;
    memcpy(p, buf, len);
    s_kv[slot].data = p;
    s_kv[slot].len = len;
    snprintf(s_kv[slot].key, sizeof s_kv[slot].key, "%s", key);
    return true;
}
