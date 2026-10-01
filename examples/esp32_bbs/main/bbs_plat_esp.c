/* bbs_plat.h on ESP-IDF: FreeRTOS task stats, heap_caps, chip info, NVS.
 * SPDX-License-Identifier: Apache-2.0 */
#include "bbs_plat.h"

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs.h"
#include "sdkconfig.h"

#define NVS_NS "glossh_bbs"

uint64_t bbs_plat_ms(void){ return (uint64_t)(esp_timer_get_time() / 1000); }

bool bbs_plat_time(time_t *now){
    time(now);
    return *now > 1700000000;           /* SNTP has run (clock is past 2023) */
}

int bbs_plat_tasks(bbs_task_t *out, int max, int16_t *busy){
    *busy = -1;
#if configUSE_TRACE_FACILITY
    static TaskStatus_t st[BBS_MAX_TASKS + 8];
    static struct { UBaseType_t num; configRUN_TIME_COUNTER_TYPE rt; } prev[BBS_MAX_TASKS + 8];
    static int nprev;
    static configRUN_TIME_COUNTER_TYPE prev_total;
    configRUN_TIME_COUNTER_TYPE total = 0;

    int n = (int)uxTaskGetSystemState(st, sizeof st / sizeof st[0], &total);
    configRUN_TIME_COUNTER_TYPE dt = total - prev_total;   /* wraps cleanly */
    bool have_dt = configGENERATE_RUN_TIME_STATS && prev_total && dt;
    uint64_t cap = (uint64_t)dt * portNUM_PROCESSORS;
    int idle_x10 = 0, out_n = 0;

    for (int i = 0; i < n && out_n < max; i++){
        bbs_task_t *o = &out[out_n++];
        snprintf(o->name, sizeof o->name, "%s", st[i].pcTaskName);
        switch (st[i].eCurrentState){
        case eRunning:   o->state = 'R'; break;
        case eReady:     o->state = 'r'; break;
        case eBlocked:   o->state = 'B'; break;
        case eSuspended: o->state = 'S'; break;
        case eDeleted:   o->state = 'D'; break;
        default:         o->state = '?'; break;
        }
        o->prio = (uint8_t)st[i].uxCurrentPriority;
        o->stack_free = (uint32_t)st[i].usStackHighWaterMark;    /* bytes on ESP-IDF */
        o->cpu_x10 = -1;
        if (have_dt){
            for (int j = 0; j < nprev; j++){
                if (prev[j].num != st[i].xTaskNumber) continue;
                configRUN_TIME_COUNTER_TYPE d = st[i].ulRunTimeCounter - prev[j].rt;
                uint64_t x10 = (uint64_t)d * 1000u / cap;
                o->cpu_x10 = (int16_t)(x10 > 1000 ? 1000 : x10);
                break;
            }
            if (o->cpu_x10 >= 0 && !strncmp(o->name, "IDLE", 4)) idle_x10 += o->cpu_x10;
        }
    }
    for (int i = 0; i < n; i++){
        prev[i].num = st[i].xTaskNumber;
        prev[i].rt = st[i].ulRunTimeCounter;
    }
    nprev = n;
    prev_total = total;
    if (have_dt) *busy = (int16_t)(idle_x10 > 1000 ? 0 : 1000 - idle_x10);
    return out_n;
#else
    (void)out; (void)max;
    return 0;
#endif
}

static const char *reset_name(esp_reset_reason_t r){
    switch (r){
    case ESP_RST_POWERON:   return "power-on";
    case ESP_RST_EXT:       return "external pin";
    case ESP_RST_SW:        return "software";
    case ESP_RST_PANIC:     return "panic";
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:       return "watchdog";
    case ESP_RST_DEEPSLEEP: return "deep sleep";
    case ESP_RST_BROWNOUT:  return "brownout";
    default:                return "other";
    }
}

void bbs_plat_sys(bbs_sys_t *o){
    memset(o, 0, sizeof *o);

    /* "esp32s3" -> "ESP32-S3" */
    char tgt[16];
    size_t i = 0;
    for (const char *p = CONFIG_IDF_TARGET; *p && i + 1 < sizeof tgt; p++)
        tgt[i++] = (*p >= 'a' && *p <= 'z') ? (char)(*p - 32) : *p;
    tgt[i] = 0;
    esp_chip_info_t ci;
    esp_chip_info(&ci);
    if (!strncmp(tgt, "ESP32", 5) && tgt[5])
        snprintf(o->chip, sizeof o->chip, "ESP32-%s rev %d.%d", tgt + 5, ci.revision / 100, ci.revision % 100);
    else
        snprintf(o->chip, sizeof o->chip, "%s rev %d.%d", tgt, ci.revision / 100, ci.revision % 100);
    o->cores = ci.cores;
#ifdef CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ
    o->mhz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;
#endif
    uint32_t flash = 0;
    if (esp_flash_get_size(NULL, &flash) == ESP_OK) o->flash_bytes = flash;
    snprintf(o->sdk, sizeof o->sdk, "ESP-IDF %s", esp_get_idf_version());
    snprintf(o->reset, sizeof o->reset, "%s", reset_name(esp_reset_reason()));

    o->heap_free    = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    o->heap_total   = (uint32_t)heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
    o->heap_min     = (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    o->heap_largest = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    o->psram_total  = (uint32_t)heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    o->psram_free   = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    o->uptime_ms    = bbs_plat_ms();

    snprintf(o->ip, sizeof o->ip, "--");
    snprintf(o->mac, sizeof o->mac, "--");
    esp_netif_t *nif = esp_netif_get_default_netif();
    if (!nif) nif = esp_netif_get_handle_from_ifkey("ETH_DEF");
    if (nif){
        esp_netif_ip_info_t ip;
        if (esp_netif_get_ip_info(nif, &ip) == ESP_OK)
            snprintf(o->ip, sizeof o->ip, IPSTR, IP2STR(&ip.ip));
        uint8_t m[6];
        if (esp_netif_get_mac(nif, m) == ESP_OK)
            snprintf(o->mac, sizeof o->mac, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    }
}

bool bbs_plat_load(const char *key, void *buf, size_t len){
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return false;
    size_t got = len;
    esp_err_t err = nvs_get_blob(h, key, buf, &got);
    nvs_close(h);
    return err == ESP_OK && got == len;
}

bool bbs_plat_save(const char *key, const void *buf, size_t len){
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return false;
    esp_err_t err = nvs_set_blob(h, key, buf, len);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err == ESP_OK;
}
