/*
 * Lint only (tools/lint.sh, *-esp checks): stand-in for ESP-IDF's esp_log.h so
 * the ESP_PLATFORM branch of littlessh parses on the host. The macros expand
 * to a call of a declared function with printf format checking, so clang-tidy
 * and cppcheck see real calls. It returns void, like esp_log_write(): a log
 * line is not a result anyone has to check.
 */
#ifndef __ESP_LOG_H__ /* the real header's guard: nothing here tells it apart */
#define __ESP_LOG_H__

void esp_log_write(int level, const char *tag, const char *format, ...)
    __attribute__((format(printf, 3, 4)));

#define ESP_LOGE(tag, format, ...) esp_log_write(1, tag, format, ##__VA_ARGS__)
#define ESP_LOGW(tag, format, ...) esp_log_write(2, tag, format, ##__VA_ARGS__)
#define ESP_LOGI(tag, format, ...) esp_log_write(3, tag, format, ##__VA_ARGS__)
#define ESP_LOGD(tag, format, ...) esp_log_write(4, tag, format, ##__VA_ARGS__)
#define ESP_LOGV(tag, format, ...) esp_log_write(5, tag, format, ##__VA_ARGS__)

#endif
