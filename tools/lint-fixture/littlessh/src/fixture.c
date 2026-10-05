/*
 * Lint selftest fixture (not built, not shipped). A miniature littlessh that
 * follows every convention tools/lint.sh enforces and passes the whole gate,
 * exit 0, in both the host and the ESP_PLATFORM configuration.
 * `bash tools/lint.sh --selftest` copies this tree, appends one violation (or
 * one negative control) and runs the real gate on the copy. Keep it green.
 */
#include "fixture.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <psa/crypto.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef ESP_PLATFORM
#include "esp_log.h"
static const char *TAG = "fixture";
#define LOGI(...) ESP_LOGI(TAG, __VA_ARGS__)
#else
#define LOGI(fmt, ...) (void)fprintf(stderr, "fixture: " fmt "\n", ##__VA_ARGS__)
#endif

#define LSSH_ASSERT(cond) assert(cond)

#define FX_ZERO(p, n) do { (void)memset((p), 0, (n)); } while (0)

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
} rdr_t;

typedef enum { FX_IDLE, FX_RUN, FX_DONE } fx_state_t;

static void rd_init(rdr_t *r, const uint8_t *p, size_t len)
{
    LSSH_ASSERT(r != NULL);
    LSSH_ASSERT(p != NULL || len == 0u);
    r->p = p;
    r->len = len;
    r->off = 0u;
}

static LSSH_MUST_CHECK bool rd_u32(rdr_t *r, uint32_t *v)
{
    LSSH_ASSERT(r != NULL);
    LSSH_ASSERT(v != NULL);
    LSSH_ASSERT(r->off <= r->len);
    if (r->len - r->off < 4u) {
        return false;
    }
    const uint8_t *b = r->p + r->off;
    *v = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
         | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
    r->off += 4u;
    return true;
}

static LSSH_MUST_CHECK int fx_send_all(int fd, const uint8_t *buf, size_t n)
{
    LSSH_ASSERT(fd >= 0);
    LSSH_ASSERT(buf != NULL);
    size_t done = 0u;
    for (int tries = 0; done < n && tries < 8; tries++) {
        ssize_t k = send(fd, buf + done, n - done, MSG_NOSIGNAL);
        if (k <= 0) {
            return -1;
        }
        done += (size_t)k;
    }
    return done == n ? 0 : -1;
}

static LSSH_MUST_CHECK int fx_digest(const uint8_t *in, size_t n, uint8_t out[32])
{
    LSSH_ASSERT(in != NULL || n == 0u);
    LSSH_ASSERT(out != NULL);
    size_t olen = 0u;
    psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, in, n, out, 32u, &olen);
    if (st != PSA_SUCCESS || olen != 32u) {
        return -1;
    }
    return 0;
}

static LSSH_MUST_CHECK int fx_step(fx_state_t st)
{
    LSSH_ASSERT(st == FX_IDLE || st == FX_RUN || st == FX_DONE);
    LSSH_ASSERT(st <= FX_DONE);
    switch (st) {
    case FX_IDLE:
        return 1;
    case FX_RUN:
        return 2;
    case FX_DONE:
        return 0;
    default:
        return -1;
    }
}

LSSH_MUST_CHECK int lssh_fixture_run(int fd, const uint8_t *msg, size_t n)
{
    LSSH_ASSERT(fd >= 0);
    LSSH_ASSERT(msg != NULL);
    rdr_t r;
    uint32_t v = 0u;
    uint8_t h[32];
    rd_init(&r, msg, n);
    if (!rd_u32(&r, &v)) {
        return -1;
    }
    if (fx_digest(msg, n, h) != 0) {
        return -1;
    }
    LOGI("value %u", (unsigned)v);
    if (fx_step((fx_state_t)(v % 3u)) < 0) {
        return -1;
    }
    int rc = fx_send_all(fd, h, sizeof h);
    FX_ZERO(h, sizeof h);
    if (rc != 0) {
        (void)close(fd);
        return -1;
    }
    return 0;
}
