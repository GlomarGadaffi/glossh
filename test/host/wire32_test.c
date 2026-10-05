/* Wire reader/writer bounds with peer-sized lengths. Build it -m32 too:
 * on a 32-bit size_t (ESP32) `off + n` wraps for n near 4 GB, which a
 * 64-bit host build can never show.
 * SPDX-License-Identifier: MIT */
#include "../../littlessh/src/littlessh.c"   /* the helpers are static */

static int fails;
#define CHECK(c, what) do { if (c) printf("PASS: %s\n", what); \
                            else { printf("FAIL: %s\n", what); fails++; } } while (0)

int main(void){
    printf("size_t is %u bytes\n", (unsigned)sizeof(size_t));

    /* string "abcd", then a string whose length claims 0xFFFFFFF8 bytes */
    static const uint8_t pkt[16] = { 0,0,0,4, 'a','b','c','d', 0xFF,0xFF,0xFF,0xF8, 1,2,3,4 };
    rdr_t r; rd_init(&r, pkt, sizeof pkt);
    const uint8_t *s; uint32_t n;
    CHECK(rd_string(&r, &s, &n) && n == 4, "rd_string reads a normal string");
    CHECK(!rd_string(&r, &s, &n), "rd_string rejects a length past the packet");
    CHECK(r.off <= r.len, "reader offset stays inside the packet");

    /* writer: 8 of 16 bytes used, then a ~4 GB append must latch err, not copy */
    uint8_t out[16]; wtr_t w; wr_init(&w, out, sizeof out);
    wr_raw(&w, pkt, 8);
    wr_raw(&w, pkt, (size_t)0xFFFFFFFCu);
    CHECK(w.err && w.len == 8, "wr_raw refuses an append past capacity");

    printf("RESULT: %s\n", fails ? "FAIL" : "PASS");
    return fails != 0;
}
