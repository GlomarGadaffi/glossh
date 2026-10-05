/*
 * littlessh — minimal SSH 2.0 server on PSA Crypto.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Protocol references: RFC 4253 (transport), RFC 4252 (userauth),
 * RFC 4254 (connection), RFC 8731 (curve25519-sha256), RFC 5656 (ECDSA),
 * RFC 5647 (AES-GCM), OpenSSH PROTOCOL (aes256-gcm@openssh.com, strict KEX).
 */

#include "littlessh.h"

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <psa/crypto.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef ESP_PLATFORM
#include "esp_log.h"
static const char *TAG = "littlessh";
#define LOGI(...) ESP_LOGI(TAG, __VA_ARGS__)
#define LOGW(...) ESP_LOGW(TAG, __VA_ARGS__)
#else
#define LOGI(fmt, ...) (void)fprintf(stderr, "littlessh: " fmt "\n", ##__VA_ARGS__)
#define LOGW(fmt, ...) (void)fprintf(stderr, "littlessh: WARN " fmt "\n", ##__VA_ARGS__)
#endif

/* ---------------------------------------------------------------- consts */

#define SSH_MSG_DISCONNECT                1
#define SSH_MSG_IGNORE                    2
#define SSH_MSG_UNIMPLEMENTED             3
#define SSH_MSG_DEBUG                     4
#define SSH_MSG_SERVICE_REQUEST           5
#define SSH_MSG_SERVICE_ACCEPT            6
#define SSH_MSG_EXT_INFO                  7
#define SSH_MSG_KEXINIT                  20
#define SSH_MSG_NEWKEYS                  21
#define SSH_MSG_KEX_ECDH_INIT            30
#define SSH_MSG_KEX_ECDH_REPLY           31
#define SSH_MSG_USERAUTH_REQUEST         50
#define SSH_MSG_USERAUTH_FAILURE         51
#define SSH_MSG_USERAUTH_SUCCESS         52
#define SSH_MSG_USERAUTH_BANNER          53
#define SSH_MSG_USERAUTH_PK_OK           60
#define SSH_MSG_GLOBAL_REQUEST           80
#define SSH_MSG_REQUEST_SUCCESS          81
#define SSH_MSG_REQUEST_FAILURE          82
#define SSH_MSG_CHANNEL_OPEN             90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91
#define SSH_MSG_CHANNEL_OPEN_FAILURE     92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST    93
#define SSH_MSG_CHANNEL_DATA             94
#define SSH_MSG_CHANNEL_EXTENDED_DATA    95
#define SSH_MSG_CHANNEL_EOF              96
#define SSH_MSG_CHANNEL_CLOSE            97
#define SSH_MSG_CHANNEL_REQUEST          98
#define SSH_MSG_CHANNEL_SUCCESS          99
#define SSH_MSG_CHANNEL_FAILURE        100
#define SSH_MSG_CONNECTION_LAST        127   /* 80..127: connection protocol */

#define SSH_DISCONNECT_PROTOCOL_ERROR              2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED         3
#define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE 14
#define SSH_DISCONNECT_BY_APPLICATION             11

#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED 1
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE        3

#define LSSH_IDENT "SSH-2.0-littlessh_" LSSH_VERSION_STR

static const char ALG_KEX[]     = "curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-s-v00@openssh.com";
static const char ALG_HOSTKEY[] = "ecdsa-sha2-nistp256";
static const char ALG_CIPHER[]  = "aes256-gcm@openssh.com";
static const char ALG_MAC[]     = "hmac-sha2-256"; /* unused with AEAD, must be non-empty */
static const char ALG_COMP[]    = "none";

#define HOSTKEY_TYPE "ecdsa-sha2-nistp256"
#define HOSTKEY_CURVE "nistp256"

/* ------------------------------------------------------------- session  */

/* A hash in progress with a latched error (like wtr_t.err): updates stay
 * flat, err is checked once before finish. */
typedef struct { psa_hash_operation_t op; bool err; } hsh_t;

/* Everything one key exchange holds: its secrets, the running hash of H and
 * the bigger scratch buffers, kept off the stack (a rekey can run inside an
 * app callback). One instance in the session; kex_ctx_wipe() clears it
 * whenever do_kex returns. */
typedef struct {
    hsh_t hop;                      /* exchange hash H, fed as the exchange goes */
    bool hop_live;
    psa_key_id_t eph;               /* ephemeral X25519 key */
    bool initial, skipped;
    bool guess_follows, client_strict, guess_ok;
    const uint8_t *ck; size_t ckn;  /* client KEXINIT (I_C), in the packet buffer */
    uint8_t kexinit[512]; size_t klen;      /* our KEXINIT (I_S) */
    uint8_t q_s[32], q_c[32];
    uint8_t secret[32];
    uint8_t kmp[40]; size_t kmp_len;        /* K as mpint, length-prefixed */
    uint8_t ksblob[128]; size_t ks_len;     /* K_S: our host key blob */
    uint8_t H[32];
    uint8_t h2[32], rs[64];                 /* SHA-256(H) and its signature */
    uint8_t rsmp[80], sigblob[160], reply[384];
    uint8_t iv_c2s[12], iv_s2c[12], key_c2s[32], key_s2c[32];
} kex_ctx_t;

struct lssh_session {
    const lssh_config_t *cfg;
    int fd;

    /* transport crypto */
    bool enc;
    bool strict_kex;
    uint32_t seq_in, seq_out;
    psa_key_id_t k_in, k_out;       /* AES-256-GCM */
    uint8_t iv_in[12], iv_out[12];
    uint8_t session_id[32];
    bool have_sid;
    kex_ctx_t kex;                  /* live only inside do_kex */

    char v_c[256];                  /* client ident line, no CRLF */

    /* host key */
    psa_key_id_t hostkey;
    uint8_t hostkey_pub[65];        /* 0x04 || X || Y */

    /* auth */
    bool svc_userauth;              /* SERVICE_REQUEST("ssh-userauth") accepted */
    bool authed;
    char username[64];
    uint32_t auth_tries;
    uint64_t auth_deadline;         /* mono ms; reads fail past it until authed */

    /* the one session channel */
    bool ch_open;
    bool ch_started;                /* shell/exec accepted (only one per channel) */
    bool ch_sent_close, ch_rcvd_close, ch_sent_eof;
    bool notified_close;
    bool has_pty;
    char term[32];
    uint32_t ch_remote_id;
    uint32_t win_out;               /* remote-granted window (we may send) */
    uint32_t max_out;               /* remote max packet size */
    uint32_t win_in;                /* our remaining receive window */

    /* App callbacks never run inside packet processing: lssh_write() may
     * pump inbound packets from within a callback, which would re-enter the
     * app and overwrite the buffer it is reading. Events are queued here and
     * dispatched from the top of the connection loop. */
    bool pend_pty, pend_open, pend_exec;
    uint16_t pend_cols, pend_rows;
    char exec_cmd[256];
    uint8_t rxq[LSSH_MAX_PACKET];   /* inbound channel data, not yet delivered */
    size_t rxq_len;

    bool dead;                      /* transport unusable */
    int  write_depth;               /* re-entrancy guard for window pumping */

    /* buffers */
    uint8_t inbuf[LSSH_MAX_PACKET + 32];   /* ciphertext / raw packet */
    uint8_t payload[LSSH_MAX_PACKET];      /* decrypted payload (in) */
    uint8_t frame[LSSH_MAX_PACKET + 32];   /* plaintext frame (out) */
    uint8_t outbuf[LSSH_MAX_PACKET + 64];  /* wire bytes (out) */
    uint8_t chdata[LSSH_MAX_PACKET];       /* outbound CHANNEL_DATA / banner assembly */
};

/* Largest CHANNEL_DATA we let the client send (advertised max packet). Kept
 * well under rxq so a few packets can queue while a write is pumping. */
#define LSSH_IN_MAXPKT (LSSH_MAX_PACKET / 4)
/* rxq bytes handed to one on_data call; the rest of rxq stays free for
 * packets that arrive if that callback's writes pump the connection. */
#define LSSH_RX_CHUNK  (LSSH_MAX_PACKET / 2)

/* Loop bounds (Power of 10 rule 2) */
#ifndef LSSH_KEX_MAX_SKIP
#define LSSH_KEX_MAX_SKIP    32   /* IGNORE/DEBUG skipped per KEX wait */
#endif
#ifndef LSSH_IO_MAX_RETRY
#define LSSH_IO_MAX_RETRY    64   /* socket waits in a row that move no bytes */
#endif
#ifndef LSSH_WRITE_MAX_PUMPS
#define LSSH_WRITE_MAX_PUMPS 256  /* packets pumped in a row without window */
#endif
#ifndef LSSH_DISPATCH_MAX
#define LSSH_DISPATCH_MAX    16   /* app callbacks per dispatch_events() */
#endif

static LSSH_MUST_CHECK uint64_t mono_ms(void);
static LSSH_MUST_CHECK int wait_readable(int fd, uint32_t ms);

/* memset the compiler may not elide */
static void wipe(void *p, size_t n){
    LSSH_ASSERT(p != NULL);
    LSSH_ASSERT(n > 0);   /* callers wipe whole objects */
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

/* ------------------------------------------------------------ wire utils */

typedef struct { const uint8_t *p; size_t len, off; } rdr_t;
typedef struct { uint8_t *p; size_t cap, len; bool err; } wtr_t;

/* Readers parse peer bytes: their asserts cover our own pointers and the
 * off <= len invariant only, never a length read off the wire. */
static void rd_init(rdr_t *r, const uint8_t *p, size_t len){
    LSSH_ASSERT(r != NULL);
    LSSH_ASSERT(p != NULL);
    r->p=p; r->len=len; r->off=0;
}
static LSSH_MUST_CHECK bool rd_u8(rdr_t *r, uint8_t *v){
    LSSH_ASSERT(r != NULL && v != NULL);
    LSSH_ASSERT(r->off <= r->len);
    if (r->off+1>r->len) return false;
    *v=r->p[r->off++]; return true;
}
static LSSH_MUST_CHECK bool rd_bool(rdr_t *r, bool *v){
    LSSH_ASSERT(r != NULL);
    LSSH_ASSERT(v != NULL);
    uint8_t b; if(!rd_u8(r,&b)) return false; *v=(b!=0); return true;
}
static LSSH_MUST_CHECK bool rd_u32(rdr_t *r, uint32_t *v){
    LSSH_ASSERT(r != NULL && v != NULL);
    LSSH_ASSERT(r->off <= r->len);
    if (r->off+4>r->len) return false;
    *v = ((uint32_t)r->p[r->off]<<24)|((uint32_t)r->p[r->off+1]<<16)|
         ((uint32_t)r->p[r->off+2]<<8)|r->p[r->off+3];
    r->off+=4; return true;
}
static LSSH_MUST_CHECK bool rd_string(rdr_t *r, const uint8_t **s, uint32_t *slen){
    LSSH_ASSERT(r != NULL);
    LSSH_ASSERT(s != NULL && slen != NULL);
    uint32_t n; if(!rd_u32(r,&n)) return false;
    if (n > r->len - r->off) return false;   /* off <= len; off+n can wrap a 32-bit size_t */
    *s=r->p+r->off; *slen=n; r->off+=n;
    LSSH_ASSERT(r->off <= r->len);
    return true;
}
/* copy a string into a NUL-terminated buffer; rejects embedded NULs */
static LSSH_MUST_CHECK bool rd_cstring(rdr_t *r, char *out, size_t cap){
    LSSH_ASSERT(r != NULL);
    LSSH_ASSERT(out != NULL && cap > 0);
    const uint8_t *s; uint32_t n;
    if(!rd_string(r,&s,&n) || n>=cap || memchr(s,0,n)) return false;
    memcpy(out,s,n); out[n]=0; return true;
}

static void wr_init(wtr_t *w, uint8_t *p, size_t cap){
    LSSH_ASSERT(w != NULL);
    LSSH_ASSERT(p != NULL && cap > 0);
    w->p=p; w->cap=cap; w->len=0; w->err=false;
}
static void wr_raw(wtr_t *w, const void *d, size_t n){
    LSSH_ASSERT(w != NULL && d != NULL);
    LSSH_ASSERT(w->len <= w->cap);
    if (w->err || n > w->cap - w->len){ w->err=true; return; }   /* len <= cap; no wrap */
    memcpy(w->p+w->len,d,n); w->len+=n;
}
static void wr_u8(wtr_t *w, uint8_t v){
    LSSH_ASSERT(w != NULL);
    LSSH_ASSERT(w->len <= w->cap);
    wr_raw(w,&v,1);
}
static void wr_bool(wtr_t *w, bool v){
    LSSH_ASSERT(w != NULL);
    wr_u8(w, v?1:0);
}
static void wr_u32(wtr_t *w, uint32_t v){
    LSSH_ASSERT(w != NULL);
    LSSH_ASSERT(w->len <= w->cap);
    const uint8_t b[4]={(uint8_t)(v>>24),(uint8_t)(v>>16),(uint8_t)(v>>8),(uint8_t)v};
    wr_raw(w,b,4);
}
static void wr_string(wtr_t *w, const void *d, size_t n){
    LSSH_ASSERT(w != NULL);
    LSSH_ASSERT(d != NULL);
    wr_u32(w,(uint32_t)n); wr_raw(w,d,n);
}
static void wr_cstr(wtr_t *w, const char *s){
    LSSH_ASSERT(w != NULL);
    LSSH_ASSERT(s != NULL);
    wr_string(w,s,strlen(s));
}
/* mpint from unsigned big-endian bytes */
static void wr_mpint(wtr_t *w, const uint8_t *d, size_t n){
    LSSH_ASSERT(w != NULL && d != NULL);
    LSSH_ASSERT(n <= 32);   /* X25519 secret, ECDSA r and s */
    while (n && *d==0){ d++; n--; }
    if (n && (d[0]&0x80)){ wr_u32(w,(uint32_t)n+1); wr_u8(w,0); wr_raw(w,d,n); }
    else wr_string(w,d,n);
}

/* does comma-separated name-list contain name? */
static LSSH_MUST_CHECK bool namelist_has(const uint8_t *list, uint32_t len, const char *name){
    LSSH_ASSERT(list != NULL);
    LSSH_ASSERT(name != NULL);
    size_t nl = strlen(name);
    LSSH_ASSERT(nl > 0);   /* our own algorithm names */
    uint32_t i = 0;
    /* i grows every pass; len is an in-packet length, so i = j+1 cannot wrap */
    while (i < len){
        uint32_t j = i;
        while (j < len && list[j] != ',') j++;
        if (j-i == nl && memcmp(list+i, name, nl)==0) return true;
        i = j+1;
    }
    return false;
}

/* -------------------------------------------------------------- sockets */

static LSSH_MUST_CHECK int io_recv_exact(lssh_session_t *s, uint8_t *buf, size_t n){
    LSSH_ASSERT(s != NULL && buf != NULL);
    /* lengths from the wire are range-checked before they get here */
    LSSH_ASSERT(n > 0 && n <= sizeof s->inbuf);
    size_t got = 0;
    unsigned stall = 0;   /* passes in a row that read nothing */
    while (got < n){
        if (stall++ >= LSSH_IO_MAX_RETRY) return -1;
        /* until auth succeeds the whole login shares one wall-clock budget,
         * so a silent or trickling client cannot hold the only slot */
        if (!s->authed && s->auth_deadline){
            uint64_t now = mono_ms();
            if (now >= s->auth_deadline) return -1;
            int w = wait_readable(s->fd, (uint32_t)(s->auth_deadline - now));
            if (w < 0) return -1;
            if (w == 0) continue;   /* timeout or EINTR: re-check the deadline */
        }
        ssize_t r = recv(s->fd, buf+got, n-got, 0);
        if (r == 0) return -1;
        if (r < 0){
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
        stall = 0;
    }
    LSSH_ASSERT(got == n);
    return 0;
}

static LSSH_MUST_CHECK int io_send_all(lssh_session_t *s, const uint8_t *buf, size_t n){
    LSSH_ASSERT(s != NULL && buf != NULL);
    LSSH_ASSERT(n > 0 && n <= sizeof s->outbuf);
    size_t sent = 0;
    unsigned stall = 0;   /* passes in a row that sent nothing */
    while (sent < n){
        if (stall++ >= LSSH_IO_MAX_RETRY) return -1;
        /* a peer that already hung up must not SIGPIPE the whole server */
        ssize_t r = send(s->fd, buf+sent, n-sent, MSG_NOSIGNAL);
        if (r < 0){
            if (errno == EINTR) continue;
            return -1;
        }
        if (r > 0) stall = 0;
        sent += (size_t)r;
    }
    return 0;
}

/* --------------------------------------------------------------- crypto */

/* psa_destroy_key / psa_hash_abort results are (void)-dropped: they run on
 * cleanup paths where a failure leaves nothing to undo or report. */

static LSSH_MUST_CHECK int rng(uint8_t *out, size_t n){
    LSSH_ASSERT(out != NULL);
    LSSH_ASSERT(n > 0);
    return psa_generate_random(out, n) == PSA_SUCCESS ? 0 : -1;
}

static LSSH_MUST_CHECK int sha256(const uint8_t *in, size_t inlen, uint8_t out[32]){
    LSSH_ASSERT(in != NULL);
    LSSH_ASSERT(out != NULL);
    size_t olen = 0;
    return psa_hash_compute(PSA_ALG_SHA_256, in, inlen, out, 32, &olen)
           == PSA_SUCCESS && olen == 32 ? 0 : -1;
}

static void iv_increment(uint8_t iv[12]){
    LSSH_ASSERT(iv != NULL);
    /* RFC 5647: 4-byte fixed field, 8-byte invocation counter, big-endian */
    for (int i = 11; i >= 4; i--){
        if (++iv[i] != 0) break;
    }
}

static LSSH_MUST_CHECK int import_gcm_key(psa_key_id_t *id, const uint8_t key[32], bool decrypt){
    LSSH_ASSERT(id != NULL);
    LSSH_ASSERT(key != NULL);
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&a, 256);
    psa_set_key_algorithm(&a, PSA_ALG_GCM);
    psa_set_key_usage_flags(&a, decrypt ? PSA_KEY_USAGE_DECRYPT : PSA_KEY_USAGE_ENCRYPT);
    if (*id){ (void)psa_destroy_key(*id); *id = 0; }
    return psa_import_key(&a, key, 32, id) == PSA_SUCCESS ? 0 : -1;
}

/* --------------------------------------------------- binary packet layer */

static LSSH_MUST_CHECK int send_packet(lssh_session_t *s, const uint8_t *payload, size_t plen){
    if (s->dead) return -1;
    if (plen == 0 || plen > LSSH_MAX_PACKET - 32) return -1;

    if (!s->enc){
        size_t pad = 8 - ((5 + plen) % 8);
        if (pad < 4) pad += 8;
        size_t pktlen = 1 + plen + pad;          /* value of the length field */
        wtr_t w; wr_init(&w, s->outbuf, sizeof s->outbuf);
        wr_u32(&w, (uint32_t)pktlen);
        wr_u8(&w, (uint8_t)pad);
        wr_raw(&w, payload, plen);
        uint8_t padding[16];
        if (rng(padding, pad)) return -1;
        wr_raw(&w, padding, pad);
        if (w.err || io_send_all(s, s->outbuf, w.len)) { s->dead = true; return -1; }
    } else {
        size_t pad = 16 - ((1 + plen) % 16);
        if (pad < 4) pad += 16;
        size_t ptlen = 1 + plen + pad;           /* encrypted portion */
        LSSH_ASSERT(pad >= 4 && ptlen % 16 == 0 && ptlen <= sizeof s->frame);
        const uint8_t aad[4] = {(uint8_t)(ptlen>>24),(uint8_t)(ptlen>>16),(uint8_t)(ptlen>>8),(uint8_t)ptlen};

        s->frame[0] = (uint8_t)pad;
        memcpy(s->frame+1, payload, plen);
        if (rng(s->frame+1+plen, pad)) return -1;

        size_t olen = 0;
        psa_status_t st = psa_aead_encrypt(s->k_out, PSA_ALG_GCM,
                                           s->iv_out, 12,
                                           aad, 4,
                                           s->frame, ptlen,
                                           s->outbuf+4, sizeof(s->outbuf)-4, &olen);
        if (st != PSA_SUCCESS || olen != ptlen + 16){ s->dead = true; return -1; }
        memcpy(s->outbuf, aad, 4);
        iv_increment(s->iv_out);
        if (io_send_all(s, s->outbuf, 4 + olen)){ s->dead = true; return -1; }
    }
    s->seq_out++;
    return 0;
}

/* Receive one packet; payload/plen point into s->payload or s->inbuf. */
static LSSH_MUST_CHECK int recv_packet(lssh_session_t *s, const uint8_t **payload, size_t *plen){
    if (s->dead) return -1;
    /* enc implies keys installed (a failed rekey leaves the session dead) */
    LSSH_ASSERT(!s->enc || s->k_in != 0);
    uint8_t lenb[4];
    if (io_recv_exact(s, lenb, 4)){ s->dead = true; return -1; }
    uint32_t pktlen = ((uint32_t)lenb[0]<<24)|((uint32_t)lenb[1]<<16)|((uint32_t)lenb[2]<<8)|lenb[3];

    if (!s->enc){
        if (pktlen < 5 || pktlen > LSSH_MAX_PACKET){ s->dead = true; return -1; }
        if (io_recv_exact(s, s->inbuf, pktlen)){ s->dead = true; return -1; }
        uint8_t pad = s->inbuf[0];
        if ((size_t)pad + 1 > pktlen){ s->dead = true; return -1; }
        *payload = s->inbuf + 1;
        *plen = pktlen - 1 - pad;
    } else {
        if (pktlen < 5 || pktlen > LSSH_MAX_PACKET){ s->dead = true; return -1; }
        if (io_recv_exact(s, s->inbuf, pktlen + 16)){ s->dead = true; return -1; }
        size_t olen = 0;
        psa_status_t st = psa_aead_decrypt(s->k_in, PSA_ALG_GCM,
                                           s->iv_in, 12,
                                           lenb, 4,
                                           s->inbuf, pktlen + 16,
                                           s->payload, sizeof s->payload, &olen);
        if (st != PSA_SUCCESS || olen != pktlen){ s->dead = true; return -1; }
        iv_increment(s->iv_in);
        uint8_t pad = s->payload[0];
        if ((size_t)pad + 1 > pktlen){ s->dead = true; return -1; }
        *payload = s->payload + 1;
        *plen = pktlen - 1 - pad;
    }
    if (*plen == 0){ s->dead = true; return -1; }
    s->seq_in++;
    return 0;
}

static void send_disconnect(lssh_session_t *s, uint32_t reason, const char *msg){
    LSSH_ASSERT(s != NULL);
    LSSH_ASSERT(reason != 0);
    if (s->dead) return;
    uint8_t buf[256]; wtr_t w; wr_init(&w, buf, sizeof buf);
    wr_u8(&w, SSH_MSG_DISCONNECT);
    wr_u32(&w, reason);
    wr_cstr(&w, msg ? msg : "");
    wr_cstr(&w, "");
    /* dead either way, so a failed send changes nothing. (void)! because GCC
     * ignores a plain (void) on a LSSH_MUST_CHECK call. */
    if (!w.err) (void)!send_packet(s, buf, w.len);
    s->dead = true;
}

/* ----------------------------------------------------------------- KEX  */

static LSSH_MUST_CHECK size_t build_kexinit(uint8_t *buf, size_t cap){
    LSSH_ASSERT(buf != NULL);
    LSSH_ASSERT(cap > 0);
    wtr_t w; wr_init(&w, buf, cap);
    uint8_t cookie[16];
    if (rng(cookie, 16)) return 0;
    wr_u8(&w, SSH_MSG_KEXINIT);
    wr_raw(&w, cookie, 16);
    wr_cstr(&w, ALG_KEX);
    wr_cstr(&w, ALG_HOSTKEY);
    wr_cstr(&w, ALG_CIPHER);   /* c2s */
    wr_cstr(&w, ALG_CIPHER);   /* s2c */
    wr_cstr(&w, ALG_MAC);
    wr_cstr(&w, ALG_MAC);
    wr_cstr(&w, ALG_COMP);
    wr_cstr(&w, ALG_COMP);
    wr_cstr(&w, "");           /* languages */
    wr_cstr(&w, "");
    wr_bool(&w, false);        /* first_kex_packet_follows */
    wr_u32(&w, 0);
    LSSH_ASSERT(w.len <= cap);
    return w.err ? 0 : w.len;
}

/* Parse client KEXINIT and check our single suite is acceptable.
 * Returns 0 ok; fills *guess_follows and *client_strict. */
static LSSH_MUST_CHECK int check_client_kexinit(const uint8_t *pl, size_t plen,
                                                bool *guess_follows, bool *client_strict,
                                                bool *guess_ok){
    LSSH_ASSERT(pl != NULL);
    LSSH_ASSERT(guess_follows != NULL && client_strict != NULL && guess_ok != NULL);
    rdr_t r; rd_init(&r, pl, plen);
    uint8_t msg; const uint8_t *l[10]; uint32_t ll[10];
    if (!rd_u8(&r,&msg) || msg != SSH_MSG_KEXINIT) return -1;
    r.off += 16; if (r.off > r.len) return -1;          /* cookie */
    for (int i = 0; i < 10; i++)
        if (!rd_string(&r, &l[i], &ll[i])) return -1;
    bool ffollows; uint32_t reserved;
    if (!rd_bool(&r,&ffollows) || !rd_u32(&r,&reserved)) return -1;

    bool kex_ok = namelist_has(l[0], ll[0], "curve25519-sha256") ||
                  namelist_has(l[0], ll[0], "curve25519-sha256@libssh.org");
    if (!kex_ok) return -2;
    if (!namelist_has(l[1], ll[1], HOSTKEY_TYPE)) return -2;
    if (!namelist_has(l[2], ll[2], ALG_CIPHER)) return -2;
    if (!namelist_has(l[3], ll[3], ALG_CIPHER)) return -2;
    /* MAC lists irrelevant for AEAD; compression must allow none */
    if (!namelist_has(l[6], ll[6], "none")) return -2;
    if (!namelist_has(l[7], ll[7], "none")) return -2;

    *client_strict = namelist_has(l[0], ll[0], "kex-strict-c-v00@openssh.com");
    *guess_follows = ffollows;
    /* the client's guess is right only if its first-listed kex and hostkey
     * algorithms match ours */
    bool g1 = (ll[0] >= 17 && memcmp(l[0], "curve25519-sha256", 17)==0 &&
               (ll[0]==17 || l[0][17]==','));
    bool g2 = (ll[1] >= sizeof(HOSTKEY_TYPE)-1 &&
               memcmp(l[1], HOSTKEY_TYPE, sizeof(HOSTKEY_TYPE)-1)==0 &&
               (ll[1]==sizeof(HOSTKEY_TYPE)-1 || l[1][sizeof(HOSTKEY_TYPE)-1]==','));
    *guess_ok = g1 && g2;
    return 0;
}

static void hs_update(hsh_t *h, const uint8_t *d, size_t n){
    LSSH_ASSERT(h != NULL);
    LSSH_ASSERT(d != NULL);
    if (!h->err && psa_hash_update(&h->op, d, n) != PSA_SUCCESS) h->err = true;
}

static void hash_string(hsh_t *h, const uint8_t *d, size_t n){
    LSSH_ASSERT(h != NULL);
    LSSH_ASSERT(d != NULL);
    const uint8_t lb[4] = {(uint8_t)(n>>24),(uint8_t)(n>>16),(uint8_t)(n>>8),(uint8_t)n};
    hs_update(h, lb, 4);
    if (n) hs_update(h, d, n);
}

#define KDF_ACC 64   /* two SHA-256 blocks: enough for a 32-byte key */

/* KDF from RFC 4253 §7.2: K1 = H(K||H||X||sid), Kn = H(K||H||K1..Kn-1).
 * Fills acc with whole blocks; kdf() owns acc and wipes it. */
static LSSH_MUST_CHECK int kdf_blocks(const uint8_t *kmp, size_t kmplen, const uint8_t H[32],
                                      const uint8_t sid[32], char letter,
                                      uint8_t *acc, size_t need){
    LSSH_ASSERT(kmp != NULL && acc != NULL);
    LSSH_ASSERT(H != NULL && sid != NULL);
    LSSH_ASSERT(need > 0 && need <= KDF_ACC);
    size_t have = 0;
    while (have < need){   /* at most KDF_ACC / 32 passes: checked below */
        hsh_t h = { PSA_HASH_OPERATION_INIT, false };
        if (psa_hash_setup(&h.op, PSA_ALG_SHA_256) != PSA_SUCCESS) return -1;
        hs_update(&h, kmp, kmplen);
        hs_update(&h, H, 32);
        if (have == 0){
            uint8_t c = (uint8_t)letter;
            hs_update(&h, &c, 1);
            hs_update(&h, sid, 32);
        } else {
            hs_update(&h, acc, have);
        }
        size_t olen = 0;
        if (h.err || have + 32 > KDF_ACC) { (void)psa_hash_abort(&h.op); return -1; }
        if (psa_hash_finish(&h.op, acc + have, 32, &olen) != PSA_SUCCESS || olen != 32)
            return -1;
        have += 32;
    }
    return 0;
}

static LSSH_MUST_CHECK int kdf(const uint8_t *kmp, size_t kmplen, const uint8_t H[32],
                               const uint8_t sid[32], char letter, uint8_t *out, size_t need){
    LSSH_ASSERT(out != NULL);
    LSSH_ASSERT(need <= KDF_ACC);
    uint8_t acc[KDF_ACC];
    int rc = kdf_blocks(kmp, kmplen, H, sid, letter, acc, need);
    if (rc == 0) memcpy(out, acc, need);
    wipe(acc, sizeof acc);
    return rc;
}

/* end of every do_kex: abort/destroy what is live, then zero the context */
static void kex_ctx_wipe(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    kex_ctx_t *k = &s->kex;
    if (k->hop_live) (void)psa_hash_abort(&k->hop.op);
    if (k->eph) (void)psa_destroy_key(k->eph);
    wipe(k, sizeof *k);
    LSSH_ASSERT(!k->hop_live && k->eph == 0);
}

/* our KEXINIT (I_S, kept for H) */
static LSSH_MUST_CHECK int kex_send_init(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    kex_ctx_t *k = &s->kex;
    k->klen = build_kexinit(k->kexinit, sizeof k->kexinit);
    LSSH_ASSERT(k->klen <= sizeof k->kexinit);
    if (!k->klen || send_packet(s, k->kexinit, k->klen)) return -1;
    return 0;
}

/* A packet in a KEX wait. Non-strict: 1 skip it (IGNORE, DEBUG,
 * UNIMPLEMENTED), -1 the client sent DISCONNECT (end quietly, no reply),
 * 0 anything else. Strict KEX skips nothing: always 0. */
static LSSH_MUST_CHECK int kex_skip(lssh_session_t *s, uint8_t t){
    LSSH_ASSERT(s != NULL);
    LSSH_ASSERT(!s->dead);   /* recv_packet just succeeded */
    if (s->strict_kex) return 0;
    if (t == SSH_MSG_DISCONNECT){ s->dead = true; return -1; }
    return t == SSH_MSG_IGNORE || t == SSH_MSG_DEBUG || t == SSH_MSG_UNIMPLEMENTED;
}

/* client KEXINIT (already consumed by the caller on the rekey path) */
static LSSH_MUST_CHECK int kex_recv_init(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    kex_ctx_t *k = &s->kex;
    for (unsigned skip = 0; !k->ck && skip <= LSSH_KEX_MAX_SKIP; skip++){
        const uint8_t *pl; size_t pn;
        if (recv_packet(s, &pl, &pn)) return -1;
        /* strict_kex is still unset: a strict client is refused below */
        int sk = kex_skip(s, pl[0]);
        if (sk < 0) return -1;
        if (sk){ k->skipped = true; continue; }
        if (pl[0] != SSH_MSG_KEXINIT){
            send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "expected KEXINIT");
            return -1;
        }
        k->ck = pl; k->ckn = pn;
    }
    if (!k->ck){
        send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "too many IGNORE/DEBUG in kex");
        return -1;
    }

    if (check_client_kexinit(k->ck, k->ckn, &k->guess_follows, &k->client_strict,
                             &k->guess_ok)){
        send_disconnect(s, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
                        "no common algorithms (littlessh offers curve25519-sha256 / "
                        "ecdsa-sha2-nistp256 / aes256-gcm@openssh.com)");
        return -1;
    }
    if (k->initial && k->client_strict){
        /* strict KEX: KEXINIT must be the very first packet */
        if (k->skipped){
            send_disconnect(s, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
                            "strict KEX: KEXINIT was not the first packet");
            return -1;
        }
        s->strict_kex = true;
    }
    LSSH_ASSERT(k->ck != NULL);
    return 0;
}

/* start H while I_C is still in the receive buffer */
static LSSH_MUST_CHECK int kex_hash_start(lssh_session_t *s){
    static const psa_hash_operation_t hop_init = PSA_HASH_OPERATION_INIT;
    LSSH_ASSERT(s != NULL);
    kex_ctx_t *k = &s->kex;
    LSSH_ASSERT(k->ck != NULL);
    LSSH_ASSERT(!k->hop_live);
    k->hop.op = hop_init;
    k->hop.err = false;
    if (psa_hash_setup(&k->hop.op, PSA_ALG_SHA_256) != PSA_SUCCESS) return -1;
    k->hop_live = true;
    hash_string(&k->hop, (const uint8_t*)s->v_c, strlen(s->v_c));
    hash_string(&k->hop, (const uint8_t*)LSSH_IDENT, strlen(LSSH_IDENT));
    hash_string(&k->hop, k->ck, k->ckn);
    hash_string(&k->hop, k->kexinit, k->klen);
    return 0;
}

/* generate ephemeral X25519 pair */
static LSSH_MUST_CHECK int kex_ephemeral(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    kex_ctx_t *k = &s->kex;
    LSSH_ASSERT(k->eph == 0);
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&a, 255);
    psa_set_key_algorithm(&a, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
    if (psa_generate_key(&a, &k->eph) != PSA_SUCCESS) return -1;
    LSSH_ASSERT(k->eph != 0);

    size_t q_s_len = 0;
    if (psa_export_public_key(k->eph, k->q_s, 32, &q_s_len) != PSA_SUCCESS || q_s_len != 32)
        return -1;
    return 0;
}

/* wait for KEX_ECDH_INIT (discarding a wrong guessed packet if flagged) */
static LSSH_MUST_CHECK int kex_recv_ecdh_init(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    kex_ctx_t *k = &s->kex;
    LSSH_ASSERT(k->eph != 0 && k->hop_live);   /* kex_ephemeral and H started */
    const uint8_t *pl; size_t pn;
    if (k->guess_follows && !k->guess_ok && recv_packet(s, &pl, &pn)) return -1;
    for (unsigned skip = 0; skip <= LSSH_KEX_MAX_SKIP; skip++){
        if (recv_packet(s, &pl, &pn)) return -1;
        int sk = kex_skip(s, pl[0]);
        if (sk < 0) return -1;
        if (sk) continue;
        if (pl[0] != SSH_MSG_KEX_ECDH_INIT){
            send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "expected ECDH_INIT");
            return -1;
        }
        LSSH_ASSERT(pn >= 1);   /* recv_packet never returns an empty payload */
        rdr_t r; rd_init(&r, pl, pn); uint8_t m;
        const uint8_t *qc = NULL; uint32_t qc_len = 0;
        if (!rd_u8(&r,&m) || !rd_string(&r, &qc, &qc_len) || qc_len != 32){
            send_disconnect(s, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "bad Q_C");
            return -1;
        }
        memcpy(k->q_c, qc, 32);
        return 0;
    }
    send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "too many IGNORE/DEBUG in kex");
    return -1;
}

/* X25519 shared secret, and K as mpint bytes (RFC 8731: output interpreted
 * as big-endian integer) */
static LSSH_MUST_CHECK int kex_shared_secret(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    kex_ctx_t *k = &s->kex;
    LSSH_ASSERT(k->eph != 0);
    size_t sec_len = 0;
    if (psa_raw_key_agreement(PSA_ALG_ECDH, k->eph, k->q_c, 32,
                              k->secret, 32, &sec_len) != PSA_SUCCESS || sec_len != 32)
        return -1;
    uint8_t z = 0;   /* reject all-zero output (low-order point) */
    for (int i = 0; i < 32; i++) z |= k->secret[i];
    if (!z){ send_disconnect(s, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "bad point"); return -1; }

    wtr_t w; wr_init(&w, k->kmp, sizeof k->kmp);
    wr_mpint(&w, k->secret, 32);
    if (w.err) return -1;
    k->kmp_len = w.len;
    LSSH_ASSERT(k->kmp_len > 4 && k->kmp_len <= sizeof k->kmp);
    return 0;
}

/* host key blob, then finish the exchange hash H */
static LSSH_MUST_CHECK int kex_finish_hash(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    kex_ctx_t *k = &s->kex;
    LSSH_ASSERT(k->hop_live);
    LSSH_ASSERT(k->kmp_len > 0 && k->kmp_len <= sizeof k->kmp);
    wtr_t w; wr_init(&w, k->ksblob, sizeof k->ksblob);
    wr_cstr(&w, HOSTKEY_TYPE);
    wr_cstr(&w, HOSTKEY_CURVE);
    wr_string(&w, s->hostkey_pub, 65);
    if (w.err) return -1;
    k->ks_len = w.len;

    hash_string(&k->hop, k->ksblob, k->ks_len);
    hash_string(&k->hop, k->q_c, 32);
    hash_string(&k->hop, k->q_s, 32);
    hs_update(&k->hop, k->kmp, k->kmp_len);   /* kmp already has length prefix */
    if (k->hop.err) return -1;                 /* still live: kex_ctx_wipe aborts it */
    size_t olen = 0;
    k->hop_live = false;
    if (psa_hash_finish(&k->hop.op, k->H, 32, &olen) != PSA_SUCCESS || olen != 32) return -1;
    if (!s->have_sid){ memcpy(s->session_id, k->H, 32); s->have_sid = true; }
    LSSH_ASSERT(s->have_sid && !k->hop_live);
    return 0;
}

/* sign H with the host key (ECDSA-SHA256 over H), send KEX_ECDH_REPLY */
static LSSH_MUST_CHECK int kex_send_reply(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    kex_ctx_t *k = &s->kex;
    LSSH_ASSERT(k->ks_len > 0 && k->ks_len <= sizeof k->ksblob);
    LSSH_ASSERT(s->hostkey != 0);
    size_t rs_len = 0;
    if (sha256(k->H, 32, k->h2)) return -1;
    if (psa_sign_hash(s->hostkey, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                      k->h2, 32, k->rs, sizeof k->rs, &rs_len) != PSA_SUCCESS || rs_len != 64)
        return -1;

    wtr_t sw; wr_init(&sw, k->sigblob, sizeof k->sigblob);
    wr_cstr(&sw, HOSTKEY_TYPE);
    wtr_t mw; wr_init(&mw, k->rsmp, sizeof k->rsmp);
    wr_mpint(&mw, k->rs, 32);
    wr_mpint(&mw, k->rs+32, 32);
    if (mw.err) return -1;
    wr_string(&sw, k->rsmp, mw.len);
    if (sw.err) return -1;

    wtr_t w; wr_init(&w, k->reply, sizeof k->reply);
    wr_u8(&w, SSH_MSG_KEX_ECDH_REPLY);
    wr_string(&w, k->ksblob, k->ks_len);
    wr_string(&w, k->q_s, 32);
    wr_string(&w, k->sigblob, sw.len);
    if (w.err || send_packet(s, k->reply, w.len)) return -1;
    return 0;
}

/* NEWKEYS both directions */
static LSSH_MUST_CHECK int kex_newkeys(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    LSSH_ASSERT(s->have_sid);
    LSSH_ASSERT(s->kex.ck != NULL);   /* the client's KEXINIT was seen */
    uint8_t nk = SSH_MSG_NEWKEYS;
    if (send_packet(s, &nk, 1)) return -1;
    for (unsigned skip = 0; skip <= LSSH_KEX_MAX_SKIP; skip++){
        const uint8_t *pl; size_t pn;
        if (recv_packet(s, &pl, &pn)) return -1;
        int sk = kex_skip(s, pl[0]);
        if (sk < 0) return -1;
        if (sk) continue;
        if (pl[0] != SSH_MSG_NEWKEYS){
            send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "expected NEWKEYS");
            return -1;
        }
        return 0;
    }
    send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "too many IGNORE/DEBUG in kex");
    return -1;
}

/* derive and install keys */
static LSSH_MUST_CHECK int kex_install(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    kex_ctx_t *k = &s->kex;
    LSSH_ASSERT(s->have_sid);
    LSSH_ASSERT(k->kmp_len > 0);
    if (kdf(k->kmp, k->kmp_len, k->H, s->session_id, 'A', k->iv_c2s, 12) ||
        kdf(k->kmp, k->kmp_len, k->H, s->session_id, 'B', k->iv_s2c, 12) ||
        kdf(k->kmp, k->kmp_len, k->H, s->session_id, 'C', k->key_c2s, 32) ||
        kdf(k->kmp, k->kmp_len, k->H, s->session_id, 'D', k->key_s2c, 32)) return -1;
    if (import_gcm_key(&s->k_in, k->key_c2s, true) ||
        import_gcm_key(&s->k_out, k->key_s2c, false)) return -1;
    LSSH_ASSERT(s->k_in != 0 && s->k_out != 0);
    memcpy(s->iv_in, k->iv_c2s, 12);
    memcpy(s->iv_out, k->iv_s2c, 12);
    s->enc = true;
    if (s->strict_kex){ s->seq_in = 0; s->seq_out = 0; }
    return 0;
}

/* Run a key exchange. If client_kexinit != NULL the client's KEXINIT was
 * already consumed by the caller (rekey path). */
static LSSH_MUST_CHECK int do_kex(lssh_session_t *s, const uint8_t *client_kexinit, size_t ck_len){
    LSSH_ASSERT(s != NULL);
    kex_ctx_t *k = &s->kex;
    LSSH_ASSERT(!k->hop_live && k->eph == 0);   /* the last exchange wiped it */
    LSSH_ASSERT(s->cfg != NULL);
    LSSH_ASSERT(s->hostkey != 0);               /* set for the whole connection */
    LSSH_ASSERT(client_kexinit != NULL || !s->have_sid);   /* only a rekey has one */
    k->initial = !s->have_sid;
    k->ck = client_kexinit; k->ckn = ck_len;
    bool fail = kex_send_init(s) || kex_recv_init(s) || kex_hash_start(s) ||
                kex_ephemeral(s) || kex_recv_ecdh_init(s) || kex_shared_secret(s) ||
                kex_finish_hash(s) || kex_send_reply(s) || kex_newkeys(s) ||
                kex_install(s);
    kex_ctx_wipe(s);
    LSSH_ASSERT(fail || (s->enc && s->have_sid));
    if (fail && !s->dead)
        send_disconnect(s, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "kex failed");
    LSSH_ASSERT(!fail || s->dead);   /* a failed exchange ends the transport */
    return fail ? -1 : 0;
}

/* ------------------------------------------------------------- userauth */

static LSSH_MUST_CHECK int send_auth_failure(lssh_session_t *s){
    LSSH_ASSERT(s != NULL && s->cfg != NULL);
    /* lssh_server_run refuses a config with neither method */
    LSSH_ASSERT(s->cfg->pubkey_auth != NULL || s->cfg->password_auth != NULL);
    char methods[64] = "";
    if (s->cfg->pubkey_auth) strcat(methods, "publickey");
    if (s->cfg->password_auth){
        if (methods[0]) strcat(methods, ",");
        strcat(methods, "password");
    }
    uint8_t buf[96]; wtr_t w; wr_init(&w, buf, sizeof buf);
    wr_u8(&w, SSH_MSG_USERAUTH_FAILURE);
    wr_cstr(&w, methods);
    wr_bool(&w, false);
    if (w.err) return -1;
    LSSH_ASSERT(w.len <= sizeof buf);
    return send_packet(s, buf, w.len);
}

/* public key blob: string type, string curve, string Q (65-byte point) */
static LSSH_MUST_CHECK bool parse_user_pubkey(const uint8_t *blob, uint32_t blob_len,
                                              const uint8_t **pt){
    LSSH_ASSERT(blob != NULL);
    LSSH_ASSERT(pt != NULL);
    rdr_t r; rd_init(&r, blob, blob_len);
    const uint8_t *t; uint32_t tl;
    if (!rd_string(&r,&t,&tl) || tl != strlen(HOSTKEY_TYPE) ||
        memcmp(t, HOSTKEY_TYPE, tl) != 0) return false;
    if (!rd_string(&r,&t,&tl) || tl != strlen(HOSTKEY_CURVE) ||
        memcmp(t, HOSTKEY_CURVE, tl) != 0) return false;
    uint32_t ptl;
    if (!rd_string(&r,pt,&ptl) || ptl != 65 || (*pt)[0] != 0x04) return false;
    return true;
}

/* signature: string alg, string( mpint r, mpint s ); r||s normalized to
 * fixed 32-byte big-endian halves of rs */
static LSSH_MUST_CHECK bool parse_user_sig(const uint8_t *sig, uint32_t sig_len,
                                           uint8_t rs[64]){
    LSSH_ASSERT(sig != NULL);
    LSSH_ASSERT(rs != NULL);
    rdr_t sr; rd_init(&sr, sig, sig_len);
    const uint8_t *t; uint32_t tl;
    if (!rd_string(&sr,&t,&tl) || tl != strlen(HOSTKEY_TYPE) ||
        memcmp(t, HOSTKEY_TYPE, tl) != 0) return false;
    const uint8_t *rsblob; uint32_t rsl;
    if (!rd_string(&sr,&rsblob,&rsl)) return false;
    rdr_t rr; rd_init(&rr, rsblob, rsl);
    const uint8_t *rb, *sb; uint32_t rbl, sbl;
    if (!rd_string(&rr,&rb,&rbl) || !rd_string(&rr,&sb,&sbl)) return false;
    /* bounded by the in-packet lengths rbl / sbl */
    while (rbl && rb[0]==0){ rb++; rbl--; }
    while (sbl && sb[0]==0){ sb++; sbl--; }
    if (rbl > 32 || sbl > 32) return false;
    memcpy(rs + (32-rbl), rb, rbl);
    memcpy(rs + 32 + (32-sbl), sb, sbl);
    return true;
}

/* Verify an ecdsa-sha2-nistp256 user signature over `data`. */
static LSSH_MUST_CHECK bool verify_user_ecdsa(const uint8_t *blob, uint32_t blob_len,
                                              const uint8_t *sig, uint32_t sig_len,
                                              const uint8_t *data, size_t data_len){
    LSSH_ASSERT(blob != NULL && sig != NULL && data != NULL);
    const uint8_t *pt = NULL;
    if (!parse_user_pubkey(blob, blob_len, &pt)) return false;
    LSSH_ASSERT(pt != NULL);
    uint8_t rs[64] = {0};
    if (!parse_user_sig(sig, sig_len, rs)) return false;

    uint8_t h[32];
    if (sha256(data, data_len, h)) return false;

    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_VERIFY_HASH);
    psa_key_id_t k = 0;
    if (psa_import_key(&a, pt, 65, &k) != PSA_SUCCESS) return false;
    psa_status_t st = psa_verify_hash(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                      h, 32, rs, 64);
    (void)psa_destroy_key(k);
    return st == PSA_SUCCESS;
}

/* password method: 0 with *ok set, -1 fatal; the password is wiped either way */
static LSSH_MUST_CHECK int auth_password(lssh_session_t *s, rdr_t *r, const char *user,
                                         bool *ok){
    LSSH_ASSERT(s != NULL && r != NULL);
    LSSH_ASSERT(user != NULL && ok != NULL);
    LSSH_ASSERT(s->cfg->password_auth != NULL);   /* handle_userauth checked */
    bool change; char pass[128];
    if (!rd_bool(r,&change) || !rd_cstring(r, pass, sizeof pass)){
        wipe(pass, sizeof pass);
        send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "bad password msg");
        return -1;
    }
    /* RFC 4252 §8: we change no passwords; a change request is a failed attempt */
    *ok = !change && s->cfg->password_auth(s->cfg->user, user, pass);
    wipe(pass, sizeof pass);
    return 0;
}

/* publickey with a signature from a known key: rebuild the signed data,
 * string(session_id) || request-without-sig, and verify. 0 with *ok set,
 * -1 fatal */
static LSSH_MUST_CHECK int auth_pk_verify(lssh_session_t *s, rdr_t *r,
                                          const char *user, const char *service,
                                          const char *alg,
                                          const uint8_t *blob, uint32_t blob_len,
                                          bool *ok){
    LSSH_ASSERT(s != NULL && r != NULL);
    LSSH_ASSERT(user != NULL && service != NULL);
    LSSH_ASSERT(alg != NULL && ok != NULL);
    LSSH_ASSERT(blob != NULL);
    LSSH_ASSERT(s->have_sid);   /* userauth only runs after the first kex */
    const uint8_t *sig; uint32_t sig_len;
    if (!rd_string(r, &sig, &sig_len)){
        send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "bad signature");
        return -1;
    }
    uint8_t data[512]; wtr_t w; wr_init(&w, data, sizeof data);
    wr_string(&w, s->session_id, 32);
    wr_u8(&w, SSH_MSG_USERAUTH_REQUEST);
    wr_cstr(&w, user);
    wr_cstr(&w, service);
    wr_cstr(&w, "publickey");
    wr_bool(&w, true);
    wr_cstr(&w, alg);
    wr_string(&w, blob, blob_len);
    if (!w.err)
        *ok = verify_user_ecdsa(blob, blob_len, sig, sig_len, data, w.len);
    return 0;
}

/* publickey method: 0 go on to accounting (*ok, *counted set), 1 already
 * answered with PK_OK, -1 fatal */
static LSSH_MUST_CHECK int auth_publickey(lssh_session_t *s, rdr_t *r,
                                          const char *user, const char *service,
                                          bool *ok, bool *counted){
    LSSH_ASSERT(s != NULL && r != NULL);
    LSSH_ASSERT(user != NULL && service != NULL);
    LSSH_ASSERT(ok != NULL && counted != NULL);
    LSSH_ASSERT(s->cfg->pubkey_auth != NULL);   /* handle_userauth checked */
    bool has_sig; char alg[40];
    const uint8_t *blob; uint32_t blob_len;
    if (!rd_bool(r,&has_sig) ||
        !rd_cstring(r, alg, sizeof alg) ||
        !rd_string(r, &blob, &blob_len)){
        send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "bad publickey msg");
        return -1;
    }
    bool key_known = strcmp(alg, HOSTKEY_TYPE) == 0 &&
                     s->cfg->pubkey_auth(s->cfg->user, user, blob, blob_len);
    if (has_sig){
        if (!key_known) return 0;
        return auth_pk_verify(s, r, user, service, alg, blob, blob_len, ok);
    }
    *counted = false;          /* probe, not an attempt */
    if (!key_known) return 0;
    uint8_t buf[256]; wtr_t w; wr_init(&w, buf, sizeof buf);
    wr_u8(&w, SSH_MSG_USERAUTH_PK_OK);
    wr_cstr(&w, alg);
    wr_string(&w, blob, blob_len);
    if (w.err || send_packet(s, buf, w.len)) return -1;
    return 1;
}

/* success, or count a failed attempt: 0 handled, -1 fatal */
static LSSH_MUST_CHECK int auth_finish(lssh_session_t *s, bool ok, bool counted,
                                       const char *user, const char *method){
    LSSH_ASSERT(s != NULL && s->cfg != NULL);
    LSSH_ASSERT(user != NULL && method != NULL);
    LSSH_ASSERT(!s->authed);                          /* handle_userauth returned */
    LSSH_ASSERT(strlen(user) < sizeof s->username);   /* rd_cstring capped it */
    if (ok){
        s->authed = true;
        memcpy(s->username, user, strlen(user) + 1);   /* both 64 bytes */
        LOGI("auth ok: user=%s method=%s", user, method);
        uint8_t b = SSH_MSG_USERAUTH_SUCCESS;
        return send_packet(s, &b, 1);
    }
    if (counted && ++s->auth_tries >= (s->cfg->auth_max_tries ? s->cfg->auth_max_tries : 5)){
        send_disconnect(s, SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "too many tries");
        return -1;
    }
    return send_auth_failure(s);
}

/* returns 0 handled, -1 fatal */
static LSSH_MUST_CHECK int handle_userauth(lssh_session_t *s, const uint8_t *pl, size_t pn){
    LSSH_ASSERT(s != NULL && s->cfg != NULL);
    LSSH_ASSERT(pl != NULL);
    LSSH_ASSERT(!s->authed && s->svc_userauth);   /* process_transport checked */
    LSSH_ASSERT(pn >= 1);
    rdr_t r; rd_init(&r, pl, pn);
    uint8_t m;
    char user[64], service[32], method[24];
    if (!rd_u8(&r,&m) || !rd_cstring(&r, user, sizeof user) ||
        !rd_cstring(&r, service, sizeof service) ||
        !rd_cstring(&r, method, sizeof method)){
        send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "bad userauth");
        return -1;
    }
    if (strcmp(service, "ssh-connection") != 0){
        send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "bad service");
        return -1;
    }

    bool ok = false;
    bool counted = true;

    if (strcmp(method, "password") == 0 && s->cfg->password_auth){
        if (auth_password(s, &r, user, &ok)) return -1;
    } else if (strcmp(method, "publickey") == 0 && s->cfg->pubkey_auth){
        int rc = auth_publickey(s, &r, user, service, &ok, &counted);
        if (rc < 0) return -1;
        if (rc > 0) return 0;     /* PK_OK sent: no accounting */
    } else if (strcmp(method, "none") == 0){
        counted = false;
    }
    return auth_finish(s, ok, counted, user, method);
}

/* ----------------------------------------------------------- connection */

static LSSH_MUST_CHECK int ch_send_u32msg(lssh_session_t *s, uint8_t msg, uint32_t v){
    LSSH_ASSERT(s != NULL);
    LSSH_ASSERT(msg >= SSH_MSG_CHANNEL_WINDOW_ADJUST && msg <= SSH_MSG_CHANNEL_FAILURE);
    const uint8_t b[5] = {msg,(uint8_t)(v>>24),(uint8_t)(v>>16),(uint8_t)(v>>8),(uint8_t)v};
    return send_packet(s, b, 5);
}

static void ch_teardown(lssh_session_t *s){
    LSSH_ASSERT(s != NULL && s->cfg != NULL);
    LSSH_ASSERT(s->write_depth == 0);   /* never from inside lssh_write */
    if (s->ch_open && !s->notified_close){
        s->notified_close = true;
        if (s->cfg->on_close) s->cfg->on_close(s->cfg->user, s);
    }
    s->ch_open = false;
}

static LSSH_MUST_CHECK int handle_channel_open(lssh_session_t *s, const uint8_t *pl, size_t pn){
    LSSH_ASSERT(s->authed);
    rdr_t r; rd_init(&r, pl, pn);
    uint8_t m;
    const uint8_t *type; uint32_t type_len;
    uint32_t sender, win, maxpkt;
    if (!rd_u8(&r,&m) || !rd_string(&r,&type,&type_len) || !rd_u32(&r,&sender) ||
        !rd_u32(&r,&win) || !rd_u32(&r,&maxpkt)){
        send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "bad channel open");
        return -1;
    }
    bool is_session = (type_len == 7 && memcmp(type, "session", 7) == 0);
    if (!is_session || s->ch_open){
        uint8_t buf[128]; wtr_t w; wr_init(&w, buf, sizeof buf);
        wr_u8(&w, SSH_MSG_CHANNEL_OPEN_FAILURE);
        wr_u32(&w, sender);
        wr_u32(&w, is_session ? SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
                              : SSH_OPEN_UNKNOWN_CHANNEL_TYPE);
        wr_cstr(&w, is_session ? "one session only" : "unsupported channel type");
        wr_cstr(&w, "");
        if (w.err) return -1;
        return send_packet(s, buf, w.len);
    }
    if (maxpkt == 0){   /* lssh_write could never send a byte */
        send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "bad channel open");
        return -1;
    }
    s->ch_open = true;
    s->ch_started = false;
    s->ch_sent_close = s->ch_rcvd_close = s->ch_sent_eof = false;
    s->notified_close = false;
    s->has_pty = false;
    s->term[0] = 0;
    s->pend_pty = s->pend_open = s->pend_exec = false;
    s->rxq_len = 0;
    s->ch_remote_id = sender;
    s->win_out = win;
    s->max_out = maxpkt;
    s->win_in = LSSH_WINDOW;

    uint8_t buf[32]; wtr_t w; wr_init(&w, buf, sizeof buf);
    wr_u8(&w, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    wr_u32(&w, sender);
    wr_u32(&w, 0);                    /* our channel id */
    wr_u32(&w, LSSH_WINDOW);
    wr_u32(&w, LSSH_IN_MAXPKT);
    if (w.err) return -1;
    return send_packet(s, buf, w.len);
}

/* CHANNEL_SUCCESS / FAILURE, only if the client asked for a reply */
static LSSH_MUST_CHECK int ch_reply(lssh_session_t *s, bool want_reply, bool ok){
    LSSH_ASSERT(s != NULL);
    LSSH_ASSERT(s->ch_open);   /* handle_channel_request checked */
    if (!want_reply) return 0;
    return ch_send_u32msg(s, ok ? SSH_MSG_CHANNEL_SUCCESS : SSH_MSG_CHANNEL_FAILURE,
                          s->ch_remote_id);
}

/* a terminal dimension from the wire, saturated to on_pty's uint16_t */
static LSSH_MUST_CHECK uint16_t clamp_u16(uint32_t v){
    uint16_t c = v > 0xFFFFu ? (uint16_t)0xFFFFu : (uint16_t)v;
    LSSH_ASSERT(c <= v);
    LSSH_ASSERT(c == v || c == 0xFFFFu);
    return c;
}

/* pty-req (pty) or window-change: TERM (pty-req only), cols, rows, pixel
 * size, modes (pty-req only). Queues on_pty with the size; false if the
 * request is malformed, leaving the session as it was. */
static LSSH_MUST_CHECK bool ch_req_size(lssh_session_t *s, rdr_t *r, bool pty){
    LSSH_ASSERT(s != NULL && r != NULL);
    LSSH_ASSERT(s->ch_open);   /* handle_channel_request checked */
    char term[32] = ""; uint32_t cols, rows, px, py;
    const uint8_t *modes; uint32_t modes_len;
    if (pty && !rd_cstring(r, term, sizeof term)) return false;
    if (!rd_u32(r,&cols) || !rd_u32(r,&rows) || !rd_u32(r,&px) || !rd_u32(r,&py) ||
        (pty && !rd_string(r,&modes,&modes_len))) return false;
    if (pty){
        s->has_pty = true;
        memcpy(s->term, term, strlen(term) + 1);
    }
    /* callbacks are queued (pend_*) and run by dispatch_events() */
    s->pend_pty = true;
    s->pend_cols = clamp_u16(cols); s->pend_rows = clamp_u16(rows);
    return true;
}

static LSSH_MUST_CHECK int handle_channel_request(lssh_session_t *s, const uint8_t *pl,
                                                  size_t pn){
    LSSH_ASSERT(s->authed);
    rdr_t r; rd_init(&r, pl, pn);
    uint8_t m; uint32_t rcpt; char req[32]; bool want_reply;
    if (!rd_u8(&r,&m) || !rd_u32(&r,&rcpt) || !rd_cstring(&r, req, sizeof req) ||
        !rd_bool(&r,&want_reply) || !s->ch_open){
        return 0; /* tolerate */
    }
    if (strcmp(req, "pty-req") == 0)
        return ch_reply(s, want_reply, ch_req_size(s, &r, true));
    if (strcmp(req, "window-change") == 0){
        (void)!ch_req_size(s, &r, false);   /* RFC 4254 §6.7: never replied to */
        return 0;
    }
    if (strcmp(req, "shell") == 0 || strcmp(req, "exec") == 0){
        bool exec = req[0] == 'e';
        /* RFC 4254 §6.5: one shell/exec per channel */
        if (s->ch_started ||
            (exec && !rd_cstring(&r, s->exec_cmd, sizeof s->exec_cmd)))
            return ch_reply(s, want_reply, false);
        if (ch_reply(s, want_reply, true)) return -1;
        s->ch_started = true;
        s->pend_open = true;
        s->pend_exec = exec;
        return 0;
    }
    if (strcmp(req, "signal") == 0)
        return ch_reply(s, want_reply, true);
    /* env (we set no environment), subsystem (sftp), x11, auth-agent, etc. */
    return ch_reply(s, want_reply, false);
}

/* SERVICE_REQUEST: only ssh-userauth; the configured banner follows the accept */
static LSSH_MUST_CHECK int handle_service_request(lssh_session_t *s, const uint8_t *pl,
                                                  size_t pn){
    LSSH_ASSERT(s != NULL && pl != NULL);
    LSSH_ASSERT(s->cfg != NULL);
    LSSH_ASSERT(pn >= 1);
    rdr_t r; rd_init(&r, pl, pn); uint8_t m;
    const uint8_t *svc; uint32_t svc_len;
    if (!rd_u8(&r,&m) || !rd_string(&r,&svc,&svc_len) || svc_len != 12 ||
        memcmp(svc, "ssh-userauth", 12) != 0){
        send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "unknown service");
        return -1;
    }
    uint8_t buf[24]; wtr_t w; wr_init(&w, buf, sizeof buf);
    wr_u8(&w, SSH_MSG_SERVICE_ACCEPT);
    wr_cstr(&w, "ssh-userauth");
    if (w.err || send_packet(s, buf, w.len)) return -1;
    s->svc_userauth = true;
    if (s->cfg->banner){
        /* chdata is free until a channel exists */
        wtr_t bw; wr_init(&bw, s->chdata, LSSH_MAX_PACKET - 32);
        wr_u8(&bw, SSH_MSG_USERAUTH_BANNER);
        wr_cstr(&bw, s->cfg->banner);
        wr_cstr(&bw, "");
        LSSH_ASSERT(bw.len <= LSSH_MAX_PACKET - 32);
        if (bw.err) LOGW("banner too long for one packet, not sent");
        else if (send_packet(s, s->chdata, bw.len)) return -1;
    }
    return 0;
}

/* GLOBAL_REQUEST: none supported; fail it if a reply is wanted */
static LSSH_MUST_CHECK int handle_global_request(lssh_session_t *s, const uint8_t *pl,
                                                 size_t pn){
    LSSH_ASSERT(s != NULL);
    LSSH_ASSERT(pl != NULL);
    LSSH_ASSERT(pn >= 1);
    rdr_t r; rd_init(&r, pl, pn); uint8_t m;
    const uint8_t *name; uint32_t nl; bool want;
    if (rd_u8(&r,&m) && rd_string(&r,&name,&nl) && rd_bool(&r,&want) && want){
        uint8_t b = SSH_MSG_REQUEST_FAILURE;
        return send_packet(s, &b, 1);
    }
    return 0;
}

/* Transport and userauth messages, allowed before auth. 0 continue, -1 end
 * the connection, 1 not one of these. */
static LSSH_MUST_CHECK int process_transport(lssh_session_t *s, const uint8_t *pl, size_t pn){
    LSSH_ASSERT(s != NULL && pl != NULL);
    LSSH_ASSERT(pn >= 1);
    LSSH_ASSERT(s->enc && s->have_sid);   /* only after the first kex */
    switch (pl[0]){
    case SSH_MSG_DISCONNECT:
        s->dead = true;
        return -1;
    case SSH_MSG_IGNORE:
    case SSH_MSG_DEBUG:
    case SSH_MSG_UNIMPLEMENTED:
    case SSH_MSG_EXT_INFO:
        return 0;

    case SSH_MSG_KEXINIT:                       /* client-initiated rekey */
        return do_kex(s, pl, pn) ? -1 : 0;

    case SSH_MSG_SERVICE_REQUEST:
        return handle_service_request(s, pl, pn);

    case SSH_MSG_USERAUTH_REQUEST:
        if (s->authed) return 0;   /* RFC 4252 §5.1: ignored silently */
        if (!s->svc_userauth){
            send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "ssh-userauth not requested");
            return -1;
        }
        return handle_userauth(s, pl, pn);

    case SSH_MSG_GLOBAL_REQUEST:
        return handle_global_request(s, pl, pn);

    default:
        return 1;
    }
}

static LSSH_MUST_CHECK int handle_window_adjust(lssh_session_t *s, const uint8_t *pl,
                                                size_t pn){
    LSSH_ASSERT(s != NULL && pl != NULL);
    LSSH_ASSERT(s->authed);
    LSSH_ASSERT(pn >= 1);
    rdr_t r; rd_init(&r, pl, pn); uint8_t m; uint32_t rcpt, add;
    if (rd_u8(&r,&m) && rd_u32(&r,&rcpt) && rd_u32(&r,&add)){
        uint64_t nw = (uint64_t)s->win_out + add;
        s->win_out = nw > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)nw;
    }
    return 0;
}

static LSSH_MUST_CHECK int handle_channel_data(lssh_session_t *s, const uint8_t *pl,
                                               size_t pn){
    LSSH_ASSERT(s != NULL && pl != NULL);
    LSSH_ASSERT(pn >= 1);
    LSSH_ASSERT(s->rxq_len <= sizeof s->rxq && s->win_in <= LSSH_WINDOW);
    rdr_t r; rd_init(&r, pl, pn); uint8_t m; uint32_t rcpt;
    const uint8_t *d; uint32_t dl;
    if (!rd_u8(&r,&m) || !rd_u32(&r,&rcpt) || !rd_string(&r,&d,&dl) || !s->ch_open) return 0;
    /* lssh_write() stops pumping before rxq could overflow, so this
     * only trips on a client ignoring our advertised max packet */
    if (dl > LSSH_IN_MAXPKT || dl > sizeof s->rxq - s->rxq_len){
        send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "channel data too large");
        return -1;
    }
    s->win_in = dl > s->win_in ? 0 : s->win_in - dl;
    if (s->win_in < LSSH_WINDOW/2){
        uint32_t add = LSSH_WINDOW - s->win_in;
        uint8_t b[16]; wtr_t w; wr_init(&w, b, sizeof b);
        wr_u8(&w, SSH_MSG_CHANNEL_WINDOW_ADJUST);
        wr_u32(&w, s->ch_remote_id);
        wr_u32(&w, add);
        LSSH_ASSERT(!w.err && w.len == 9);
        if (send_packet(s, b, w.len)) return -1;
        s->win_in += add;
    }
    LSSH_ASSERT(s->win_in <= LSSH_WINDOW);
    memcpy(s->rxq + s->rxq_len, d, dl);
    s->rxq_len += dl;
    LSSH_ASSERT(s->rxq_len <= sizeof s->rxq);
    return 0;
}

static LSSH_MUST_CHECK int handle_channel_close(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    LSSH_ASSERT(s->authed);
    s->ch_rcvd_close = true;
    if (!s->ch_sent_close){
        s->ch_sent_close = true;
        if (ch_send_u32msg(s, SSH_MSG_CHANNEL_CLOSE, s->ch_remote_id)) return -1;
    }
    LSSH_ASSERT(s->ch_sent_close && s->ch_rcvd_close);
    /* on_close runs from serve_connection(), never inside a callback */
    return -1;  /* single-channel server: connection is done */
}

/* Connection-protocol messages, after auth. 0 continue, -1 end the
 * connection, 1 not one of these. */
static LSSH_MUST_CHECK int process_channel(lssh_session_t *s, const uint8_t *pl, size_t pn){
    LSSH_ASSERT(s != NULL && pl != NULL);
    LSSH_ASSERT(pn >= 1);
    LSSH_ASSERT(s->authed);   /* process_packet checked */
    if (pl[0] >= SSH_MSG_CHANNEL_WINDOW_ADJUST && pl[0] <= SSH_MSG_CHANNEL_FAILURE &&
        pn >= 5){
        /* we only ever hand out channel id 0 */
        uint32_t rcpt = ((uint32_t)pl[1]<<24)|((uint32_t)pl[2]<<16)|((uint32_t)pl[3]<<8)|pl[4];
        if (rcpt != 0){
            send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "unknown channel");
            return -1;
        }
    }

    switch (pl[0]){
    case SSH_MSG_CHANNEL_OPEN:
        return handle_channel_open(s, pl, pn);

    case SSH_MSG_CHANNEL_REQUEST:
        return handle_channel_request(s, pl, pn);

    case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        return handle_window_adjust(s, pl, pn);

    case SSH_MSG_CHANNEL_DATA:
        return handle_channel_data(s, pl, pn);

    case SSH_MSG_CHANNEL_EXTENDED_DATA:
    case SSH_MSG_CHANNEL_EOF:
        return 0;

    case SSH_MSG_CHANNEL_CLOSE:
        return handle_channel_close(s);

    default:
        return 1;
    }
}

/* unknown message */
static LSSH_MUST_CHECK int send_unimplemented(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    uint8_t b[8]; wtr_t w; wr_init(&w, b, sizeof b);
    wr_u8(&w, SSH_MSG_UNIMPLEMENTED);
    wr_u32(&w, s->seq_in - 1);
    LSSH_ASSERT(!w.err && w.len == 5);
    return send_packet(s, b, w.len);
}

/* Process exactly one inbound packet. Returns 0 to continue, -1 to end the
 * connection. */
static LSSH_MUST_CHECK int process_packet(lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    LSSH_ASSERT(s->write_depth >= 0 && s->write_depth <= 1);
    const uint8_t *pl; size_t pn;
    if (recv_packet(s, &pl, &pn)) return -1;
    LSSH_ASSERT(pl != NULL && pn >= 1);

    int rc = process_transport(s, pl, pn);
    if (rc <= 0) return rc;

    if (s->authed){
        rc = process_channel(s, pl, pn);
        if (rc <= 0) return rc;
    } else if (pl[0] >= SSH_MSG_GLOBAL_REQUEST && pl[0] <= SSH_MSG_CONNECTION_LAST){
        send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "not authenticated");
        return -1;
    }
    /* RFC 4253 §11.4, before auth too */
    return send_unimplemented(s);
}

/* Run queued app callbacks: pty, then open, then data, in arrival order
 * per kind. Only from the connection loop (write_depth == 0). Data is
 * delivered out of rxq; packets pumped by writes inside on_data append
 * behind the delivered bytes, so the callback's pointer stays valid.
 * At most LSSH_DISPATCH_MAX callbacks; true if it stopped there, so the
 * caller comes back before blocking on the socket. */
static LSSH_MUST_CHECK bool dispatch_events(lssh_session_t *s){
    LSSH_ASSERT(s != NULL && s->cfg != NULL);
    LSSH_ASSERT(s->write_depth >= 0);
    const lssh_config_t *c = s->cfg;
    for (unsigned i = 0; i < LSSH_DISPATCH_MAX; i++){
        if (s->dead || !s->ch_open || s->ch_rcvd_close || s->write_depth != 0)
            return false;
        if (s->pend_pty){
            s->pend_pty = false;
            if (c->on_pty) c->on_pty(c->user, s, s->pend_cols, s->pend_rows);
        } else if (s->pend_open){
            s->pend_open = false;
            if (c->on_open) c->on_open(c->user, s, s->pend_exec ? s->exec_cmd : NULL);
        } else if (s->rxq_len){
            size_t n = s->rxq_len < LSSH_RX_CHUNK ? s->rxq_len : LSSH_RX_CHUNK;
            LSSH_ASSERT(n > 0 && s->rxq_len <= sizeof s->rxq);
            if (c->on_data) c->on_data(c->user, s, s->rxq, n);
            /* writes inside on_data only append behind the delivered bytes */
            LSSH_ASSERT(n <= s->rxq_len && s->rxq_len <= sizeof s->rxq);
            memmove(s->rxq, s->rxq + n, s->rxq_len - n);
            s->rxq_len -= n;
        } else {
            return false;
        }
    }
    return true;
}

/* ------------------------------------------------------------ public API */

/* asserts on arguments here catch app programming errors, not peer input */
const char *lssh_username(const lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    return s->username;
}
bool lssh_has_pty(const lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    return s->has_pty;
}
const char *lssh_term(const lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    return s->term;
}
const char *lssh_client_version(const lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    return s->v_c;
}

ssize_t lssh_write(lssh_session_t *s, const void *data, size_t len){
    LSSH_ASSERT(data != NULL || len == 0);
    if (!s->ch_open || s->ch_sent_close || s->ch_sent_eof || s->dead) return -1;
    LSSH_ASSERT(s->max_out > 0);   /* handle_channel_open refused 0 */
    const uint8_t *d = data;
    size_t left = len;
    unsigned pumps = 0;   /* packets pumped since the window last grew */
    /* each pass sends >= 1 byte (max_out > 0) or pumps a counted packet */
    while (left){
        if (s->win_out == 0){
            /* pump the connection until the client grants window. Pumped
             * packets only queue events (no callbacks run here), so depth
             * stays at 1. Stop, short, if rxq could not take another data
             * packet: the client is typing while refusing our output; or
             * after LSSH_WRITE_MAX_PUMPS packets that granted nothing. */
            if (s->write_depth > 0 || pumps >= LSSH_WRITE_MAX_PUMPS ||
                sizeof s->rxq - s->rxq_len < LSSH_IN_MAXPKT)
                return (ssize_t)(len - left);
            s->write_depth++;
            int rc = process_packet(s);
            s->write_depth--;
            if (rc) return -1;
            pumps = s->win_out ? 0 : pumps + 1;
            continue;
        }
        size_t chunk = left;
        if (chunk > s->win_out) chunk = s->win_out;
        if (chunk > s->max_out) chunk = s->max_out;
        if (chunk > LSSH_MAX_PACKET - 96) chunk = LSSH_MAX_PACKET - 96;
        LSSH_ASSERT(chunk > 0 && chunk <= s->win_out);

        /* assemble the CHANNEL_DATA payload in a dedicated buffer
         * (s->frame is consumed by send_packet for the AEAD plaintext) */
        wtr_t w; wr_init(&w, s->chdata, sizeof s->chdata);
        wr_u8(&w, SSH_MSG_CHANNEL_DATA);
        wr_u32(&w, s->ch_remote_id);
        wr_string(&w, d, chunk);
        if (w.err || send_packet(s, s->chdata, w.len)) return -1;
        s->win_out -= (uint32_t)chunk;
        d += chunk; left -= chunk;
    }
    return (ssize_t)len;
}

ssize_t lssh_printf(lssh_session_t *s, const char *fmt, ...){
    LSSH_ASSERT(s != NULL);
    LSSH_ASSERT(fmt != NULL);
    char buf[512];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n >= sizeof buf) n = sizeof buf - 1;
    LSSH_ASSERT((size_t)n < sizeof buf);
    return lssh_write(s, buf, (size_t)n);
}

int lssh_exit(lssh_session_t *s, uint32_t exit_status){
    LSSH_ASSERT(s != NULL);
    if (!s->ch_open || s->ch_sent_close || s->dead) return -1;
    uint8_t buf[64]; wtr_t w; wr_init(&w, buf, sizeof buf);
    wr_u8(&w, SSH_MSG_CHANNEL_REQUEST);
    wr_u32(&w, s->ch_remote_id);
    wr_cstr(&w, "exit-status");
    wr_bool(&w, false);
    wr_u32(&w, exit_status);
    if (w.err || send_packet(s, buf, w.len)) return -1;
    if (ch_send_u32msg(s, SSH_MSG_CHANNEL_EOF, s->ch_remote_id)) return -1;
    s->ch_sent_eof = true;
    s->ch_sent_close = true;
    LSSH_ASSERT(s->ch_open);   /* only ch_teardown clears it */
    return ch_send_u32msg(s, SSH_MSG_CHANNEL_CLOSE, s->ch_remote_id);
}

/* --------------------------------------------------------- host key mgmt */

static LSSH_MUST_CHECK int hostkey_import(const uint8_t *scalar, psa_key_id_t *id,
                                          uint8_t pub[65]){
    LSSH_ASSERT(id != NULL);
    LSSH_ASSERT(pub != NULL);
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH);
    psa_key_id_t k = 0;
    if (scalar){
        if (psa_import_key(&a, scalar, 32, &k) != PSA_SUCCESS) return -1;
    } else {
        if (psa_generate_key(&a, &k) != PSA_SUCCESS) return -1;
        LOGW("no host key configured: using an EPHEMERAL host key");
    }
    size_t olen = 0;
    if (psa_export_public_key(k, pub, 65, &olen) != PSA_SUCCESS || olen != 65){
        (void)psa_destroy_key(k);
        return -1;
    }
    *id = k;
    LSSH_ASSERT(*id != 0 && pub[0] == 0x04);   /* uncompressed point */
    return 0;
}

int lssh_hostkey_generate(uint8_t out[32]){
    LSSH_ASSERT(out != NULL);
    if (psa_crypto_init() != PSA_SUCCESS) return -1;
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
    psa_key_id_t k = 0;
    if (psa_generate_key(&a, &k) != PSA_SUCCESS) return -1;
    LSSH_ASSERT(k != 0);
    size_t olen = 0;
    int rc = (psa_export_key(k, out, 32, &olen) == PSA_SUCCESS && olen == 32) ? 0 : -1;
    (void)psa_destroy_key(k);
    return rc;
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int lssh_hostkey_fingerprint(const uint8_t key[32], char *out, size_t outlen){
    LSSH_ASSERT(out != NULL);
    if (psa_crypto_init() != PSA_SUCCESS) return -1;
    psa_key_id_t k = 0; uint8_t pub[65];
    int rc = -1;
    if (hostkey_import(key, &k, pub) == 0){
        uint8_t blob[128]; wtr_t w; wr_init(&w, blob, sizeof blob);
        wr_cstr(&w, HOSTKEY_TYPE);
        wr_cstr(&w, HOSTKEY_CURVE);
        wr_string(&w, pub, 65);
        uint8_t h[32];
        if (!w.err && !sha256(blob, w.len, h)){
            /* OpenSSH style: SHA256: + unpadded base64 */
            if (outlen >= 8 + 43 + 1){
                char *p = out;
                memcpy(p, "SHA256:", 7); p += 7;
                for (int i = 0; i < 30; i += 3){
                    uint32_t v = (h[i]<<16)|(h[i+1]<<8)|h[i+2];
                    *p++ = B64[(v>>18)&63]; *p++ = B64[(v>>12)&63];
                    *p++ = B64[(v>>6)&63];  *p++ = B64[v&63];
                }
                uint32_t v = (h[30]<<8)|h[31];
                *p++ = B64[(v>>10)&63]; *p++ = B64[(v>>4)&63]; *p++ = B64[(v<<2)&63];
                LSSH_ASSERT(p - out == 7 + 43 && (size_t)(p - out) < outlen);
                *p = 0;
                rc = 0;
            }
        }
        (void)psa_destroy_key(k);
    }
    return rc;
}

/* ------------------------------------------------------------ main loops */

static LSSH_MUST_CHECK int version_exchange(lssh_session_t *s){
    LSSH_ASSERT(s != NULL && s->fd >= 0);
    LSSH_ASSERT(!s->enc && !s->have_sid);   /* fresh state from serve_client */
    const char *ident = LSSH_IDENT "\r\n";
    if (io_send_all(s, (const uint8_t*)ident, strlen(ident))) return -1;
    /* read the client identification line (byte-at-a-time; happens once) */
    size_t n = 0;
    while (n < sizeof(s->v_c) - 1){   /* one byte per pass */
        uint8_t c;
        if (io_recv_exact(s, &c, 1)) return -1;
        if (c == '\n'){
            while (n && (s->v_c[n-1] == '\r')) n--;
            LSSH_ASSERT(n < sizeof s->v_c);
            s->v_c[n] = 0;
            if (strncmp(s->v_c, "SSH-2.0-", 8) == 0 ||
                strncmp(s->v_c, "SSH-1.99-", 9) == 0)
                return 0;
            return -1;
        }
        s->v_c[n++] = (char)c;
    }
    return -1;
}

static uint64_t mono_ms(void){
    struct timespec ts;
    /* cannot fail (supported clock, our own timespec); if it did, fail
     * closed: every deadline has passed */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return UINT64_MAX;
    LSSH_ASSERT(ts.tv_sec >= 0);
    LSSH_ASSERT(ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* 1 readable, 0 timeout, -1 error */
static int wait_readable(int fd, uint32_t ms){
    LSSH_ASSERT(fd >= 0);
    LSSH_ASSERT(fd < FD_SETSIZE);   /* FD_SET past it is undefined */
    fd_set rf; FD_ZERO(&rf); FD_SET(fd, &rf);
    struct timeval tv = { (time_t)(ms / 1000), (suseconds_t)((ms % 1000) * 1000) };
    int r = select(fd + 1, &rf, NULL, NULL, &tv);
    if (r < 0) return errno == EINTR ? 0 : -1;
    return r > 0;
}

static LSSH_MUST_CHECK bool ticking(const lssh_session_t *s){
    LSSH_ASSERT(s != NULL);
    LSSH_ASSERT(s->cfg != NULL);
    return s->cfg->on_tick && s->cfg->tick_ms &&
           s->ch_open && !s->ch_sent_close && !s->dead;
}

static void serve_connection(lssh_session_t *s){
    LSSH_ASSERT(s != NULL && s->cfg != NULL);
    LSSH_ASSERT(s->hostkey != 0);
    if (version_exchange(s)) return;
    if (do_kex(s, NULL, 0)) return;
    const lssh_config_t *c = s->cfg;
    uint64_t last_rx = mono_ms(), next_tick = 0;
    /* event loop: bounded by the auth deadline, the idle timeout and the peer */
    while (!s->dead){
        bool more = dispatch_events(s);
        LSSH_ASSERT(s->write_depth == 0);   /* every lssh_write pump unwound */
        if (s->dead || s->ch_rcvd_close) break;   /* close seen by a write's pump */
        if (more) continue;                        /* the rest before blocking */
        /* With ticks on, wait for the next packet in select() so on_tick can
         * run in between; SO_RCVTIMEO never fires there, so enforce the idle
         * timeout here. A packet that has started arriving is still read
         * whole by the blocking path below. */
        if (ticking(s)){
            uint64_t now = mono_ms();
            if (c->recv_timeout_ms && now - last_rx >= c->recv_timeout_ms) break;
            if (now >= next_tick){
                next_tick = now + c->tick_ms;
                c->on_tick(c->user, s);
                continue;
            }
            uint64_t wait = next_tick - now;
            if (c->recv_timeout_ms && last_rx + c->recv_timeout_ms - now < wait)
                wait = last_rx + c->recv_timeout_ms - now;
            int r = wait_readable(s->fd, (uint32_t)wait);
            if (r < 0) break;
            if (r == 0) continue;
        }
        if (process_packet(s)) break;
        last_rx = mono_ms();
    }
    ch_teardown(s);
}

/* our own listening socket on cfg->port (0 => 22); -1 on failure */
static LSSH_MUST_CHECK int listen_socket(const lssh_config_t *cfg){
    LSSH_ASSERT(cfg != NULL);
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return -1;
    int one = 1;
    /* without it a quick restart may fail to bind, which bind() reports */
    (void)setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(cfg->port ? cfg->port : 22);
    LSSH_ASSERT(sa.sin_port != 0);   /* port 0 means 22, never "any" */
    if (bind(lfd, (struct sockaddr*)&sa, sizeof sa) || listen(lfd, 1)){
        (void)close(lfd);   /* close() results are dropped: the fd is gone either way */
        return -1;
    }
    return lfd;
}

/* one accepted connection: socket options, fresh per-connection state in
 * the kept allocation, serve it, then release its keys and socket */
static void serve_client(lssh_session_t *s, const lssh_config_t *cfg, int cfd,
                         psa_key_id_t hostkey, const uint8_t hostkey_pub[65]){
    LSSH_ASSERT(s != NULL && cfg != NULL);
    LSSH_ASSERT(hostkey != 0 && hostkey_pub != NULL);
    LSSH_ASSERT(cfd >= 0);
    int one = 1;
    (void)setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);   /* latency only */
    if (cfg->recv_timeout_ms){
        struct timeval tv = { (time_t)(cfg->recv_timeout_ms / 1000),
                              (suseconds_t)((cfg->recv_timeout_ms % 1000) * 1000) };
        /* the idle timeout is a security property: no timeout, no connection */
        if (setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0){
            LOGW("SO_RCVTIMEO failed, dropping connection");
            (void)close(cfd);
            return;
        }
    }

    /* reset per-connection state, keep the allocation */
    memset(s, 0, sizeof *s);
    s->cfg = cfg;
    s->fd = cfd;
    s->hostkey = hostkey;
    memcpy(s->hostkey_pub, hostkey_pub, 65);
    s->auth_deadline = mono_ms() +
        (cfg->auth_timeout_ms ? cfg->auth_timeout_ms : LSSH_AUTH_TIMEOUT_DEFAULT_MS);
    serve_connection(s);
    LSSH_ASSERT(!s->ch_open && s->write_depth == 0);   /* torn down, unwound */
    if (s->k_in) (void)psa_destroy_key(s->k_in);
    if (s->k_out) (void)psa_destroy_key(s->k_out);
    (void)close(cfd);
    LOGI("connection closed");
}

int lssh_server_run(const lssh_config_t *cfg){
    if (!cfg || (!cfg->password_auth && !cfg->pubkey_auth)) return -1;
    if (psa_crypto_init() != PSA_SUCCESS) return -2;

    int lfd = cfg->listen_fd;
    bool own_lfd = false;
    /* <=0 means "create the socket": 0 is a valid fd (stdin) and the common
     * result of a zero-initialized config, never a real listening socket. */
    if (lfd <= 0){
        lfd = listen_socket(cfg);
        if (lfd < 0) return -3;
        own_lfd = true;
    }

    lssh_session_t *s = calloc(1, sizeof *s);
    if (!s){ if (own_lfd) (void)close(lfd); return -4; }

    /* one host key for the server's lifetime: with no configured key this
     * is the ephemeral key, so it changes per boot, not per connection */
    psa_key_id_t hostkey = 0; uint8_t hostkey_pub[65];
    if (hostkey_import(cfg->host_key, &hostkey, hostkey_pub)){
        free(s); if (own_lfd) (void)close(lfd); return -5;
    }
    LSSH_ASSERT(hostkey != 0 && lfd >= 0);

    LOGI("listening (%s)", LSSH_IDENT);

    int rc = 0;
    /* event loop: bounded by cfg->stop (runs for the server's lifetime) */
    while (!(cfg->stop && *cfg->stop)){
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0){
            if (errno == EINTR) continue;
            rc = -6;
            break;
        }
        serve_client(s, cfg, cfd, hostkey, hostkey_pub);
    }

    (void)psa_destroy_key(hostkey);
    wipe(s, sizeof *s);
    free(s);
    if (own_lfd) (void)close(lfd);
    return rc;
}
