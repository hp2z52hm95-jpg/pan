/*
 * util.c - strings, hashing, base64url, INI, version compare.
 * Portable C99: compiled both into PandoraLauncher.exe and into the host tests.
 */
#include "pandora.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* allocation                                                          */
/* ------------------------------------------------------------------ */

void *p_malloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) {
        fputs("Pandora Launcher: out of memory\n", stderr);
        exit(2);
    }
    return p;
}

void *p_realloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        fputs("Pandora Launcher: out of memory\n", stderr);
        exit(2);
    }
    return q;
}

char *p_strdup(const char *s)
{
    if (!s)
        return NULL;
    return p_strndup(s, strlen(s));
}

char *p_strndup(const char *s, size_t n)
{
    char *p = (char *)p_malloc(n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

char *p_asprintf(const char *fmt, ...)
{
    va_list ap;
    int n;
    char *buf;

    va_start(ap, fmt);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0)
        n = 0;
    buf = (char *)p_malloc((size_t)n + 1);
    va_start(ap, fmt);
    vsnprintf(buf, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return buf;
}

/* ------------------------------------------------------------------ */
/* string buffer                                                       */
/* ------------------------------------------------------------------ */

void sb_init(sbuf *b)
{
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
}

void sb_free(sbuf *b)
{
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

void sb_reset(sbuf *b)
{
    b->len = 0;
    if (b->p)
        b->p[0] = 0;
}

static void sb_reserve(sbuf *b, size_t extra)
{
    size_t need = b->len + extra + 1;
    if (need <= b->cap)
        return;
    if (b->cap == 0)
        b->cap = 128;
    while (b->cap < need)
        b->cap *= 2;
    b->p = (char *)p_realloc(b->p, b->cap);
}

void sb_add(sbuf *b, const char *s, size_t n)
{
    if (!s || n == 0)
        return;
    sb_reserve(b, n);
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}

void sb_adds(sbuf *b, const char *s)
{
    if (s)
        sb_add(b, s, strlen(s));
}

void sb_addc(sbuf *b, char c)
{
    sb_add(b, &c, 1);
}

void sb_addf(sbuf *b, const char *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n <= 0)
        return;
    sb_reserve(b, (size_t)n);
    va_start(ap, fmt);
    vsnprintf(b->p + b->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)n;
}

/* appends a JSON string literal (with quotes), escaping what must be escaped */
void sb_add_json_string(sbuf *b, const char *s, size_t n)
{
    size_t i;
    sb_addc(b, '"');
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  sb_adds(b, "\\\""); break;
        case '\\': sb_adds(b, "\\\\"); break;
        case '\b': sb_adds(b, "\\b");  break;
        case '\f': sb_adds(b, "\\f");  break;
        case '\n': sb_adds(b, "\\n");  break;
        case '\r': sb_adds(b, "\\r");  break;
        case '\t': sb_adds(b, "\\t");  break;
        default:
            if (c < 0x20)
                sb_addf(b, "\\u%04x", c);
            else
                sb_addc(b, (char)c);
            break;
        }
    }
    sb_addc(b, '"');
}

char *sb_take(sbuf *b)
{
    char *p = b->p ? b->p : p_strdup("");
    b->p = NULL;
    b->len = b->cap = 0;
    return p;
}

/* ------------------------------------------------------------------ */
/* small text helpers                                                  */
/* ------------------------------------------------------------------ */

int ascii_icmp(const char *a, const char *b)
{
    int ca, cb;
    if (!a)
        a = "";
    if (!b)
        b = "";
    for (;;) {
        ca = tolower((unsigned char)*a++);
        cb = tolower((unsigned char)*b++);
        if (ca != cb)
            return ca - cb;
        if (!ca)
            return 0;
    }
}

void trim_inplace(char *s)
{
    size_t n;
    char *p = s;

    if (!s)
        return;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1]))
        s[--n] = 0;
}

/* ------------------------------------------------------------------ */
/* SHA-256                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t h[8];
    uint64_t bits;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        t1 = h + S1 + ch + sha256_k[i] + w[i];
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
    c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85;
    c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
    c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c;
    c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
    c->bits = 0;
    c->buflen = 0;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t n)
{
    const uint8_t *p = (const uint8_t *)data;

    c->bits += (uint64_t)n * 8;
    while (n > 0) {
        size_t take = 64 - c->buflen;
        if (take > n)
            take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->bits;
    uint8_t pad = 0x80;
    uint8_t zero = 0;
    uint8_t len[8];
    int i;

    sha256_update(c, &pad, 1);
    while (c->buflen != 56)
        sha256_update(c, &zero, 1);
    for (i = 0; i < 8; i++)
        len[i] = (uint8_t)(bits >> (56 - i * 8));
    sha256_update(c, len, 8);
    for (i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c->h[i];
    }
}

void sha256(const void *data, size_t n, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, n);
    sha256_final(&c, out);
}

int sha256_file(const char *path, char hex[65], char *err, size_t errlen)
{
    FILE *f;
    sha256_ctx c;
    uint8_t buf[64 * 1024];
    uint8_t digest[32];
    size_t got;

    f = fs_fopen_read(path);
    if (!f) {
        if (err)
            snprintf(err, errlen, "cannot open %s", path);
        return -1;
    }
    sha256_init(&c);
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_update(&c, buf, got);
    fclose(f);
    sha256_final(&c, digest);
    hex_lower(digest, 32, hex);
    return 0;
}

void hex_lower(const uint8_t *d, size_t n, char *out)
{
    static const char *hx = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[i * 2]     = hx[d[i] >> 4];
        out[i * 2 + 1] = hx[d[i] & 15];
    }
    out[n * 2] = 0;
}

/* ------------------------------------------------------------------ */
/* CRC-32 (IEEE, as used by ZIP)                                       */
/* ------------------------------------------------------------------ */

static uint32_t crc_table[256];
static int crc_table_ready = 0;

static void crc32_init(void)
{
    uint32_t i, j, c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++)
            c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
        crc_table[i] = c;
    }
    crc_table_ready = 1;
}

uint32_t crc32_update(uint32_t crc, const void *data, size_t n)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t i;

    if (!crc_table_ready)
        crc32_init();
    crc = ~crc;
    for (i = 0; i < n; i++)
        crc = crc_table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
    return ~crc;
}

/* ------------------------------------------------------------------ */
/* base64url                                                           */
/* ------------------------------------------------------------------ */

static const char b64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

char *b64url_encode(const uint8_t *data, size_t n)
{
    size_t i, o = 0;
    char *out = (char *)p_malloc((n + 2) / 3 * 4 + 1);

    for (i = 0; i < n; i += 3) {
        size_t left = n - i;
        uint32_t v = (uint32_t)data[i] << 16;
        if (left > 1)
            v |= (uint32_t)data[i + 1] << 8;
        if (left > 2)
            v |= (uint32_t)data[i + 2];
        out[o++] = b64_chars[(v >> 18) & 63];
        out[o++] = b64_chars[(v >> 12) & 63];
        if (left > 1)
            out[o++] = b64_chars[(v >> 6) & 63];
        if (left > 2)
            out[o++] = b64_chars[v & 63];
    }
    out[o] = 0;
    return out;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

int b64url_decode(const char *s, uint8_t **out, size_t *outlen)
{
    size_t n, i, o = 0;
    uint8_t *buf;
    uint32_t acc = 0;
    int nbits = 0;

    *out = NULL;
    *outlen = 0;
    if (!s)
        return -1;
    n = strlen(s);
    buf = (uint8_t *)p_malloc(n / 4 * 3 + 4);
    for (i = 0; i < n; i++) {
        int v;
        if (s[i] == '=' || s[i] == '\n' || s[i] == '\r')
            continue;
        v = b64_val(s[i]);
        if (v < 0) {
            free(buf);
            return -1;
        }
        acc = (acc << 6) | (uint32_t)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            buf[o++] = (uint8_t)((acc >> nbits) & 0xff);
        }
    }
    *out = buf;
    *outlen = o;
    return 0;
}

/* ------------------------------------------------------------------ */
/* version compare                                                     */
/* ------------------------------------------------------------------ */

int version_compare(const char *a, const char *b)
{
    for (;;) {
        long x = 0, y = 0;
        int had_x = 0, had_y = 0;

        while (*a && !isdigit((unsigned char)*a)) a++;
        while (*b && !isdigit((unsigned char)*b)) b++;
        while (isdigit((unsigned char)*a)) { x = x * 10 + (*a - '0'); a++; had_x = 1; }
        while (isdigit((unsigned char)*b)) { y = y * 10 + (*b - '0'); b++; had_y = 1; }
        if (!had_x && !had_y)
            return 0;
        if (x < y) return -1;
        if (x > y) return 1;
        if (!*a && !*b)
            return 0;
    }
}

/* ------------------------------------------------------------------ */
/* INI                                                                 */
/* ------------------------------------------------------------------ */

char *ini_read(const char *text, const char *section, const char *key, const char *def)
{
    const char *p;
    char cur[128];
    size_t seclen = strlen(section);

    cur[0] = 0;
    if (!text)
        return p_strdup(def ? def : "");
    p = text;
    while (*p) {
        const char *eol = p;
        size_t linelen;
        char *line;

        while (*eol && *eol != '\n' && *eol != '\r')
            eol++;
        linelen = (size_t)(eol - p);
        line = p_strndup(p, linelen);
        trim_inplace(line);

        if (line[0] == ';' || line[0] == '#' || line[0] == 0) {
            free(line);
        } else if (line[0] == '[') {
            char *end = strchr(line, ']');
            if (end)
                *end = 0;
            snprintf(cur, sizeof(cur), "%s", line + 1);
            trim_inplace(cur);
            free(line);
        } else {
            char *eq = strchr(line, '=');
            if (eq) {
                char *k, *v;
                *eq = 0;
                k = line;
                v = eq + 1;
                trim_inplace(k);
                trim_inplace(v);
                if (ascii_icmp(cur, section) == 0 && ascii_icmp(k, key) == 0) {
                    /* strip surrounding quotes if present */
                    size_t vl = strlen(v);
                    if (vl >= 2 && ((v[0] == '"' && v[vl - 1] == '"') ||
                                    (v[0] == '\'' && v[vl - 1] == '\''))) {
                        v[vl - 1] = 0;
                        v++;
                    }
                    {
                        char *r = p_strdup(v);
                        free(line);
                        return r;
                    }
                }
            }
            free(line);
        }
        /* skip trailing blank lines */
        if (*eol == 0)
            break;
        while (*eol == '\n' || *eol == '\r')
            eol++;
        p = eol;
    }
    (void)seclen;
    return p_strdup(def ? def : "");
}

int ini_read_bool(const char *text, const char *section, const char *key, int def)
{
    char *v = ini_read(text, section, key, def ? "1" : "0");
    int r;
    if (ascii_icmp(v, "1") == 0 || ascii_icmp(v, "true") == 0 ||
        ascii_icmp(v, "yes") == 0 || ascii_icmp(v, "on") == 0)
        r = 1;
    else if (ascii_icmp(v, "0") == 0 || ascii_icmp(v, "false") == 0 ||
             ascii_icmp(v, "no") == 0 || ascii_icmp(v, "off") == 0)
        r = 0;
    else
        r = def;
    free(v);
    return r;
}
