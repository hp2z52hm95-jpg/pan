/*
 * util.c - portable helpers for the Pandora Launcher (see util.h).
 * Plain C99, no third-party code, no Windows dependencies.
 */

#include "util.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
/* On Windows all util.c paths are UTF-8; fopen()/mkdir() are ANSI-only.
 * Route them through the wide APIs so non-ASCII install paths work. */
static FILE *u_fopen(const char *utf8_path, const char *mode)
{
    wchar_t wpath[32768], wmode[16];
    if (!utf8_path || MultiByteToWideChar(CP_UTF8, 0, utf8_path, -1, wpath, 32768) == 0)
        return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 16) == 0)
        return NULL;
    return _wfopen(wpath, wmode);
}
#define fopen(p, m) u_fopen((p), (m))
static int u_mkdir(const char *utf8_path)
{
    wchar_t wpath[32768];
    if (MultiByteToWideChar(CP_UTF8, 0, utf8_path, -1, wpath, 32768) == 0)
        return -1;
    return _wmkdir(wpath) == 0 ? 0 : -1;
}
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

/* ================================================================== */
/* byte buffer                                                        */
/* ================================================================== */

void buf_init(buf_t *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void buf_free(buf_t *b)
{
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

void buf_clear(buf_t *b)
{
    b->len = 0;
}

int buf_reserve(buf_t *b, size_t extra)
{
    size_t need = b->len + extra + 1; /* +1 keeps room for NUL */
    size_t cap;
    unsigned char *p;

    if (need <= b->cap)
        return 0;
    cap = b->cap ? b->cap : 256;
    while (cap < need) {
        if (cap > (size_t)-1 / 2)
            return -1;
        cap *= 2;
    }
    p = (unsigned char *)realloc(b->data, cap);
    if (!p)
        return -1;
    b->data = p;
    b->cap = cap;
    return 0;
}

int buf_append(buf_t *b, const void *data, size_t len)
{
    if (len == 0)
        return 0;
    if (buf_reserve(b, len) != 0)
        return -1;
    memcpy(b->data + b->len, data, len);
    b->len += len;
    b->data[b->len] = 0;
    return 0;
}

int buf_append_str(buf_t *b, const char *s)
{
    return s ? buf_append(b, s, strlen(s)) : 0;
}

int buf_append_byte(buf_t *b, unsigned char c)
{
    return buf_append(b, &c, 1);
}

int buf_printf(buf_t *b, const char *fmt, ...)
{
    char stack[512];
    va_list ap;
    int n;
    char *heap = NULL;

    va_start(ap, fmt);
    n = vsnprintf(stack, sizeof(stack), fmt, ap);
    va_end(ap);
    if (n < 0)
        return -1;
    if ((size_t)n < sizeof(stack))
        return buf_append(b, stack, (size_t)n);

    heap = (char *)malloc((size_t)n + 1);
    if (!heap)
        return -1;
    va_start(ap, fmt);
    vsnprintf(heap, (size_t)n + 1, fmt, ap);
    va_end(ap);
    n = buf_append(b, heap, (size_t)n);
    free(heap);
    return n;
}

char *buf_cstr(buf_t *b)
{
    if (!b->data)
        return NULL;
    b->data[b->len] = 0;
    return (char *)b->data;
}

/* ================================================================== */
/* base64url                                                          */
/* ================================================================== */

static const char B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

char *b64u_encode(const unsigned char *data, size_t len)
{
    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char *out = (char *)malloc(out_len);
    size_t i = 0, o = 0;

    if (!out)
        return NULL;
    while (i + 3 <= len) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) |
                     (uint32_t)data[i + 2];
        out[o++] = B64_ALPHABET[(v >> 18) & 63];
        out[o++] = B64_ALPHABET[(v >> 12) & 63];
        out[o++] = B64_ALPHABET[(v >> 6) & 63];
        out[o++] = B64_ALPHABET[v & 63];
        i += 3;
    }
    if (len - i == 1) {
        uint32_t v = (uint32_t)data[i] << 16;
        out[o++] = B64_ALPHABET[(v >> 18) & 63];
        out[o++] = B64_ALPHABET[(v >> 12) & 63];
    } else if (len - i == 2) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8);
        out[o++] = B64_ALPHABET[(v >> 18) & 63];
        out[o++] = B64_ALPHABET[(v >> 12) & 63];
        out[o++] = B64_ALPHABET[(v >> 6) & 63];
    }
    out[o] = 0;
    return out;
}

static int b64_value(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '-' || c == '+')
        return 62;
    if (c == '_' || c == '/')
        return 63;
    return -1;
}

unsigned char *b64u_decode(const char *s, size_t *out_len)
{
    size_t len, i = 0, o = 0;
    unsigned char *out;
    uint32_t acc = 0;
    int bits = 0;

    if (out_len)
        *out_len = 0;
    if (!s)
        return NULL;
    len = strlen(s);
    out = (unsigned char *)malloc((len / 4 + 1) * 3 + 3);
    if (!out)
        return NULL;
    while (i < len) {
        int c = (unsigned char)s[i];
        int v;
        if (c == '=')
            break;
        v = b64_value(c);
        if (v < 0) { /* skip whitespace, reject nothing else */
            if (isspace(c)) {
                i++;
                continue;
            }
            free(out);
            return NULL;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char)((acc >> bits) & 0xFF);
        }
        i++;
    }
    if (out_len)
        *out_len = o;
    return out;
}

/* ================================================================== */
/* SHA-256                                                            */
/* ================================================================== */

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *ctx, const unsigned char *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(w[i - 15], 7) ^ ROTR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR32(w[i - 2], 17) ^ ROTR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t1 = h + S1 + ch + SHA256_K[i] + w[i];
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(sha256_ctx *ctx)
{
    static const uint32_t init[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    memcpy(ctx->state, init, sizeof(init));
    ctx->bitlen = 0;
    ctx->block_len = 0;
}

void sha256_update(sha256_ctx *ctx, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;

    ctx->bitlen += (uint64_t)len * 8;
    if (ctx->block_len) {
        size_t need = 64 - ctx->block_len;
        if (len < need) {
            memcpy(ctx->block + ctx->block_len, p, len);
            ctx->block_len += len;
            return;
        }
        memcpy(ctx->block + ctx->block_len, p, need);
        sha256_block(ctx, ctx->block);
        p += need;
        len -= need;
        ctx->block_len = 0;
    }
    while (len >= 64) {
        sha256_block(ctx, p);
        p += 64;
        len -= 64;
    }
    if (len) {
        memcpy(ctx->block, p, len);
        ctx->block_len = len;
    }
}

void sha256_final(sha256_ctx *ctx, unsigned char out[32])
{
    unsigned char pad[72];
    size_t padlen;
    uint64_t bits = ctx->bitlen;
    int i;

    padlen = (ctx->block_len < 56) ? (56 - ctx->block_len) : (120 - ctx->block_len);
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    for (i = 0; i < 8; i++)
        pad[padlen + i] = (unsigned char)(bits >> (56 - i * 8));
    sha256_update(ctx, pad, padlen + 8);

    for (i = 0; i < 8; i++) {
        out[i * 4] = (unsigned char)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(ctx->state[i]);
    }
}

void sha256(const void *data, size_t len, unsigned char out[32])
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

char *sha256_hex(const unsigned char digest[32])
{
    static const char hexd[] = "0123456789abcdef";
    char *out = (char *)malloc(65);
    int i;

    if (!out)
        return NULL;
    for (i = 0; i < 32; i++) {
        out[i * 2] = hexd[digest[i] >> 4];
        out[i * 2 + 1] = hexd[digest[i] & 15];
    }
    out[64] = 0;
    return out;
}

char *sha256_file_hex(const char *path)
{
    FILE *f = fopen(path, "rb");
    unsigned char chunk[64 * 1024];
    unsigned char digest[32];
    sha256_ctx ctx;
    size_t n;

    if (!f)
        return NULL;
    sha256_init(&ctx);
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
        sha256_update(&ctx, chunk, n);
    if (ferror(f)) {
        fclose(f);
        return NULL;
    }
    fclose(f);
    sha256_final(&ctx, digest);
    return sha256_hex(digest);
}

uint32_t crc32_buf(const void *data, size_t len, uint32_t crc)
{
    static uint32_t table[256];
    static int ready = 0;
    const unsigned char *p = (const unsigned char *)data;
    size_t i;

    if (!ready) {
        uint32_t c;
        int n, k;
        for (n = 0; n < 256; n++) {
            c = (uint32_t)n;
            for (k = 0; k < 8; k++)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[n] = c;
        }
        ready = 1;
    }
    crc = crc ^ 0xFFFFFFFFu;
    for (i = 0; i < len; i++)
        crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* ================================================================== */
/* JSON                                                               */
/* ================================================================== */

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } json_type;

struct json {
    json_type type;
    double num;
    int boolean;
    char *str;          /* J_STR */
    struct json **items; /* J_ARR / J_OBJ values */
    char **keys;         /* J_OBJ keys */
    size_t count;
};

typedef struct {
    const char *p;
    const char *end;
    int depth;
} jparser;

#define JSON_MAX_DEPTH 64

static void json_skip_ws(jparser *j)
{
    while (j->p < j->end &&
           (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r'))
        j->p++;
}

static struct json *json_parse_value(jparser *j);

static struct json *json_new(json_type t)
{
    struct json *v = (struct json *)calloc(1, sizeof(struct json));
    if (v)
        v->type = t;
    return v;
}

void json_free(json_t *v)
{
    size_t i;

    if (!v)
        return;
    if (v->type == J_STR)
        free(v->str);
    if (v->type == J_OBJ) {
        for (i = 0; i < v->count; i++)
            free(v->keys[i]);
        free(v->keys);
    }
    if (v->type == J_ARR || v->type == J_OBJ) {
        for (i = 0; i < v->count; i++)
            json_free(v->items[i]);
        free(v->items);
    }
    free(v);
}

static int hex4(const char *p, unsigned *out)
{
    unsigned v = 0;
    int i;
    for (i = 0; i < 4; i++) {
        int c = (unsigned char)p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

static void utf8_append(buf_t *b, unsigned cp)
{
    if (cp < 0x80) {
        buf_append_byte(b, (unsigned char)cp);
    } else if (cp < 0x800) {
        buf_append_byte(b, (unsigned char)(0xC0 | (cp >> 6)));
        buf_append_byte(b, (unsigned char)(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        buf_append_byte(b, (unsigned char)(0xE0 | (cp >> 12)));
        buf_append_byte(b, (unsigned char)(0x80 | ((cp >> 6) & 0x3F)));
        buf_append_byte(b, (unsigned char)(0x80 | (cp & 0x3F)));
    } else {
        buf_append_byte(b, (unsigned char)(0xF0 | (cp >> 18)));
        buf_append_byte(b, (unsigned char)(0x80 | ((cp >> 12) & 0x3F)));
        buf_append_byte(b, (unsigned char)(0x80 | ((cp >> 6) & 0x3F)));
        buf_append_byte(b, (unsigned char)(0x80 | (cp & 0x3F)));
    }
}

static char *json_parse_string(jparser *j)
{
    buf_t b;
    char *out;

    if (j->p >= j->end || *j->p != '"')
        return NULL;
    j->p++;
    buf_init(&b);
    while (j->p < j->end) {
        unsigned char c = (unsigned char)*j->p++;
        if (c == '"') {
            if (buf_reserve(&b, 1) != 0) {
                buf_free(&b);
                return NULL;
            }
            out = (char *)b.data;
            out[b.len] = 0;
            return out;
        }
        if (c == '\\') {
            if (j->p >= j->end)
                break;
            c = (unsigned char)*j->p++;
            switch (c) {
            case '"': buf_append_byte(&b, '"'); break;
            case '\\': buf_append_byte(&b, '\\'); break;
            case '/': buf_append_byte(&b, '/'); break;
            case 'b': buf_append_byte(&b, '\b'); break;
            case 'f': buf_append_byte(&b, '\f'); break;
            case 'n': buf_append_byte(&b, '\n'); break;
            case 'r': buf_append_byte(&b, '\r'); break;
            case 't': buf_append_byte(&b, '\t'); break;
            case 'u': {
                unsigned cp;
                if (j->end - j->p < 4 || hex4(j->p, &cp) != 0) {
                    buf_free(&b);
                    return NULL;
                }
                j->p += 4;
                if (cp >= 0xD800 && cp <= 0xDBFF && j->end - j->p >= 6 &&
                    j->p[0] == '\\' && j->p[1] == 'u') {
                    unsigned lo;
                    if (hex4(j->p + 2, &lo) == 0 && lo >= 0xDC00 && lo <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        j->p += 6;
                    }
                }
                utf8_append(&b, cp);
                break;
            }
            default:
                buf_free(&b);
                return NULL;
            }
            continue;
        }
        buf_append_byte(&b, c);
    }
    buf_free(&b);
    return NULL;
}

static struct json *json_parse_array(jparser *j)
{
    struct json *arr;

    j->p++; /* '[' */
    arr = json_new(J_ARR);
    if (!arr)
        return NULL;
    json_skip_ws(j);
    if (j->p < j->end && *j->p == ']') {
        j->p++;
        return arr;
    }
    for (;;) {
        struct json *item;
        struct json **grown;

        item = json_parse_value(j);
        if (!item) {
            json_free(arr);
            return NULL;
        }
        grown = (struct json **)realloc(arr->items,
                                        (arr->count + 1) * sizeof(*arr->items));
        if (!grown) {
            json_free(item);
            json_free(arr);
            return NULL;
        }
        arr->items = grown;
        arr->items[arr->count++] = item;

        json_skip_ws(j);
        if (j->p < j->end && *j->p == ',') {
            j->p++;
            json_skip_ws(j);
            continue;
        }
        if (j->p < j->end && *j->p == ']') {
            j->p++;
            return arr;
        }
        json_free(arr);
        return NULL;
    }
}

static struct json *json_parse_object(jparser *j)
{
    struct json *obj;

    j->p++; /* '{' */
    obj = json_new(J_OBJ);
    if (!obj)
        return NULL;
    json_skip_ws(j);
    if (j->p < j->end && *j->p == '}') {
        j->p++;
        return obj;
    }
    for (;;) {
        char *key;
        struct json *val;
        struct json **items;
        char **keys;

        json_skip_ws(j);
        key = json_parse_string(j);
        if (!key) {
            json_free(obj);
            return NULL;
        }
        json_skip_ws(j);
        if (j->p >= j->end || *j->p != ':') {
            free(key);
            json_free(obj);
            return NULL;
        }
        j->p++;
        val = json_parse_value(j);
        if (!val) {
            free(key);
            json_free(obj);
            return NULL;
        }
        items = (struct json **)realloc(obj->items,
                                        (obj->count + 1) * sizeof(*items));
        keys = (char **)realloc(obj->keys, (obj->count + 1) * sizeof(*keys));
        if (!items || !keys) {
            free(key);
            json_free(val);
            json_free(obj);
            return NULL;
        }
        obj->items = items;
        obj->keys = keys;
        obj->keys[obj->count] = key;
        obj->items[obj->count] = val;
        obj->count++;

        json_skip_ws(j);
        if (j->p < j->end && *j->p == ',') {
            j->p++;
            continue;
        }
        if (j->p < j->end && *j->p == '}') {
            j->p++;
            return obj;
        }
        json_free(obj);
        return NULL;
    }
}

static struct json *json_parse_value(jparser *j)
{
    struct json *v;

    if (j->depth >= JSON_MAX_DEPTH)
        return NULL;
    json_skip_ws(j);
    if (j->p >= j->end)
        return NULL;

    switch (*j->p) {
    case '{':
        j->depth++;
        v = json_parse_object(j);
        j->depth--;
        return v;
    case '[':
        j->depth++;
        v = json_parse_array(j);
        j->depth--;
        return v;
    case '"': {
        char *s = json_parse_string(j);
        if (!s)
            return NULL;
        v = json_new(J_STR);
        if (!v) {
            free(s);
            return NULL;
        }
        v->str = s;
        return v;
    }
    case 't':
        if (j->end - j->p >= 4 && memcmp(j->p, "true", 4) == 0) {
            j->p += 4;
            v = json_new(J_BOOL);
            if (v)
                v->boolean = 1;
            return v;
        }
        return NULL;
    case 'f':
        if (j->end - j->p >= 5 && memcmp(j->p, "false", 5) == 0) {
            j->p += 5;
            return json_new(J_BOOL);
        }
        return NULL;
    case 'n':
        if (j->end - j->p >= 4 && memcmp(j->p, "null", 4) == 0) {
            j->p += 4;
            return json_new(J_NULL);
        }
        return NULL;
    default: {
        char numbuf[64];
        size_t n = 0;
        char *endp = NULL;
        if (*j->p == '-' || *j->p == '+' || (*j->p >= '0' && *j->p <= '9')) {
            while (j->p < j->end && n < sizeof(numbuf) - 1 &&
                   (isdigit((unsigned char)*j->p) || *j->p == '-' || *j->p == '+' ||
                    *j->p == '.' || *j->p == 'e' || *j->p == 'E'))
                numbuf[n++] = *j->p++;
            numbuf[n] = 0;
            v = json_new(J_NUM);
            if (!v)
                return NULL;
            v->num = strtod(numbuf, &endp);
            if (endp == numbuf) {
                json_free(v);
                return NULL;
            }
            return v;
        }
        return NULL;
    }
    }
}

json_t *json_parse(const char *text, size_t len)
{
    jparser j;
    struct json *v;

    if (!text)
        return NULL;
    j.p = text;
    j.end = text + len;
    j.depth = 0;
    v = json_parse_value(&j);
    if (!v)
        return NULL;
    json_skip_ws(&j);
    /* Trailing garbage (except whitespace) invalidates the document. */
    if (j.p != j.end) {
        json_free(v);
        return NULL;
    }
    return v;
}

/* --- path lookups ------------------------------------------------- */

static const struct json *json_lookup(const json_t *v, const char *path)
{
    const char *p = path;

    if (!v || !path || !*path)
        return v;
    while (*p) {
        if (*p == '.') {
            p++;
            continue;
        }
        if (*p == '[') {
            char *endp = NULL;
            long idx = strtol(p + 1, &endp, 10);
            if (!endp || *endp != ']' || v->type != J_ARR)
                return NULL;
            if (idx < 0 || (size_t)idx >= v->count)
                return NULL;
            v = v->items[idx];
            p = endp + 1;
            continue;
        }
        if (v->type != J_OBJ)
            return NULL;
        {
            const char *start = p;
            size_t klen;
            size_t i;
            const struct json *next = NULL;
            while (*p && *p != '.' && *p != '[')
                p++;
            klen = (size_t)(p - start);
            for (i = 0; i < v->count; i++) {
                if (strlen(v->keys[i]) == klen && strncmp(v->keys[i], start, klen) == 0) {
                    next = v->items[i];
                    break;
                }
            }
            if (!next)
                return NULL;
            v = next;
        }
    }
    return v;
}

const char *json_str(const json_t *v, const char *path, const char *def)
{
    const struct json *r = json_lookup(v, path);
    if (!r)
        return def;
    if (r->type == J_STR)
        return r->str;
    if (r->type == J_NUM || r->type == J_BOOL)
        return NULL; /* wrong type: caller gets default via helper below */
    return def;
}

long long json_int(const json_t *v, const char *path, long long def)
{
    const struct json *r = json_lookup(v, path);
    if (!r)
        return def;
    if (r->type == J_NUM)
        return (long long)r->num;
    if (r->type == J_STR && r->str && *r->str)
        return strtoll(r->str, NULL, 10);
    if (r->type == J_BOOL)
        return r->boolean;
    return def;
}

double json_num(const json_t *v, const char *path, double def)
{
    const struct json *r = json_lookup(v, path);
    if (!r)
        return def;
    if (r->type == J_NUM)
        return r->num;
    if (r->type == J_STR && r->str)
        return strtod(r->str, NULL);
    if (r->type == J_BOOL)
        return r->boolean ? 1 : 0;
    return def;
}

int json_bool(const json_t *v, const char *path, int def)
{
    const struct json *r = json_lookup(v, path);
    if (!r)
        return def;
    if (r->type == J_BOOL)
        return r->boolean;
    if (r->type == J_NUM)
        return r->num != 0;
    if (r->type == J_STR && r->str)
        return (strcmp(r->str, "true") == 0) || (strcmp(r->str, "1") == 0);
    return def;
}

size_t json_count(const json_t *v, const char *path)
{
    const struct json *r = json_lookup(v, path);
    return (r && r->type == J_ARR) ? r->count : 0;
}

int json_has(const json_t *v, const char *path)
{
    return json_lookup(v, path) != NULL;
}

/* ================================================================== */
/* inflate (deflate decompression) - classic Mark Adler "puff" logic   */
/* ================================================================== */

typedef struct {
    const unsigned char *in;
    size_t in_len;
    size_t in_pos;
    uint32_t bitbuf;
    int bitcnt;
    buf_t *out;
} inflate_state;

static int inf_bits(inflate_state *s, int need, unsigned *out)
{
    while (s->bitcnt < need) {
        if (s->in_pos >= s->in_len)
            return -1;
        s->bitbuf |= (uint32_t)s->in[s->in_pos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    *out = s->bitbuf & ((1u << need) - 1);
    s->bitbuf >>= need;
    s->bitcnt -= need;
    return 0;
}

typedef struct {
    short *count;  /* number of symbols of each length */
    short *symbol; /* canonically ordered symbols */
} huffman;

static int huff_build(huffman *h, const short *lengths, int n)
{
    int len, left, offs[16], i;

    for (i = 0; i < 16; i++)
        h->count[i] = 0;
    for (i = 0; i < n; i++)
        h->count[lengths[i]]++;
    if (h->count[0] == n)
        return 0; /* complete code is empty */
    left = 1;
    for (len = 1; len < 16; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0)
            return -1; /* over-subscribed */
    }
    offs[1] = 0;
    for (len = 1; len < 15; len++)
        offs[len + 1] = offs[len] + h->count[len];
    for (i = 0; i < n; i++)
        if (lengths[i])
            h->symbol[offs[lengths[i]]++] = (short)i;
    return left; /* 0 = complete, >0 = incomplete */
}

static int huff_decode(inflate_state *s, const huffman *h, int *out)
{
    int len, code = 0, first = 0, index = 0, count;
    unsigned bits;

    for (len = 1; len <= 15; len++) {
        if (inf_bits(s, 1, &bits) != 0)
            return -1;
        code |= (int)bits;
        count = h->count[len];
        if (code - count < first) {
            *out = h->symbol[index + (code - first)];
            return 0;
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

static const short LEN_BASE[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67,
    83, 99, 115, 131, 163, 195, 227, 258
};
static const short LEN_EXTRA[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5,
    5, 5, 5, 0
};
static const short DIST_BASE[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
    769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};
static const short DIST_EXTRA[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
    11, 11, 12, 12, 13, 13
};

static int inf_codes(inflate_state *s, const huffman *lencode,
                     const huffman *distcode)
{
    int symbol;
    unsigned bits;
    int i;

    for (;;) {
        if (huff_decode(s, lencode, &symbol) != 0)
            return -1;
        if (symbol < 256) {
            if (buf_append_byte(s->out, (unsigned char)symbol) != 0)
                return -1;
        } else if (symbol == 256) {
            return 0;
        } else {
            int len, dist;
            unsigned extra;
            int base, extra_bits;

            symbol -= 257;
            if (symbol >= 29)
                return -1;
            if (inf_bits(s, LEN_EXTRA[symbol], &bits) != 0)
                return -1;
            len = LEN_BASE[symbol] + (int)bits;
            if (huff_decode(s, distcode, &dist) != 0)
                return -1;
            if (dist >= 30)
                return -1;
            extra = 0;
            base = DIST_BASE[dist];
            extra_bits = DIST_EXTRA[dist];
            if (extra_bits && inf_bits(s, extra_bits, &extra) != 0)
                return -1;
            {
                size_t from = s->out->len - (size_t)(base + (int)extra);
                if ((base + (int)extra) > (int)s->out->len)
                    return -1; /* distance too far back */
                for (i = 0; i < len; i++) {
                    unsigned char c = s->out->data[from + (size_t)i];
                    if (buf_append_byte(s->out, c) != 0)
                        return -1;
                }
            }
        }
    }
}

static int inf_stored(inflate_state *s)
{
    unsigned len, nlen;
    s->bitbuf = 0;
    s->bitcnt = 0;
    if (s->in_pos + 4 > s->in_len)
        return -1;
    len = (unsigned)s->in[s->in_pos] | ((unsigned)s->in[s->in_pos + 1] << 8);
    nlen = (unsigned)s->in[s->in_pos + 2] | ((unsigned)s->in[s->in_pos + 3] << 8);
    s->in_pos += 4;
    if ((len ^ 0xFFFFu) != nlen)
        return -1;
    if (s->in_pos + len > s->in_len)
        return -1;
    if (buf_append(s->out, s->in + s->in_pos, len) != 0)
        return -1;
    s->in_pos += len;
    return 0;
}

static int inf_fixed(inflate_state *s)
{
    huffman lencode, distcode;
    short lengths[320];
    int i;

    for (i = 0; i < 144; i++) lengths[i] = 8;
    for (; i < 256; i++) lengths[i] = 9;
    for (; i < 280; i++) lengths[i] = 7;
    for (; i < 288; i++) lengths[i] = 8;
    lencode.count = (short *)calloc(16, sizeof(short));
    lencode.symbol = (short *)calloc(288, sizeof(short));
    distcode.count = (short *)calloc(16, sizeof(short));
    distcode.symbol = (short *)calloc(30, sizeof(short));
    if (!lencode.count || !lencode.symbol || !distcode.count || !distcode.symbol) {
        free(lencode.count); free(lencode.symbol);
        free(distcode.count); free(distcode.symbol);
        return -1;
    }
    huff_build(&lencode, lengths, 288);
    for (i = 0; i < 30; i++) lengths[i] = 5;
    huff_build(&distcode, lengths, 30);
    i = inf_codes(s, &lencode, &distcode);
    free(lencode.count); free(lencode.symbol);
    free(distcode.count); free(distcode.symbol);
    return i;
}

static int inf_dynamic(inflate_state *s)
{
    static const short ORDER[19] = {
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
    };
    int nlen, ndist, ncode, i, result = -1;
    unsigned bits;
    short lengths[320];
    huffman lencode, distcode;

    lencode.count = (short *)calloc(16, sizeof(short));
    lencode.symbol = (short *)calloc(288, sizeof(short));
    distcode.count = (short *)calloc(16, sizeof(short));
    distcode.symbol = (short *)calloc(30, sizeof(short));
    if (!lencode.count || !lencode.symbol || !distcode.count || !distcode.symbol)
        goto done;

    if (inf_bits(s, 5, &bits) != 0) goto done;
    nlen = (int)bits + 257;
    if (inf_bits(s, 5, &bits) != 0) goto done;
    ndist = (int)bits + 1;
    if (inf_bits(s, 4, &bits) != 0) goto done;
    ncode = (int)bits + 4;
    if (nlen > 286 || ndist > 30)
        goto done;

    for (i = 0; i < 19; i++) lengths[i] = 0;
    for (i = 0; i < ncode; i++) {
        if (inf_bits(s, 3, &bits) != 0) goto done;
        lengths[ORDER[i]] = (short)bits;
    }
    if (huff_build(&lencode, lengths, 19) != 0)
        goto done; /* code-length code must be complete */

    i = 0;
    while (i < nlen + ndist) {
        int symbol;
        if (huff_decode(s, &lencode, &symbol) != 0) goto done;
        if (symbol < 16) {
            lengths[i++] = (short)symbol;
        } else {
            int len = 0, rep;
            if (symbol == 16) {
                if (i == 0) goto done;
                len = lengths[i - 1];
                if (inf_bits(s, 2, &bits) != 0) goto done;
                rep = 3 + (int)bits;
            } else if (symbol == 17) {
                if (inf_bits(s, 3, &bits) != 0) goto done;
                rep = 3 + (int)bits;
            } else {
                if (inf_bits(s, 7, &bits) != 0) goto done;
                rep = 11 + (int)bits;
            }
            if (i + rep > nlen + ndist)
                goto done;
            while (rep--)
                lengths[i++] = (short)len;
        }
    }
    if (lengths[256] == 0)
        goto done; /* no end-of-block code */

    if (huff_build(&lencode, lengths, nlen) != 0)
        goto done;
    if (huff_build(&distcode, lengths + nlen, ndist) != 0)
        goto done; /* distances may be incomplete (single distance) */

    result = inf_codes(s, &lencode, &distcode);

done:
    free(lencode.count); free(lencode.symbol);
    free(distcode.count); free(distcode.symbol);
    return result;
}

int inflate_raw(const unsigned char *in, size_t in_len, buf_t *out)
{
    inflate_state s;
    int last, type;

    s.in = in;
    s.in_len = in_len;
    s.in_pos = 0;
    s.bitbuf = 0;
    s.bitcnt = 0;
    s.out = out;

    do {
        unsigned bits;
        if (inf_bits(&s, 1, &bits) != 0)
            return -1;
        last = (int)bits;
        if (inf_bits(&s, 2, &bits) != 0)
            return -1;
        type = (int)bits;
        if (type == 0) {
            if (inf_stored(&s) != 0)
                return -1;
        } else if (type == 1) {
            if (inf_fixed(&s) != 0)
                return -1;
        } else if (type == 2) {
            if (inf_dynamic(&s) != 0)
                return -1;
        } else {
            return -1;
        }
    } while (!last);
    return 0;
}

/* ================================================================== */
/* ZIP                                                                */
/* ================================================================== */

static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint16_t rd16(const unsigned char *p)
{
    return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

void zip_free(zip_entry *entries, size_t count)
{
    size_t i;
    if (!entries)
        return;
    for (i = 0; i < count; i++)
        free(entries[i].name);
    free(entries);
}

int zip_list(const char *zip_path, zip_entry **out_entries, size_t *out_count)
{
    FILE *f;
    long fsize;
    unsigned char *cd = NULL;
    size_t cd_size = 0;
    uint64_t cd_offset;
    size_t n, i;
    zip_entry *entries = NULL;
    int rc = -1;

    *out_entries = NULL;
    *out_count = 0;

    f = fopen(zip_path, "rb");
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    fsize = ftell(f);
    if (fsize < 22) {
        fclose(f);
        return -1;
    }

    /* Find End Of Central Directory: scan back over an optional comment. */
    {
        size_t max_back = (size_t)fsize < 65557 ? (size_t)fsize : 65557;
        unsigned char *tail = (unsigned char *)malloc(max_back);
        long pos;
        int found = 0;
        uint32_t cd_count, cd_size32, cd_off32;

        if (!tail) {
            fclose(f);
            return -1;
        }
        if (fseek(f, fsize - (long)max_back, SEEK_SET) != 0) {
            free(tail);
            fclose(f);
            return -1;
        }
        if (fread(tail, 1, max_back, f) != max_back) {
            free(tail);
            fclose(f);
            return -1;
        }
        for (pos = (long)max_back - 22; pos >= 0; pos--) {
            if (rd32(tail + pos) == 0x06054b50u) {
                cd_count = rd16(tail + pos + 10);
                cd_size32 = rd32(tail + pos + 12);
                cd_off32 = rd32(tail + pos + 16);
                if (cd_count == 0xFFFFu || cd_size32 == 0xFFFFFFFFu ||
                    cd_off32 == 0xFFFFFFFFu) {
                    free(tail);
                    fclose(f);
                    return -1; /* ZIP64 archives are not supported */
                }
                cd_size = cd_size32;
                cd_offset = cd_off32;
                n = cd_count;
                found = 1;
                break;
            }
        }
        free(tail);
        if (!found) {
            fclose(f);
            return -1;
        }
    }

    if (cd_size == 0 || (uint64_t)fsize < cd_offset + cd_size) {
        fclose(f);
        return -1;
    }
    cd = (unsigned char *)malloc(cd_size);
    if (!cd) {
        fclose(f);
        return -1;
    }
    if (fseek(f, (long)cd_offset, SEEK_SET) != 0 ||
        fread(cd, 1, cd_size, f) != cd_size)
        goto done;

    entries = (zip_entry *)calloc(n ? n : 1, sizeof(zip_entry));
    if (!entries)
        goto done;

    {
        size_t p = 0;
        for (i = 0; i < n; i++) {
            uint16_t name_len, extra_len, comment_len, method, flags;
            uint32_t crc, csize, usize, off;
            char *name;

            if (p + 46 > cd_size || rd32(cd + p) != 0x02014b50u)
                goto done;
            flags = rd16(cd + p + 8);
            method = rd16(cd + p + 10);
            crc = rd32(cd + p + 16);
            csize = rd32(cd + p + 20);
            usize = rd32(cd + p + 24);
            name_len = rd16(cd + p + 28);
            extra_len = rd16(cd + p + 30);
            comment_len = rd16(cd + p + 32);
            off = rd32(cd + p + 42);
            if (p + 46 + name_len + extra_len + comment_len > cd_size)
                goto done;
            if (csize == 0xFFFFFFFFu || usize == 0xFFFFFFFFu || off == 0xFFFFFFFFu)
                goto done; /* ZIP64 */
            name = (char *)malloc((size_t)name_len + 1);
            if (!name)
                goto done;
            memcpy(name, cd + p + 46, name_len);
            name[name_len] = 0;
            {
                size_t k;
                for (k = 0; k < name_len; k++)
                    if (name[k] == '\\')
                        name[k] = '/';
            }
            entries[i].name = name;
            entries[i].method = method;
            entries[i].crc = crc;
            entries[i].csize = csize;
            entries[i].usize = usize;
            entries[i].offset = off;
            (void)flags;
            p += 46 + (size_t)name_len + extra_len + comment_len;
        }
    }

    *out_entries = entries;
    *out_count = n;
    entries = NULL;
    rc = 0;

done:
    free(cd);
    zip_free(entries, n);
    fclose(f);
    return rc;
}

int path_is_safe_relative(const char *name)
{
    const char *p;

    if (!name || !*name)
        return -1;
    if (name[0] == '/' || name[0] == '\\')
        return -1;
    if (isalpha((unsigned char)name[0]) && name[1] == ':')
        return -1;
    for (p = name; *p;) {
        if (p[0] == '.' && p[1] == '.' &&
            (p[2] == '/' || p[2] == '\\' || p[2] == 0))
            return -1;
        p++;
    }
    {
        size_t len = strlen(name);
        if (len >= 1 && (name[len - 1] == '/' || name[len - 1] == '\\'))
            return -1; /* directory entry - callers skip these */
    }
    return 0;
}

char *path_join(const char *dir, const char *name)
{
    size_t dl = dir ? strlen(dir) : 0;
    size_t nl = name ? strlen(name) : 0;
    int needs_sep = (dl > 0 && dir[dl - 1] != '/' && dir[dl - 1] != '\\');
    char *out = (char *)malloc(dl + nl + 2);

    if (!out)
        return NULL;
    if (dl)
        memcpy(out, dir, dl);
    if (needs_sep)
        out[dl++] = '/';
    if (nl)
        memcpy(out + dl, name, nl);
    out[dl + nl] = 0;
    return out;
}

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p)
        memcpy(p, s, n);
    return p;
}

static int mkdir_one(const char *path)
{
#ifdef _WIN32
    return u_mkdir(path);
#else
    return mkdir(path, 0777) == 0 ? 0 : -1;
#endif
}

static int mkdir_p(const char *path)
{
    char *tmp = (char *)malloc(strlen(path) + 1);
    char *p;
    int rc = -1;

    if (!tmp)
        return -1;
    strcpy(tmp, path);
    for (p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char save = *p;
            *p = 0;
            {
                /* Ignore "already exists" (ENOTDIR/EEXIST handled by caller). */
                mkdir_one(tmp);
            }
            *p = save;
        }
    }
    rc = mkdir_one(tmp);
    free(tmp);
    return rc;
}

int zip_extract_entry(const char *zip_path, const zip_entry *e,
                      const char *dest_path)
{
    FILE *f;
    unsigned char lh[30];
    unsigned char *comp = NULL;
    buf_t plain;
    uint16_t name_len, extra_len;
    char *dir = NULL;
    FILE *out;
    int rc = -1;

    buf_init(&plain);
    f = fopen(zip_path, "rb");
    if (!f)
        return -1;
    if (fseek(f, (long)e->offset, SEEK_SET) != 0)
        goto done;
    if (fread(lh, 1, 30, f) != 30 || rd32(lh) != 0x04034b50u)
        goto done;
    name_len = rd16(lh + 26);
    extra_len = rd16(lh + 28);
    if (fseek(f, (long)e->offset + 30 + name_len + extra_len, SEEK_SET) != 0)
        goto done;

    if (e->usize > ((uint64_t)1 << 32) || e->csize > ((uint64_t)1 << 32))
        goto done; /* sanity limit: 4 GiB */

    if (e->method != 0 && e->method != 8) {
        rc = -2; /* unsupported compression method */
        goto done;
    }
    if (e->csize > 0) {
        comp = (unsigned char *)malloc((size_t)e->csize);
        if (!comp)
            goto done;
        if (fread(comp, 1, (size_t)e->csize, f) != (size_t)e->csize)
            goto done;
    }

    if (e->method == 0) {
        if (buf_append(&plain, comp, (size_t)e->csize) != 0)
            goto done;
    } else {
        if (inflate_raw(comp, (size_t)e->csize, &plain) != 0)
            goto done;
    }

    if (plain.len != (size_t)e->usize)
        goto done;
    if (crc32_buf(plain.data, plain.len, CRC32_INIT) != e->crc)
        goto done;

    dir = xstrdup(dest_path);
    if (!dir)
        goto done;
    {
        char *slash = strrchr(dir, '/');
#ifdef _WIN32
        char *bslash = strrchr(dir, '\\');
        if (bslash && (!slash || bslash > slash))
            slash = bslash;
#endif
        if (slash) {
            *slash = 0;
            if (*dir)
                mkdir_p(dir);
        }
    }

    out = fopen(dest_path, "wb");
    if (!out)
        goto done;
    if (plain.len && fwrite(plain.data, 1, plain.len, out) != plain.len) {
        fclose(out);
        goto done;
    }
    if (fclose(out) != 0)
        goto done;
    rc = 0;

done:
    free(dir);
    free(comp);
    buf_free(&plain);
    fclose(f);
    return rc;
}
