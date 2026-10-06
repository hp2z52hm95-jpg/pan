/*
 * inflate.c - RFC 1951 DEFLATE decoder.
 *
 * Self contained (no zlib) so the launcher has no third-party dependency.
 * Decodes straight into a 64 KB sliding window and streams whole 32 KB blocks
 * to a sink, so unpacking a 200 MB package costs constant memory.
 *
 * Verification: src/tests/run.c decompresses real .zip member data produced by
 * several different compressors (zlib levels 1..9, stored, and the fixed /
 * dynamic / stored block types) and compares the result byte for byte.
 */
#include "pandora.h"

#include <stdlib.h>
#include <string.h>

#define MAXBITS 15
#define WINDOW_SIZE 32768
#define WINDOW_KEEP WINDOW_SIZE       /* bytes kept for back-references */
#define WINDOW_CAP  (WINDOW_SIZE * 2)

typedef struct {
    short count[MAXBITS + 1];
    short symbol[288];
} huff;

typedef struct {
    const uint8_t *in;
    size_t         inlen;
    size_t         inpos;
    uint32_t       bitbuf;
    int            bitcnt;

    uint8_t       *win;
    size_t         winlen;

    uint64_t       total;        /* total bytes produced */
    uint64_t       expected;     /* 0 = unknown */
    int            error;

    int          (*sink)(void *ud, const uint8_t *data, size_t n);
    void          *sink_ud;
} inf_state;

/* ---------------- bit reader (LSB first) ---------------- */

static unsigned inf_bits(inf_state *s, int need)
{
    unsigned val;

    if (need == 0)
        return 0;
    while (s->bitcnt < need) {
        if (s->inpos >= s->inlen) {
            s->error = 1;
            return 0;
        }
        s->bitbuf |= (uint32_t)s->in[s->inpos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    val = s->bitbuf & ((1u << need) - 1u);
    s->bitbuf >>= need;
    s->bitcnt -= need;
    return val;
}

/* ---------------- output window ---------------- */

static int inf_flush(inf_state *s, size_t keep)
{
    size_t n;

    if (s->winlen <= keep)
        return 0;
    n = s->winlen - keep;
    if (s->sink && s->sink(s->sink_ud, s->win, n) != 0) {
        s->error = 2;
        return -1;
    }
    memmove(s->win, s->win + n, keep);
    s->winlen = keep;
    return 0;
}

static int inf_put(inf_state *s, uint8_t b)
{
    if (s->winlen == WINDOW_CAP && inf_flush(s, WINDOW_KEEP) != 0)
        return -1;
    s->win[s->winlen++] = b;
    s->total++;
    return 0;
}

static int inf_put_run(inf_state *s, const uint8_t *data, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (inf_put(s, data[i]) != 0)
            return -1;
    return 0;
}

static int inf_copy_back(inf_state *s, size_t dist, size_t len)
{
    size_t i;

    if (dist == 0 || dist > s->total || dist > WINDOW_KEEP) {
        s->error = 3;
        return -1;
    }
    for (i = 0; i < len; i++) {
        uint8_t b;
        /* the flush inside inf_put() keeps at least WINDOW_KEEP bytes, so a
         * distance of at most WINDOW_KEEP always stays addressable */
        if (dist > s->winlen) {
            s->error = 3;
            return -1;
        }
        b = s->win[s->winlen - dist];
        if (inf_put(s, b) != 0)
            return -1;
    }
    return 0;
}

/* ---------------- Huffman ---------------- */

/* Builds a canonical code. Returns 0 for a complete code, >0 for an
 * incomplete one (allowed for a single-code tree), <0 for invalid. */
static int huff_build(huff *h, const uint8_t *length, int n)
{
    int len, left, i;
    short offs[MAXBITS + 1];

    memset(h->count, 0, sizeof(h->count));
    for (i = 0; i < n; i++)
        h->count[length[i]]++;
    if (h->count[0] == n) {
        /* no codes at all */
        h->count[0] = 0;
        return 0;
    }
    left = 1;
    for (len = 1; len <= MAXBITS; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0)
            return -1;                 /* over-subscribed */
    }
    offs[1] = 0;
    for (len = 1; len < MAXBITS; len++)
        offs[len + 1] = (short)(offs[len] + h->count[len]);
    for (i = 0; i < n; i++)
        if (length[i] != 0)
            h->symbol[offs[length[i]]++] = (short)i;
    return left;
}

static int huff_decode(inf_state *s, const huff *h)
{
    int len, code, first, index, count;

    code = first = index = 0;
    for (len = 1; len <= MAXBITS; len++) {
        code |= (int)inf_bits(s, 1);
        if (s->error)
            return -1;
        count = h->count[len];
        if (code - count < first)
            return h->symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

/* ---------------- block types ---------------- */

static const short len_base[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
    67, 83, 99, 115, 131, 163, 195, 227, 258
};
static const short len_extra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 0
};
static const short dist_base[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385,
    513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};
static const short dist_extra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};
static const short clc_order[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

static int inf_codes(inf_state *s, huff *lencode, huff *distcode,
                     const uint8_t *lengths, int nlen, int ndist)
{
    int err;

    err = huff_build(lencode, lengths, nlen);
    if (err != 0 && !(err > 0 && nlen == lencode->count[0] + lencode->count[1])) {
        s->error = 4;
        return -1;
    }
    err = huff_build(distcode, lengths + nlen, ndist);
    if (err != 0 && !(err > 0 && ndist == distcode->count[0] + distcode->count[1])) {
        /* one distance code is fine, anything else incomplete is not */
        if (err < 0 || distcode->count[0] + distcode->count[1] + distcode->count[2] < ndist) {
            s->error = 4;
            return -1;
        }
    }
    return 0;
}

static int inf_codes_block(inf_state *s, const huff *lencode, const huff *distcode)
{
    for (;;) {
        int sym = huff_decode(s, lencode);
        if (sym < 0) {
            s->error = 5;
            return -1;
        }
        if (sym < 256) {
            if (inf_put(s, (uint8_t)sym) != 0)
                return -1;
        } else if (sym == 256) {
            return 0;
        } else {
            int len, dist, dsym;
            sym -= 257;
            if (sym >= 29) {
                s->error = 6;
                return -1;
            }
            len = len_base[sym] + (int)inf_bits(s, len_extra[sym]);
            dsym = huff_decode(s, distcode);
            if (dsym < 0 || dsym >= 30) {
                s->error = 6;
                return -1;
            }
            dist = dist_base[dsym] + (int)inf_bits(s, dist_extra[dsym]);
            if (s->error)
                return -1;
            if (inf_copy_back(s, (size_t)dist, (size_t)len) != 0)
                return -1;
        }
        if (s->error)
            return -1;
    }
}

static int inf_stored(inf_state *s)
{
    size_t len, nlen;
    uint32_t discard;

    /* drop remaining bits of the current byte */
    discard = s->bitcnt % 8;
    if (discard)
        inf_bits(s, (int)discard);
    len = inf_bits(s, 16);
    nlen = inf_bits(s, 16);
    if (s->error || ((len ^ 0xffffu) != nlen)) {
        s->error = 7;
        return -1;
    }
    if (s->inpos + len > s->inlen) {
        s->error = 8;
        return -1;
    }
    if (inf_put_run(s, s->in + s->inpos, len) != 0)
        return -1;
    s->inpos += len;
    return 0;
}

static int inf_fixed(inf_state *s)
{
    uint8_t lengths[288 + 32];
    huff lencode, distcode;
    int i;

    for (i = 0; i < 144; i++) lengths[i] = 8;
    for (; i < 256; i++)       lengths[i] = 9;
    for (; i < 280; i++)       lengths[i] = 7;
    for (; i < 288; i++)       lengths[i] = 8;
    for (i = 0; i < 32; i++)   lengths[288 + i] = 5;

    if (inf_codes(s, &lencode, &distcode, lengths, 288, 32) != 0)
        return -1;
    return inf_codes_block(s, &lencode, &distcode);
}

static int inf_dynamic(inf_state *s)
{
    uint8_t lengths[288 + 32];
    uint8_t cl_lengths[19];
    huff lencode, distcode;
    int nlen, ndist, ncode, index, i;

    nlen = (int)inf_bits(s, 5) + 257;
    ndist = (int)inf_bits(s, 5) + 1;
    ncode = (int)inf_bits(s, 4) + 4;
    if (s->error || nlen > 288 || ndist > 32) {
        s->error = 9;
        return -1;
    }
    memset(cl_lengths, 0, sizeof(cl_lengths));
    for (i = 0; i < ncode; i++)
        cl_lengths[clc_order[i]] = (uint8_t)inf_bits(s, 3);
    if (s->error) {
        s->error = 9;
        return -1;
    }
    if (huff_build(&lencode, cl_lengths, 19) != 0) {
        s->error = 9;
        return -1;
    }

    index = 0;
    while (index < nlen + ndist) {
        int sym = huff_decode(s, &lencode);
        int rep, val;

        if (sym < 0) {
            s->error = 9;
            return -1;
        }
        if (sym < 16) {
            lengths[index++] = (uint8_t)sym;
            continue;
        }
        if (sym == 16) {
            if (index == 0) {
                s->error = 9;
                return -1;
            }
            val = lengths[index - 1];
            rep = 3 + (int)inf_bits(s, 2);
        } else if (sym == 17) {
            val = 0;
            rep = 3 + (int)inf_bits(s, 3);
        } else {
            val = 0;
            rep = 11 + (int)inf_bits(s, 7);
        }
        if (s->error || index + rep > nlen + ndist) {
            s->error = 9;
            return -1;
        }
        while (rep-- > 0)
            lengths[index++] = (uint8_t)val;
    }

    if (inf_codes(s, &lencode, &distcode, lengths, nlen, ndist) != 0)
        return -1;
    return inf_codes_block(s, &lencode, &distcode);
}

/* ---------------- driver ---------------- */

static int inf_blocks(inf_state *s)
{
    int last;

    do {
        last = (int)inf_bits(s, 1);
        {
            int type = (int)inf_bits(s, 2);
            if (s->error)
                return -1;
            if (type == 0) {
                if (inf_stored(s) != 0)
                    return -1;
            } else if (type == 1) {
                if (inf_fixed(s) != 0)
                    return -1;
            } else if (type == 2) {
                if (inf_dynamic(s) != 0)
                    return -1;
            } else {
                s->error = 10;
                return -1;
            }
        }
        if (s->error)
            return -1;
    } while (!last);
    return 0;
}

static void inf_state_init(inf_state *s, const uint8_t *src, size_t srclen)
{
    memset(s, 0, sizeof(*s));
    s->in = src;
    s->inlen = srclen;
    s->win = (uint8_t *)p_malloc(WINDOW_CAP);
}

static int inf_finish(inf_state *s)
{
    int rc = 0;
    if (!s->error && inf_flush(s, 0) != 0)
        rc = -1;
    if (s->error)
        rc = -1;
    free(s->win);
    return rc;
}

typedef struct {
    uint8_t *dst;
    size_t   cap;
    size_t   len;
} mem_sink;

static int mem_sink_write(void *ud, const uint8_t *data, size_t n)
{
    mem_sink *m = (mem_sink *)ud;
    if (m->len + n > m->cap)
        return -1;
    memcpy(m->dst + m->len, data, n);
    m->len += n;
    return 0;
}

static int file_sink_write(void *ud, const uint8_t *data, size_t n)
{
    FILE *f = (FILE *)ud;
    if (!f)
        return -1;
    return fwrite(data, 1, n, f) == n ? 0 : -1;
}

int inflate_raw(const uint8_t *src, size_t srclen, uint8_t *dst, size_t dstcap,
                size_t *outlen)
{
    mem_sink mem;
    inf_state s;
    int rc;

    mem.dst = dst;
    mem.cap = dstcap;
    mem.len = 0;

    inf_state_init(&s, src, srclen);
    s.sink_ud = &mem;
    s.sink = mem_sink_write;
    rc = inf_blocks(&s);
    /* inf_finish() flushes what is still in the window, so the sink sees the
     * whole stream before it is measured */
    if (inf_finish(&s) != 0 || s.error)
        rc = -1;
    if (rc == 0 && s.total != (uint64_t)mem.len)
        rc = -1;                        /* the sink refused part of the stream */
    if (outlen)
        *outlen = mem.len;
    return rc;
}

int inflate_to_sink(const uint8_t *src, size_t srclen,
                    int (*sink)(void *ud, const uint8_t *data, size_t n), void *ud,
                    uint64_t expected, uint64_t *written)
{
    inf_state s;
    int rc;

    inf_state_init(&s, src, srclen);
    s.expected = expected;
    s.sink_ud = ud;
    s.sink = sink;
    rc = inf_blocks(&s);
    if (rc == 0 && expected != 0 && s.total != expected)
        rc = -1;
    if (written)
        *written = s.total;
    if (inf_finish(&s) != 0 || s.error)
        rc = -1;
    return rc;
}

int inflate_to_file(const uint8_t *src, size_t srclen, FILE *out, uint64_t expected,
                    uint64_t *written)
{
    return inflate_to_sink(src, srclen, file_sink_write, out, expected, written);
}
