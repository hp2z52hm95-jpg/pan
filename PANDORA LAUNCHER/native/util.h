/*
 * util.h - portable helpers for the Pandora Launcher.
 *
 * Everything in this file is plain C99 with no Windows dependencies, so it can
 * be compiled and unit-tested on any platform (see tests/).
 *
 *   - byte buffers
 *   - base64url (WebAuthn encoding)
 *   - SHA-256 + CRC-32
 *   - a small JSON reader (read-only, path based lookups)
 *   - a small ZIP reader/writer-free extractor (store + deflate)
 *   - path helpers
 */
#ifndef PANDORA_UTIL_H
#define PANDORA_UTIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* byte buffer                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} buf_t;

void  buf_init(buf_t *b);
void  buf_free(buf_t *b);
int   buf_reserve(buf_t *b, size_t extra);
int   buf_append(buf_t *b, const void *data, size_t len);
int   buf_append_str(buf_t *b, const char *s);
int   buf_append_byte(buf_t *b, unsigned char c);
int   buf_printf(buf_t *b, const char *fmt, ...);
/* NUL-terminate and return the buffer (may be NULL when empty). */
char *buf_cstr(buf_t *b);
void  buf_clear(buf_t *b);

/* ------------------------------------------------------------------ */
/* base64url                                                          */
/* ------------------------------------------------------------------ */

/* Returns a malloc'd NUL-terminated base64url string (no padding). */
char *b64u_encode(const unsigned char *data, size_t len);
/* Accepts base64url and standard base64, with or without padding.
 * Returns malloc'd bytes, sets *out_len; NULL on error. */
unsigned char *b64u_decode(const char *s, size_t *out_len);

/* ------------------------------------------------------------------ */
/* SHA-256 / CRC-32                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    unsigned char block[64];
    size_t block_len;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx *ctx, unsigned char out[32]);
void sha256(const void *data, size_t len, unsigned char out[32]);
/* malloc'd lowercase hex digest, NULL on I/O error. */
char *sha256_file_hex(const char *path);
char *sha256_hex(const unsigned char digest[32]);

uint32_t crc32_buf(const void *data, size_t len, uint32_t crc);
#define CRC32_INIT 0u

/* ------------------------------------------------------------------ */
/* JSON (read-only)                                                   */
/* ------------------------------------------------------------------ */

typedef struct json json_t;

json_t *json_parse(const char *text, size_t len); /* NULL on invalid JSON */
void    json_free(json_t *v);

/* Path syntax: "user.displayName", "packages[0].file", "[2].id" */
const char *json_str (const json_t *v, const char *path, const char *def);
long long   json_int (const json_t *v, const char *path, long long def);
double      json_num (const json_t *v, const char *path, double def);
int         json_bool(const json_t *v, const char *path, int def);
/* number of elements for an array path; 0 when missing/not an array */
size_t      json_count(const json_t *v, const char *path);
/* object/array presence check */
int         json_has  (const json_t *v, const char *path);

/* ------------------------------------------------------------------ */
/* ZIP extractor (store + deflate, CRC-32 verified)                   */
/* ------------------------------------------------------------------ */

typedef struct {
    char    *name;      /* normalized: '/' separators */
    uint16_t method;    /* 0 = store, 8 = deflate */
    uint32_t crc;
    uint64_t csize;
    uint64_t usize;
    uint64_t offset;    /* local header offset */
} zip_entry;

/* Reads the central directory. On success returns 0 and fills *entries
 * (malloc'd array, free with zip_free) and *count. */
int  zip_list(const char *zip_path, zip_entry **entries, size_t *count);
void zip_free(zip_entry *entries, size_t count);

/* Extracts one entry to dest_path. Returns 0 on success, -1 on I/O or
 * corruption (CRC mismatch), -2 for unsupported compression method.
 * Missing parent directories are created. */
int  zip_extract_entry(const char *zip_path, const zip_entry *e,
                       const char *dest_path);

/* Raw DEFLATE decompression (zlib "deflate" stream without header).
 * Appends the decompressed bytes to *out. 0 on success, -1 on corruption. */
int  inflate_raw(const unsigned char *in, size_t in_len, buf_t *out);

/* 0 = safe relative name, -1 = unsafe (absolute, drive letter, "..", empty) */
int  path_is_safe_relative(const char *name);

/* Joins dir + name with '/'; returns malloc'd string. */
char *path_join(const char *dir, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* PANDORA_UTIL_H */
