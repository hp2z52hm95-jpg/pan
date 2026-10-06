/*
 * pandora.h - shared declarations for PandoraLauncher (C implementation)
 *
 * PandoraLauncher.exe sits next to PandoraTool.exe and, in order:
 *   1. signs the user in (password or Windows Hello / security-key passkey),
 *   2. checks the update server and applies a verified update,
 *   3. starts PandoraTool.exe with the login session on its command line.
 *
 * Modules
 *   util.c      string buffer, SHA-256, CRC-32, base64url, INI reader,
 *               version compare, UTF-8 helpers
 *   json.c      small JSON parser (server responses)
 *   inflate.c   RFC 1951 DEFLATE decoder (used for update .zip packages)
 *   zip.c       ZIP reader/extractor built on inflate.c
 *   fs.c        file system (Unicode paths on Windows, POSIX for host tests)
 *   url.c       base-URL parsing + percent encoding
 *   http.c      HTTP/HTTPS client (WinHTTP)
 *   webauthn.c  Windows WebAuthn (webauthn.dll) passkey ceremony
 *   update.c    version check, download+verify, close app, backup, apply
 *   ui.c        launcher window + sign-in dialog
 *   main.c      startup, configuration, flow, --self-test
 *
 * Everything except http.c/webauthn.c/update.c/ui.c/main.c is portable C99 so
 * the same sources are compiled by the host test harness (src/tests/run.c).
 */
#ifndef PANDORA_H
#define PANDORA_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PANDORA_APP_NAME    "PandoraTool"
#define PANDORA_LAUNCHER_VER "1.0.0.0"

/* ------------------------------------------------------------------ */
/* string buffer                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *p;
    size_t len;
    size_t cap;
} sbuf;

void  sb_init(sbuf *b);
void  sb_free(sbuf *b);
void  sb_reset(sbuf *b);
void  sb_add(sbuf *b, const char *s, size_t n);
void  sb_adds(sbuf *b, const char *s);
void  sb_addc(sbuf *b, char c);
void  sb_addf(sbuf *b, const char *fmt, ...);
void  sb_add_json_string(sbuf *b, const char *s, size_t n); /* escaped, quoted */
char *sb_take(sbuf *b);                                     /* malloc'd, NUL-terminated */

/* ------------------------------------------------------------------ */
/* util.c                                                             */
/* ------------------------------------------------------------------ */

void *p_malloc(size_t n);
void *p_realloc(void *p, size_t n);
char *p_strdup(const char *s);
char *p_strndup(const char *s, size_t n);

void sha256(const void *data, size_t n, uint8_t out[32]);
/* returns 0 on success, fills hex[65] */
int  sha256_file(const char *path, char hex[65], char *err, size_t errlen);
void hex_lower(const uint8_t *d, size_t n, char *out);

char *b64url_encode(const uint8_t *data, size_t n);            /* malloc'd */
int   b64url_decode(const char *s, uint8_t **out, size_t *outlen); /* 0 on ok */

uint32_t crc32_update(uint32_t crc, const void *data, size_t n);

/* dotted numeric version compare: -1 / 0 / 1 */
int  version_compare(const char *a, const char *b);

/* case-insensitive ASCII compare / trim */
int  ascii_icmp(const char *a, const char *b);
void trim_inplace(char *s);

/* returns a malloc'd value copied out of an INI file text */
char *ini_read(const char *text, const char *section, const char *key, const char *def);
int   ini_read_bool(const char *text, const char *section, const char *key, int def);

/* printf-style into a malloc'd buffer (caller frees) */
char *p_asprintf(const char *fmt, ...);
/* message + GetLastError()/errno text */
char *p_strerror_sys(const char *what);

/* ------------------------------------------------------------------ */
/* json.c                                                             */
/* ------------------------------------------------------------------ */

typedef enum { JSON_NULL, JSON_BOOL, JSON_NUM, JSON_STR, JSON_ARR, JSON_OBJ } jtype;

typedef struct json json;
struct json {
    jtype   t;
    int     b;          /* JSON_BOOL */
    double  num;        /* JSON_NUM  */
    char   *raw;        /* numbers / strings kept verbatim (strings unescaped, NUL terminated) */
    size_t  rawlen;
    json  **items;      /* JSON_ARR */
    size_t  nitems;
    char  **keys;       /* JSON_OBJ */
    json  **vals;
    size_t  nkeys;
};

json *json_parse(const char *s, size_t n);
void  json_free(json *v);

const json *json_get(const json *obj, const char *key);
const char *json_str(const json *obj, const char *key, const char *def);
int         json_bool(const json *obj, const char *key, int def);
double      json_num(const json *obj, const char *key, double def);
size_t      json_len(const json *arr);
const json *json_at(const json *arr, size_t i);

/* ------------------------------------------------------------------ */
/* inflate.c                                                          */
/* ------------------------------------------------------------------ */

/* Raw DEFLATE. dst must be large enough (size known from the zip header).
 * Returns 0 on success. */
int inflate_raw(const uint8_t *src, size_t srclen, uint8_t *dst, size_t dstcap,
                size_t *outlen);

/* streams into a file (constant memory, 32 KB window) */
int inflate_to_file(const uint8_t *src, size_t srclen, FILE *out, uint64_t expected,
                    uint64_t *written);
/* streams into an arbitrary sink (used by zip.c so the CRC-32 is computed
 * while unpacking) */
int inflate_to_sink(const uint8_t *src, size_t srclen,
                    int (*sink)(void *ud, const uint8_t *data, size_t n), void *ud,
                    uint64_t expected, uint64_t *written);

/* ------------------------------------------------------------------ */
/* fs.c                                                              */
/* ------------------------------------------------------------------ */

int  fs_exists(const char *path);
int  fs_is_dir(const char *path);
int64_t fs_size(const char *path);
int  fs_read_all(const char *path, char **out, size_t *len);   /* malloc'd NUL-terminated */
int  fs_write_all(const char *path, const void *data, size_t len, char *err, size_t errlen);
int  fs_mkdirs(const char *path);
int  fs_copy(const char *src, const char *dst, int fail_if_exists);
int  fs_move_over(const char *src, const char *dst);           /* replace dst */
int  fs_delete(const char *path);
int  fs_remove_tree(const char *path);
/* dir part of a path, with trailing separator ("C:\app\PandoraTool.exe" -> "C:\app\") */
void fs_dir_of(const char *path, char *out, size_t outsz);
void fs_join(char *out, size_t outsz, const char *dir, const char *name);
/* join and convert '/' to '\' on Windows */
void fs_join_norm(char *out, size_t outsz, const char *dir, const char *rel);
int  fs_set_mtime(const char *path, uint64_t unix_time);
/* fresh, empty scratch directory (removed and recreated) */
int  fs_make_temp(char *out, size_t outsz);
char *fs_temp_dir(void);

int  fs_last_error(void);       /* GetLastError() / errno */
int  fs_err_is_access_denied(int e);

/* Unicode-safe stdio (UTF-8 paths; UTF-8 text streams). */
FILE *fs_fopen_read(const char *path);
FILE *fs_fopen_write(const char *path, int append);

/* ------------------------------------------------------------------ */
/* url.c                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    int   tls;              /* https */
    char *host;             /* "updates.example.com" */
    int   port;             /* 443 / 80 unless given */
    char *prefix;           /* "" or "/sub/dir" (no trailing slash) */
    int   default_port;
} url_base;

int  url_parse(const char *url, url_base *out, char *err, size_t errlen);
void url_free(url_base *u);
char *url_join(const url_base *u, const char *path); /* malloc'd full URL */
char *url_encode_query(const char *s);               /* malloc'd */

/* ------------------------------------------------------------------ */
/* http.c  (Windows only - WinHTTP)                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    url_base base;
    void    *session;   /* HINTERNET */
    int      connect_timeout_ms;
    int      recv_timeout_ms;
} http_client;

typedef struct {
    int    status;
    char  *body;        /* malloc'd, NUL terminated (may contain binary) */
    size_t len;
} http_resp;

int  http_init(http_client *c, const char *base_url, char *err, size_t errlen);
void http_free(http_client *c);
void http_resp_free(http_resp *r);

int http_post_json(http_client *c, const char *path, const char *body,
                   const char *bearer, http_resp *resp, char *err, size_t errlen);
int http_get(http_client *c, const char *path, const char *bearer,
             http_resp *resp, char *err, size_t errlen);

typedef void (*http_progress_fn)(void *ud, int64_t got, int64_t total, int *abort);

/* streams the body straight to dest_path (UTF-8 path). */
int http_get_file(http_client *c, const char *path, const char *bearer,
                  const char *dest_path, http_progress_fn cb, void *ud,
                  char *err, size_t errlen);

/* ------------------------------------------------------------------ */
/* zip.c                                                              */
/* ------------------------------------------------------------------ */

typedef void (*zip_log_fn)(void *ud, const char *msg);

typedef struct {
    char *name;                 /* UTF-8, '/' separators, malloc'd */
    uint64_t usize;
} zip_entry;

/* Lists entries (caller frees via zip_entries_free). Returns 0 on success. */
int  zip_list(const char *zip_path, zip_entry **entries, size_t *count,
              char *err, size_t errlen);
void zip_entries_free(zip_entry *entries, size_t count);

/* Extracts everything into dest_dir. When backup_dir is not NULL every file
 * that is about to be overwritten is first copied there (same relative path).
 * Returns 0 on success. */
int  zip_extract(const char *zip_path, const char *dest_dir, const char *backup_dir,
                 zip_log_fn log, void *ud, char *err, size_t errlen);

/* ------------------------------------------------------------------ */
/* webauthn.c (Windows only)                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    int   ok;
    char *token;        /* malloc'd */
    char *username;     /* malloc'd */
    char *display_name; /* malloc'd */
    char *error;        /* malloc'd, set when !ok */
} passkey_result;

/* Runs the whole ceremony: /api/passkey/authenticate/begin -> Windows Hello
 * prompt -> /api/passkey/authenticate/complete. */
int passkey_sign_in(void *hwnd_owner, http_client *c, const char *rp_id,
                    const char *origin, const char *username, passkey_result *out);

/* ------------------------------------------------------------------ */
/* update.c (Windows only)                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    char  app_dir[1024];    /* UTF-8, with trailing separator */
    char  app_exe[300];
    char  version[64];      /* installed version of app_exe */
    int   elevated;
} app_ctx;

int  app_installed_version(const char *exe_path, char *out, size_t outsz);
int  app_is_elevated(void);
int  app_close_running(const char *exe_name, void (*log)(void *, const char *), void *ud);
int  app_launch(const char *app_dir, const char *exe_name, const char *args);
int  app_relaunch_elevated(const char *exe_path, const char *app_dir);

typedef struct {
    int   available;
    char *latest;    /* malloc'd */
    char *notes;     /* malloc'd */
    json *packages;  /* owned by the caller (json_free) */
} update_info;

void update_info_free(update_info *u);

/* GET /api/updates/check - "is there a newer version than `current`?" */
int  update_check(http_client *c, const char *current, update_info *out,
                  char *err, size_t errlen);

/* Download + verify every package, close the app, back up, unpack, and report.
 * `log`/`progress` may be NULL. Returns 0 when the install folder is updated. */
int  update_download_and_apply(http_client *c, const char *token, const app_ctx *app,
                               const json *packages, const char *latest,
                               void (*log)(void *, const char *),
                               void (*progress)(void *, int), void *ud,
                               char *err, size_t errlen);

/* ------------------------------------------------------------------ */
/* launcher configuration (launcher.ini) and the signed-in session     */
/* ------------------------------------------------------------------ */

typedef struct {
    char *base_url;
    char *rp_id;
    char *origin;
    char *app_exe;
    char *launch_args;
    int   auto_update;
    int   auto_launch;
    char  ini_path[1024];
} launcher_cfg;

typedef struct {
    char *token;
    char *username;
    char *display_name;
} session_t;

void session_free(session_t *s);

/* ------------------------------------------------------------------ */
/* ui.c - the launcher window and sign-in dialog (Windows only)        */
/* ------------------------------------------------------------------ */

typedef struct launcher_ui launcher_ui;

launcher_ui *ui_create(void *inst, const launcher_cfg *cfg);   /* inst = HINSTANCE */
void ui_destroy(launcher_ui *ui);
void ui_show(launcher_ui *ui);
void ui_set_flow(launcher_ui *ui, void (*fn)(void *ctx), void *ctx); /* starts it */
void ui_set_exit_code(launcher_ui *ui, int code);

/* safe to call from the worker thread */
void ui_log(launcher_ui *ui, const char *msg);
void ui_status(launcher_ui *ui, const char *text);
void ui_progress(launcher_ui *ui, int pct);
void ui_message(launcher_ui *ui, const char *text);
void ui_close(launcher_ui *ui);
void ui_flow_done(launcher_ui *ui);
int  ui_cancelled(launcher_ui *ui);
int  ui_confirm_elevate(launcher_ui *ui);          /* asks, returns 1 = yes */
int  ui_do_login(launcher_ui *ui);                 /* runs the dialog, 1 = signed in */
void ui_set_http(launcher_ui *ui, void *http);
session_t *ui_session(launcher_ui *ui);            /* set by ui_login */

#ifdef __cplusplus
}
#endif
#endif /* PANDORA_H */
