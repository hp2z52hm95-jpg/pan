/*
 * http.c - HTTP/HTTPS client for the launcher (WinHTTP).
 *
 * Only what the launcher needs:
 *   - POST JSON with an optional "Authorization: Bearer <jwt>"
 *   - GET JSON
 *   - GET a file to disk with progress reporting (update packages)
 *
 * WinHTTP is used instead of WinINet so the launcher is not tied to the
 * interactive IE proxy stack, and HTTPS works without any extra setup.
 */
#include "pandora.h"

#include <windows.h>
#include <winhttp.h>

#include <stdlib.h>
#include <string.h>

#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4
#endif

#define USER_AGENT L"PandoraLauncher/1.0"

static wchar_t *u2w(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w;
    if (n <= 0)
        return NULL;
    w = (wchar_t *)p_malloc((size_t)n * sizeof(wchar_t));
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

/* WinHTTP / Win32 error -> something a user can act on */
static void http_error_text(DWORD e, char *err, size_t errlen)
{
    const char *hint = NULL;
    switch (e) {
    case 12007: hint = "the server name could not be resolved (check BaseURL / internet)"; break;
    case 12029: hint = "could not connect to the update server"; break;
    case 12002: hint = "the server did not answer in time"; break;
    case 12017: hint = "the connection was closed by the server"; break;
    case 12175: hint = "TLS/certificate problem (is the server certificate valid?)"; break;
    case 12038: hint = "the server certificate is not trusted"; break;
    case 12045: hint = "the server certificate is invalid"; break;
    case 12006: hint = "connection failed"; break;
    case 12019: hint = "the server sent an invalid response"; break;
    case 12057: hint = "certificate revocation check failed (offline?)"; break;
    default: break;
    }
    if (hint)
        snprintf(err, errlen, "%s (WinHTTP %lu)", hint, (unsigned long)e);
    else
        snprintf(err, errlen, "network error %lu", (unsigned long)e);
}

int http_init(http_client *c, const char *base_url, char *err, size_t errlen)
{
    memset(c, 0, sizeof(*c));
    if (url_parse(base_url, &c->base, err, errlen) != 0)
        return -1;

    c->session = WinHttpOpen(USER_AGENT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!c->session)
        c->session = WinHttpOpen(USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!c->session) {
        if (err)
            http_error_text(GetLastError(), err, errlen);
        url_free(&c->base);
        return -1;
    }
    c->connect_timeout_ms = 15000;
    c->recv_timeout_ms = 60000;
    WinHttpSetTimeouts((HINTERNET)c->session, c->connect_timeout_ms,
                       c->connect_timeout_ms, c->recv_timeout_ms, c->recv_timeout_ms);
    return 0;
}

void http_free(http_client *c)
{
    if (c->session) {
        WinHttpCloseHandle((HINTERNET)c->session);
        c->session = NULL;
    }
    url_free(&c->base);
}

void http_resp_free(http_resp *r)
{
    free(r->body);
    r->body = NULL;
    r->len = 0;
    r->status = 0;
}

/* Opens a request handle; *out_conn must be closed by the caller. */
static HINTERNET open_request(http_client *c, const wchar_t *verb, const char *path,
                              int recv_timeout_ms, char *err, size_t errlen)
{
    wchar_t *host = u2w(c->base.host);
    wchar_t *wpath;
    HINTERNET conn, req;

    if (!host) {
        if (err) snprintf(err, errlen, "invalid server host name");
        return NULL;
    }
    conn = WinHttpConnect((HINTERNET)c->session, host, (INTERNET_PORT)c->base.port, 0);
    free(host);
    if (!conn) {
        if (err) http_error_text(GetLastError(), err, errlen);
        return NULL;
    }

    wpath = u2w(path);
    if (!wpath) {
        if (err) snprintf(err, errlen, "invalid request path");
        WinHttpCloseHandle(conn);
        return NULL;
    }
    req = WinHttpOpenRequest(conn, verb, wpath, NULL, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                             c->base.tls ? WINHTTP_FLAG_SECURE : 0);
    free(wpath);
    if (!req) {
        if (err) http_error_text(GetLastError(), err, errlen);
        WinHttpCloseHandle(conn);
        return NULL;
    }
    WinHttpSetTimeouts(req, c->connect_timeout_ms, c->connect_timeout_ms,
                       recv_timeout_ms, recv_timeout_ms);
    return req;
}

static int add_bearer(HINTERNET req, const char *bearer, char *err, size_t errlen)
{
    if (bearer && *bearer) {
        char header[4200];
        wchar_t *wh;
        snprintf(header, sizeof(header), "Authorization: Bearer %s\r\n", bearer);
        wh = u2w(header);
        if (!wh) {
            if (err) snprintf(err, errlen, "out of memory");
            return -1;
        }
        WinHttpAddRequestHeaders(req, wh, (DWORD)-1L,
                                 WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
        free(wh);
    }
    return 0;
}

static int read_body(HINTERNET req, http_resp *resp, char *err, size_t errlen)
{
    sbuf b;

    sb_init(&b);
    for (;;) {
        DWORD avail = 0;
        DWORD got = 0;
        char buf[16384];

        if (!WinHttpQueryDataAvailable(req, &avail)) {
            if (err) http_error_text(GetLastError(), err, errlen);
            sb_free(&b);
            return -1;
        }
        if (avail == 0)
            break;
        if (avail > sizeof(buf))
            avail = sizeof(buf);
        if (!WinHttpReadData(req, buf, avail, &got)) {
            if (err) http_error_text(GetLastError(), err, errlen);
            sb_free(&b);
            return -1;
        }
        if (got == 0)
            break;
        sb_add(&b, buf, got);
    }
    resp->len = b.len;
    resp->body = sb_take(&b);
    return 0;
}

static int query_status(HINTERNET req, int *status)
{
    DWORD code = 0, len = sizeof(code);
    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &code, &len,
                             WINHTTP_NO_HEADER_INDEX))
        return -1;
    *status = (int)code;
    return 0;
}

/* The server answers errors as {"error":"..."} - prefer that text. */
static void json_error_message(const http_resp *r, const char *fallback,
                               char *err, size_t errlen)
{
    if (r->body && r->len) {
        json *j = json_parse(r->body, r->len);
        if (j) {
            const char *msg = json_str(j, "error", NULL);
            if (msg && *msg) {
                snprintf(err, errlen, "%s", msg);
                json_free(j);
                return;
            }
            json_free(j);
        }
    }
    snprintf(err, errlen, "%s", fallback);
}

int http_post_json(http_client *c, const char *path, const char *body,
                   const char *bearer, http_resp *resp, char *err, size_t errlen)
{
    HINTERNET req;
    wchar_t *headers = u2w("Content-Type: application/json\r\n");

    memset(resp, 0, sizeof(*resp));
    req = open_request(c, L"POST", path, c->recv_timeout_ms, err, errlen);
    if (!req) {
        free(headers);
        return -1;
    }
    if (add_bearer(req, bearer, err, errlen) != 0) {
        free(headers);
        WinHttpCloseHandle(req);
        return -1;
    }
    if (!WinHttpSendRequest(req, headers ? headers : WINHTTP_NO_ADDITIONAL_HEADERS, -1L,
                            (LPVOID)body, (DWORD)(body ? strlen(body) : 0),
                            (DWORD)(body ? strlen(body) : 0), 0)) {
        if (err) http_error_text(GetLastError(), err, errlen);
        free(headers);
        WinHttpCloseHandle(req);
        return -1;
    }
    free(headers);
    if (!WinHttpReceiveResponse(req, NULL)) {
        if (err) http_error_text(GetLastError(), err, errlen);
        WinHttpCloseHandle(req);
        return -1;
    }
    if (query_status(req, &resp->status) != 0) {
        if (err) snprintf(err, errlen, "the server sent no status code");
        WinHttpCloseHandle(req);
        return -1;
    }
    if (read_body(req, resp, err, errlen) != 0) {
        WinHttpCloseHandle(req);
        http_resp_free(resp);
        return -1;
    }
    WinHttpCloseHandle(req);

    if (resp->status >= 400) {
        char fallback[128];
        snprintf(fallback, sizeof(fallback), "Request failed (HTTP %d)", resp->status);
        json_error_message(resp, fallback, err, errlen);
        if (resp->status == 401)
            snprintf(err, errlen, "%s", "Invalid username or password, or the session expired.");
        return -1;
    }
    return 0;
}

int http_get(http_client *c, const char *path, const char *bearer,
             http_resp *resp, char *err, size_t errlen)
{
    HINTERNET req;

    memset(resp, 0, sizeof(*resp));
    req = open_request(c, L"GET", path, c->recv_timeout_ms, err, errlen);
    if (!req)
        return -1;
    if (add_bearer(req, bearer, err, errlen) != 0) {
        WinHttpCloseHandle(req);
        return -1;
    }
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(req, NULL)) {
        if (err) http_error_text(GetLastError(), err, errlen);
        WinHttpCloseHandle(req);
        return -1;
    }
    if (query_status(req, &resp->status) != 0) {
        if (err) snprintf(err, errlen, "the server sent no status code");
        WinHttpCloseHandle(req);
        return -1;
    }
    if (read_body(req, resp, err, errlen) != 0) {
        WinHttpCloseHandle(req);
        http_resp_free(resp);
        return -1;
    }
    WinHttpCloseHandle(req);

    if (resp->status >= 400) {
        char fallback[128];
        snprintf(fallback, sizeof(fallback), "Request failed (HTTP %d)", resp->status);
        json_error_message(resp, fallback, err, errlen);
        if (resp->status == 401)
            snprintf(err, errlen, "%s", "Session expired - please sign in again.");
        return -1;
    }
    return 0;
}

int http_get_file(http_client *c, const char *path, const char *bearer,
                  const char *dest_path, http_progress_fn cb, void *ud,
                  char *err, size_t errlen)
{
    HINTERNET req;
    int status = 0;
    int64_t total = 0, got_total = 0;
    FILE *out = NULL;
    int rc = -1;
    char small[2048];
    size_t small_len = 0;
    int aborted = 0;

    req = open_request(c, L"GET", path, 30 * 60 * 1000, err, errlen);  /* 30 min */
    if (!req)
        return -1;
    if (add_bearer(req, bearer, err, errlen) != 0)
        goto done;
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(req, NULL)) {
        if (err) http_error_text(GetLastError(), err, errlen);
        goto done;
    }
    if (query_status(req, &status) != 0) {
        if (err) snprintf(err, errlen, "the server sent no status code");
        goto done;
    }
    {
        wchar_t lenbuf[64];
        DWORD len = sizeof(lenbuf);
        if (WinHttpQueryHeaders(req, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX,
                                lenbuf, &len, WINHTTP_NO_HEADER_INDEX) && len >= 2) {
            total = _wtoi64(lenbuf);
        }
    }

    if (status != 200) {
        /* the server's JSON error is small - read it to report the reason */
        for (;;) {
            DWORD avail = 0, got = 0;
            char buf[512];
            if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0)
                break;
            if (avail > sizeof(buf))
                avail = sizeof(buf);
            if (!WinHttpReadData(req, buf, avail, &got) || got == 0)
                break;
            if (small_len + got < sizeof(small) - 1) {
                memcpy(small + small_len, buf, got);
                small_len += got;
                small[small_len] = 0;
            }
        }
        {
            http_resp r;
            char fallback[128];
            r.status = status;
            r.body = small_len ? small : NULL;
            r.len = small_len;
            snprintf(fallback, sizeof(fallback), "Download failed (HTTP %d)", status);
            json_error_message(&r, fallback, err, errlen);
        }
        goto done;
    }

    out = fs_fopen_write(dest_path, 0);
    if (!out) {
        if (err) snprintf(err, errlen, "cannot create %s", dest_path);
        goto done;
    }

    for (;;) {
        DWORD avail = 0, got = 0;
        static char buf[128 * 1024];

        if (!WinHttpQueryDataAvailable(req, &avail)) {
            if (err) http_error_text(GetLastError(), err, errlen);
            goto done;
        }
        if (avail == 0)
            break;
        if (avail > sizeof(buf))
            avail = sizeof(buf);
        if (!WinHttpReadData(req, buf, avail, &got)) {
            if (err) http_error_text(GetLastError(), err, errlen);
            goto done;
        }
        if (got == 0)
            break;
        if (fwrite(buf, 1, got, out) != got) {
            if (err) snprintf(err, errlen, "not enough space to write %s", dest_path);
            goto done;
        }
        got_total += got;
        if (cb) {
            cb(ud, got_total, total, &aborted);
            if (aborted) {
                if (err) snprintf(err, errlen, "download cancelled");
                goto done;
            }
        }
    }
    rc = 0;
done:
    if (out) {
        fclose(out);
        if (rc != 0)
            fs_delete(dest_path);
    }
    WinHttpCloseHandle(req);
    return rc;
}
