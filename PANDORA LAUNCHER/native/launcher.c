/*
 * PandoraLauncher.exe - native Win32 launcher for PandoraTool.exe
 * ===============================================================
 *
 * Drop-in implementation of the launcher described in
 * "PANDORA LAUNCHER/README.md" and the Delphi sources next to this file.
 * Same flow, same launcher.ini, same server API:
 *
 *   sign in (password or WebAuthn passkey / Windows Hello)
 *      -> check /api/updates/check
 *      -> download + verify (SHA-256, size) every package
 *      -> close PandoraTool.exe if it is running
 *      -> back up replaced files to Backup\<old-version>\
 *      -> extract packages / replace files
 *      -> start PandoraTool.exe --pandora-session <jwt> --pandora-user "<name>"
 *
 * Why C instead of the Delphi project: this file can be compiled with free,
 * scriptable toolchains (see build.bat / build.sh) and cross-compiled from
 * Linux, so the repository can actually ship a PandoraLauncher.exe. No
 * third-party libraries: Win32 + WinHTTP + the Windows WebAuthn API only.
 *
 * Build (Windows, MSVC):      build.bat
 * Build (Linux -> Windows):   sh build.sh   (uses zig cc / mingw-w64)
 */

#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 /* Windows 7+ APIs */
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <winhttp.h>
#include <commctrl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winver.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <stdint.h>

#include "util.h"
#include "webauthn.h"

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */

#ifndef ARRAY_LEN
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define OL(x) ((const wchar_t *)(x))

/* Window messages used to hand work between the flow thread and the UI. */
#define WM_APP_LOG (WM_APP + 1)      /* lParam: wchar_t* (receiver frees) */
#define WM_APP_STATUS (WM_APP + 2)   /* lParam: wchar_t* (receiver frees) */
#define WM_APP_PROGRESS (WM_APP + 3) /* wParam: percent */
#define WM_APP_DO_LOGIN (WM_APP + 4) /* handled by the main window */
#define WM_APP_DONE (WM_APP + 5)     /* flow thread finished */
#define WM_APP_BUSY (WM_APP + 6)     /* wParam: 1 = work in progress */

static wchar_t *wcs_dup(const wchar_t *s)
{
    size_t n;
    wchar_t *p;
    if (!s)
        return NULL;
    n = (wcslen(s) + 1) * sizeof(wchar_t);
    p = (wchar_t *)malloc(n);
    if (p)
        memcpy(p, s, n);
    return p;
}

static wchar_t *w_from_utf8(const char *s)
{
    int n;
    wchar_t *out;
    if (!s)
        return NULL;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0)
        return NULL;
    out = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!out)
        return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, out, n);
    return out;
}

static char *utf8_from_w(const wchar_t *s)
{
    int n;
    char *out;
    if (!s)
        return NULL;
    n = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
    if (n <= 0)
        return NULL;
    out = (char *)malloc((size_t)n);
    if (!out)
        return NULL;
    WideCharToMultiByte(CP_UTF8, 0, s, -1, out, n, NULL, NULL);
    return out;
}

/* ------------------------------------------------------------------ */
/* configuration (launcher.ini)                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    wchar_t base_url[512];
    wchar_t rp_id[256];
    wchar_t origin[512];
    wchar_t app_exe[260];
    wchar_t launch_args[1024];
    int auto_update;
    int auto_launch;
    wchar_t app_dir[32768]; /* with trailing backslash */
} config_t;

static config_t g_cfg;

static void config_load(void)
{
    wchar_t path[32768];
    wchar_t buf[1024];

    lstrcpyW(g_cfg.base_url, L"http://localhost:3000");
    lstrcpyW(g_cfg.rp_id, L"localhost");
    lstrcpyW(g_cfg.origin, L"http://localhost:3000");
    lstrcpyW(g_cfg.app_exe, L"PandoraTool.exe");
    g_cfg.launch_args[0] = 0;
    g_cfg.auto_update = 1;
    g_cfg.auto_launch = 1;

    lstrcpyW(path, g_cfg.app_dir);
    lstrcatW(path, L"launcher.ini");

    GetPrivateProfileStringW(L"Server", L"BaseURL", g_cfg.base_url, g_cfg.base_url,
                             ARRAY_LEN(g_cfg.base_url), path);
    GetPrivateProfileStringW(L"Server", L"RpId", g_cfg.rp_id, g_cfg.rp_id,
                             ARRAY_LEN(g_cfg.rp_id), path);
    GetPrivateProfileStringW(L"Server", L"Origin", g_cfg.origin, g_cfg.origin,
                             ARRAY_LEN(g_cfg.origin), path);
    GetPrivateProfileStringW(L"App", L"Exe", g_cfg.app_exe, g_cfg.app_exe,
                             ARRAY_LEN(g_cfg.app_exe), path);
    GetPrivateProfileStringW(L"App", L"LaunchArgs", L"", g_cfg.launch_args,
                             ARRAY_LEN(g_cfg.launch_args), path);
    g_cfg.auto_update = GetPrivateProfileIntW(L"App", L"AutoUpdate", 1, path) != 0;
    g_cfg.auto_launch = GetPrivateProfileIntW(L"App", L"AutoLaunch", 1, path) != 0;

    /* Trim whitespace the user may have left in the ini. */
    GetPrivateProfileStringW(L"Server", L"RpId", g_cfg.rp_id, buf, ARRAY_LEN(buf), path);
    {
        wchar_t *p = buf;
        while (*p == L' ' || *p == L'\t')
            p++;
        while (*p) {
            size_t len = wcslen(p);
            if (len && (p[len - 1] == L' ' || p[len - 1] == L'\t' || p[len - 1] == L'\r'))
                p[len - 1] = 0;
            else
                break;
        }
        if (*p)
            lstrcpynW(g_cfg.rp_id, p, ARRAY_LEN(g_cfg.rp_id));
    }

    /* Default RpId/Origin from the BaseURL when they were left blank. */
    if (g_cfg.rp_id[0] == 0 || g_cfg.origin[0] == 0) {
        wchar_t host[256] = L"";
        URL_COMPONENTS uc;
        memset(&uc, 0, sizeof(uc));
        uc.dwStructSize = sizeof(uc);
        uc.lpszHostName = host;
        uc.dwHostNameLength = ARRAY_LEN(host);
        if (WinHttpCrackUrl(g_cfg.base_url, 0, 0, &uc)) {
            if (g_cfg.rp_id[0] == 0)
                lstrcpynW(g_cfg.rp_id, host, ARRAY_LEN(g_cfg.rp_id));
            if (g_cfg.origin[0] == 0)
                lstrcpynW(g_cfg.origin, g_cfg.base_url, ARRAY_LEN(g_cfg.origin));
        }
    }
}

/* ------------------------------------------------------------------ */
/* logging to the UI (safe from any thread)                           */
/* ------------------------------------------------------------------ */

static HWND g_main, g_log, g_progress, g_status, g_btn_run, g_btn_exit;
static HWND g_login, g_edit_user, g_edit_pass, g_login_status, g_btn_login,
    g_btn_passkey, g_btn_cancel;
static HFONT g_font, g_font_bold, g_font_title;
static int g_login_result;
static int g_busy;

static HFONT font_from_system(int bold, int size_delta, int *out_height)
{
    NONCLIENTMETRICSW ncm;
    LOGFONTW lf;
    memset(&ncm, 0, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
        lf = ncm.lfMessageFont;
    } else {
        memset(&lf, 0, sizeof(lf));
        lf.lfHeight = -12;
        lstrcpyW(lf.lfFaceName, L"Segoe UI");
    }
    if (bold)
        lf.lfWeight = FW_BOLD;
    if (size_delta) {
        HDC dc = GetDC(NULL);
        lf.lfHeight = -MulDiv(12 + size_delta, GetDeviceCaps(dc, LOGPIXELSY), 72);
        ReleaseDC(NULL, dc);
    }
    if (out_height)
        *out_height = lf.lfHeight < 0 ? -lf.lfHeight : lf.lfHeight;
    return CreateFontIndirectW(&lf);
}

static void ui_log(const char *fmt, ...)
{
    char stack[1024];
    char *heap = NULL;
    wchar_t *w;
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(stack, sizeof(stack), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n >= sizeof(stack)) {
        heap = (char *)malloc((size_t)n + 1);
        if (!heap)
            return;
        va_start(ap, fmt);
        vsnprintf(heap, (size_t)n + 1, fmt, ap);
        va_end(ap);
    }
    w = w_from_utf8(heap ? heap : stack);
    free(heap);
    if (!w)
        return;
    if (g_main)
        PostMessageW(g_main, WM_APP_LOG, 0, (LPARAM)w);
    else
        free(w);
}

/* Logs a UTF-8 prefix followed by a wide string (paths, versions, ...).
 * Avoids "%ls" so the code works with every Windows CRT. */
static void ui_log_wide(const char *prefix, const wchar_t *w)
{
    char *u = utf8_from_w(w);
    ui_log("%s%s", prefix, u ? u : "?");
    free(u);
}

static void ui_status(const char *fmt, ...)
{
    char stack[512];
    wchar_t *w;
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(stack, sizeof(stack), fmt, ap);
    va_end(ap);
    w = w_from_utf8(stack);
    if (!w)
        return;
    if (g_main)
        PostMessageW(g_main, WM_APP_STATUS, 0, (LPARAM)w);
    else
        free(w);
}

static void ui_progress(int percent)
{
    if (g_main)
        PostMessageW(g_main, WM_APP_PROGRESS, (WPARAM)percent, 0);
}

/* ------------------------------------------------------------------ */
/* WinHTTP client                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    HINTERNET session;
    wchar_t host[256];
    INTERNET_PORT port;
    int secure;
    wchar_t base_path[512];
} http_client;

static int http_open(http_client *c, const wchar_t *base_url)
{
    wchar_t host[256] = L"";
    wchar_t path[512] = L"";
    URL_COMPONENTS uc;
    int ok;

    memset(c, 0, sizeof(*c));
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host;
    uc.dwHostNameLength = ARRAY_LEN(host);
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = ARRAY_LEN(path);

    if (!WinHttpCrackUrl(base_url, 0, 0, &uc))
        return -1;
    if (uc.nScheme != INTERNET_SCHEME_HTTP && uc.nScheme != INTERNET_SCHEME_HTTPS)
        return -1;
    lstrcpynW(c->host, host, ARRAY_LEN(c->host));
    c->port = uc.nPort;
    c->secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    lstrcpynW(c->base_path, path, ARRAY_LEN(c->base_path));
    while (wcslen(c->base_path) > 1 &&
           c->base_path[wcslen(c->base_path) - 1] == L'/')
        c->base_path[wcslen(c->base_path) - 1] = 0;

    c->session = WinHttpOpen(L"PandoraLauncher/1.0",
                             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!c->session)
        return -1;
    WinHttpSetTimeouts(c->session, 15000, 15000, 60000, 60000);
    ok = 1;
    return ok ? 0 : -1;
}

static void http_close(http_client *c)
{
    if (c->session) {
        WinHttpCloseHandle(c->session);
        c->session = NULL;
    }
}

/* Builds the full request path (base path + endpoint). */
static wchar_t *http_full_path(const http_client *c, const wchar_t *endpoint)
{
    size_t n = wcslen(c->base_path) + wcslen(endpoint) + 1;
    wchar_t *p = (wchar_t *)malloc(n * sizeof(wchar_t));
    if (!p)
        return NULL;
    lstrcpyW(p, c->base_path);
    lstrcatW(p, endpoint);
    return p;
}

/*
 * Performs one request. Returns 0 when the request completed (HTTP status in
 * *status, body appended to *out), -1 on a transport error.
 */
static int http_request(http_client *c, const wchar_t *method,
                        const wchar_t *endpoint, const char *body, size_t body_len,
                        const wchar_t *bearer, buf_t *out, DWORD *status)
{
    HINTERNET req = NULL;
    wchar_t *path = NULL;
    wchar_t headers[1024];
    DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    int rc = -1;
    int expect_body = (body != NULL && body_len > 0);

    if (status)
        *status = 0;
    path = http_full_path(c, endpoint);
    if (!path)
        return -1;

    req = WinHttpOpenRequest(c->session, method, path, NULL, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                             c->secure ? WINHTTP_FLAG_SECURE : 0);
    if (!req)
        goto done;
    WinHttpSetOption(req, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));

    headers[0] = 0;
    if (expect_body)
        lstrcpyW(headers, L"Content-Type: application/json\r\n");
    if (bearer && bearer[0]) {
        lstrcatW(headers, L"Authorization: Bearer ");
        lstrcatW(headers, bearer);
        lstrcatW(headers, L"\r\n");
    }

    if (!WinHttpSendRequest(req, headers[0] ? headers : WINHTTP_NO_ADDITIONAL_HEADERS,
                            headers[0] ? -1L : 0,
                            expect_body ? (LPVOID)body : WINHTTP_NO_REQUEST_DATA,
                            expect_body ? (DWORD)body_len : 0,
                            expect_body ? (DWORD)body_len : 0, 0))
        goto done;
    if (!WinHttpReceiveResponse(req, NULL))
        goto done;

    if (status) {
        DWORD len = sizeof(DWORD);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, status, &len,
                            WINHTTP_NO_HEADER_INDEX);
    }

    if (out) {
        for (;;) {
            DWORD avail = 0, read = 0;
            if (!WinHttpQueryDataAvailable(req, &avail))
                goto done;
            if (avail == 0)
                break;
            if (buf_reserve(out, avail) != 0)
                goto done;
            if (!WinHttpReadData(req, out->data + out->len, avail, &read))
                goto done;
            if (read == 0)
                break;
            out->len += read;
            out->data[out->len] = 0;
        }
    } else {
        char sink[8192];
        DWORD read = 0;
        do {
            read = 0;
            if (!WinHttpReadData(req, sink, sizeof(sink), &read))
                break;
        } while (read > 0);
    }
    rc = 0;

done:
    if (rc != 0)
        ui_log("Network error (WinHTTP %lu)", GetLastError());
    free(path);
    if (req)
        WinHttpCloseHandle(req);
    return rc;
}

/* Streams a file to disk, reporting progress. Returns 0 on success. */
static int http_download(http_client *c, const wchar_t *endpoint,
                         const wchar_t *bearer, const wchar_t *local_path,
                         uint64_t expect_size)
{
    HINTERNET req = NULL;
    wchar_t *path = NULL;
    wchar_t headers[1024];
    DWORD status = 0, policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    FILE *f = NULL;
    int rc = -1;
    uint64_t total = 0;

    path = http_full_path(c, endpoint);
    if (!path)
        return -1;
    req = WinHttpOpenRequest(c->session, L"GET", path, NULL, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                             c->secure ? WINHTTP_FLAG_SECURE : 0);
    if (!req)
        goto done;
    WinHttpSetOption(req, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));

    headers[0] = 0;
    if (bearer && bearer[0]) {
        lstrcpyW(headers, L"Authorization: Bearer ");
        lstrcatW(headers, bearer);
        lstrcatW(headers, L"\r\n");
    }
    if (!WinHttpSendRequest(req, headers[0] ? headers : WINHTTP_NO_ADDITIONAL_HEADERS,
                            headers[0] ? -1L : 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        goto done;
    if (!WinHttpReceiveResponse(req, NULL))
        goto done;

    {
        DWORD len = sizeof(DWORD);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &len,
                            WINHTTP_NO_HEADER_INDEX);
    }
    if (status != 200) {
        /* The server's JSON error is in the body; show it. */
        buf_t err;
        char *msg = NULL;
        buf_init(&err);
        for (;;) {
            DWORD avail = 0, read = 0;
            if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0)
                break;
            if (buf_reserve(&err, avail) != 0)
                break;
            if (!WinHttpReadData(req, err.data + err.len, avail, &read) || read == 0)
                break;
            err.len += read;
            err.data[err.len] = 0;
        }
        if (err.data) {
            json_t *j = json_parse((const char *)err.data, err.len);
            const char *e = j ? json_str(j, "error", NULL) : NULL;
            if (e)
                msg = _strdup(e);
            json_free(j);
        }
        ui_log("Download failed (HTTP %lu)%s%s", status, msg ? ": " : "",
               msg ? msg : "");
        free(msg);
        buf_free(&err);
        goto done;
    }

    if (!expect_size) {
        DWORD len = sizeof(uint64_t);
        uint64_t cl = 0;
        if (WinHttpQueryHeaders(req,
                                WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &cl, &len,
                                WINHTTP_NO_HEADER_INDEX))
            expect_size = cl;
    }

    f = _wfopen(local_path, L"wb");
    if (!f) {
        ui_log_wide("Cannot write ", local_path);
        ui_log("  (error %lu - check permissions / disk space)", GetLastError());
        goto done;
    }
    for (;;) {
        DWORD avail = 0, read = 0;
        if (!WinHttpQueryDataAvailable(req, &avail))
            goto done;
        if (avail == 0)
            break;
        {
            /* Read in chunks so progress updates stay responsive. */
            char chunk[64 * 1024];
            DWORD want = avail > sizeof(chunk) ? (DWORD)sizeof(chunk) : avail;
            if (!WinHttpReadData(req, chunk, want, &read))
                goto done;
            if (read == 0)
                break;
            if (fwrite(chunk, 1, read, f) != read) {
                ui_log_wide("Write failed (disk full, read-only folder?): ", local_path);
                goto done;
            }
            total += read;
            if (expect_size)
                ui_progress((int)(total * 100 / expect_size));
        }
    }
    rc = 0;

done:
    if (f)
        fclose(f);
    free(path);
    if (req)
        WinHttpCloseHandle(req);
    if (rc != 0) {
        DeleteFileW(local_path); /* never leave a half-written package behind */
        if (status == 0)
            ui_log("Download failed to start (WinHTTP %lu)", GetLastError());
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Pandora server API                                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    http_client http;
    char *token; /* JWT, UTF-8, owned */
    wchar_t user[256];
    wchar_t display[256];
} api_ctx;

static api_ctx g_api;

static char *json_escape(const char *s)
{
    buf_t b;
    buf_init(&b);
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"': buf_append_str(&b, "\\\""); break;
        case '\\': buf_append_str(&b, "\\\\"); break;
        case '\n': buf_append_str(&b, "\\n"); break;
        case '\r': buf_append_str(&b, "\\r"); break;
        case '\t': buf_append_str(&b, "\\t"); break;
        default:
            if (c < 0x20)
                buf_printf(&b, "\\u%04x", c);
            else
                buf_append_byte(&b, c);
        }
    }
    return buf_cstr(&b) ? (char *)b.data : NULL;
}

/*
 * POST a JSON body. On success returns the parsed response (caller frees) and
 * *status. On failure returns NULL and fills *err with a UTF-8 message
 * (malloc'd; caller frees).
 */
static json_t *api_post(http_client *c, const wchar_t *endpoint, const char *body,
                        const wchar_t *bearer, DWORD *status, char **err)
{
    buf_t resp;
    json_t *j = NULL;
    DWORD code = 0;

    *err = NULL;
    buf_init(&resp);
    if (http_request(c, L"POST", endpoint, body, strlen(body), bearer, &resp, &code) != 0) {
        *err = _strdup("Cannot reach the server. Check launcher.ini (BaseURL) and your network.");
        buf_free(&resp);
        return NULL;
    }
    if (status)
        *status = code;
    if (resp.data)
        j = json_parse((const char *)resp.data, resp.len);
    if (!j) {
        *err = (char *)malloc(128);
        if (*err)
            snprintf(*err, 128, "Unexpected server response (HTTP %lu)", code);
        buf_free(&resp);
        return NULL;
    }
    if (code >= 400) {
        const char *e = json_str(j, "error", NULL);
        if (e) {
            *err = _strdup(e);
        } else {
            *err = (char *)malloc(128);
            if (*err)
                snprintf(*err, 128, "Request failed (HTTP %lu)", code);
        }
        json_free(j);
        buf_free(&resp);
        return NULL;
    }
    buf_free(&resp);
    return j;
}

static json_t *api_get(http_client *c, const wchar_t *endpoint, const wchar_t *bearer,
                       DWORD *status, char **err)
{
    buf_t resp;
    json_t *j = NULL;
    DWORD code = 0;

    *err = NULL;
    buf_init(&resp);
    if (http_request(c, L"GET", endpoint, NULL, 0, bearer, &resp, &code) != 0) {
        *err = _strdup("Cannot reach the server. Check launcher.ini (BaseURL) and your network.");
        buf_free(&resp);
        return NULL;
    }
    if (status)
        *status = code;
    if (resp.data)
        j = json_parse((const char *)resp.data, resp.len);
    if (!j || code >= 400) {
        const char *e = j ? json_str(j, "error", NULL) : NULL;
        if (e) {
            *err = _strdup(e);
        } else {
            *err = (char *)malloc(128);
            if (*err)
                snprintf(*err, 128, "Request failed (HTTP %lu)", code);
        }
        json_free(j);
        buf_free(&resp);
        return NULL;
    }
    buf_free(&resp);
    return j;
}

static int api_login(const char *username, const char *password, char **err)
{
    buf_t body;
    char *eu = json_escape(username);
    char *ep = json_escape(password);
    json_t *j;
    DWORD status = 0;
    int ok = 0;

    buf_init(&body);
    buf_printf(&body, "{\"username\":\"%s\",\"password\":\"%s\"}", eu ? eu : "",
               ep ? ep : "");
    free(eu);
    free(ep);

    j = api_post(&g_api.http, L"/api/auth/login", (const char *)body.data, NULL,
                 &status, err);
    buf_free(&body);
    if (!j)
        return 0;
    {
        const char *token = json_str(j, "token", NULL);
        const char *user = json_str(j, "user.username", username);
        const char *disp = json_str(j, "user.displayName", user);
        if (token && *token) {
            free(g_api.token);
            g_api.token = _strdup(token);
            MultiByteToWideChar(CP_UTF8, 0, user, -1, g_api.user,
                                (int)ARRAY_LEN(g_api.user));
            MultiByteToWideChar(CP_UTF8, 0, disp, -1, g_api.display,
                                (int)ARRAY_LEN(g_api.display));
            ok = 1;
        } else {
            *err = _strdup("Server did not return a session token.");
        }
    }
    json_free(j);
    return ok;
}

/* ------------------------------------------------------------------ */
/* WebAuthn passkey sign-in                                           */
/* ------------------------------------------------------------------ */

static int uv_requirement(const char *s)
{
    if (s && _stricmp(s, "required") == 0)
        return WEBAUTHN_UV_REQUIRED;
    if (s && _stricmp(s, "discouraged") == 0)
        return WEBAUTHN_UV_DISCOURAGED;
    return WEBAUTHN_UV_PREFERRED;
}

static int passkey_sign_in(HWND parent, const char *username, char **err)
{
    webauthn_api *wa = NULL;
    json_t *begin = NULL, *done = NULL;
    buf_t client_data, resp_json;
    char *challenge = NULL;
    const char *challenge_id = NULL, *user_id = NULL, *rp_id = NULL, *uv = NULL;
    wchar_t *rp_id_w = NULL;
    int rc = 0;
    size_t i, ncred = 0;
    PWEBAUTHN_CREDENTIAL creds = NULL;
    HRESULT hr;
    PWEBAUTHN_ASSERTION assertion = NULL;
    DWORD status = 0;

    buf_init(&client_data);
    buf_init(&resp_json);

    wa = webauthn_load();
    if (!wa) {
        *err = _strdup("Passkeys need Windows 10 1903+ with Windows Hello set up. "
                       "Use password sign-in instead.");
        return 0;
    }
    if (wa->GetApiVersionNumber && wa->GetApiVersionNumber() < 1) {
        *err = _strdup("This Windows build does not support the WebAuthn API. "
                       "Use password sign-in instead.");
        goto done;
    }
    if (wa->IsUserVerifyingPlatformAuthenticatorAvailable) {
        BOOL have_uv = FALSE;
        if (SUCCEEDED(wa->IsUserVerifyingPlatformAuthenticatorAvailable(&have_uv)) && !have_uv)
            ui_log("No Windows Hello / security key detected - a security key can still be used.");
    }

    /* 1. ask the server for authentication options */
    {
        buf_t body;
        char *eu = json_escape(username);
        buf_init(&body);
        buf_printf(&body, "{\"username\":\"%s\"}", eu ? eu : "");
        free(eu);
        begin = api_post(&g_api.http, L"/api/passkey/authenticate/begin",
                         (const char *)body.data, NULL, &status, err);
        buf_free(&body);
        if (!begin)
            goto done;
    }

    challenge = _strdup(json_str(begin, "challenge", ""));
    challenge_id = json_str(begin, "challengeId", NULL);
    user_id = json_str(begin, "userId", NULL);
    rp_id = json_str(begin, "rpId", NULL);
    uv = json_str(begin, "userVerification", "preferred");
    if (!challenge || !*challenge || !challenge_id || !user_id) {
        *err = _strdup("Bad WebAuthn options from the server.");
        goto done;
    }
    if (rp_id && *rp_id) {
        rp_id_w = w_from_utf8(rp_id);
    }
    if (!rp_id_w)
        rp_id_w = wcs_dup(g_cfg.rp_id);

    /* 2. build the client data JSON (exactly what the server verifies) */
    {
        char *origin = utf8_from_w(g_cfg.origin);
        buf_printf(&client_data,
                   "{\"type\":\"webauthn.get\",\"challenge\":\"%s\",\"origin\":\"%s\","
                   "\"crossOrigin\":false}",
                   challenge, origin ? origin : "");
        free(origin);
    }

    /* 3. allow-list of credentials registered for this user */
    ncred = json_count(begin, "allowCredentials");
    if (ncred > 0) {
        creds = (PWEBAUTHN_CREDENTIAL)calloc(ncred, sizeof(WEBAUTHN_CREDENTIAL));
        if (!creds) {
            *err = _strdup("Out of memory.");
            goto done;
        }
        ncred = 0;
        for (i = 0; i < json_count(begin, "allowCredentials"); i++) {
            char path[64];
            const char *id64;
            unsigned char *raw;
            size_t rawlen = 0;

            snprintf(path, sizeof(path), "allowCredentials[%u].id", (unsigned)i);
            id64 = json_str(begin, path, NULL);
            if (!id64 || !*id64)
                continue;
            raw = b64u_decode(id64, &rawlen);
            if (!raw || rawlen == 0) {
                free(raw);
                continue;
            }
            creds[ncred].dwVersion = 1;
            creds[ncred].cbId = (DWORD)rawlen;
            creds[ncred].pbId = (PBYTE)raw;
            creds[ncred].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
            ncred++;
        }
    }

    /* 4. run the Windows Hello / security key ceremony */
    {
        WEBAUTHN_CLIENT_DATA cd;
        WEBAUTHN_GET_ASSERTION_OPTIONS opts;
        int timeout = (int)json_int(begin, "timeout", 60000);

        if (timeout < 10000)
            timeout = 10000;
        if (timeout > 295000)
            timeout = 295000;

        memset(&cd, 0, sizeof(cd));
        cd.dwVersion = 1;
        cd.cbClientDataJSON = (DWORD)client_data.len;
        cd.pbClientDataJSON = client_data.data;
        cd.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

        memset(&opts, 0, sizeof(opts));
        opts.dwVersion = 1;
        opts.dwTimeoutMilliseconds = (DWORD)timeout;
        opts.CredentialList.cCredentials = (DWORD)ncred;
        opts.CredentialList.pCredentials = creds;
        opts.dwAuthenticatorAttachment = WEBAUTHN_ATTACHMENT_ANY;
        opts.dwUserVerificationRequirement = (DWORD)uv_requirement(uv);

        hr = wa->AuthenticatorGetAssertion(parent, rp_id_w, &cd, &opts, &assertion);
        if (FAILED(hr) || !assertion) {
            const wchar_t *msg = webauthn_error_text(wa, hr);
            *err = utf8_from_w(msg);
            if (!*err)
                *err = _strdup("Passkey sign-in failed.");
            goto done;
        }
    }

    /* 5. send the assertion to the server */
    {
        char *id64 = b64u_encode(assertion->Credential.pbId, assertion->Credential.cbId);
        char *adh64 = b64u_encode(assertion->pbAuthenticatorData, assertion->cbAuthenticatorData);
        char *sig64 = b64u_encode(assertion->pbSignature, assertion->cbSignature);
        char *cd64 = b64u_encode(client_data.data, client_data.len);
        char *uh64 = assertion->cbUserId
                         ? b64u_encode(assertion->pbUserId, assertion->cbUserId)
                         : NULL;
        buf_t body;

        buf_init(&body);
        buf_printf(&body,
                   "{\"challengeId\":\"%s\",\"userId\":%s,\"response\":{"
                   "\"id\":\"%s\",\"rawId\":\"%s\",\"type\":\"public-key\",\"response\":{"
                   "\"clientDataJSON\":\"%s\",\"authenticatorData\":\"%s\","
                   "\"signature\":\"%s\"%s%s%s}}}",
                   challenge_id, user_id, id64 ? id64 : "", id64 ? id64 : "",
                   cd64 ? cd64 : "", adh64 ? adh64 : "", sig64 ? sig64 : "",
                   uh64 ? ",\"userHandle\":\"" : "", uh64 ? uh64 : "",
                   uh64 ? "\"" : "");
        free(id64);
        free(adh64);
        free(sig64);
        free(cd64);
        free(uh64);

        done = api_post(&g_api.http, L"/api/passkey/authenticate/complete",
                        (const char *)body.data, NULL, &status, err);
        buf_free(&body);
        if (!done)
            goto done;
    }

    {
        const char *token = json_str(done, "token", NULL);
        const char *user = json_str(done, "user.username", username);
        const char *disp = json_str(done, "user.displayName", user);
        if (!token || !*token) {
            *err = _strdup("Server did not return a session token.");
            goto done;
        }
        free(g_api.token);
        g_api.token = _strdup(token);
        MultiByteToWideChar(CP_UTF8, 0, user, -1, g_api.user, (int)ARRAY_LEN(g_api.user));
        MultiByteToWideChar(CP_UTF8, 0, disp, -1, g_api.display, (int)ARRAY_LEN(g_api.display));
        rc = 1;
    }

done:
    if (creds) {
        for (i = 0; i < ncred; i++)
            free(creds[i].pbId);
        free(creds);
    }
    if (assertion && wa)
        wa->FreeAssertion(assertion);
    json_free(begin);
    json_free(done);
    buf_free(&client_data);
    buf_free(&resp_json);
    free(challenge);
    free(rp_id_w);
    webauthn_unload(wa);
    return rc;
}

/* ------------------------------------------------------------------ */
/* update engine                                                      */
/* ------------------------------------------------------------------ */

static int read_installed_version(const wchar_t *app_dir, const wchar_t *exe,
                                  wchar_t out[64])
{
    wchar_t path[32768];
    DWORD dummy = 0, size;
    BYTE *buf;
    lstrcpyW(out, L"0.0.0.0");

    lstrcpyW(path, app_dir);
    lstrcatW(path, exe);
    size = GetFileVersionInfoSizeW(path, &dummy);
    if (size) {
        buf = (BYTE *)malloc(size);
        if (buf) {
            if (GetFileVersionInfoW(path, 0, size, buf)) {
                VS_FIXEDFILEINFO *info = NULL;
                UINT len = 0;
                if (VerQueryValueW(buf, L"\\", (LPVOID *)&info, &len) && info &&
                    len >= sizeof(VS_FIXEDFILEINFO)) {
                    wsprintfW(out, L"%u.%u.%u.%u", HIWORD(info->dwFileVersionMS),
                              LOWORD(info->dwFileVersionMS), HIWORD(info->dwFileVersionLS),
                              LOWORD(info->dwFileVersionLS));
                }
            }
            free(buf);
        }
    }

    /* Fallback: version recorded by a previous launcher-driven update. */
    if (lstrcmpW(out, L"0.0.0.0") == 0) {
        wchar_t vpath[32768], ver[64];
        lstrcpyW(vpath, app_dir);
        lstrcatW(vpath, L"PandoraLauncher.version");
        if (GetPrivateProfileStringW(L"App", L"Version", L"", ver, ARRAY_LEN(ver),
                                     vpath) > 0)
            lstrcpynW(out, ver, 64);
    }
    return 0;
}

static void write_installed_version(const wchar_t *app_dir, const wchar_t *version)
{
    wchar_t vpath[32768];
    lstrcpyW(vpath, app_dir);
    lstrcatW(vpath, L"PandoraLauncher.version");
    WritePrivateProfileStringW(L"App", L"Version", version, vpath);
}

static int find_pids(const wchar_t *exe_name, DWORD *pids, int max)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    int count = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe_name) == 0 && count < max)
                pids[count++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return count;
}

typedef struct {
    DWORD pid;
} close_ctx;

static BOOL CALLBACK enum_close_proc(HWND wnd, LPARAM param)
{
    close_ctx *ctx = (close_ctx *)param;
    DWORD pid = 0;
    GetWindowThreadProcessId(wnd, &pid);
    if (pid == ctx->pid && IsWindowVisible(wnd))
        PostMessageW(wnd, WM_CLOSE, 0, 0);
    return TRUE;
}

/* Asks the running app to close, then force-terminates if it does not. */
static int close_running_app(const wchar_t *exe_name)
{
    DWORD pids[64];
    int count = find_pids(exe_name, pids, (int)ARRAY_LEN(pids));
    int i, still_running = 0;

    if (count == 0)
        return 1; /* nothing running */

    for (i = 0; i < count; i++) {
        close_ctx ctx;
        ctx.pid = pids[i];
        EnumWindows(enum_close_proc, (LPARAM)&ctx);
    }
    for (i = 0; i < count; i++) {
        HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pids[i]);
        if (!h)
            continue;
        if (WaitForSingleObject(h, 15000) == WAIT_TIMEOUT) {
            ui_log("Process %lu did not exit, force-closing...", pids[i]);
            TerminateProcess(h, 0);
            WaitForSingleObject(h, 5000);
        }
        CloseHandle(h);
    }
    Sleep(500);
    if (find_pids(exe_name, pids, (int)ARRAY_LEN(pids)) > 0)
        still_running = 1;
    return still_running ? 0 : 1;
}

/* Copies dir\name under backup_dir, creating parent folders. */
static int backup_file(const wchar_t *app_dir, const wchar_t *backup_dir,
                       const wchar_t *rel_name)
{
    wchar_t src[32768], dst[32768];
    wchar_t *p;

    lstrcpyW(src, app_dir);
    lstrcatW(src, rel_name);
    if (GetFileAttributesW(src) == INVALID_FILE_ATTRIBUTES)
        return 1; /* not replacing anything - nothing to back up */

    lstrcpyW(dst, backup_dir);
    lstrcatW(dst, rel_name);
    for (p = dst + lstrlenW(backup_dir); *p; p++) {
        if (*p == L'/')
            *p = L'\\';
    }
    for (p = dst + lstrlenW(backup_dir); *p; p++) {
        if (*p == L'\\') {
            *p = 0;
            CreateDirectoryW(dst, NULL);
            *p = L'\\';
        }
    }
    if (!CopyFileW(src, dst, FALSE)) {
        ui_log("Backup failed for %s (error %lu)", utf8_from_w(rel_name) ? utf8_from_w(rel_name) : "?", GetLastError());
        return 0;
    }
    return 1;
}

/* Replaces a single file package (kind != "zip"). */
static int apply_single_file(const wchar_t *downloaded, const wchar_t *app_dir,
                             const wchar_t *backup_dir, const char *rel_name_utf8)
{
    wchar_t rel[32768], dst[32768];
    wchar_t *p;

    if (path_is_safe_relative(rel_name_utf8) != 0) {
        ui_log("Refusing unsafe package path: %s", rel_name_utf8);
        return 0;
    }
    {
        wchar_t *w = w_from_utf8(rel_name_utf8);
        if (!w)
            return 0;
        lstrcpynW(rel, w, ARRAY_LEN(rel));
        free(w);
    }
    for (p = rel; *p; p++)
        if (*p == L'/')
            *p = L'\\';

    if (!backup_file(app_dir, backup_dir, rel))
        return 0;

    lstrcpyW(dst, app_dir);
    lstrcatW(dst, rel);
    for (p = dst + lstrlenW(app_dir); *p; p++) {
        if (*p == L'\\') {
            *p = 0;
            CreateDirectoryW(dst, NULL);
            *p = L'\\';
        }
    }
    if (!CopyFileW(downloaded, dst, FALSE)) {
        ui_log("Replace failed for %s (error %lu)", utf8_from_w(rel) ? utf8_from_w(rel) : "?", GetLastError());
        return 0;
    }
    return 1;
}

/* Backs up and extracts one zip package over the app folder. */
static int apply_zip(const wchar_t *zip_path_w, const wchar_t *app_dir,
                     const wchar_t *backup_dir)
{
    char *zip_utf8 = utf8_from_w(zip_path_w);
    char *app_utf8 = utf8_from_w(app_dir);
    char *backup_utf8 = utf8_from_w(backup_dir);
    zip_entry *entries = NULL;
    size_t count = 0, i;
    int ok = 1;

    if (!zip_utf8 || !app_utf8 || !backup_utf8) {
        ui_log("Path conversion failed");
        ok = 0;
        goto out;
    }
    if (zip_list(zip_utf8, &entries, &count) != 0) {
        ui_log("Cannot read update package (not a valid zip?): %s", zip_utf8);
        ok = 0;
        goto out;
    }

    /* 1. back up every file the package will overwrite */
    for (i = 0; i < count && ok; i++) {
        wchar_t rel[32768];
        wchar_t *w;
        wchar_t *p;
        if (path_is_safe_relative(entries[i].name) != 0)
            continue; /* directory entry or unsafe name - skip */
        w = w_from_utf8(entries[i].name);
        if (!w) {
            ok = 0;
            break;
        }
        lstrcpynW(rel, w, ARRAY_LEN(rel));
        free(w);
        for (p = rel; *p; p++)
            if (*p == L'/')
                *p = L'\\';
        if (!backup_file(app_dir, backup_dir, rel))
            ok = 0;
    }

    /* 2. extract */
    for (i = 0; i < count && ok; i++) {
        char *dest;
        int rc;
        if (path_is_safe_relative(entries[i].name) != 0)
            continue;
        dest = path_join(app_utf8, entries[i].name);
        if (!dest) {
            ok = 0;
            break;
        }
        rc = zip_extract_entry(zip_utf8, &entries[i], dest);
        if (rc != 0) {
            ui_log("Extract failed for %s (%s)", entries[i].name,
                   rc == -2 ? "unsupported compression method" : "corrupt archive");
            ok = 0;
        }
        free(dest);
    }

out:
    zip_free(entries, count);
    free(zip_utf8);
    free(app_utf8);
    free(backup_utf8);
    return ok;
}

/* Declared here; defined below (update step helpers). */
static int app_dir_writable(void);
static int already_elevated_retry(void);
static int try_elevate_self(void);
static int launch_app(void);

/*
 * The whole update step: download + verify, close the app, back up, apply.
 * Returns:
 *   0 - nothing to do, or the update failed (the log says why)
 *   1 - an update was applied
 *   2 - this process is restarting itself elevated (caller must stop)
 */
static int run_update_flow(void)
{
    wchar_t cur[64], endpoint[512];
    json_t *check = NULL;
    char *err = NULL;
    DWORD status = 0;
    int update_available = 0;
    size_t npkgs, i;
    char *app_utf8 = NULL;
    int applied = 0;

    read_installed_version(g_cfg.app_dir, g_cfg.app_exe, cur);
    ui_log_wide("Installed version: ", cur);

    {
        char *cur_utf8 = utf8_from_w(cur);
        char url[256];
        wchar_t *w;
        /* Version strings are digits and dots, so no URL escaping is needed. */
        snprintf(url, sizeof(url), "/api/updates/check?app=PandoraTool&current=%s",
                 cur_utf8 ? cur_utf8 : "0.0.0.0");
        free(cur_utf8);
        w = w_from_utf8(url);
        if (!w) {
            ui_log("Out of memory while building the update URL.");
            return 0;
        }
        lstrcpynW(endpoint, w, ARRAY_LEN(endpoint));
        free(w);
    }

    check = api_get(&g_api.http, endpoint, NULL, &status, &err);
    if (!check) {
        ui_log("Update check failed: %s", err ? err : "unknown error");
        free(err);
        return 0;
    }

    update_available = json_bool(check, "updateAvailable", 0);
    npkgs = json_count(check, "packages");
    if (!update_available || npkgs == 0) {
        ui_log("Already up to date (%s).", json_str(check, "latest", "?"));
        json_free(check);
        return 0;
    }

    {
        const char *latest = json_str(check, "latest", "?");
        const char *notes = json_str(check, "notes", NULL);
        app_utf8 = utf8_from_w(g_cfg.app_dir);

        ui_log("Update found: %s", latest);

        /* Work folder for the downloaded packages: <app>\Update\ */
        if (app_utf8) {
            char *update_dir = path_join(app_utf8, "Update");
            if (update_dir) {
                wchar_t *w = w_from_utf8(update_dir);
                if (w) {
                    if (!CreateDirectoryW(w, NULL) &&
                        GetLastError() != ERROR_ALREADY_EXISTS) {
                        ui_log("Cannot create the Update folder (error %lu).",
                               GetLastError());
                        free(w);
                        free(update_dir);
                        goto cleanup;
                    }
                    free(w);
                }
                free(update_dir);
            }
        }
        if (notes && *notes)
            ui_log("%s", notes);

        /*
         * 0. Make sure this process may write to the install folder. This is
         *    the Program Files case: ask Windows to restart us elevated
         *    (single UAC prompt) instead of failing halfway through.
         */
        if (!app_dir_writable()) {
            ui_log("The PandoraTool folder is not writable by this user.");
            if (!already_elevated_retry() && try_elevate_self()) {
                ui_log("Restarting as administrator to install the update...");
                applied = 2;
                PostMessageW(g_main, WM_CLOSE, 0, 0);
                goto cleanup;
            }
            ui_log("Update skipped: start PandoraLauncher.exe as administrator "
                   "(right-click - Run as administrator) to install updates.");
            goto cleanup;
        }

        /* 1. download and verify everything before touching the install */
        for (i = 0; i < npkgs; i++) {
            char path[64];
            const char *file, *hash, *kind;
            long long size;
            wchar_t *file_w, *local_w, *endpoint_w, *token_w;
            char url[1024];
            char *local_utf8;
            char *actual_hash;

            snprintf(path, sizeof(path), "packages[%u].file", (unsigned)i);
            file = json_str(check, path, NULL);
            snprintf(path, sizeof(path), "packages[%u].sha256", (unsigned)i);
            hash = json_str(check, path, NULL);
            snprintf(path, sizeof(path), "packages[%u].kind", (unsigned)i);
            kind = json_str(check, path, "zip");
            snprintf(path, sizeof(path), "packages[%u].size", (unsigned)i);
            size = json_int(check, path, 0);

            if (!file || !*file || path_is_safe_relative(file) != 0 ||
                strstr(file, "..") != NULL) {
                ui_log("Bad manifest entry, update aborted.");
                goto cleanup;
            }
            (void)kind;

            snprintf(url, sizeof(url), "/api/updates/download/%s", file);
            local_utf8 = path_join(app_utf8, "Update");
            {
                char *tmp = path_join(local_utf8, file);
                free(local_utf8);
                local_utf8 = tmp;
            }
            file_w = w_from_utf8(file);
            endpoint_w = w_from_utf8(url);
            local_w = w_from_utf8(local_utf8);
            token_w = w_from_utf8(g_api.token ? g_api.token : "");
            if (!file_w || !endpoint_w || !local_w || !token_w) {
                free(file_w);
                free(endpoint_w);
                free(local_w);
                free(token_w);
                free(local_utf8);
                goto cleanup;
            }

            ui_log("Downloading %s ...", file);
            ui_progress(0);
            if (http_download(&g_api.http, endpoint_w, token_w, local_w,
                              (uint64_t)size) != 0) {
                ui_log("Download failed: %s", file);
                free(file_w);
                free(endpoint_w);
                free(local_w);
                free(token_w);
                free(local_utf8);
                goto cleanup;
            }
            ui_progress(100);

            if (size > 0) {
                FILE *f = _wfopen(local_w, L"rb");
                if (f) {
                    long long actual = 0;
                    _fseeki64(f, 0, SEEK_END);
                    actual = _ftelli64(f);
                    fclose(f);
                    if (actual != size) {
                        ui_log("Size mismatch on %s, update aborted.", file);
                        free(file_w);
                        free(endpoint_w);
                        free(local_w);
                        free(token_w);
                        free(local_utf8);
                        goto cleanup;
                    }
                }
            }
            if (hash && *hash) {
                actual_hash = sha256_file_hex(local_utf8);
                if (!actual_hash || _stricmp(actual_hash, hash) != 0) {
                    ui_log("SHA-256 mismatch on %s, update aborted.", file);
                    free(actual_hash);
                    free(file_w);
                    free(endpoint_w);
                    free(local_w);
                    free(token_w);
                    free(local_utf8);
                    goto cleanup;
                }
                free(actual_hash);
            }
            ui_log("Verified %s", file);
            free(file_w);
            free(endpoint_w);
            free(local_w);
            free(token_w);
            free(local_utf8);
        }

        /* 2. close the running app (Windows cannot overwrite a running .exe) */
        ui_log_wide("Closing ", g_cfg.app_exe);
        if (!close_running_app(g_cfg.app_exe)) {
            ui_log("Could not close the running app, update aborted.");
            goto cleanup;
        }

        /* 3. back up + apply */
        {
            wchar_t backup_dir[32768];
            lstrcpyW(backup_dir, g_cfg.app_dir);
            lstrcatW(backup_dir, L"Backup\\");
            lstrcatW(backup_dir, cur);
            lstrcatW(backup_dir, L"\\");
            CreateDirectoryW(backup_dir, NULL);

            for (i = 0; i < npkgs; i++) {
                char path[64];
                const char *file, *kind;
                char *local_utf8, *update_dir;
                wchar_t *local_w;
                int ok;

                snprintf(path, sizeof(path), "packages[%u].file", (unsigned)i);
                file = json_str(check, path, NULL);
                snprintf(path, sizeof(path), "packages[%u].kind", (unsigned)i);
                kind = json_str(check, path, "zip");
                if (!file)
                    goto cleanup;

                update_dir = path_join(app_utf8, "Update");
                local_utf8 = path_join(update_dir, file);
                free(update_dir);
                local_w = w_from_utf8(local_utf8);
                if (!local_w) {
                    free(local_utf8);
                    goto cleanup;
                }

                if (kind && _stricmp(kind, "zip") == 0)
                    ok = apply_zip(local_w, g_cfg.app_dir, backup_dir);
                else
                    ok = apply_single_file(local_w, g_cfg.app_dir, backup_dir, file);

                if (!ok) {
                    ui_log("Update failed while applying %s.", file);
                    ui_log_wide("Backup kept in ", backup_dir);
                    free(local_w);
                    free(local_utf8);
                    goto cleanup;
                }
                ui_log("Applied %s", file);
                DeleteFileW(local_w);
                free(local_w);
                free(local_utf8);
            }
            ui_log("Updated to %s.", latest);
            ui_log_wide("Backup kept in ", backup_dir);
            {
                wchar_t *latest_w = w_from_utf8(latest);
                if (latest_w) {
                    write_installed_version(g_cfg.app_dir, latest_w);
                    free(latest_w);
                }
            }
        }
        applied = 1;
    }

cleanup:
    json_free(check);
    free(app_utf8);
    if (applied == 0)
        ui_log("Update aborted - PandoraTool.exe was not changed.");
    return applied;
}

/* Can this process create files in the app folder? */
static int app_dir_writable(void)
{
    wchar_t probe[32768];
    HANDLE h;

    lstrcpyW(probe, g_cfg.app_dir);
    lstrcatW(probe, L"PandoraLauncher.write-test");
    h = CreateFileW(probe, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    CloseHandle(h);
    return 1;
}

/* True when this process was started by our own elevation retry. */
static int already_elevated_retry(void)
{
    return wcsstr(GetCommandLineW(), L"--elevated") != NULL;
}

/* Restarts the launcher elevated (UAC). Returns 1 when the elevated copy
 * started, 0 when the user declined or elevation is unavailable. */
static int try_elevate_self(void)
{
    wchar_t self[32768];
    HINSTANCE r;

    if (already_elevated_retry())
        return 0;
    if (GetModuleFileNameW(NULL, self, ARRAY_LEN(self)) == 0)
        return 0;
    r = ShellExecuteW(NULL, L"runas", self, L"--elevated", g_cfg.app_dir,
                      SW_SHOWNORMAL);
    if ((INT_PTR)r <= 32) {
        ui_log("Elevation was declined (code %ld).", (long)(INT_PTR)r);
        return 0;
    }
    return 1;
}

static int launch_app(void)
{
    wchar_t args[8192];
    HINSTANCE r;
    wchar_t exe_path[32768];

    lstrcpyW(exe_path, g_cfg.app_dir);
    lstrcatW(exe_path, g_cfg.app_exe);

    lstrcpynW(args, g_cfg.launch_args, ARRAY_LEN(args));
    if (args[0] && args[lstrlenW(args) - 1] != L' ')
        lstrcatW(args, L" ");
    lstrcatW(args, L"--pandora-session ");
    {
        wchar_t *token = w_from_utf8(g_api.token ? g_api.token : "");
        lstrcatW(args, token ? token : L"");
        free(token);
    }
    lstrcatW(args, L" --pandora-user \"");
    lstrcatW(args, g_api.user);
    lstrcatW(args, L"\"");

    if (GetFileAttributesW(exe_path) == INVALID_FILE_ATTRIBUTES) {
        ui_log_wide("Cannot find the configured app (App\\Exe in launcher.ini): ", g_cfg.app_exe);
        return 0;
    }
    ui_log_wide("Starting ", g_cfg.app_exe);
    r = ShellExecuteW(NULL, L"open", exe_path, args, g_cfg.app_dir, SW_SHOWNORMAL);
    if ((INT_PTR)r <= 32) {
        ui_log("Could not start the app (code %ld)", (long)(INT_PTR)r);
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* login window (modal, runs on the UI thread)                        */
/* ------------------------------------------------------------------ */

static void login_set_busy(int busy)
{
    g_busy = busy;
    EnableWindow(g_edit_user, !busy);
    EnableWindow(g_edit_pass, !busy);
    EnableWindow(g_btn_login, !busy);
    EnableWindow(g_btn_passkey, !busy);
    EnableWindow(g_btn_cancel, !busy);
    SetCursor(LoadCursorW(NULL, busy ? IDC_WAIT : IDC_ARROW));
}

static void login_status(const wchar_t *text)
{
    SetWindowTextW(g_login_status, text);
    UpdateWindow(g_login_status);
}

static void login_status_utf8(char *msg)
{
    wchar_t *w;
    if (!msg)
        return;
    w = w_from_utf8(msg);
    if (w) {
        login_status(w);
        free(w);
    }
    free(msg);
}

static void login_password(void)
{
    wchar_t user_w[256], pass_w[256];
    char *user, *pass, *err = NULL, *err_utf8 = NULL;

    GetWindowTextW(g_edit_user, user_w, ARRAY_LEN(user_w));
    GetWindowTextW(g_edit_pass, pass_w, ARRAY_LEN(pass_w));
    if (user_w[0] == 0) {
        login_status(L"Enter your username.");
        SetFocus(g_edit_user);
        return;
    }
    if (pass_w[0] == 0) {
        login_status(L"Enter your password.");
        SetFocus(g_edit_pass);
        return;
    }

    user = utf8_from_w(user_w);
    pass = utf8_from_w(pass_w);
    login_set_busy(1);
    login_status(L"Signing in...");
    if (api_login(user ? user : "", pass ? pass : "", &err)) {
        g_login_result = 1;
        DestroyWindow(g_login);
    } else {
        err_utf8 = err;
        login_status_utf8(err_utf8);
        login_set_busy(0);
    }
    free(user);
    free(pass);
}

static void login_passkey(void)
{
    wchar_t user_w[256];
    char *user, *err = NULL;
    char status[256];

    GetWindowTextW(g_edit_user, user_w, ARRAY_LEN(user_w));
    if (user_w[0] == 0) {
        login_status(L"Enter your username, then use your passkey.");
        SetFocus(g_edit_user);
        return;
    }
    user = utf8_from_w(user_w);
    login_set_busy(1);
    login_status(L"Waiting for Windows Hello / security key ...");
    if (passkey_sign_in(g_login, user ? user : "", &err)) {
        g_login_result = 1;
        DestroyWindow(g_login);
    } else {
        if (err && strlen(err) < 200) {
            snprintf(status, sizeof(status), "%s", err);
            login_status_utf8(_strdup(status));
        } else {
            login_status(L"Passkey sign-in failed.");
        }
        free(err);
        login_set_busy(0);
    }
    free(user);
}

static LRESULT CALLBACK login_proc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDOK:
            if (!g_busy)
                login_password();
            return 0;
        case IDCANCEL:
            if (!g_busy) {
                g_login_result = 0;
                DestroyWindow(wnd);
            }
            return 0;
        case 101: /* Sign in with passkey */
            if (!g_busy)
                login_passkey();
            return 0;
        }
        break;
    case WM_CLOSE:
        if (!g_busy) {
            g_login_result = 0;
            DestroyWindow(wnd);
        }
        return 0;
    case DM_GETDEFID: /* makes Enter trigger the default button */
        return MAKELONG(IDOK, DC_HASDEFID);
    case WM_CTLCOLORSTATIC:
        if ((HWND)lp == g_login_status) {
            SetTextColor((HDC)wp, RGB(0xB0, 0x20, 0x20));
            SetBkMode((HDC)wp, TRANSPARENT);
            return (LRESULT)GetSysColorBrush(COLOR_3DFACE);
        }
        break;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

static HWND make_control(const wchar_t *cls, const wchar_t *text, DWORD style,
                         DWORD exstyle, int x, int y, int w, int height, HWND parent,
                         HFONT font, int id)
{
    HWND ctl = CreateWindowExW(exstyle, cls, text, WS_CHILD | WS_VISIBLE | style, x, y,
                               w, height, parent, (HMENU)(INT_PTR)id,
                               GetModuleHandleW(NULL), NULL);
    if (ctl && font)
        SendMessageW(ctl, WM_SETFONT, (WPARAM)font, TRUE);
    return ctl;
}

static void login_create_controls(HWND wnd)
{
    g_login_status = make_control(L"STATIC", L"", SS_LEFT, 0, 24, 210, 332, 40, wnd,
                                  g_font, 0);
    make_control(L"STATIC", L"Sign in to Pandora Tool", SS_CENTER, 0, 24, 16, 332,
                 28, wnd, g_font_title, 0);
    make_control(L"STATIC", L"Username", SS_LEFT, 0, 24, 56, 120, 18, wnd, g_font, 0);
    g_edit_user = make_control(L"EDIT", L"", ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, 24, 74,
                               332, 26, wnd, g_font, 100);
    make_control(L"STATIC", L"Password", SS_LEFT, 0, 24, 108, 120, 18, wnd, g_font, 0);
    g_edit_pass = make_control(L"EDIT", L"", ES_AUTOHSCROLL | ES_PASSWORD,
                               WS_EX_CLIENTEDGE, 24, 126, 332, 26, wnd, g_font, 102);
    g_btn_login = make_control(L"BUTTON", L"Sign in", BS_DEFPUSHBUTTON, 0, 24, 164,
                               332, 30, wnd, g_font, IDOK);
    g_btn_passkey = make_control(L"BUTTON", L"Sign in with passkey", BS_PUSHBUTTON, 0,
                                 24, 200, 332, 30, wnd, g_font, 101);
    g_btn_cancel = make_control(L"BUTTON", L"Cancel", BS_PUSHBUTTON, 0, 24, 240, 332,
                                30, wnd, g_font, IDCANCEL);
}

/* Returns 1 when sign-in succeeded. Runs on the UI thread. */
static int do_login_modal(void)
{
    WNDCLASSEXW wc;
    HWND wnd;
    MSG msg;
    int had_quit = 0;

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = login_proc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_3DFACE + 1);
    wc.lpszClassName = L"PandoraLauncherLogin";
    RegisterClassExW(&wc);

    g_login_result = 0;
    g_busy = 0;
    wnd = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT,
                          L"PandoraLauncherLogin", L"Pandora Tool - Sign in",
                          WS_POPUP | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT,
                          CW_USEDEFAULT, 396, 316, g_main, NULL,
                          GetModuleHandleW(NULL), NULL);
    if (!wnd)
        return 0;
    g_login = wnd;
    login_create_controls(wnd);
    EnableWindow(g_main, FALSE);
    ShowWindow(wnd, SW_SHOW);
    SetFocus(g_edit_user);

    while (IsWindow(wnd)) {
        BOOL got = GetMessageW(&msg, NULL, 0, 0);
        if (got == 0) {
            had_quit = 1;
            break;
        }
        if (!IsDialogMessageW(wnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    g_login = NULL;
    EnableWindow(g_main, TRUE);
    SetActiveWindow(g_main);
    if (had_quit)
        PostQuitMessage(0);
    return g_login_result;
}

/* ------------------------------------------------------------------ */
/* flow thread                                                        */
/* ------------------------------------------------------------------ */

static int g_flow_running;

static DWORD WINAPI flow_thread(LPVOID param)
{
    int launched = 0;
    (void)param;

    config_load();

    ui_log("Pandora Launcher");
    ui_log_wide("Server: ", g_cfg.base_url);

    if (http_open(&g_api.http, g_cfg.base_url) != 0) {
        ui_status("Invalid server URL in launcher.ini.");
        ui_log_wide("BaseURL is not a valid http(s) URL: ", g_cfg.base_url);
        goto done;
    }

    /* 1. sign in (password or passkey) - required for update downloads */
    ui_status("Waiting for sign-in...");
    if (!SendMessageW(g_main, WM_APP_DO_LOGIN, 0, 0)) {
        ui_status("Sign-in cancelled.");
        goto done;
    }
    ui_log_wide("Signed in as ", g_api.user);

    /* 2. update */
    if (g_cfg.auto_update) {
        int upd;
        ui_status("Checking for updates...");
        PostMessageW(g_main, WM_APP_BUSY, 1, 0);
        upd = run_update_flow();
        PostMessageW(g_main, WM_APP_BUSY, 0, 0);
        ui_progress(0);
        if (upd == 2)
            goto done; /* an elevated copy of the launcher takes over */
    }

    /* 3. start the tool with the login session */
    launched = launch_app();
    ui_status(launched ? "Running." : "Could not start the app - see the log.");

done:
    http_close(&g_api.http);
    PostMessageW(g_main, WM_APP_DONE, 0, launched);
    return 0;
}

static void flow_start(void)
{
    HANDLE h;
    if (g_flow_running)
        return;
    g_flow_running = 1;
    if (g_btn_run)
        EnableWindow(g_btn_run, FALSE);
    h = CreateThread(NULL, 0, flow_thread, NULL, 0, NULL);
    if (h)
        CloseHandle(h);
    else
        g_flow_running = 0;
}

/* ------------------------------------------------------------------ */
/* main window                                                        */
/* ------------------------------------------------------------------ */

static void main_create_controls(HWND wnd)
{
    g_status = make_control(L"STATIC", L"Ready.", SS_LEFT, 0, 12, 8, 596, 20, wnd,
                            g_font, 0);
    g_log = make_control(L"EDIT", L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL |
                                       WS_VSCROLL | WS_TABSTOP,
                         WS_EX_CLIENTEDGE, 12, 34, 596, 320, wnd, g_font, 200);
    g_progress = make_control(PROGRESS_CLASSW, L"", 0, 0, 12, 364, 596, 18, wnd,
                              g_font, 0);
    SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    g_btn_run = make_control(L"BUTTON", L"Start", BS_PUSHBUTTON | WS_TABSTOP, 0, 436,
                             396, 80, 28, wnd, g_font, 300);
    g_btn_exit = make_control(L"BUTTON", L"Exit", BS_PUSHBUTTON | WS_TABSTOP, 0, 528,
                              396, 80, 28, wnd, g_font, 301);
}

static LRESULT CALLBACK main_proc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        main_create_controls(wnd);
        return 0;
    case WM_APP_LOG: {
        wchar_t *text = (wchar_t *)lp;
        int len = GetWindowTextLengthW(g_log);
        SendMessageW(g_log, EM_SETSEL, (WPARAM)len, (LPARAM)len);
        SendMessageW(g_log, EM_REPLACESEL, FALSE, (LPARAM)text);
        SendMessageW(g_log, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
        SendMessageW(g_log, EM_SCROLLCARET, 0, 0);
        free(text);
        return 0;
    }
    case WM_APP_STATUS: {
        wchar_t *text = (wchar_t *)lp;
        SetWindowTextW(g_status, text);
        free(text);
        return 0;
    }
    case WM_APP_PROGRESS: {
        int pct = (int)wp;
        if (pct < 0)
            pct = 0;
        if (pct > 100)
            pct = 100;
        SendMessageW(g_progress, PBM_SETPOS, (WPARAM)pct, 0);
        return 0;
    }
    case WM_APP_DO_LOGIN:
        return (LRESULT)do_login_modal();
    case WM_APP_BUSY:
        g_busy = (int)wp;
        SetCursor(LoadCursorW(NULL, g_busy ? IDC_WAIT : IDC_ARROW));
        return 0;
    case WM_APP_DONE:
        g_flow_running = 0;
        g_busy = 0;
        if (g_btn_run)
            EnableWindow(g_btn_run, TRUE);
        if (lp && g_cfg.auto_launch)
            PostMessageW(wnd, WM_CLOSE, 0, 0); /* app started: close the launcher */
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == 300)
            flow_start();
        else if (LOWORD(wp) == 301)
            PostMessageW(wnd, WM_CLOSE, 0, 0);
        return 0;
    case WM_CLOSE:
        if (g_busy) {
            /* A flow is mid-flight; ask before quitting. */
            if (MessageBoxW(wnd, L"An update is in progress. Quit anyway?",
                             L"Pandora Launcher", MB_ICONWARNING | MB_YESNO) != IDYES)
                return 0;
        }
        DestroyWindow(wnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

static void get_app_dir(wchar_t *out, size_t out_count)
{
    DWORD n = GetModuleFileNameW(NULL, out, (DWORD)out_count);
    wchar_t *p;
    if (n == 0 || n >= out_count) {
        out[0] = 0;
        return;
    }
    p = wcsrchr(out, L'\\');
    if (p)
        p[1] = 0;
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmdline, int show)
{
    WNDCLASSEXW wc;
    HWND wnd;
    MSG msg;
    HWND existing;

    (void)inst;
    (void)prev;
    (void)cmdline;
    (void)show;

    /* Single instance: if the launcher is already open, focus it. (When we
     * elevate ourselves the original process is on its way out, so the flag
     * below lets the new one start.) */
    existing = wcsstr(GetCommandLineW(), L"--elevated")
                   ? NULL
                   : FindWindowW(L"PandoraLauncherMain", NULL);
    if (existing) {
        ShowWindow(existing, SW_RESTORE);
        SetForegroundWindow(existing);
        return 0;
    }

    get_app_dir(g_cfg.app_dir, ARRAY_LEN(g_cfg.app_dir));

    InitCommonControls();

    g_font = font_from_system(0, 0, NULL);
    g_font_bold = font_from_system(1, 0, NULL);
    g_font_title = font_from_system(1, 4, NULL);

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = main_proc;
    wc.hInstance = inst;
    wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"PandoraLauncherMain";
    wc.hIconSm = wc.hIcon;
    if (!RegisterClassExW(&wc))
        return 1;

    /* 620x432 client area, not resizable. */
    wnd = CreateWindowExW(0, L"PandoraLauncherMain", L"Pandora Launcher",
                          WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                          CW_USEDEFAULT, CW_USEDEFAULT, 634, 505, NULL, NULL, inst,
                          NULL);
    if (!wnd)
        return 1;
    g_main = wnd;

    ShowWindow(wnd, SW_SHOW);
    UpdateWindow(wnd);

    /* Kick the flow off as soon as the window is up (like the Delphi timer). */
    PostMessageW(wnd, WM_COMMAND, 300, 0);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_font)
        DeleteObject(g_font);
    if (g_font_bold)
        DeleteObject(g_font_bold);
    if (g_font_title)
        DeleteObject(g_font_title);
    free(g_api.token);
    return 0;
}
