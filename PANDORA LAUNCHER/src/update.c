/*
 * update.c - version check, verified download, close, backup, apply, relaunch.
 *
 * How a running app gets updated on Windows:
 *   1. every package is downloaded and hash-verified BEFORE anything is touched
 *   2. the running PandoraTool.exe is asked to close (WM_CLOSE), waited on,
 *      then force-closed if it is still there - Windows cannot overwrite a
 *      running .exe
 *   3. files that are about to be replaced are copied to Backup\<old-version>\
 *   4. the .zip packages are unpacked over the install folder
 *   5. the app is started again with the login session on its command line
 *
 * If a step fails, the Backup folder lets you restore the previous version by
 * hand.
 */
#include "pandora.h"

#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* installed version                                                   */
/* ------------------------------------------------------------------ */

int app_installed_version(const char *exe_path, char *out, size_t outsz)
{
    DWORD dummy = 0, size;
    wchar_t *wpath = NULL;
    void *buf = NULL;
    int ok = 0;

    snprintf(out, outsz, "0.0.0.0");
    {
        int n = MultiByteToWideChar(CP_UTF8, 0, exe_path, -1, NULL, 0);
        if (n > 0) {
            wpath = (wchar_t *)p_malloc((size_t)n * sizeof(wchar_t));
            MultiByteToWideChar(CP_UTF8, 0, exe_path, -1, wpath, n);
        }
    }
    if (!wpath)
        return -1;

    size = GetFileVersionInfoSizeW(wpath, &dummy);
    if (size == 0)
        goto done;
    buf = p_malloc(size);
    if (!GetFileVersionInfoW(wpath, 0, size, buf))
        goto done;
    {
        VS_FIXEDFILEINFO *info = NULL;
        UINT len = 0;
        if (VerQueryValueW(buf, L"\\", (LPVOID *)&info, &len) && info && len >= sizeof(*info)) {
            snprintf(out, outsz, "%u.%u.%u.%u",
                     (unsigned)HIWORD(info->dwFileVersionMS),
                     (unsigned)LOWORD(info->dwFileVersionMS),
                     (unsigned)HIWORD(info->dwFileVersionLS),
                     (unsigned)LOWORD(info->dwFileVersionLS));
            ok = 1;
        }
    }
done:
    free(buf);
    free(wpath);
    return ok ? 0 : -1;
}

int app_is_elevated(void)
{
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(elevation);
    int elevated = 0;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenElevation, &elevation, size, &size))
            elevated = elevation.TokenIsElevated ? 1 : 0;
        CloseHandle(token);
    }
    return elevated;
}

/* ------------------------------------------------------------------ */
/* close / launch                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    DWORD pid;
} close_ctx;

static BOOL CALLBACK enum_close_proc(HWND wnd, LPARAM param)
{
    DWORD pid = 0;
    GetWindowThreadProcessId(wnd, &pid);
    if (pid == ((close_ctx *)param)->pid && IsWindowVisible(wnd))
        PostMessageW(wnd, WM_CLOSE, 0, 0);
    return TRUE;
}

static int find_pids(const char *exe_name, DWORD *pids, int max)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    int n = 0;
    wchar_t *wexe = NULL;
    int wn = MultiByteToWideChar(CP_UTF8, 0, exe_name, -1, NULL, 0);

    if (wn > 0) {
        wexe = (wchar_t *)p_malloc((size_t)wn * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, exe_name, -1, wexe, wn);
    }
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        free(wexe);
        return 0;
    }
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (wexe && _wcsicmp(pe.szExeFile, wexe) == 0 && n < max)
                pids[n++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    free(wexe);
    return n;
}

int app_close_running(const char *exe_name, void (*log)(void *, const char *), void *ud)
{
    DWORD pids[64];
    int n, i;

    n = find_pids(exe_name, pids, 64);
    if (n == 0)
        return 0;   /* not running */

    for (i = 0; i < n; i++) {
        close_ctx ctx;
        ctx.pid = pids[i];
        EnumWindows(enum_close_proc, (LPARAM)&ctx);
    }
    for (i = 0; i < n; i++) {
        HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pids[i]);
        if (!h)
            continue;   /* already gone */
        if (WaitForSingleObject(h, 15000) == WAIT_TIMEOUT) {
            if (log)
                log(ud, "Process did not exit, force-closing...");
            TerminateProcess(h, 0);
            WaitForSingleObject(h, 5000);
        }
        CloseHandle(h);
    }
    Sleep(500);
    return find_pids(exe_name, pids, 64) == 0 ? 0 : -1;
}

int app_launch(const char *app_dir, const char *exe_name, const char *args)
{
    char exe_path[2048];
    wchar_t *wexe = NULL, *wargs = NULL, *wdir = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    int n, rc = -1;

    fs_join(exe_path, sizeof(exe_path), app_dir, exe_name);
    n = MultiByteToWideChar(CP_UTF8, 0, exe_path, -1, NULL, 0);
    if (n > 0) {
        wexe = (wchar_t *)p_malloc((size_t)n * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, exe_path, -1, wexe, n);
    }
    n = MultiByteToWideChar(CP_UTF8, 0, args ? args : "", -1, NULL, 0);
    if (n > 0) {
        wargs = (wchar_t *)p_malloc((size_t)n * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, args ? args : "", -1, wargs, n);
    }
    n = MultiByteToWideChar(CP_UTF8, 0, app_dir, -1, NULL, 0);
    if (n > 0) {
        wdir = (wchar_t *)p_malloc((size_t)n * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, app_dir, -1, wdir, n);
    }
    if (!wexe || !wargs || !wdir)
        goto done;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    {
        /* CreateProcess needs the quoted image path plus the arguments */
        wchar_t *cmdline = (wchar_t *)p_malloc((wcslen(wexe) + wcslen(wargs) + 8) *
                                               sizeof(wchar_t));
        wcscpy(cmdline, L"\"");
        wcscat(cmdline, wexe);
        wcscat(cmdline, L"\" ");
        wcscat(cmdline, wargs);
        if (CreateProcessW(wexe, cmdline, NULL, NULL, FALSE, 0, NULL, wdir, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            rc = 0;
        }
        free(cmdline);
    }
done:
    free(wexe);
    free(wargs);
    free(wdir);
    return rc;
}

int app_relaunch_elevated(const char *exe_path, const char *app_dir)
{
    wchar_t *wexe = NULL, *wdir = NULL;
    HINSTANCE r;
    int n;

    n = MultiByteToWideChar(CP_UTF8, 0, exe_path, -1, NULL, 0);
    if (n > 0) {
        wexe = (wchar_t *)p_malloc((size_t)n * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, exe_path, -1, wexe, n);
    }
    n = MultiByteToWideChar(CP_UTF8, 0, app_dir, -1, NULL, 0);
    if (n > 0) {
        wdir = (wchar_t *)p_malloc((size_t)n * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, app_dir, -1, wdir, n);
    }
    if (!wexe) {
        free(wdir);
        return -1;
    }
    r = ShellExecuteW(NULL, L"runas", wexe, NULL, wdir, SW_SHOWNORMAL);
    free(wexe);
    free(wdir);
    return ((INT_PTR)r > 32) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* update check                                                        */
/* ------------------------------------------------------------------ */

void update_info_free(update_info *u)
{
    free(u->latest);
    free(u->notes);
    json_free(u->packages);
    memset(u, 0, sizeof(*u));
}

int update_check(http_client *c, const char *current, update_info *out, char *err,
                 size_t errlen)
{
    http_resp r;
    json *j = NULL;
    char *q_app, *q_cur;
    char path[512];
    int rc = -1;

    memset(out, 0, sizeof(*out));
    q_app = url_encode_query(PANDORA_APP_NAME);
    q_cur = url_encode_query(current && *current ? current : "0.0.0.0");
    snprintf(path, sizeof(path), "/api/updates/check?app=%s&current=%s", q_app, q_cur);
    free(q_app);
    free(q_cur);

    if (http_get(c, path, NULL, &r, err, errlen) != 0)
        return -1;
    j = json_parse(r.body, r.len);
    if (!j) {
        snprintf(err, errlen, "Invalid server response (update check)");
        goto done;
    }
    out->available = json_bool(j, "updateAvailable", 0);
    out->latest = p_strdup(json_str(j, "latest", current ? current : ""));
    out->notes = p_strdup(json_str(j, "notes", ""));
    if (out->available) {
        const json *pkgs = json_get(j, "packages");
        if (!pkgs || json_len(pkgs) == 0) {
            out->available = 0;   /* nothing to install */
        } else {
            out->packages = (json *)pkgs;
            /* keep the packages subtree, free the rest */
            {
                json *whole = j;
                size_t i;
                for (i = 0; i < whole->nkeys; i++) {
                    if (whole->vals[i] == pkgs) {
                        whole->vals[i] = NULL;   /* transferred to out */
                        break;
                    }
                }
                json_free(whole);
                j = NULL;
            }
        }
    }
    rc = 0;
done:
    json_free(j);
    http_resp_free(&r);
    return rc;
}

/* ------------------------------------------------------------------ */
/* download + apply                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    void (*log)(void *, const char *);
    void (*progress)(void *, int);
    void *ud;
    int64_t total_bytes;   /* sum of every package size in the manifest */
    int64_t base_bytes;    /* bytes of the packages already verified */
    int64_t done_bytes;
    int     zip_shown;     /* limits "Unpacking" lines in the log */
} up_progress;

/* a .zip always starts with "PK\x03\x04" (empty zips with "PK\x05\x06") */
static int file_is_zip(const char *path)
{
    FILE *f = fs_fopen_read(path);
    unsigned char sig[4] = { 0, 0, 0, 0 };
    size_t got;

    if (!f)
        return 0;
    got = fread(sig, 1, 4, f);
    fclose(f);
    return got == 4 && sig[0] == 'P' && sig[1] == 'K';
}

static int is_safe_file_name(const char *name)
{
    const char *p;
    if (!name || !*name)
        return 0;
    if (strstr(name, ".."))
        return 0;
    for (p = name; *p; p++)
        if (*p == '/' || *p == '\\' || *p == ':')
            return 0;
    return 1;
}

static void up_log(up_progress *up, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (up->log)
        up->log(up->ud, buf);
}

static void zip_entry_log(void *ud, const char *name)
{
    /* one line per member would flood the window for big packages */
    up_progress *up = (up_progress *)ud;
    if (up->zip_shown < 12) {
        char line[512];
        snprintf(line, sizeof(line), "  %s", name);
        if (up->log)
            up->log(up->ud, line);
        up->zip_shown++;
        if (up->zip_shown == 12 && up->log)
            up->log(up->ud, "  ...");
    }
}

static void http_progress_cb(void *ud, int64_t got, int64_t total, int *abort)
{
    up_progress *up = (up_progress *)ud;
    (void)total;
    (void)abort;
    up->done_bytes = up->base_bytes + got;
    if (up->progress) {
        int pct = up->total_bytes > 0
                      ? (int)(up->done_bytes * 100 / up->total_bytes)
                      : 0;
        if (pct > 100)
            pct = 100;
        up->progress(up->ud, pct);
    }
}

int update_download_and_apply(http_client *c, const char *token, const app_ctx *app,
                              const json *packages, const char *latest,
                              void (*log)(void *, const char *),
                              void (*progress)(void *, int), void *ud,
                              char *err, size_t errlen)
{
    up_progress up;
    size_t count = json_len(packages), i;
    char work_dir[2048], backup_dir[2048];
    char *names = NULL;
    int rc = -1;

    memset(&up, 0, sizeof(up));
    up.log = log;
    up.progress = progress;
    up.ud = ud;

    fs_join(work_dir, sizeof(work_dir), app->app_dir, "Update");
    fs_join(backup_dir, sizeof(backup_dir), app->app_dir, "Backup");
    {
        char sub[2048];
        fs_join(sub, sizeof(sub), backup_dir, app->version);
        snprintf(backup_dir, sizeof(backup_dir), "%s", sub);
    }
    fs_remove_tree(work_dir);
    if (fs_mkdirs(work_dir) != 0) {
        snprintf(err, errlen, "cannot create %s (access denied?)", work_dir);
        return -1;
    }

    /* total size for the progress bar */
    up.total_bytes = 0;
    for (i = 0; i < count; i++) {
        const json *pkg = json_at(packages, i);
        up.total_bytes += (int64_t)json_num(pkg, "size", 0);
    }

    /* ---- 1. download and verify everything first ---- */
    for (i = 0; i < count; i++) {
        const json *pkg = json_at(packages, i);
        const char *file = json_str(pkg, "file", "");
        const char *hash = json_str(pkg, "sha256", "");
        int64_t size = (int64_t)json_num(pkg, "size", 0);
        char local[2048];
        char hex[65];
        int64_t got;

        if (!is_safe_file_name(file)) {
            snprintf(err, errlen, "The update manifest has an invalid file name");
            goto cleanup;
        }
        fs_join(local, sizeof(local), work_dir, file);
        up_log(&up, "Downloading %s ...", file);
        if (progress)
            progress(ud, 0);

        {
            char *path = p_asprintf("/api/updates/download/%s", url_encode_query(file));
            int dr = http_get_file(c, path, token, local, http_progress_cb, &up, err, errlen);
            free(path);
            if (dr != 0)
                goto cleanup;
        }
        got = fs_size(local);
        if (size > 0 && got != size) {
            snprintf(err, errlen, "Size mismatch on %s (got %lld, expected %lld)",
                     file, (long long)got, (long long)size);
            goto cleanup;
        }
        if (!hash || !*hash) {
            up_log(&up, "  (no SHA-256 in the manifest for %s - not verified)", file);
        }
        if (hash && *hash) {
            if (sha256_file(local, hex, err, errlen) != 0) {
                snprintf(err, errlen, "cannot read %s", file);
                goto cleanup;
            }
            {
                char want[128];
                size_t k;
                snprintf(want, sizeof(want), "%s", hash);
                for (k = 0; want[k]; k++)
                    want[k] = (char)tolower((unsigned char)want[k]);
                if (strcmp(hex, want) != 0) {
                    snprintf(err, errlen, "SHA-256 mismatch on %s - update aborted", file);
                    goto cleanup;
                }
            }
        }
        up_log(&up, "Verified %s", file);
        up.base_bytes += got;
        up.done_bytes = up.base_bytes;
        if (progress)
            progress(ud, up.total_bytes > 0
                            ? (int)(up.base_bytes * 100 / up.total_bytes)
                            : 100);
    }

    /* ---- 2. close the running app ---- */
    free(names);
    names = p_strdup(app->app_exe);
    up_log(&up, "Closing %s ...", app->app_exe);
    if (app_close_running(app->app_exe, log, ud) != 0) {
        snprintf(err, errlen, "Could not close the running app - close it by hand and "
                              "run the launcher again");
        goto cleanup;
    }

    /* ---- 3. apply ---- */
    fs_mkdirs(backup_dir);
    for (i = 0; i < count; i++) {
        const json *pkg = json_at(packages, i);
        const char *file = json_str(pkg, "file", "");
        const char *kind = json_str(pkg, "kind", "zip");
        char local[2048];
        int is_zip;

        fs_join(local, sizeof(local), work_dir, file);
        /* Trust the bytes over the manifest: "kind" defaults to "zip" even for
         * .exe/.dll packages, and a zip always starts with "PK". */
        is_zip = ascii_icmp(kind, "zip") == 0 && file_is_zip(local);
        if (is_zip) {
            char zerr[512];
            up_log(&up, "Unpacking %s ...", file);
            up.zip_shown = 0;
            zerr[0] = 0;
            if (zip_extract(local, app->app_dir, backup_dir, zip_entry_log, &up,
                            zerr, sizeof(zerr)) != 0) {
                snprintf(err, errlen, "%s", zerr[0] ? zerr : "cannot unpack the package");
                goto cleanup;
            }
        } else {
            /* single file: back up the target, then replace it */
            char target[2048];
            fs_join(target, sizeof(target), app->app_dir, file);
            if (fs_exists(target)) {
                char bak[2048];
                fs_join(bak, sizeof(bak), backup_dir, file);
                if (fs_copy(target, bak, 1) != 0) {
                    snprintf(err, errlen, "Backup failed for %s", file);
                    goto cleanup;
                }
            }
            if (ascii_icmp(kind, "zip") == 0 && !is_zip)
                up_log(&up, "  (%s is not a zip - replacing it as a single file)",
                       file);
            if (fs_move_over(local, target) != 0) {
                int e = fs_last_error();
                snprintf(err, errlen, "Replace failed for %s (error %d%s)", file, e,
                         fs_err_is_access_denied(e)
                             ? " - access denied, run the launcher as administrator"
                             : "");
                goto cleanup;
            }
        }
        up_log(&up, "Applied %s", file);
        fs_delete(local);
    }

    up_log(&up, "Updated to %s. The previous version is in %s", latest, backup_dir);
    rc = 0;

cleanup:
    free(names);
    fs_remove_tree(work_dir);
    return rc;
}
