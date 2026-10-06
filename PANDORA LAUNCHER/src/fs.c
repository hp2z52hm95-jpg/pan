/*
 * fs.c - file system helpers.
 *
 * On Windows every path is UTF-8 and is converted to UTF-16 before the call,
 * so installs in folders with non-ASCII names work. On POSIX (host tests) the
 * same code runs on plain fopen/mkdir so the update logic can be tested.
 */
#include "pandora.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#endif

/* ------------------------------------------------------------------ */
/* UTF-8 <-> UTF-16                                                    */
/* ------------------------------------------------------------------ */

#ifdef _WIN32
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

char *w2u(const wchar_t *w)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *s;
    if (n <= 0)
        return p_strdup("");
    s = (char *)p_malloc((size_t)n);
    if (WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL) <= 0) {
        free(s);
        return p_strdup("");
    }
    return s;
}
#endif

FILE *fs_fopen_read(const char *path)
{
#ifdef _WIN32
    wchar_t *w = u2w(path);
    FILE *f;
    if (!w)
        return NULL;
    f = _wfopen(w, L"rb");
    free(w);
    return f;
#else
    return fopen(path, "rb");
#endif
}

FILE *fs_fopen_write(const char *path, int append)
{
#ifdef _WIN32
    wchar_t *w = u2w(path);
    FILE *f;
    if (!w)
        return NULL;
    f = _wfopen(w, append ? L"ab" : L"wb");
    free(w);
    return f;
#else
    return fopen(path, append ? "ab" : "wb");
#endif
}

/* ------------------------------------------------------------------ */
/* queries                                                             */
/* ------------------------------------------------------------------ */

int fs_exists(const char *path)
{
#ifdef _WIN32
    wchar_t *w = u2w(path);
    DWORD a;
    int r;
    if (!w)
        return 0;
    a = GetFileAttributesW(w);
    r = (a != INVALID_FILE_ATTRIBUTES);
    free(w);
    return r;
#else
    struct stat st;
    return stat(path, &st) == 0;
#endif
}

int fs_is_dir(const char *path)
{
#ifdef _WIN32
    wchar_t *w = u2w(path);
    DWORD a;
    int r = 0;
    if (!w)
        return 0;
    a = GetFileAttributesW(w);
    if (a != INVALID_FILE_ATTRIBUTES)
        r = (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
    free(w);
    return r;
#else
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

int64_t fs_size(const char *path)
{
#ifdef _WIN32
    wchar_t *w = u2w(path);
    WIN32_FILE_ATTRIBUTE_DATA fd;
    int64_t r = -1;
    if (!w)
        return -1;
    if (GetFileAttributesExW(w, GetFileExInfoStandard, &fd))
        r = ((int64_t)fd.nFileSizeHigh << 32) | (int64_t)fd.nFileSizeLow;
    free(w);
    return r;
#else
    struct stat st;
    return stat(path, &st) == 0 ? (int64_t)st.st_size : -1;
#endif
}

int fs_read_all(const char *path, char **out, size_t *len)
{
    FILE *f = fs_fopen_read(path);
    sbuf b;
    char chunk[16384];
    size_t got;

    *out = NULL;
    if (len)
        *len = 0;
    if (!f)
        return -1;
    sb_init(&b);
    while ((got = fread(chunk, 1, sizeof(chunk), f)) > 0)
        sb_add(&b, chunk, got);
    fclose(f);
    if (len)
        *len = b.len;
    *out = sb_take(&b);
    return 0;
}

int fs_write_all(const char *path, const void *data, size_t len, char *err, size_t errlen)
{
    FILE *f = fs_fopen_write(path, 0);
    if (!f) {
        if (err)
            snprintf(err, errlen, "cannot create %s", path);
        return -1;
    }
    if (len && fwrite(data, 1, len, f) != len) {
        if (err)
            snprintf(err, errlen, "write failed for %s", path);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

int fs_mkdirs(const char *path)
{
    char tmp[4096];
    size_t i, n;

    if (!path || !*path)
        return 0;
    if (fs_is_dir(path))
        return 0;
    n = strlen(path);
    if (n >= sizeof(tmp))
        return -1;
    memcpy(tmp, path, n + 1);
    for (i = 1; i < n; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            char c = tmp[i];
            tmp[i] = 0;
            if (tmp[0] && !(i == 2 && tmp[1] == ':')) {
                if (!fs_is_dir(tmp)) {
#ifdef _WIN32
                    wchar_t *w = u2w(tmp);
                    if (w) {
                        CreateDirectoryW(w, NULL);
                        free(w);
                    }
#else
                    mkdir(tmp, 0777);
#endif
                }
            }
            tmp[i] = c;
        }
    }
#ifdef _WIN32
    {
        wchar_t *w = u2w(tmp);
        int r = 0;
        if (w) {
            if (!CreateDirectoryW(w, NULL) && fs_last_error() != 183 /*ALREADY_EXISTS*/)
                r = -1;
            free(w);
        } else
            r = -1;
        return r;
    }
#else
    if (mkdir(tmp, 0777) != 0 && !fs_is_dir(tmp))
        return -1;
    return 0;
#endif
}

int fs_copy(const char *src, const char *dst, int fail_if_exists)
{
#ifdef _WIN32
    wchar_t *ws = u2w(src);
    wchar_t *wd = u2w(dst);
    int r;
    if (!ws || !wd) {
        free(ws);
        free(wd);
        return -1;
    }
    r = CopyFileW(ws, wd, fail_if_exists ? TRUE : FALSE) ? 0 : -1;
    free(ws);
    free(wd);
    return r;
#else
    FILE *a = fs_fopen_read(src), *b;
    char buf[65536];
    size_t got;
    if (!a)
        return -1;
    if (fail_if_exists && fs_exists(dst)) {
        fclose(a);
        return -1;
    }
    b = fs_fopen_write(dst, 0);
    if (!b) {
        fclose(a);
        return -1;
    }
    while ((got = fread(buf, 1, sizeof(buf), a)) > 0) {
        if (fwrite(buf, 1, got, b) != got) {
            fclose(a);
            fclose(b);
            return -1;
        }
    }
    fclose(a);
    fclose(b);
    return 0;
#endif
}

int fs_move_over(const char *src, const char *dst)
{
#ifdef _WIN32
    wchar_t *ws = u2w(src);
    wchar_t *wd = u2w(dst);
    int r;
    if (!ws || !wd) {
        free(ws);
        free(wd);
        return -1;
    }
    r = MoveFileExW(ws, wd, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED) ? 0 : -1;
    free(ws);
    free(wd);
    return r;
#else
    if (rename(src, dst) == 0)
        return 0;
    if (fs_copy(src, dst, 0) == 0) {
        remove(src);
        return 0;
    }
    return -1;
#endif
}

int fs_delete(const char *path)
{
#ifdef _WIN32
    wchar_t *w = u2w(path);
    int r;
    if (!w)
        return -1;
    if (DeleteFileW(w))
        r = 0;
    else
        r = fs_last_error() == 2 /* FILE_NOT_FOUND */ ? 0 : -1;
    free(w);
    return r;
#else
    return remove(path) == 0 ? 0 : 0;
#endif
}

int fs_remove_tree(const char *path)
{
#ifdef _WIN32
    char pattern[4300];
    wchar_t *wp = u2w(path);
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int rc = 0;
    size_t n;

    if (!wp)
        return -1;
    n = strlen(path);
    if (n > 0 && (path[n - 1] == '\\' || path[n - 1] == '/'))
        snprintf(pattern, sizeof(pattern), "%s*", path);
    else
        snprintf(pattern, sizeof(pattern), "%s\\*", path);

    {
        wchar_t *wpat = u2w(pattern);
        if (!wpat) {
            free(wp);
            return -1;
        }
        h = FindFirstFileW(wpat, &fd);
        free(wpat);
    }
    if (h != INVALID_HANDLE_VALUE) {
        do {
            char *name_utf8;
            char child[4300];
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                continue;
            name_utf8 = w2u(fd.cFileName);
            snprintf(child, sizeof(child), "%s/%s", path, name_utf8);
            free(name_utf8);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (fs_remove_tree(child) != 0)
                    rc = -1;
            } else {
                wchar_t *wc = u2w(child);
                if (wc) {
                    DeleteFileW(wc);
                    free(wc);
                }
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (!RemoveDirectoryW(wp))
        rc = -1;
    free(wp);
    return rc;
#else
    DIR *d = opendir(path);
    struct dirent *e;
    if (!d)
        return remove(path) == 0 ? 0 : -1;
    while ((e = readdir(d)) != NULL) {
        char child[4096];
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
        if (fs_is_dir(child))
            fs_remove_tree(child);
        else
            remove(child);
    }
    closedir(d);
    return rmdir(path);
#endif
}

void fs_dir_of(const char *path, char *out, size_t outsz)
{
    size_t i, n = path ? strlen(path) : 0;
    size_t cut = 0;

    if (n >= outsz)
        n = outsz - 1;
    for (i = 0; i < n; i++) {
        if (path[i] == '/' || path[i] == '\\')
            cut = i + 1;
    }
    memcpy(out, path ? path : "", cut);
    out[cut] = 0;
}

void fs_join(char *out, size_t outsz, const char *dir, const char *name)
{
    size_t n = strlen(dir);
    int need_sep = n > 0 && dir[n - 1] != '/' && dir[n - 1] != '\\';
    snprintf(out, outsz, "%s%s%s", dir, need_sep ? "/" : "", name ? name : "");
}

/* join, then use the platform's separator (Windows accepts '/' too, but the
 * replacement paths look right in the log with backslashes) */
void fs_join_norm(char *out, size_t outsz, const char *dir, const char *rel)
{
    char tmp[4096];
    fs_join(tmp, sizeof(tmp), dir, rel);
    snprintf(out, outsz, "%s", tmp);
#ifdef _WIN32
    {
        size_t i;
        for (i = 0; out[i]; i++)
            if (out[i] == '/')
                out[i] = '\\';
    }
#endif
}

int fs_set_mtime(const char *path, uint64_t unix_time)
{
#ifdef _WIN32
    wchar_t *w = u2w(path);
    HANDLE h;
    FILETIME ft;
    uint64_t t = (unix_time + 11644473600ULL) * 10000000ULL;
    if (!w)
        return -1;
    h = CreateFileW(w, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    ft.dwLowDateTime = (DWORD)(t & 0xffffffffu);
    ft.dwHighDateTime = (DWORD)(t >> 32);
    SetFileTime(h, NULL, NULL, &ft);
    CloseHandle(h);
    return 0;
#else
    (void)path; (void)unix_time;
    return 0;
#endif
}

char *fs_temp_dir(void)
{
#ifdef _WIN32
    wchar_t wtmp[MAX_PATH + 1];
    DWORD n = GetTempPathW(MAX_PATH, wtmp);
    char *base, *out;
    if (n == 0 || n > MAX_PATH) {
        base = p_strdup("C:\\Windows\\Temp");
    } else {
        base = w2u(wtmp);
    }
    out = p_asprintf("%s\\pandora-launcher-selftest-%lu", base,
                     (unsigned long)GetCurrentProcessId());
    free(base);
    return out;
#else
    return p_asprintf("/tmp/pandora-launcher-selftest-%lu", (unsigned long)getpid());
#endif
}

int fs_make_temp(char *out, size_t outsz)
{
    char *dir = fs_temp_dir();
    snprintf(out, outsz, "%s", dir);
    free(dir);
    if (fs_exists(out))
        fs_remove_tree(out);
    if (fs_mkdirs(out) != 0)
        return -1;
    return 0;
}

int fs_last_error(void)
{
#ifdef _WIN32
    return (int)GetLastError();
#else
    return errno;
#endif
}

int fs_err_is_access_denied(int e)
{
#ifdef _WIN32
    return e == 5;   /* ERROR_ACCESS_DENIED */
#else
    return e == 13 || e == 1; /* EACCES / EPERM */
#endif
}
