/*
 * zip.c - minimal ZIP reader / extractor (portable C99, no zlib).
 *
 * Supports what the update packages use: store (0) and deflate (8), the
 * central-directory layout written by every normal zip tool, CRC-32 checking
 * and safe path handling (no absolute paths, no "..", no symlink games).
 * Zip64 archives are reported as unsupported so the caller can fall back.
 *
 * Before a file is overwritten it can be copied into a backup directory
 * (same relative path) - that is the rollback copy the launcher keeps in
 * Backup\<old-version>\.
 */
#include "pandora.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define ZIP_LOCAL_SIG   0x04034b50u
#define ZIP_CENTRAL_SIG 0x02014b50u
#define ZIP_EOCD_SIG    0x06054b50u

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

typedef struct {
    char    *name;
    uint16_t method;
    uint32_t crc;
    uint64_t csize;
    uint64_t usize;
    uint64_t local_off;
} zentry;

typedef struct {
    zentry *v;
    size_t  n;
} zlist;

static void zlist_free(zlist *l)
{
    size_t i;
    for (i = 0; i < l->n; i++)
        free(l->v[i].name);
    free(l->v);
    l->v = NULL;
    l->n = 0;
}

/* rejects anything that could escape the destination directory */
static int name_is_safe(const char *name)
{
    const char *p;

    if (!name || !*name)
        return 0;
    if (name[0] == '/' || name[0] == '\\')
        return 0;
    if (name[0] && name[1] == ':' && ((name[0] >= 'A' && name[0] <= 'Z') ||
                                      (name[0] >= 'a' && name[0] <= 'z')))
        return 0;
    for (p = name; *p; p++) {
        if (p[0] == '.' && p[1] == '.') {
            int at_start = (p == name) || p[-1] == '/' || p[-1] == '\\';
            int at_end = (p[2] == 0) || p[2] == '/' || p[2] == '\\';
            if (at_start && at_end)
                return 0;
        }
    }
    return 1;
}

static int zlist_read(const char *zip_path, zlist *out, uint32_t *cd_offset_hint,
                      char *err, size_t errlen)
{
    FILE *f = fs_fopen_read(zip_path);
    int64_t fsize;
    uint8_t *tail = NULL;
    size_t tail_max, tail_len, i;
    int64_t eocd = -1;
    uint64_t cd_off, cd_size;
    uint64_t entries;
    uint8_t *cd = NULL;
    size_t pos;
    int rc = -1;

    memset(out, 0, sizeof(*out));
    if (!f) {
        if (err) snprintf(err, errlen, "cannot open %s", zip_path);
        return -1;
    }
    fsize = fs_size(zip_path);
    if (fsize < 22) {
        if (err) snprintf(err, errlen, "%s is too small to be a zip file", zip_path);
        fclose(f);
        return -1;
    }
    tail_max = 66000;  /* EOCD + comment can be up to 64 KB + 22 */
    if ((int64_t)tail_max > fsize)
        tail_max = (size_t)fsize;
    tail = (uint8_t *)p_malloc(tail_max);
    if (fseek(f, (long)(fsize - (int64_t)tail_max), SEEK_SET) != 0) {
        if (err) snprintf(err, errlen, "cannot seek in %s", zip_path);
        goto done;
    }
    tail_len = fread(tail, 1, tail_max, f);
    for (i = tail_len >= 22 ? tail_len - 22 : 0;; i--) {
        if (rd32(tail + i) == ZIP_EOCD_SIG) {
            eocd = (int64_t)i;
            break;
        }
        if (i == 0)
            break;
    }
    if (eocd < 0) {
        if (err) snprintf(err, errlen, "%s is not a zip file (no central directory)", zip_path);
        goto done;
    }
    cd_size = rd32(tail + eocd + 12);
    cd_off = rd32(tail + eocd + 16);
    entries = rd16(tail + eocd + 10);
    if (cd_off == 0xffffffffu || cd_size == 0xffffffffu || entries == 0xffffu) {
        if (err) snprintf(err, errlen, "zip64 archives are not supported");
        goto done;
    }
    if (cd_offset_hint)
        *cd_offset_hint = (uint32_t)cd_off;
    if (cd_off + cd_size > (uint64_t)fsize) {
        if (err) snprintf(err, errlen, "%s is truncated", zip_path);
        goto done;
    }

    cd = (uint8_t *)p_malloc((size_t)cd_size ? (size_t)cd_size : 1);
    if (fseek(f, (long)cd_off, SEEK_SET) != 0 ||
        fread(cd, 1, (size_t)cd_size, f) != (size_t)cd_size) {
        if (err) snprintf(err, errlen, "cannot read the central directory of %s", zip_path);
        goto done;
    }

    out->v = (zentry *)p_malloc(sizeof(zentry) * (entries ? (size_t)entries : 1));
    pos = 0;
    for (i = 0; i < entries; i++) {
        zentry e;
        uint16_t nlen, elen, clen;
        uint32_t lho;

        if (pos + 46 > cd_size || rd32(cd + pos) != ZIP_CENTRAL_SIG) {
            if (err) snprintf(err, errlen, "damaged central directory in %s", zip_path);
            goto done;
        }
        memset(&e, 0, sizeof(e));
        e.method = rd16(cd + pos + 10);
        e.crc = rd32(cd + pos + 16);
        e.csize = rd32(cd + pos + 20);
        e.usize = rd32(cd + pos + 24);
        nlen = rd16(cd + pos + 28);
        elen = rd16(cd + pos + 30);
        clen = rd16(cd + pos + 32);
        lho = rd32(cd + pos + 42);
        if (pos + 46 + nlen + elen + clen > cd_size) {
            if (err) snprintf(err, errlen, "damaged central directory in %s", zip_path);
            goto done;
        }
        e.local_off = lho;
        e.name = p_strndup((const char *)(cd + pos + 46), nlen);
        /* convert to UTF-8 separators; names are stored as UTF-8 or CP437 */
        {
            size_t k;
            for (k = 0; e.name[k]; k++)
                if (e.name[k] == '\\')
                    e.name[k] = '/';
        }
        if (e.csize == 0xffffffffu || e.usize == 0xffffffffu || lho == 0xffffffffu) {
            free(e.name);
            if (err) snprintf(err, errlen, "zip64 archives are not supported");
            goto done;
        }
        out->v[out->n++] = e;
        pos += 46 + nlen + elen + clen;
    }
    rc = 0;
done:
    free(cd);
    free(tail);
    fclose(f);
    if (rc != 0)
        zlist_free(out);
    return rc;
}

int zip_list(const char *zip_path, zip_entry **entries, size_t *count,
             char *err, size_t errlen)
{
    zlist l;
    size_t i, n = 0;

    *entries = NULL;
    *count = 0;
    if (zlist_read(zip_path, &l, NULL, err, errlen) != 0)
        return -1;
    *entries = (zip_entry *)p_malloc(sizeof(zip_entry) * (l.n ? l.n : 1));
    for (i = 0; i < l.n; i++) {
        size_t nlen = strlen(l.v[i].name);
        if (nlen == 0 || l.v[i].name[nlen - 1] == '/')
            continue;                        /* directory entry */
        (*entries)[n].name = p_strdup(l.v[i].name);
        (*entries)[n].usize = l.v[i].usize;
        n++;
    }
    *count = n;
    zlist_free(&l);
    return 0;
}

void zip_entries_free(zip_entry *entries, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        free(entries[i].name);
    free(entries);
}

typedef struct {
    FILE    *f;
    uint32_t crc;
} zsink;

static int zsink_write(void *ud, const uint8_t *data, size_t n)
{
    zsink *z = (zsink *)ud;
    z->crc = crc32_update(z->crc, data, n);
    return fwrite(data, 1, n, z->f) == n ? 0 : -1;
}

static int extract_one(FILE *f, const zentry *e, const char *dest_dir,
                       const char *backup_dir, zip_log_fn log, void *ud,
                       char *err, size_t errlen)
{
    uint8_t lh[30];
    uint16_t nlen, elen;
    uint8_t *cdata = NULL;
    char dest[4300];
    char backup[4300];
    FILE *out = NULL;
    int rc = -1;
    uint64_t written = 0;
    uint32_t crc = 0;

    if (!name_is_safe(e->name)) {
        if (err) snprintf(err, errlen, "unsafe path in package: %s", e->name);
        return -1;
    }
    if (fseek(f, (long)e->local_off, SEEK_SET) != 0 ||
        fread(lh, 1, 30, f) != 30 || rd32(lh) != ZIP_LOCAL_SIG) {
        if (err) snprintf(err, errlen, "damaged local header for %s", e->name);
        return -1;
    }
    nlen = rd16(lh + 26);
    elen = rd16(lh + 28);
    if (fseek(f, (long)nlen + (long)elen, SEEK_CUR) != 0) {
        if (err) snprintf(err, errlen, "cannot seek to %s data", e->name);
        return -1;
    }

    fs_join_norm(dest, sizeof(dest), dest_dir, e->name);
    {
        char dir[4300];
        fs_dir_of(dest, dir, sizeof(dir));
        if (dir[0] && !fs_is_dir(dir) && fs_mkdirs(dir) != 0) {
            if (err) snprintf(err, errlen, "cannot create folder %s", dir);
            return -1;
        }
    }

    /* rollback copy: before anything is overwritten, keep the old file */
    if (backup_dir && fs_exists(dest)) {
        char bdir[4300];
        fs_join_norm(backup, sizeof(backup), backup_dir, e->name);
        fs_dir_of(backup, bdir, sizeof(bdir));
        if (bdir[0])
            fs_mkdirs(bdir);
        if (fs_copy(dest, backup, 1) != 0 && log)
            log(ud, "  (could not back up the current file, continuing)");
    }

    if (e->method != 0 && e->method != 8) {
        if (err) snprintf(err, errlen, "unsupported compression method %u for %s",
                          (unsigned)e->method, e->name);
        return -1;
    }

    cdata = (uint8_t *)p_malloc((size_t)(e->csize ? e->csize : 1));
    if (fread(cdata, 1, (size_t)e->csize, f) != (size_t)e->csize) {
        if (err) snprintf(err, errlen, "truncated package data for %s", e->name);
        goto done;
    }

    out = fs_fopen_write(dest, 0);
    if (!out) {
        if (err) snprintf(err, errlen, "cannot write %s", dest);
        goto done;
    }

    if (e->method == 0) {
        crc = crc32_update(crc, cdata, (size_t)e->csize);
        if (fwrite(cdata, 1, (size_t)e->csize, out) != (size_t)e->csize) {
            if (err) snprintf(err, errlen, "write failed for %s", dest);
            goto done;
        }
        written = e->csize;
    } else {
        zsink z;
        z.f = out;
        z.crc = 0;
        if (inflate_to_sink(cdata, (size_t)e->csize, zsink_write, &z, e->usize,
                            &written) != 0) {
            if (err) snprintf(err, errlen, "cannot unpack %s (damaged package)", e->name);
            goto done;
        }
        crc = z.crc;
    }
    fclose(out);
    out = NULL;

    if (written != e->usize) {
        if (err) snprintf(err, errlen, "size mismatch unpacking %s", e->name);
        goto done;
    }
    if (crc != e->crc) {
        if (err) snprintf(err, errlen, "CRC mismatch unpacking %s", e->name);
        goto done;
    }

    rc = 0;
done:
    if (out)
        fclose(out);
    if (rc != 0)
        fs_delete(dest);
    free(cdata);
    return rc;
}

int zip_extract(const char *zip_path, const char *dest_dir, const char *backup_dir,
                zip_log_fn log, void *ud, char *err, size_t errlen)
{
    zlist l;
    size_t i;
    FILE *f = NULL;
    int rc = -1;

    if (zlist_read(zip_path, &l, NULL, err, errlen) != 0)
        return -1;

    f = fs_fopen_read(zip_path);
    if (!f) {
        if (err) snprintf(err, errlen, "cannot open %s", zip_path);
        zlist_free(&l);
        return -1;
    }
    fs_mkdirs(dest_dir);
    if (backup_dir)
        fs_mkdirs(backup_dir);

    for (i = 0; i < l.n; i++) {
        size_t nlen = strlen(l.v[i].name);
        if (nlen == 0 || l.v[i].name[nlen - 1] == '/')
            continue;
        if (log)
            log(ud, l.v[i].name);
        if (extract_one(f, &l.v[i], dest_dir, backup_dir, log, ud, err, errlen) != 0)
            goto done;
    }
    rc = 0;
done:
    fclose(f);
    zlist_free(&l);
    return rc;
}
