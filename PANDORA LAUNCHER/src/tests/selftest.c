/*
 * selftest.c - the launcher's own test suite.
 *
 * Runs in two places, from the very same code:
 *   - host tests:  src/tests/run.c  (gcc, Linux `make -C "PANDORA LAUNCHER/src/tests"`)
 *   - the real .exe: PandoraLauncher.exe --self-test
 *
 * The .exe variant unpacks an embedded, real update package (testzip.h) and
 * checks every member against its expected SHA-256, so a broken inflate/zip/
 * SHA-256 path on the actual Windows binary is caught before release.
 */
#include "pandora.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "deflate.h"
#include "expected.h"
#include "hostilezip.h"
#include "testzip.h"

typedef struct {
    char  *out;
    size_t cap;
    size_t len;
    int    failed;
    int    checks;
} st_ctx;

static void st_add(st_ctx *c, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (!c || !c->out || c->len + 2 >= c->cap)
        return;
    va_start(ap, fmt);
    n = vsnprintf(c->out + c->len, c->cap - c->len - 1, fmt, ap);
    va_end(ap);
    if (n > 0)
        c->len += (size_t)n;
    if (c->len + 2 < c->cap) {
        c->out[c->len++] = '\n';
        c->out[c->len] = 0;
    }
}

static void st_ok(st_ctx *c, const char *what)
{
    c->checks++;
    st_add(c, "  ok   %s", what);
}

static void st_fail(st_ctx *c, const char *what)
{
    c->checks++;
    c->failed++;
    st_add(c, "  FAIL %s", what);
}

#define CHECK(c, cond, what) do { if (cond) st_ok(c, what); else st_fail(c, what); } while (0)

/* ------------------------------------------------------------------ */

static void test_sha256(st_ctx *c)
{
    static const char *abc_hex =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    static const char *empty_hex =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    uint8_t d[32];
    char hex[65];
    sbuf b;
    int i;

    sha256("abc", 3, d);
    hex_lower(d, 32, hex);
    CHECK(c, strcmp(hex, abc_hex) == 0, "SHA-256(\"abc\")");

    sha256("", 0, d);
    hex_lower(d, 32, hex);
    CHECK(c, strcmp(hex, empty_hex) == 0, "SHA-256(\"\")");

    /* one million 'a' - the classic long-message vector */
    {
        char chunk[1000];
        memset(chunk, 'a', sizeof(chunk));
        sb_init(&b);
        for (i = 0; i < 1000; i++)
            sb_add(&b, chunk, sizeof(chunk));
        sha256(b.p, b.len, d);
        hex_lower(d, 32, hex);
        CHECK(c, b.len == 1000000 &&
                 strcmp(hex,
                        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0,
              "SHA-256(1,000,000 x 'a')");
        sb_free(&b);
    }
}

static void test_base64(st_ctx *c)
{
    static const uint8_t raw[] = { 0xfb, 0xff, 0xbf, 0x00, 0x10, 0x7f };
    char *enc = b64url_encode(raw, sizeof(raw));
    uint8_t *dec = NULL;
    size_t declen = 0;
    int ok;

    CHECK(c, strcmp(enc, "-_-_ABB_") == 0, "base64url encode");
    ok = b64url_decode(enc, &dec, &declen) == 0 && declen == sizeof(raw) &&
         memcmp(dec, raw, sizeof(raw)) == 0;
    CHECK(c, ok, "base64url decode round trip");
    free(dec);
    free(enc);

    /* the encoding used for WebAuthn challenges is unpadded */
    enc = b64url_encode((const uint8_t *)"a", 1);
    CHECK(c, strcmp(enc, "YQ") == 0, "base64url is unpadded");
    free(enc);
}

static void test_version_compare(st_ctx *c)
{
    CHECK(c, version_compare("10.2.20.0", "10.2.21.0") < 0, "10.2.20.0 < 10.2.21.0");
    CHECK(c, version_compare("10.2.21.0", "10.2.20.0") > 0, "10.2.21.0 > 10.2.20.0");
    CHECK(c, version_compare("1.0.0.0", "1.0.0.0") == 0, "equal versions");
    CHECK(c, version_compare("1.2", "1.2.0.0") == 0, "1.2 == 1.2.0.0");
    CHECK(c, version_compare("0.0.0.0", "10.0.0.0") < 0, "0.0.0.0 < 10.0.0.0");
    CHECK(c, version_compare("10.2.20.0", "10.2.9.0") > 0, "10.2.20.0 > 10.2.9.0");
    CHECK(c, version_compare("", "1.0.0.0") < 0, "empty version is older");
}

static void test_ini(st_ctx *c)
{
    const char *text =
        "; comment\n"
        "[Server]\n"
        "BaseURL=https://updates.example.com\n"
        "RpId = updates.example.com   ; inline comment stays part of the value\n"
        "\n"
        "[App]\n"
        "Exe=PandoraTool.exe\n"
        "AutoUpdate=0\n"
        "AutoLaunch=yes\n"
        "LaunchArgs=--silent --lang de\n";
    char *v;
    int r;

    v = ini_read(text, "Server", "BaseURL", "?");
    CHECK(c, strcmp(v, "https://updates.example.com") == 0, "INI reads BaseURL");
    free(v);
    v = ini_read(text, "App", "Exe", "?");
    CHECK(c, strcmp(v, "PandoraTool.exe") == 0, "INI reads App/Exe");
    free(v);
    v = ini_read(text, "App", "LaunchArgs", "?");
    CHECK(c, strcmp(v, "--silent --lang de") == 0, "INI keeps spaces in a value");
    free(v);
    v = ini_read(text, "Missing", "Key", "fallback");
    CHECK(c, strcmp(v, "fallback") == 0, "INI falls back for unknown keys");
    free(v);
    r = ini_read_bool(text, "App", "AutoUpdate", 1);
    CHECK(c, r == 0, "INI AutoUpdate=0");
    r = ini_read_bool(text, "App", "AutoLaunch", 0);
    CHECK(c, r == 1, "INI AutoLaunch=yes");
    r = ini_read_bool(text, "App", "NotThere", 1);
    CHECK(c, r == 1, "INI default for missing bool");
}

static void test_json(st_ctx *c)
{
    const char *check =
        "{\"updateAvailable\":true,\"current\":\"10.2.20.0\",\"latest\":\"10.2.21.0\","
        "\"notes\":\"line1\\nline2 \\\"quoted\\\" \\u00fcber\","
        "\"packages\":[{\"file\":\"PandoraTool-10.2.21.0.zip\",\"kind\":\"zip\","
        "\"size\":123456,\"sha256\":\"abc\"},{\"file\":\"extra.dll\",\"kind\":\"file\"}],"
        "\"publishedAt\":null,\"ratio\":0.75,\"flag\":false}";
    json *j = json_parse(check, strlen(check));
    json *pkg;
    const json *pkgs;

    CHECK(c, j != NULL, "JSON parses a server response");
    if (!j)
        return;
    CHECK(c, json_bool(j, "updateAvailable", 0) == 1, "JSON bool true");
    CHECK(c, json_bool(j, "flag", 1) == 0, "JSON bool false");
    CHECK(c, strcmp(json_str(j, "latest", ""), "10.2.21.0") == 0, "JSON string");
    CHECK(c, strcmp(json_str(j, "notes", ""), "line1\nline2 \"quoted\" \xc3\xbc""ber") == 0,
          "JSON escapes and \\uXXXX -> UTF-8");
    CHECK(c, json_num(j, "ratio", 0) > 0.74 && json_num(j, "ratio", 0) < 0.76,
          "JSON number");
    CHECK(c, json_get(j, "publishedAt") != NULL &&
             json_get(j, "publishedAt")->t == JSON_NULL, "JSON null");
    pkgs = json_get(j, "packages");
    CHECK(c, json_len(pkgs) == 2, "JSON array length");
    pkg = (json *)json_at(pkgs, 0);
    CHECK(c, strcmp(json_str(pkg, "file", ""), "PandoraTool-10.2.21.0.zip") == 0,
          "JSON nested object");
    CHECK(c, (int)json_num(pkg, "size", 0) == 123456, "JSON nested number");
    json_free(j);

    /* the shapes the login / passkey endpoints return */
    {
        const char *login =
            "{\"success\":true,\"token\":\"eyJhbGciOiJIUzI1NiJ9.x.y\","
            "\"user\":{\"id\":\"u-1\",\"username\":\"alice\",\"displayName\":\"Alice A\"}}";
        json *l = json_parse(login, strlen(login));
        CHECK(c, l && strcmp(json_str(l, "token", ""), "eyJhbGciOiJIUzI1NiJ9.x.y") == 0,
              "JSON login token");
        CHECK(c, l && strcmp(json_str(json_get(l, "user"), "displayName", ""), "Alice A") == 0,
              "JSON login user.displayName");
        json_free(l);
    }

    CHECK(c, json_parse("{", 1) == NULL, "JSON rejects truncated input");
    CHECK(c, json_parse("{\"a\":1}garbage", 14) == NULL, "JSON rejects trailing garbage");
    CHECK(c, json_parse("", 0) == NULL, "JSON rejects empty input");
}

static void test_inflate(st_ctx *c)
{
    size_t i;

    for (i = 0; i < DEFLATE_VECTOR_COUNT; i++) {
        const deflate_vector *v = &deflate_vectors[i];
        uint8_t *out = (uint8_t *)p_malloc(v->plainlen ? v->plainlen : 1);
        size_t got = 0;
        char label[128];
        int ok = inflate_raw(v->comp, v->complen, out, v->plainlen, &got) == 0 &&
                 got == v->plainlen &&
                 (v->plainlen == 0 || memcmp(out, v->plain, v->plainlen) == 0);
        snprintf(label, sizeof(label), "DEFLATE %s (%lu -> %lu bytes)",
                 v->name, v->complen, v->plainlen);
        CHECK(c, ok, label);
        free(out);
    }

    /* truncated / corrupt input must fail instead of returning junk */
    if (DEFLATE_VECTOR_COUNT > 0) {
        const deflate_vector *v = &deflate_vectors[DEFLATE_VECTOR_COUNT - 1];
        uint8_t *out = (uint8_t *)p_malloc(v->plainlen + 16);
        size_t got = 0;
        int r = v->complen > 4
                    ? inflate_raw(v->comp, v->complen / 2, out, v->plainlen + 16, &got)
                    : -1;
        CHECK(c, r != 0, "DEFLATE rejects a truncated stream");
        free(out);
    }
}

static void test_update_packages(st_ctx *c)
{
    char tmp[1024], out_dir[1024], backup_dir[1024], path[1600];
    zip_entry *entries = NULL;
    size_t count = 0, i;
    char err[512];
    int rc, missing = 0, mismatched = 0;

    if (fs_make_temp(tmp, sizeof(tmp)) != 0) {
        st_fail(c, "temporary directory for the zip test");
        return;
    }
    /* the embedded zip lives in memory: write it out first */
    fs_join(path, sizeof(path), tmp, "packages.zip");
    if (fs_write_all(path, test_zip, test_zip_len, err, sizeof(err)) != 0) {
        st_fail(c, "write the embedded test package");
        return;
    }

    err[0] = 0;
    rc = zip_list(path, &entries, &count, err, sizeof(err));
    CHECK(c, rc == 0 && count >= 9, "zip_list finds every member");
    if (rc == 0) {
        for (i = 0; i < count; i++) {
            size_t k;
            int found = 0;
            for (k = 0; k < EXPECT_COUNT; k++)
                if (strcmp(expect_table[k].name, entries[i].name) == 0)
                    found = 1;
            if (!found)
                mismatched++;
        }
        CHECK(c, mismatched == 0, "zip_list reports the expected member names");
    }
    zip_entries_free(entries, count);

    fs_join(out_dir, sizeof(out_dir), tmp, "install");
    fs_join(backup_dir, sizeof(backup_dir), tmp, "backup");
    err[0] = 0;
    rc = zip_extract(path, out_dir, backup_dir, NULL, NULL, err, sizeof(err));
    CHECK(c, rc == 0, rc == 0 ? "zip_extract unpacks the package" : err);

    for (i = 0; i < EXPECT_COUNT; i++) {
        char file[1600], hex[65];
        char label[256];
        int64_t size;
        fs_join_norm(file, sizeof(file), out_dir, expect_table[i].name);
        snprintf(label, sizeof(label), "unpacked %s matches the expected bytes",
                 expect_table[i].name);
        size = fs_size(file);
        if (size < 0) {
            missing++;
            st_fail(c, label);
            continue;
        }
        if ((unsigned long)size != expect_table[i].size) {
            st_fail(c, label);
            continue;
        }
        if (sha256_file(file, hex, err, sizeof(err)) != 0 || strcmp(hex, expect_table[i].sha256) != 0) {
            st_fail(c, label);
            continue;
        }
        st_ok(c, label);
    }
    (void)missing;

    /* second run over a changed file: rollback copy + replace */
    {
        char pkg[1600], target[1600], bak[1600], hex[65];
        char *content = NULL;
        size_t got = 0;

        fs_join(pkg, sizeof(pkg), tmp, "packages.zip");
        fs_join_norm(target, sizeof(target), out_dir, "readme.txt");
        fs_write_all(target, "old version", 11, err, sizeof(err));

        err[0] = 0;
        rc = zip_extract(pkg, out_dir, backup_dir, NULL, NULL, err, sizeof(err));
        CHECK(c, rc == 0, "zip_extract overwrites an existing install");

        fs_join_norm(bak, sizeof(bak), backup_dir, "readme.txt");
        CHECK(c, fs_exists(bak), "the replaced file is copied to the backup folder");
        if (fs_read_all(bak, &content, &got) == 0) {
            CHECK(c, got == 11 && memcmp(content, "old version", 11) == 0,
                  "the backup holds the previous content");
            free(content);
            content = NULL;
        }
        if (fs_read_all(target, &content, &got) == 0) {
            const char *want = NULL;
            size_t k;
            for (k = 0; k < EXPECT_COUNT; k++)
                if (strcmp(expect_table[k].name, "readme.txt") == 0)
                    want = expect_table[k].sha256;
            CHECK(c, want && sha256_file(target, hex, err, sizeof(err)) == 0 &&
                     strcmp(hex, want) == 0,
                  "the installed file is the new content again");
            free(content);
        }
    }

    /* a package with a "../" member must be rejected */
    {
        char evil[1600], evil_out[1024];
        fs_join(evil, sizeof(evil), tmp, "hostile.zip");
        fs_write_all(evil, hostile_zip, hostile_zip_len, err, sizeof(err));
        fs_join(evil_out, sizeof(evil_out), tmp, "evil-install");
        err[0] = 0;
        rc = zip_extract(evil, evil_out, NULL, NULL, NULL, err, sizeof(err));
        CHECK(c, rc != 0, "zip_extract refuses a package with ..\\..\\ paths");
        fs_join_norm(evil_out, sizeof(evil_out), tmp, "evil.txt");
        CHECK(c, !fs_exists(evil_out), "no file escaped into the parent folder");
    }

    fs_remove_tree(tmp);
}

static void test_fs_and_paths(st_ctx *c)
{
    char dir[512];

    fs_dir_of("C:\\Pandora\\PandoraTool.exe", dir, sizeof(dir));
    CHECK(c, strcmp(dir, "C:\\Pandora\\") == 0, "fs_dir_of keeps the separator");
    fs_dir_of("PandoraTool.exe", dir, sizeof(dir));
    CHECK(c, strcmp(dir, "") == 0, "fs_dir_of of a bare name");
}

static void test_url(st_ctx *c)
{
    url_base u;
    char err[256];
    char *s;

    err[0] = 0;
    CHECK(c, url_parse("https://updates.example.com", &u, err, sizeof(err)) == 0 &&
             u.tls == 1 && u.port == 443 &&
             strcmp(u.host, "updates.example.com") == 0 && strcmp(u.prefix, "") == 0,
          "url_parse https host");
    s = url_join(&u, "/api/updates/check?app=PandoraTool&current=10.2.20.0");
    CHECK(c, strcmp(s, "https://updates.example.com/api/updates/check?app=PandoraTool&current=10.2.20.0") == 0,
          "url_join builds the request URL");
    free(s);
    url_free(&u);

    CHECK(c, url_parse("http://localhost:3000/", &u, err, sizeof(err)) == 0 &&
             u.tls == 0 && u.port == 3000 && strcmp(u.prefix, "") == 0,
          "url_parse http + port");
    url_free(&u);

    CHECK(c, url_parse("https://example.com/updates/", &u, err, sizeof(err)) == 0 &&
             strcmp(u.prefix, "/updates") == 0,
          "url_parse keeps a sub-path prefix");
    url_free(&u);

    CHECK(c, url_parse("updates.example.com", &u, err, sizeof(err)) != 0,
          "url_parse rejects a URL without a scheme");

    s = url_encode_query("PandoraTool-10.2.21.0.zip");
    CHECK(c, strcmp(s, "PandoraTool-10.2.21.0.zip") == 0, "url_encode_query leaves plain names");
    free(s);
    s = url_encode_query("a b&c=d");
    CHECK(c, strcmp(s, "a%20b%26c%3Dd") == 0, "url_encode_query escapes");
    free(s);
}

/* ------------------------------------------------------------------ */

int selftest_run(char *report, size_t report_cap)
{
    st_ctx c;

    c.out = report;
    c.cap = report_cap;
    c.len = 0;
    c.failed = 0;
    c.checks = 0;
    report[0] = 0;

    st_add(&c, "Pandora Launcher self-test (build %s)", PANDORA_LAUNCHER_VER);

    st_add(&c, "SHA-256:");
    test_sha256(&c);
    st_add(&c, "base64url:");
    test_base64(&c);
    st_add(&c, "versions:");
    test_version_compare(&c);
    st_add(&c, "launcher.ini:");
    test_ini(&c);
    st_add(&c, "JSON:");
    test_json(&c);
    st_add(&c, "DEFLATE:");
    test_inflate(&c);
    st_add(&c, "URLs:");
    test_url(&c);
    st_add(&c, "paths:");
    test_fs_and_paths(&c);
    st_add(&c, "update packages:");
    test_update_packages(&c);

    st_add(&c, "%s - %d checks, %d failed", c.failed == 0 ? "PASSED" : "FAILED",
           c.checks, c.failed);
    return c.failed;
}
