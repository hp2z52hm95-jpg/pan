/*
 * test_util.c - unit tests for the portable launcher core (util.c).
 *
 * Runs on Linux/macOS/Windows with a plain C compiler. Exercises the pieces
 * that are easy to get wrong and hard to debug on Windows: base64url,
 * SHA-256, CRC-32, JSON lookups, DEFLATE inflate and ZIP extraction.
 *
 * Usage: test_util <workdir>
 */
#include "../util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        checks++;                                                              \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, (msg));             \
        }                                                                      \
    } while (0)

#define CHECK_STR(got, want, msg)                                              \
    do {                                                                       \
        const char *g_ = (got);                                                \
        checks++;                                                              \
        if (!g_ || strcmp(g_, (want)) != 0) {                                  \
            failures++;                                                        \
            printf("FAIL %s:%d  %s\n  got : %s\n  want: %s\n", __FILE__,       \
                   __LINE__, (msg), g_ ? g_ : "(null)", (want));               \
        }                                                                      \
    } while (0)

static void test_base64(void)
{
    static const struct { const char *in; const char *out; } cases[] = {
        { "", "" },
        { "f", "Zg" },
        { "fo", "Zm8" },
        { "foo", "Zm9v" },
        { "foob", "Zm9vYg" },
        { "fooba", "Zm9vYmE" },
        { "foobar", "Zm9vYmFy" },
        /* WebAuthn-style binary data with +/ and padding characters */
        { "\xfb\xff\xfe", "-__-" },
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *enc = b64u_encode((const unsigned char *)cases[i].in,
                                strlen(cases[i].in));
        CHECK_STR(enc, cases[i].out, "base64url encode");
        {
            size_t len = 0;
            unsigned char *dec = b64u_decode(cases[i].out, &len);
            CHECK(dec != NULL, "base64url decode non-null");
            if (dec) {
                CHECK(len == strlen(cases[i].in), "base64url decoded length");
                CHECK(memcmp(dec, cases[i].in, len) == 0, "base64url roundtrip");
                free(dec);
            }
        }
        free(enc);
    }
    /* Standard-alphabet input (server sometimes sends padded base64). */
    {
        size_t len = 0;
        unsigned char *dec = b64u_decode("Zm9vYmFy==", &len);
        CHECK(dec && len == 6 && memcmp(dec, "foobar", 6) == 0,
              "accepts padded base64");
        free(dec);
    }
    /* 32 random-ish bytes roundtrip (challenge/credential sizes) */
    {
        unsigned char raw[32];
        char *enc;
        unsigned char *dec;
        size_t len = 0, i;
        for (i = 0; i < sizeof(raw); i++)
            raw[i] = (unsigned char)(i * 7 + 3);
        enc = b64u_encode(raw, sizeof(raw));
        dec = b64u_decode(enc, &len);
        CHECK(len == sizeof(raw) && memcmp(dec, raw, sizeof(raw)) == 0,
              "32-byte roundtrip");
        CHECK(strchr(enc, '=') == NULL, "no padding emitted");
        free(enc);
        free(dec);
    }
}

static void test_sha256(void)
{
    unsigned char d[32];
    char *hex;

    sha256("", 0, d);
    hex = sha256_hex(d);
    CHECK_STR(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              "sha256 of empty string");
    free(hex);

    sha256("abc", 3, d);
    hex = sha256_hex(d);
    CHECK_STR(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
              "sha256 of \"abc\"");
    free(hex);

    sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    hex = sha256_hex(d);
    CHECK_STR(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
              "sha256 of the 56-byte NIST vector");
    free(hex);
}

static void test_crc32(void)
{
    uint32_t c = crc32_buf("123456789", 9, CRC32_INIT);
    CHECK(c == 0xCBF43926u, "crc32 of \"123456789\"");
}

static void test_json(void)
{
    /* Shaped like the real server responses (see src/routes/passkey.js). */
    const char *auth_begin =
        "{\"challenge\":\"Z7zY2m3bXQ\",\"rpId\":\"updates.example.com\","
        "\"allowCredentials\":[{\"id\":\"AbCd-_12\",\"type\":\"public-key\","
        "\"transports\":[\"internal\"]},{\"id\":\"EfGh\",\"type\":\"public-key\"}],"
        "\"userVerification\":\"preferred\",\"timeout\":300000,"
        "\"challengeId\":\"8f14e45f-ceea-467a\",\"userId\":7}";
    const char *login =
        "{\"success\":true,\"token\":\"eyJhbGciOi\",\"user\":{\"id\":7,"
        "\"username\":\"alice\",\"displayName\":\"Alice \\u00c4\",\"credits\":3},"
        "\"expiresAt\":\"2026-10-07T00:00:00.000Z\"}";
    const char *update =
        "{\"updateAvailable\":true,\"current\":\"10.2.20.0\","
        "\"latest\":\"10.2.21.0\",\"notes\":\"Fixes\",\"packages\":["
        "{\"file\":\"PandoraTool-10.2.21.0.zip\",\"kind\":\"zip\","
        "\"sha256\":\"ABC123\",\"size\":4096,\"version\":\"10.2.21.0\"}]}";
    json_t *j;

    j = json_parse(auth_begin, strlen(auth_begin));
    CHECK(j != NULL, "auth/begin parses");
    if (j) {
        CHECK_STR(json_str(j, "challenge", NULL), "Z7zY2m3bXQ", "challenge");
        CHECK_STR(json_str(j, "rpId", NULL), "updates.example.com", "rpId");
        CHECK_STR(json_str(j, "userVerification", "preferred"), "preferred", "uv");
        CHECK(json_int(j, "timeout", 0) == 300000, "timeout is a number");
        CHECK(json_int(j, "userId", 0) == 7, "userId is a number (not string)");
        CHECK(json_count(j, "allowCredentials") == 2, "allowCredentials count");
        CHECK_STR(json_str(j, "allowCredentials[0].id", NULL), "AbCd-_12",
                  "credential id 0");
        CHECK_STR(json_str(j, "allowCredentials[1].id", NULL), "EfGh",
                  "credential id 1");
        CHECK_STR(json_str(j, "allowCredentials[0].transports[0]", NULL),
                  "internal", "nested array");
        CHECK(!json_has(j, "allowCredentials[2].id"), "out-of-range index");
        CHECK_STR(json_str(j, "missing.key", "fallback"), "fallback", "defaults");
        json_free(j);
    }

    j = json_parse(login, strlen(login));
    CHECK(j != NULL, "login parses");
    if (j) {
        CHECK(json_bool(j, "success", 0) == 1, "login success flag");
        CHECK_STR(json_str(j, "token", NULL), "eyJhbGciOi", "token");
        CHECK_STR(json_str(j, "user.username", NULL), "alice", "username");
        CHECK_STR(json_str(j, "user.displayName", NULL), "Alice \xc3\x84",
                  "\\u escape decoded as UTF-8");
        CHECK_STR(json_str(j, "user.displayName", "def"), "Alice \xc3\x84",
                  "displayName present");
        json_free(j);
    }

    j = json_parse(update, strlen(update));
    CHECK(j != NULL, "update response parses");
    if (j) {
        CHECK(json_bool(j, "updateAvailable", 0) == 1, "updateAvailable");
        CHECK_STR(json_str(j, "latest", NULL), "10.2.21.0", "latest");
        CHECK(json_count(j, "packages") == 1, "packages count");
        CHECK_STR(json_str(j, "packages[0].file", NULL),
                  "PandoraTool-10.2.21.0.zip", "package file");
        CHECK(json_int(j, "packages[0].size", 0) == 4096, "package size");
        json_free(j);
    }

    /* Malformed input must be rejected, not crash. */
    CHECK(json_parse("{\"a\":", 5) == NULL, "incomplete JSON rejected");
    CHECK(json_parse("not json", 8) == NULL, "garbage rejected");
    CHECK(json_parse("{} trailing", 11) == NULL, "trailing garbage rejected");
    j = json_parse("{\"a\":{},\"b\":[]}", strlen("{\"a\":{},\"b\":[]}"));
    CHECK(j != NULL, "empty containers parse");
    CHECK(json_count(j, "b") == 0, "empty array count");
    json_free(j);
}

static int file_contains(const char *path, const char *needle)
{
    FILE *f = fopen(path, "rb");
    char chunk[4096];
    size_t n;
    int found = 0;
    if (!f)
        return 0;
    while ((n = fread(chunk, 1, sizeof(chunk) - 1, f)) > 0) {
        chunk[n] = 0;
        if (strstr(chunk, needle))
            found = 1;
    }
    fclose(f);
    return found;
}

static void test_zip(const char *workdir)
{
    char zip_store[1024], zip_deflate[1024];
    char *joined;
    zip_entry *entries = NULL;
    size_t count = 0, i;
    int ok = 1;

    joined = path_join(workdir, "store.zip");
    strcpy(zip_store, joined);
    free(joined);
    joined = path_join(workdir, "deflate.zip");
    strcpy(zip_deflate, joined);
    free(joined);

    /* Files produced by tests/run_tests.sh with `zip` / python zipfile. */
    if (zip_list(zip_store, &entries, &count) != 0) {
        printf("FAIL cannot list %s (run via tests/run_tests.sh)\n", zip_store);
        failures++;
        return;
    }
    CHECK(count == 3, "store.zip has 3 entries");
    for (i = 0; i < count; i++)
        if (entries[i].method != 0)
            ok = 0;
    CHECK(ok, "store.zip really is stored (method 0)");
    {
        char *dest = path_join(workdir, "out_store/PandoraTool.exe");
        int rc = -1;
        for (i = 0; i < count; i++)
            if (strcmp(entries[i].name, "PandoraTool.exe") == 0)
                rc = zip_extract_entry(zip_store, &entries[i], dest);
        CHECK(rc == 0, "extract stored entry returns 0");
        CHECK(file_contains(dest, "PANDORA-TOOL-STORE-PAYLOAD"),
              "stored entry contents");
        free(dest);
    }
    zip_free(entries, count);

    entries = NULL;
    count = 0;
    if (zip_list(zip_deflate, &entries, &count) != 0) {
        printf("FAIL cannot list %s\n", zip_deflate);
        failures++;
        return;
    }
    CHECK(count == 4, "deflate.zip entry count");
    {
        char *dest = path_join(workdir, "out_deflate/PandoraTool.exe");
        int rc = -1;
        size_t n = 0;
        for (i = 0; i < count; i++)
            if (strcmp(entries[i].name, "PandoraTool.exe") == 0) {
                rc = zip_extract_entry(zip_deflate, &entries[i], dest);
                n = (size_t)entries[i].usize;
            }
        CHECK(rc == 0, "extract deflated entry returns 0");
        CHECK(n > 100000, "deflated entry is large (real compression)");
        {
            char *hex = sha256_file_hex(dest);
            char ref[1024];
            FILE *f;
            snprintf(ref, sizeof(ref), "%s/ref/PandoraTool.exe.sha256", workdir);
            f = fopen(ref, "rb");
            CHECK(f != NULL, "reference digest exists");
            if (f) {
                char buf[80] = {0};
                if (fgets(buf, sizeof(buf), f)) {
                    char *nl = strchr(buf, '\n');
                    if (nl)
                        *nl = 0;
                    CHECK_STR(hex, buf, "extracted exe SHA-256 matches original");
                }
                fclose(f);
            }
            free(hex);
        }
        free(dest);
    }
    {
        char *dest = path_join(workdir, "out_deflate/sub/dir/deep.txt");
        int rc = -1;
        for (i = 0; i < count; i++)
            if (strcmp(entries[i].name, "sub/dir/deep.txt") == 0)
                rc = zip_extract_entry(zip_deflate, &entries[i], dest);
        CHECK(rc == 0, "extract nested entry");
        CHECK(file_contains(dest, "deep file inside a subdirectory"),
              "nested entry contents");
        free(dest);
    }
    zip_free(entries, count);

    /* Corruption detection: flip a byte in the deflate stream. */
    {
        FILE *f = fopen(zip_deflate, "rb");
        FILE *g;
        char *copy = path_join(workdir, "corrupt.zip");
        if (f) {
            g = fopen(copy, "wb");
            int c;
            long pos = 0;
            while ((c = fgetc(f)) != EOF) {
                /* First local header is at 0; its name is "PandoraTool.exe"
                 * (15 bytes) then 30-byte header -> data starts at 45. */
                if (pos == 46)
                    c ^= 0xFF;
                fputc(c, g);
                pos++;
            }
            fclose(g);
            fclose(f);
        }
        {
            zip_entry *ce = NULL;
            size_t cc = 0;
            if (zip_list(copy, &ce, &cc) == 0) {
                int rc = -1;
                for (i = 0; i < cc; i++)
                    if (strcmp(ce[i].name, "PandoraTool.exe") == 0) {
                        char *dest = path_join(workdir, "out_corrupt/x");
                        rc = zip_extract_entry(copy, &ce[i], dest);
                        free(dest);
                    }
                CHECK(rc != 0, "corrupted deflate stream is rejected");
                zip_free(ce, cc);
            }
        }
        free(copy);
    }

    /* Path traversal safety */
    CHECK(path_is_safe_relative("PandoraTool.exe") == 0, "plain name safe");
    CHECK(path_is_safe_relative("sub/dir/file") == 0, "nested name safe");
    CHECK(path_is_safe_relative("../evil.exe") != 0, ".. rejected");
    CHECK(path_is_safe_relative("sub/../../evil.exe") != 0, "nested .. rejected");
    CHECK(path_is_safe_relative("/etc/passwd") != 0, "absolute rejected");
    CHECK(path_is_safe_relative("C:/Windows/evil") != 0, "drive letter rejected");
    CHECK(path_is_safe_relative("..") != 0, "bare .. rejected");
    CHECK(path_is_safe_relative("") != 0, "empty rejected");
    CHECK(path_is_safe_relative("dir/") != 0, "directory entry rejected");
}

int main(int argc, char **argv)
{
    const char *workdir = argc > 1 ? argv[1] : ".";

    printf("Pandora Launcher core tests (workdir: %s)\n", workdir);
    test_base64();
    test_sha256();
    test_crc32();
    test_json();
    test_zip(workdir);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
