/*
 * run.c - host (Linux/CI) runner for the launcher self-test.
 *
 *   make -C "PANDORA LAUNCHER/src/tests" && "PANDORA LAUNCHER/src/tests/run"
 *
 * It runs exactly the same checks as PandoraLauncher.exe --self-test, and
 * additionally unpacks the on-disk fixture package and compares it with the
 * fixture tree, member by member.
 */
#include "pandora.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int selftest_run(char *report, size_t report_cap);

static int compare_tree(const char *zip, const char *root, char *report, size_t cap)
{
    /* walks tests/fixtures/tree and the extracted copy of packages.zip */
    char tree[1200], out[1200];
    char err[512];
    zip_entry *entries = NULL;
    size_t count = 0, i;
    int failed = 0, checked = 0;

    snprintf(tree, sizeof(tree), "%s", root);
    snprintf(out, sizeof(out), "%s.extracted", root);
    fs_remove_tree(out);
    if (fs_mkdirs(out) != 0) {
        snprintf(report, cap, "cannot create %s", out);
        return 1;
    }
    err[0] = 0;
    if (zip_extract(zip, out, NULL, NULL, NULL, err, sizeof(err)) != 0) {
        snprintf(report, cap, "zip_extract(%s) failed: %s", zip, err);
        fs_remove_tree(out);
        return 1;
    }
    if (zip_list(zip, &entries, &count, err, sizeof(err)) != 0) {
        snprintf(report, cap, "zip_list(%s) failed: %s", zip, err);
        fs_remove_tree(out);
        return 1;
    }
    for (i = 0; i < count; i++) {
        char a[1600], b[1600], ha[65], hb[65];
        char *ea = NULL, *eb = NULL;
        size_t la = 0, lb = 0;

        if (entries[i].name[strlen(entries[i].name) - 1] == '/')
            continue;
        fs_join_norm(a, sizeof(a), tree, entries[i].name);
        fs_join_norm(b, sizeof(b), out, entries[i].name);
        checked++;
        if (fs_read_all(a, &ea, &la) != 0 || fs_read_all(b, &eb, &lb) != 0) {
            snprintf(report + strlen(report), cap - strlen(report),
                     "missing file for %s\n", entries[i].name);
            failed++;
        } else if (la != lb || memcmp(ea, eb, la) != 0) {
            snprintf(report + strlen(report), cap - strlen(report),
                     "content differs for %s\n", entries[i].name);
            failed++;
        } else if (sha256_file(b, hb, err, sizeof(err)) == 0 &&
                   sha256_file(a, ha, err, sizeof(err)) == 0 && strcmp(ha, hb) != 0) {
            failed++;
        }
        free(ea);
        free(eb);
    }
    zip_entries_free(entries, count);
    fs_remove_tree(out);
    snprintf(report + strlen(report), cap - strlen(report),
             "%s: %d members compared against the fixture tree\n",
             failed == 0 ? "ok  " : "FAIL", checked);
    return failed;
}

int main(int argc, char **argv)
{
    char *report = (char *)malloc(512 * 1024);
    int failed;
    const char *fixtures = argc > 1 ? argv[1] : "fixtures/tree";
    const char *package = argc > 2 ? argv[2] : "fixtures/packages.zip";
    char tree_report[8192];

    if (!report) {
        fputs("out of memory\n", stderr);
        return 2;
    }
    failed = selftest_run(report, 512 * 1024);
    fputs(report, stdout);

    tree_report[0] = 0;
    if (fs_is_dir(fixtures)) {
        /* only when run from the source tree */
        int extra = compare_tree(package, fixtures, tree_report, sizeof(tree_report));
        if (tree_report[0]) {
            fputs(tree_report, stdout);
            if (tree_report[0] != 'o')
                failed += extra;
        }
    }
    free(report);
    printf("\n%s\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");
    return failed == 0 ? 0 : 1;
}
