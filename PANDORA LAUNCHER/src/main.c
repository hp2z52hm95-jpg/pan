/*
 * main.c - PandoraLauncher.exe
 *
 *   PandoraLauncher.exe              : normal start (window, sign-in, update, run)
 *   PandoraLauncher.exe --self-test  : runs the built-in test suite, writes
 *                                     pandora-launcher-selftest.txt next to the
 *                                     .exe and shows the result
 *                        --quiet      : with --self-test: no message box (used by
 *                                     the automated build/CI check)
 *
 * Flow (on a worker thread, see ui.c):
 *   1. read launcher.ini next to this .exe
 *   2. sign in (password or passkey) - no session, no update, no tool
 *   3. ask the server for updates and apply them (verified downloads only)
 *   4. start PandoraTool.exe with
 *        --pandora-session <jwt> --pandora-user "<name>"
 */
#include "pandora.h"

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>

#include <stdlib.h>
#include <string.h>

int selftest_run(char *report, size_t report_cap);

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static wchar_t *to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s ? s : "", -1, NULL, 0);
    wchar_t *w;
    if (n <= 0)
        return NULL;
    w = (wchar_t *)p_malloc((size_t)n * sizeof(wchar_t));
    if (MultiByteToWideChar(CP_UTF8, 0, s ? s : "", -1, w, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

/* Full path of this .exe, UTF-8, malloc'd. */
static char *launcher_exe_path(void)
{
    wchar_t wexe[1024];
    DWORD n = GetModuleFileNameW(NULL, wexe, 1024);
    char *utf8;
    int need;

    if (n == 0 || n >= 1024)
        return p_strdup("");
    need = WideCharToMultiByte(CP_UTF8, 0, wexe, (int)n, NULL, 0, NULL, NULL);
    utf8 = (char *)p_malloc((size_t)need + 1);
    WideCharToMultiByte(CP_UTF8, 0, wexe, (int)n, utf8, need, NULL, NULL);
    utf8[need] = 0;
    return utf8;
}

void session_free(session_t *s)
{
    if (!s)
        return;
    free(s->token);
    free(s->username);
    free(s->display_name);
    s->token = s->username = s->display_name = NULL;
}

/* ------------------------------------------------------------------ */
/* configuration                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    launcher_ui  *ui;
    launcher_cfg *cfg;
    app_ctx      *app;
    http_client  *http;
} flow_state;

static void cfg_defaults(launcher_cfg *cfg)
{
    cfg->base_url = p_strdup("http://localhost:3000");
    cfg->rp_id = p_strdup("localhost");
    cfg->origin = p_strdup("http://localhost:3000");
    cfg->app_exe = p_strdup("PandoraTool.exe");
    cfg->launch_args = p_strdup("");
    cfg->auto_update = 1;
    cfg->auto_launch = 1;
    cfg->ini_path[0] = 0;
}

static void cfg_free(launcher_cfg *cfg)
{
    free(cfg->base_url);
    free(cfg->rp_id);
    free(cfg->origin);
    free(cfg->app_exe);
    free(cfg->launch_args);
}

/* launcher.ini lives next to this .exe; missing file = built-in defaults */
static void cfg_load(launcher_cfg *cfg, void (*log)(void *, const char *), void *ud)
{
    char *exe = launcher_exe_path();
    char dir[1024];
    char ini_path[1200];
    char *text = NULL;
    size_t len = 0;

    fs_dir_of(exe, dir, sizeof(dir));
    free(exe);
    snprintf(ini_path, sizeof(ini_path), "%slauncher.ini", dir);
    snprintf(cfg->ini_path, sizeof(cfg->ini_path), "%s", ini_path);

    if (fs_read_all(ini_path, &text, &len) == 0) {
        char *v;
        v = ini_read(text, "Server", "BaseURL", cfg->base_url);
        free(cfg->base_url);
        cfg->base_url = v;
        v = ini_read(text, "Server", "RpId", cfg->rp_id);
        free(cfg->rp_id);
        cfg->rp_id = v;
        v = ini_read(text, "Server", "Origin", cfg->origin);
        free(cfg->origin);
        cfg->origin = v;
        v = ini_read(text, "App", "Exe", cfg->app_exe);
        free(cfg->app_exe);
        cfg->app_exe = v;
        v = ini_read(text, "App", "LaunchArgs", cfg->launch_args);
        free(cfg->launch_args);
        cfg->launch_args = v;
        cfg->auto_update = ini_read_bool(text, "App", "AutoUpdate", cfg->auto_update);
        cfg->auto_launch = ini_read_bool(text, "App", "AutoLaunch", cfg->auto_launch);
        free(text);
        trim_inplace(cfg->app_exe);
        trim_inplace(cfg->base_url);
        trim_inplace(cfg->rp_id);
        trim_inplace(cfg->origin);
        if (log)
            log(ud, "launcher.ini loaded.");
    } else if (log) {
        log(ud, "No launcher.ini next to the launcher - using built-in defaults.");
    }
}

/* ------------------------------------------------------------------ */
/* the flow (worker thread)                                            */
/* ------------------------------------------------------------------ */

static void flow_log(void *ud, const char *msg)
{
    ui_log(((flow_state *)ud)->ui, msg);
}

static void flow_progress(void *ud, int pct)
{
    ui_progress(((flow_state *)ud)->ui, pct);
}

static void restart_elevated(flow_state *fs)
{
    char *exe = launcher_exe_path();
    char *dir = (char *)p_malloc(strlen(exe) + 1);

    fs_dir_of(exe, dir, strlen(exe) + 1);
    ui_log(fs->ui, "Restarting the launcher as administrator...");
    if (app_relaunch_elevated(exe, dir) == 0)
        ui_close(fs->ui);
    else
        ui_message(fs->ui, "Could not restart as administrator.\n\n"
                           "Right-click PandoraLauncher.exe and choose "
                           "\"Run as administrator\".");
    free(dir);
    free(exe);
}

static void flow_thread_proc(void *ctx)
{
    flow_state *fs = (flow_state *)ctx;
    launcher_ui *ui = fs->ui;
    launcher_cfg *cfg = fs->cfg;
    app_ctx *app = fs->app;
    http_client *http = fs->http;
    session_t *sess = NULL;
    char err[512];
    char line[1600];
    update_info info;
    int denied = 0;

    memset(&info, 0, sizeof(info));
    err[0] = 0;

    cfg_load(cfg, flow_log, fs);
    snprintf(app->app_exe, sizeof(app->app_exe), "%s", cfg->app_exe);

    ui_log(ui, "");
    ui_log(ui, "Pandora Launcher " PANDORA_LAUNCHER_VER);
    snprintf(line, sizeof(line), "Server:   %s", cfg->base_url);
    ui_log(ui, line);
    snprintf(line, sizeof(line), "Install:  %s%s", app->app_dir, app->app_exe);
    ui_log(ui, line);
    snprintf(line, sizeof(line), "Elevated: %s", app->elevated ? "yes" : "no");
    ui_log(ui, line);

    fs_join(line, sizeof(line), app->app_dir, app->app_exe);
    if (!fs_exists(line)) {
        ui_log(ui, "Warning: the app .exe was not found in the install folder.");
        app_installed_version(line, app->version, sizeof(app->version));
    } else {
        app_installed_version(line, app->version, sizeof(app->version));
    }

    if (http_init(http, cfg->base_url, err, sizeof(err)) != 0) {
        ui_log(ui, "Cannot reach the update server:");
        ui_log(ui, err);
        ui_status(ui, "Cannot reach the update server.");
        return;
    }
    ui_set_http(ui, http);

    /* ---- 1. sign in (password or passkey) ---- */
    ui_status(ui, "Waiting for sign-in...");
    ui_progress(ui, 0);
    if (!ui_do_login(ui)) {
        ui_log(ui, "Sign-in cancelled - nothing was updated and nothing was started.");
        ui_status(ui, "Sign-in cancelled.");
        goto done;
    }
    sess = ui_session(ui);
    if (!sess || !sess->token || !*sess->token) {
        ui_log(ui, "Sign-in did not return a session.");
        ui_status(ui, "Sign-in failed.");
        goto done;
    }
    snprintf(line, sizeof(line), "Signed in as %s",
             sess->display_name && *sess->display_name ? sess->display_name
                                                       : sess->username);
    ui_log(ui, line);

    /* ---- 2. updates ---- */
    if (cfg->auto_update) {
        ui_status(ui, "Checking for updates...");
        snprintf(line, sizeof(line), "Installed version: %s", app->version);
        ui_log(ui, line);
        if (update_check(http, app->version, &info, err, sizeof(err)) != 0) {
            ui_log(ui, "Update check failed:");
            ui_log(ui, err);
            ui_status(ui, "Update check failed - see log.");
            goto done;
        }
        if (info.available) {
            snprintf(line, sizeof(line), "Update available: %s", info.latest);
            ui_log(ui, line);
            if (info.notes && *info.notes)
                ui_log(ui, info.notes);
            snprintf(line, sizeof(line), "Updating to %s ...", info.latest);
            ui_status(ui, line);

            if (update_download_and_apply(http, sess->token, app, info.packages,
                                          info.latest, flow_log, flow_progress, fs,
                                          err, sizeof(err)) != 0) {
                ui_log(ui, "Update failed:");
                ui_log(ui, err);
                ui_status(ui, "Update failed - see log.");
                denied = (strstr(err, "access denied") != NULL ||
                          strstr(err, "administrator") != NULL);
                update_info_free(&info);
                if (denied && !app->elevated && ui_confirm_elevate(ui))
                    restart_elevated(fs);
                goto done;
            }
            ui_progress(ui, 100);
            app_installed_version(line, app->version, sizeof(app->version));
            snprintf(line, sizeof(line), "Installed version is now %s", app->version);
            ui_log(ui, line);
        } else {
            snprintf(line, sizeof(line), "Already up to date (%s).", info.latest);
            ui_log(ui, line);
        }
        update_info_free(&info);
    }

    /* ---- 3. start the tool with the login session ---- */
    {
        sbuf args;
        sb_init(&args);
        if (cfg->launch_args && *cfg->launch_args) {
            sb_adds(&args, cfg->launch_args);
            sb_addc(&args, ' ');
        }
        sb_addf(&args, "--pandora-session %s --pandora-user \"%s\"",
                sess->token, sess->username ? sess->username : "");
        snprintf(line, sizeof(line), "Starting %s ...", app->app_exe);
        ui_status(ui, line);
        if (app_launch(app->app_dir, app->app_exe, args.p ? args.p : "") != 0) {
            snprintf(line, sizeof(line), "Could not start %s (error %d).",
                     app->app_exe, fs_last_error());
            ui_log(ui, line);
            ui_status(ui, "Could not start the tool - see log.");
            sb_free(&args);
            goto done;
        }
        sb_free(&args);
        ui_log(ui, "PandoraTool is running.");
        ui_status(ui, "Running.");
        if (cfg->auto_launch)
            ui_close(ui);
    }

done:
    http_free(http);
    ui_set_http(ui, NULL);
}

/* ------------------------------------------------------------------ */
/* self-test                                                           */
/* ------------------------------------------------------------------ */

static int run_self_test(int quiet)
{
    char *report = (char *)p_malloc(512 * 1024);
    int failed;
    char out_path[1200];
    char dir[1024];
    char *exe = launcher_exe_path();

    fs_dir_of(exe, dir, sizeof(dir));
    free(exe);

    failed = selftest_run(report, 512 * 1024);
    snprintf(out_path, sizeof(out_path), "%spandora-launcher-selftest.txt", dir);
    fs_write_all(out_path, report, strlen(report), NULL, 0);

    if (!quiet) {
        char summary[2400];
        wchar_t *w;
        snprintf(summary, sizeof(summary),
                 "%s\n\n%d check(s) failed.\n\nThe full report was written to:\n%s",
                 failed == 0 ? "Self-test PASSED." : "Self-test FAILED.",
                 failed, out_path);
        w = to_wide(summary);
        if (w) {
            MessageBoxW(NULL, w, L"Pandora Launcher",
                        MB_OK | (failed == 0 ? MB_ICONINFORMATION : MB_ICONERROR));
            free(w);
        }
    } else {
        fprintf(stderr, "%s: %d check(s) failed (%s)\n",
                failed == 0 ? "PASSED" : "FAILED", failed, out_path);
    }
    free(report);
    return failed == 0 ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/* WinMain                                                             */
/* ------------------------------------------------------------------ */

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmdline, int show)
{
    launcher_cfg cfg;
    app_ctx app;
    http_client http;
    flow_state fs;
    launcher_ui *ui;
    MSG msg;
    INITCOMMONCONTROLSEX icc;
    int argc = 0;
    LPWSTR *argv;
    char *exe;
    char dir[1024];

    (void)prev;
    (void)show;
    (void)cmdline;

    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        int i, selftest = 0, quiet = 0;
        for (i = 1; i < argc; i++) {
            if (_wcsicmp(argv[i], L"--self-test") == 0 ||
                _wcsicmp(argv[i], L"/self-test") == 0)
                selftest = 1;
            else if (_wcsicmp(argv[i], L"--quiet") == 0)
                quiet = 1;
        }
        LocalFree(argv);
        if (selftest)
            return run_self_test(quiet);
    }

    memset(&cfg, 0, sizeof(cfg));
    memset(&app, 0, sizeof(app));
    memset(&http, 0, sizeof(http));
    memset(&fs, 0, sizeof(fs));
    cfg_defaults(&cfg);

    /* the install folder is the folder this launcher sits in */
    exe = launcher_exe_path();
    fs_dir_of(exe, dir, sizeof(dir));
    free(exe);
    snprintf(app.app_dir, sizeof(app.app_dir), "%s", dir);
    snprintf(app.app_exe, sizeof(app.app_exe), "%s", cfg.app_exe);
    app.elevated = app_is_elevated();

    ui = ui_create(inst, &cfg);
    if (!ui) {
        MessageBoxW(NULL, L"Could not create the launcher window.\n\n"
                          L"PandoraLauncher.exe needs Windows 7 or newer.",
                    L"Pandora Launcher", MB_OK | MB_ICONERROR);
        return 2;
    }
    fs.ui = ui;
    fs.cfg = &cfg;
    fs.app = &app;
    fs.http = &http;
    ui_set_flow(ui, flow_thread_proc, &fs);
    ui_show(ui);

    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    cfg_free(&cfg);
    ui_destroy(ui);
    return 0;
}
