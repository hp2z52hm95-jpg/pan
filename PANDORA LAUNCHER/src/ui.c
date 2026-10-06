/*
 * ui.c - the launcher window and the sign-in dialog (plain Win32, no resources
 *        needed beyond the icon/version-info block in app.rc).
 *
 * Threading model
 *   - the window, the log and the sign-in dialog live on the UI thread
 *   - the whole "sign in -> update -> start the tool" flow runs on a worker
 *     thread, so the window keeps painting and the update progress bar moves
 *   - the worker talks to the UI with PostMessage (log/status/progress) and
 *     SendMessage for things that need an answer (the sign-in dialog, the
 *     "restart as administrator?" prompt)
 *   - network calls that belong to the sign-in dialog run on a short-lived
 *     worker thread while the dialog keeps pumping messages (see ui_run_job),
 *     so a slow server never looks like a frozen window
 */
#include "pandora.h"

#include <windows.h>
#include <commctrl.h>

#include <stdlib.h>
#include <string.h>

typedef void (*flow_fn)(void *ctx);
typedef int  (*job_fn)(void *ctx);

#define WM_APP_LOG      (WM_APP + 1)   /* lparam: char* (owned by the handler) */
#define WM_APP_STATUS   (WM_APP + 2)
#define WM_APP_LOGIN    (WM_APP + 3)   /* lparam: login_req*, result = 1/0 */
#define WM_APP_CONFIRM  (WM_APP + 4)   /* result = 1/0 */
#define WM_APP_MESSAGE  (WM_APP + 5)
#define WM_APP_FLOWDONE (WM_APP + 6)
#define WM_APP_START    (WM_APP + 7)
#define WM_APP_QUIT     (WM_APP + 8)   /* destroy the window now (flow finished) */

/* control ids (deliberately not 1/2 - those are IDOK/IDCANCEL) */
#define IDC_EDIT_USER   1001
#define IDC_EDIT_PASS   1002
#define IDC_SIGNIN      1010
#define IDC_PASSKEY     1011
#define IDC_CANCEL      1012

struct launcher_ui {
    HINSTANCE  inst;
    HWND       hwnd;
    HWND       hLog, hStatus, hBar, hRun, hExit, hTitle, hSub;
    HFONT      hFont, hFontBold, hFontMono;
    int        busy;
    int        exit_code;
    volatile LONG progress;

    /* flow plumbing */
    flow_fn    flow;
    void      *flow_ctx;
    HANDLE     flow_thread;
    volatile LONG stop_flow;

    /* sign-in */
    void      *http;
    void      *cfg;
    session_t  session;
    int        session_ok;
};

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static const wchar_t *WCLASS_MAIN  = L"PandoraLauncherWindow";
static const wchar_t *WCLASS_LOGIN = L"PandoraLauncherLogin";

static wchar_t *u2w(const char *s)
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

static void ui_set_font(HWND ctl, HFONT f)
{
    SendMessageW(ctl, WM_SETFONT, (WPARAM)f, TRUE);
}

static void ui_log_now(launcher_ui *ui, const char *msg)
{
    wchar_t *w = u2w(msg);
    int len;
    if (!w || !ui->hLog)
        return;
    len = GetWindowTextLengthW(ui->hLog);
    SendMessageW(ui->hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(ui->hLog, EM_REPLACESEL, FALSE, (LPARAM)w);
    SendMessageW(ui->hLog, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
    SendMessageW(ui->hLog, EM_SCROLLCARET, 0, 0);
    free(w);
}

void ui_log(launcher_ui *ui, const char *msg)
{
    char *copy;
    if (!ui || !msg)
        return;
    copy = p_strdup(msg);
    if (!PostMessageW(ui->hwnd, WM_APP_LOG, 0, (LPARAM)copy))
        free(copy);
}

void ui_status(launcher_ui *ui, const char *text)
{
    char *copy;
    if (!ui || !text)
        return;
    copy = p_strdup(text);
    if (!PostMessageW(ui->hwnd, WM_APP_STATUS, 0, (LPARAM)copy))
        free(copy);
}

void ui_progress(launcher_ui *ui, int pct)
{
    InterlockedExchange(&ui->progress, pct);
}

void ui_message(launcher_ui *ui, const char *text)
{
    char *copy = p_strdup(text ? text : "");
    if (!PostMessageW(ui->hwnd, WM_APP_MESSAGE, 0, (LPARAM)copy))
        free(copy);
}

void ui_close(launcher_ui *ui)
{
    if (ui && ui->hwnd)
        PostMessageW(ui->hwnd, WM_APP_QUIT, 0, 0);
}

void ui_flow_done(launcher_ui *ui)
{
    if (ui && ui->hwnd)
        PostMessageW(ui->hwnd, WM_APP_FLOWDONE, 0, 0);
}

int ui_cancelled(launcher_ui *ui)
{
    return ui && InterlockedCompareExchange(&ui->stop_flow, 0, 0) != 0;
}

/* ------------------------------------------------------------------ */
/* short-lived worker threads that keep the UI pumping                 */
/* ------------------------------------------------------------------ */

typedef struct {
    job_fn  fn;
    void   *ctx;
    HANDLE  done;
    int     rc;
    HWND    dialog;      /* for IsDialogMessage while waiting */
} ui_job;

static DWORD WINAPI ui_job_thread(LPVOID param)
{
    ui_job *j = (ui_job *)param;
    j->rc = j->fn(j->ctx);
    SetEvent(j->done);
    return 0;
}

/* Runs `fn(ctx)` on another thread while this thread keeps the dialog alive. */
static int ui_run_job(HWND dialog, job_fn fn, void *ctx)
{
    ui_job j;
    HANDLE th;
    MSG msg;

    memset(&j, 0, sizeof(j));
    j.fn = fn;
    j.ctx = ctx;
    j.dialog = dialog;
    j.done = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!j.done)
        return -1;
    th = CreateThread(NULL, 0, ui_job_thread, &j, 0, NULL);
    if (!th) {
        CloseHandle(j.done);
        return -1;
    }
    for (;;) {
        DWORD w = MsgWaitForMultipleObjects(1, &j.done, FALSE, INFINITE, QS_ALLINPUT);
        if (w == WAIT_OBJECT_0)
            break;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT)
                continue;   /* never kill a request half way through */
            if (!j.dialog || !IsDialogMessageW(j.dialog, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    CloseHandle(j.done);
    return j.rc;
}

/* ------------------------------------------------------------------ */
/* sign-in dialog                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    HWND  hwnd;
    HWND  owner;
    HWND  hUser, hPass, hSignIn, hPasskey, hCancel, hStatus, hHint;
    HFONT hFont, hFontBold;
    int   done;
    int   result;
    int   busy;
    const launcher_cfg *cfg;
    http_client        *http;
    session_t          *out;

    /* what the dialog is signing in to (display only) */
    char  server[256];

    char *err;   /* last error, owned */
} login_state;

static void login_set_status(login_state *st, const char *text)
{
    wchar_t *w = u2w(text);
    if (w) {
        SetWindowTextW(st->hStatus, w);
        free(w);
    }
}

static void login_busy(login_state *st, int busy, const char *status)
{
    st->busy = busy;
    EnableWindow(st->hUser, !busy);
    EnableWindow(st->hPass, !busy);
    EnableWindow(st->hSignIn, !busy);
    EnableWindow(st->hPasskey, !busy);
    EnableWindow(st->hCancel, TRUE);
    if (status)
        login_set_status(st, status);
    if (!busy && st->hUser)
        SetFocus(st->hUser);
    UpdateWindow(st->hwnd);
}

/* --- the two sign-in paths, run off the UI thread for password --- */

typedef struct {
    login_state      *st;
    session_t        *out;
    char              err[512];
    int               ok;
} login_job_ctx;

static int job_password_login(void *ctx)
{
    login_job_ctx *j = (login_job_ctx *)ctx;
    http_resp r;
    json *res = NULL, *user;
    char body[2048];
    wchar_t wuser[256], wpass[512];
    char *auser, *apass;
    int rc = -1;

    GetWindowTextW(j->st->hUser, wuser, 256);
    GetWindowTextW(j->st->hPass, wpass, 512);
    auser = NULL;
    apass = NULL;
    {
        int n = WideCharToMultiByte(CP_UTF8, 0, wuser, -1, NULL, 0, NULL, NULL);
        if (n > 0) {
            auser = (char *)p_malloc((size_t)n);
            WideCharToMultiByte(CP_UTF8, 0, wuser, -1, auser, n, NULL, NULL);
        }
        n = WideCharToMultiByte(CP_UTF8, 0, wpass, -1, NULL, 0, NULL, NULL);
        if (n > 0) {
            apass = (char *)p_malloc((size_t)n);
            WideCharToMultiByte(CP_UTF8, 0, wpass, -1, apass, n, NULL, NULL);
        }
    }
    if (!auser || !*auser) {
        snprintf(j->err, sizeof(j->err), "Enter your username.");
        goto done;
    }
    if (!apass || !*apass) {
        snprintf(j->err, sizeof(j->err), "Enter your password.");
        goto done;
    }

    {
        sbuf b;
        sb_init(&b);
        sb_adds(&b, "{\"username\":");
        sb_add_json_string(&b, auser, strlen(auser));
        sb_adds(&b, ",\"password\":");
        sb_add_json_string(&b, apass, strlen(apass));
        sb_addc(&b, '}');
        snprintf(body, sizeof(body), "%s", b.p ? b.p : "{}");
        sb_free(&b);
    }
    memset(&r, 0, sizeof(r));
    if (http_post_json(j->st->http, "/api/auth/login", body, NULL, &r, j->err,
                       sizeof(j->err)) != 0)
        goto done;
    res = json_parse(r.body, r.len);
    if (!res) {
        snprintf(j->err, sizeof(j->err), "Invalid server response");
        goto done;
    }
    user = (json *)json_get(res, "user");
    {
        const char *token = json_str(res, "token", "");
        if (!*token) {
            snprintf(j->err, sizeof(j->err), "The server did not return a session");
            goto done;
        }
        j->out->token = p_strdup(token);
        j->out->username = p_strdup(json_str(user, "username", auser));
        j->out->display_name = p_strdup(json_str(user, "displayName",
                                                 json_str(user, "username", auser)));
        j->ok = 1;
        rc = 0;
    }
done:
    json_free(res);
    http_resp_free(&r);
    free(auser);
    free(apass);
    return rc;
}

static void login_do_password(login_state *st)
{
    login_job_ctx j;

    memset(&j, 0, sizeof(j));
    j.st = st;
    j.out = st->out;
    login_busy(st, 1, "Signing in...");
    ui_run_job(st->hwnd, job_password_login, &j);
    if (j.ok) {
        st->result = 1;
        st->done = 1;
    } else {
        login_set_status(st, j.err[0] ? j.err : "Sign-in failed.");
        login_busy(st, 0, NULL);
        SetFocus(st->hPass);
        SendMessageW(st->hPass, EM_SETSEL, 0, -1);
    }
}

static void login_do_passkey(login_state *st)
{
    passkey_result r;
    char user[256];
    wchar_t wuser[256];

    GetWindowTextW(st->hUser, wuser, 256);
    {
        char *a = NULL;
        int n = WideCharToMultiByte(CP_UTF8, 0, wuser, -1, NULL, 0, NULL, NULL);
        if (n > 0) {
            a = (char *)p_malloc((size_t)n);
            WideCharToMultiByte(CP_UTF8, 0, wuser, -1, a, n, NULL, NULL);
        }
        snprintf(user, sizeof(user), "%s", a ? a : "");
        free(a);
    }
    if (!user[0]) {
        login_set_status(st, "Enter your username, then use your passkey.");
        SetFocus(st->hUser);
        return;
    }

    login_busy(st, 1, "Waiting for Windows Hello / security key...");

    /* The Windows prompt is modal and the two server calls are quick, so the
     * ceremony runs right here (same as the browser flow does). */
    memset(&r, 0, sizeof(r));
    if (passkey_sign_in(st->hwnd, st->http, st->cfg->rp_id, st->cfg->origin,
                        user, &r) == 0 && r.ok) {
        st->out->token = r.token ? p_strdup(r.token) : NULL;
        st->out->username = r.username ? p_strdup(r.username) : p_strdup(user);
        st->out->display_name = r.display_name ? p_strdup(r.display_name)
                                               : p_strdup(user);
        st->result = 1;
        st->done = 1;
        free(r.token);
        free(r.username);
        free(r.display_name);
        free(r.error);
        return;
    }
    login_set_status(st, r.error ? r.error : "Passkey sign-in failed.");
    free(r.token);
    free(r.username);
    free(r.display_name);
    free(r.error);
    login_busy(st, 0, NULL);
}

static LRESULT CALLBACK login_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    login_state *st = (login_state *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW *)lp;
        HFONT f;
        st = (login_state *)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)st);
        st->hwnd = hwnd;
        f = st->hFont;

        st->hHint = CreateWindowExW(0, L"STATIC", L"Sign in to Pandora", WS_CHILD | WS_VISIBLE,
                                    16, 14, 360, 20, hwnd, NULL, NULL, NULL);
        ui_set_font(st->hHint, st->hFontBold);
        ui_set_font(st->hHint, st->hFontBold);

        st->hUser = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                    16, 60, 356, 24, hwnd, (HMENU)IDC_EDIT_USER, NULL, NULL);
        ui_set_font(st->hUser, f);
        st->hPass = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD |
                                        ES_AUTOHSCROLL,
                                    16, 118, 356, 24, hwnd, (HMENU)IDC_EDIT_PASS, NULL, NULL);
        ui_set_font(st->hPass, f);

        {
            HWND l1 = CreateWindowExW(0, L"STATIC", L"Username", WS_CHILD | WS_VISIBLE,
                                      16, 42, 120, 18, hwnd, NULL, NULL, NULL);
            HWND l2 = CreateWindowExW(0, L"STATIC", L"Password", WS_CHILD | WS_VISIBLE,
                                      16, 100, 120, 18, hwnd, NULL, NULL, NULL);
            HWND l3 = CreateWindowExW(0, L"STATIC", L"Server", WS_CHILD | WS_VISIBLE,
                                      16, 156, 60, 18, hwnd, NULL, NULL, NULL);
            HWND l4 = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                      80, 156, 292, 18, hwnd, NULL, NULL, NULL);
            wchar_t *w = u2w(st->server);
            if (w) {
                SetWindowTextW(l4, w);
                free(w);
            }
            ui_set_font(l1, f);
            ui_set_font(l2, f);
            ui_set_font(l3, f);
            ui_set_font(l4, f);
        }

        st->hSignIn = CreateWindowExW(0, L"BUTTON", L"Sign in",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                      16, 190, 100, 30, hwnd, (HMENU)IDC_SIGNIN, NULL, NULL);
        st->hPasskey = CreateWindowExW(0, L"BUTTON", L"Use passkey",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                       124, 190, 130, 30, hwnd, (HMENU)IDC_PASSKEY, NULL, NULL);
        st->hCancel = CreateWindowExW(0, L"BUTTON", L"Cancel",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                      262, 190, 110, 30, hwnd, (HMENU)IDC_CANCEL, NULL, NULL);
        ui_set_font(st->hSignIn, f);
        ui_set_font(st->hPasskey, f);
        ui_set_font(st->hCancel, f);

        st->hStatus = CreateWindowExW(0, L"STATIC",
                                      L"Sign in with your password or a passkey "
                                      L"(Windows Hello).",
                                      WS_CHILD | WS_VISIBLE | SS_LEFT,
                                      16, 232, 356, 48, hwnd, NULL, NULL, NULL);
        ui_set_font(st->hStatus, f);
        return 0;
    }

    case WM_COMMAND: {
        WORD id = LOWORD(wp);
        WORD code = HIWORD(wp);

        if (!st)
            break;
        /* Enter (from IsDialogMessage) arrives as IDOK/BN_CLICKED; edit
         * notifications must never look like a click, hence the code check */
        if ((id == IDC_SIGNIN || id == IDOK) && code == BN_CLICKED) {
            if (!st->busy)
                login_do_password(st);
            return 0;
        }
        if (id == IDC_PASSKEY && code == BN_CLICKED) {
            if (!st->busy)
                login_do_passkey(st);
            return 0;
        }
        if ((id == IDC_CANCEL || id == IDCANCEL) && code == BN_CLICKED) {
            st->result = 0;
            st->done = 1;
            return 0;
        }
        return 0;
    }

    case WM_CLOSE:
        if (st) {
            st->result = 0;
            st->done = 1;
        }
        return 0;

    case WM_CTLCOLORSTATIC:
        SetBkMode((HDC)wp, TRANSPARENT);
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int ui_login(launcher_ui *ui, http_client *http, const launcher_cfg *cfg, session_t *out)
{
    login_state st;
    MSG msg;
    RECT r, ro;
    int w = 400, h = 300;

    memset(&st, 0, sizeof(st));
    st.owner = ui->hwnd;
    st.cfg = cfg;
    st.http = http;
    st.out = out;
    snprintf(st.server, sizeof(st.server), "%s", cfg->base_url ? cfg->base_url : "");
    st.hFont = ui->hFont;
    st.hFontBold = ui->hFontBold;

    GetWindowRect(ui->hwnd, &ro);
    r.left = ro.left + ((ro.right - ro.left) - w) / 2;
    r.top = ro.top + ((ro.bottom - ro.top) - h) / 2;

    st.hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, WCLASS_LOGIN,
                              L"Pandora Launcher - Sign in",
                              WS_POPUP | WS_CAPTION | WS_SYSMENU,
                              r.left, r.top, w, h, ui->hwnd, NULL, ui->inst, &st);
    if (!st.hwnd)
        return 0;

    EnableWindow(ui->hwnd, FALSE);
    ShowWindow(st.hwnd, SW_SHOW);
    SetForegroundWindow(st.hwnd);
    SetFocus(st.hUser);

    while (!st.done) {
        DWORD w2 = MsgWaitForMultipleObjects(0, NULL, FALSE, INFINITE, QS_ALLINPUT);
        (void)w2;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                st.done = 1;
                st.result = 0;
                PostQuitMessage((int)msg.wParam);
                break;
            }
            if (!IsDialogMessageW(st.hwnd, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    EnableWindow(ui->hwnd, TRUE);
    SetActiveWindow(ui->hwnd);
    DestroyWindow(st.hwnd);
    return st.result;
}

/* ------------------------------------------------------------------ */
/* main window                                                         */
/* ------------------------------------------------------------------ */

static DWORD WINAPI flow_thread(LPVOID param)
{
    launcher_ui *ui = (launcher_ui *)param;
    ui->flow(ui->flow_ctx);
    ui_flow_done(ui);
    return 0;
}

static void main_start_flow(launcher_ui *ui)
{
    if (ui->busy || !ui->flow)
        return;
    ui->busy = 1;
    EnableWindow(ui->hRun, FALSE);
    EnableWindow(ui->hExit, FALSE);
    InterlockedExchange(&ui->stop_flow, 0);
    ui->flow_thread = CreateThread(NULL, 0, flow_thread, ui, 0, NULL);
    if (!ui->flow_thread)
        ui->busy = 0;
}

static int login_request_ok(launcher_ui *ui);

static LRESULT CALLBACK main_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    launcher_ui *ui = (launcher_ui *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW *)lp;
        ui = (launcher_ui *)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)ui);
        ui->hwnd = hwnd;

        ui->hTitle = CreateWindowExW(0, L"STATIC", L"Pandora Launcher",
                                     WS_CHILD | WS_VISIBLE, 16, 12, 400, 26, hwnd, NULL,
                                     NULL, NULL);
        ui_set_font(ui->hTitle, ui->hFontBold);
        ui->hSub = CreateWindowExW(0, L"STATIC",
                                   L"Sign in, apply updates, then start PandoraTool.",
                                   WS_CHILD | WS_VISIBLE, 16, 40, 560, 18, hwnd, NULL,
                                   NULL, NULL);
        ui_set_font(ui->hSub, ui->hFont);

        ui->hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                   WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                       ES_READONLY | ES_AUTOVSCROLL,
                                   16, 66, 608, 300, hwnd, (HMENU)100, NULL, NULL);
        ui_set_font(ui->hLog, ui->hFont);
        {
            /* the log looks better with a fixed-pitch font */
            ui->hFontMono = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                        FIXED_PITCH | FF_MODERN, L"Consolas");
            if (ui->hFontMono)
                ui_set_font(ui->hLog, ui->hFontMono);
        }

        ui->hBar = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
                                   WS_CHILD | WS_VISIBLE, 16, 376, 608, 18, hwnd,
                                   (HMENU)101, NULL, NULL);
        SendMessageW(ui->hBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

        ui->hStatus = CreateWindowExW(0, L"STATIC", L"Starting...",
                                      WS_CHILD | WS_VISIBLE, 16, 402, 608, 20, hwnd,
                                      NULL, NULL, NULL);
        ui_set_font(ui->hStatus, ui->hFont);

        ui->hRun = CreateWindowExW(0, L"BUTTON", L"Start now",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   408, 430, 104, 30, hwnd, (HMENU)110, NULL, NULL);
        ui->hExit = CreateWindowExW(0, L"BUTTON", L"Exit",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                    520, 430, 104, 30, hwnd, (HMENU)111, NULL, NULL);
        ui_set_font(ui->hRun, ui->hFont);
        ui_set_font(ui->hExit, ui->hFont);

        SetTimer(hwnd, 1, 400, NULL);   /* kick the flow off after painting */
        return 0;
    }

    case WM_TIMER:
        if (wp == 1) {
            KillTimer(hwnd, 1);
            main_start_flow(ui);
        } else if (wp == 2 && ui) {
            int p = (int)InterlockedCompareExchange(&ui->progress, 0, 0);
            SendMessageW(ui->hBar, PBM_SETPOS, (WPARAM)(p < 0 ? 0 : (p > 100 ? 100 : p)), 0);
        }
        return 0;

    case WM_APP_LOG:
        if (lp) {
            ui_log_now(ui, (const char *)lp);
            free((void *)lp);
        }
        return 0;

    case WM_APP_STATUS:
        if (lp) {
            wchar_t *w = u2w((const char *)lp);
            if (w) {
                SetWindowTextW(ui->hStatus, w);
                free(w);
            }
            free((void *)lp);
        }
        return 0;

    case WM_APP_MESSAGE:
        if (lp) {
            wchar_t *w = u2w((const char *)lp);
            if (w) {
                MessageBoxW(hwnd, w, L"Pandora Launcher", MB_OK | MB_ICONINFORMATION);
                free(w);
            }
            free((void *)lp);
        }
        return 0;

    case WM_APP_LOGIN:
        return login_request_ok(ui);

    case WM_APP_CONFIRM: {
        wchar_t *w = u2w("The update could not be applied because the Pandora folder "
                         "needs administrator rights.\r\n\r\n"
                         "Restart the launcher as administrator?");
        int r = MessageBoxW(hwnd, w, L"Pandora Launcher",
                            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON1);
        free(w);
        return r == IDYES ? 1 : 0;
    }

    case WM_APP_FLOWDONE:
        ui->busy = 0;
        EnableWindow(ui->hRun, TRUE);
        EnableWindow(ui->hExit, TRUE);
        return 0;

    case WM_COMMAND:
        if (!ui || HIWORD(wp) != BN_CLICKED)
            return 0;
        if (LOWORD(wp) == 110 && !ui->busy)
            main_start_flow(ui);
        else if (LOWORD(wp) == 111)
            PostMessageW(hwnd, WM_CLOSE, 0, 0);   /* ignored while a flow runs */
        return 0;

    case WM_CTLCOLORSTATIC:
        SetBkMode((HDC)wp, TRANSPARENT);
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);

    case WM_APP_QUIT:
        DestroyWindow(hwnd);
        return 0;

    case WM_CLOSE:
        if (ui && ui->busy) {
            InterlockedExchange(&ui->stop_flow, 1);
            return 0;     /* the flow decides when it is safe to close */
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, 1);
        KillTimer(hwnd, 2);
        PostQuitMessage(ui ? ui->exit_code : 0);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* worker -> UI: show the sign-in dialog and hand back the session */
static int login_request_ok(launcher_ui *ui)
{
    session_t s;
    int ok;

    memset(&s, 0, sizeof(s));
    ok = ui_login(ui, (http_client *)ui->http, (const launcher_cfg *)ui->cfg, &s);
    if (ok) {
        session_free(&ui->session);
        ui->session = s;
        ui->session_ok = 1;
    } else {
        session_free(&s);
    }
    return ok;
}

/* ------------------------------------------------------------------ */
/* public entry points                                                 */
/* ------------------------------------------------------------------ */

launcher_ui *ui_create(void *inst_v, const launcher_cfg *cfg)
{
    HINSTANCE inst = (HINSTANCE)inst_v;
    launcher_ui *ui = (launcher_ui *)p_malloc(sizeof(launcher_ui));
    WNDCLASSEXW wc;
    RECT r;
    int w = 656, h = 512;
    int x, y;

    memset(ui, 0, sizeof(*ui));
    ui->inst = inst;
    ui->cfg = (void *)cfg;

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = main_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);
    wc.lpszClassName = WCLASS_MAIN;
    wc.hIcon = (HICON)LoadImageW(inst, L"MAINICON", IMAGE_ICON, 0, 0,
                                 LR_DEFAULTSIZE | LR_SHARED);
    wc.hIconSm = wc.hIcon;
    RegisterClassExW(&wc);

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = login_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);
    wc.lpszClassName = WCLASS_LOGIN;
    RegisterClassExW(&wc);

    ui->hFont = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    ui->hFontBold = CreateFontW(-18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    r.left = 0; r.top = 0; r.right = w; r.bottom = h;
    AdjustWindowRect(&r, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);
    x = (GetSystemMetrics(SM_CXSCREEN) - (r.right - r.left)) / 2;
    y = (GetSystemMetrics(SM_CYSCREEN) - (r.bottom - r.top)) / 3;

    ui->hwnd = CreateWindowExW(0, WCLASS_MAIN, L"Pandora Launcher",
                               WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                               x < 0 ? 0 : x, y < 0 ? 0 : y, r.right - r.left,
                               r.bottom - r.top, NULL, NULL, inst, ui);
    SetTimer(ui->hwnd, 2, 200, NULL);   /* progress bar repaint */
    return ui;
}

void ui_set_flow(launcher_ui *ui, flow_fn fn, void *ctx)
{
    ui->flow = fn;
    ui->flow_ctx = ctx;
}

void ui_show(launcher_ui *ui)
{
    ShowWindow(ui->hwnd, SW_SHOW);
    UpdateWindow(ui->hwnd);
    SetForegroundWindow(ui->hwnd);
}

session_t *ui_session(launcher_ui *ui)
{
    return ui->session_ok ? &ui->session : NULL;
}

void ui_set_http(launcher_ui *ui, void *http)
{
    ui->http = http;
}

/* worker -> UI: run the sign-in dialog on the UI thread and wait for it.
 * Returns 1 when the user signed in (the session is then in ui_session()). */
int ui_do_login(launcher_ui *ui)
{
    if (!ui || !ui->hwnd)
        return 0;
    return (int)SendMessageW(ui->hwnd, WM_APP_LOGIN, 0, 0);
}

void ui_set_exit_code(launcher_ui *ui, int code)
{
    ui->exit_code = code;
}

int ui_confirm_elevate(launcher_ui *ui)
{
    return (int)SendMessageW(ui->hwnd, WM_APP_CONFIRM, 0, 0);
}

void ui_destroy(launcher_ui *ui)
{
    if (!ui)
        return;
    if (ui->flow_thread) {
        WaitForSingleObject(ui->flow_thread, 30000);
        CloseHandle(ui->flow_thread);
        ui->flow_thread = NULL;
    }
    if (ui->hFont)
        DeleteObject(ui->hFont);
    if (ui->hFontBold)
        DeleteObject(ui->hFontBold);
    if (ui->hFontMono)
        DeleteObject(ui->hFontMono);
    session_free(&ui->session);
    free(ui);
}
