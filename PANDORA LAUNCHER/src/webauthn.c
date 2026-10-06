/*
 * webauthn.c - desktop passkey sign-in using the real Windows WebAuthn API
 * (Windows Hello / PIN / fingerprint / security key).
 *
 * The same passkeys work in the browser login page and in this launcher: the
 * launcher performs the standard ceremony
 *
 *   POST /api/passkey/authenticate/begin   -> challenge + allowCredentials
 *   WebAuthNAuthenticatorGetAssertion      -> Windows Hello prompt
 *   POST /api/passkey/authenticate/complete -> JWT session
 *
 * webauthn.dll is loaded dynamically, so on Windows versions without it the
 * launcher still starts and password sign-in keeps working.
 *
 * RpId / Origin must exactly match the server's RP_ID / WEBAUTHN_ORIGIN
 * (launcher.ini) - that exact match is what makes passkeys phishing-proof.
 */
#include "pandora.h"

#include <windows.h>

#include <stdlib.h>
#include <string.h>

/* ---------------- webauthn.h structures (API version 1) ---------------- */

#define WEBAUTHN_HASH_ALGORITHM_SHA256 L"SHA-256"
#define WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY L"public-key"

typedef struct {
    DWORD  dwVersion;
    DWORD  cbClientDataJSON;
    PBYTE  pbClientDataJSON;
    PCWSTR pwszHashAlgId;
} WN_CLIENT_DATA;

typedef struct {
    DWORD    dwVersion;
    DWORD    cbId;
    PBYTE    pbId;
    PCWSTR   pwszCredentialType;
} WN_CREDENTIAL, *PWN_CREDENTIAL;

typedef struct {
    DWORD          cCredentials;
    PWN_CREDENTIAL pCredentials;
} WN_CREDENTIALS;

typedef struct {
    DWORD  cExtensions;
    void  *pExtensions;
} WN_EXTENSIONS;

/* v1 prefix of WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS */
typedef struct {
    DWORD          dwVersion;
    DWORD          dwTimeoutMilliseconds;
    WN_CREDENTIALS CredentialList;
    WN_EXTENSIONS  Extensions;
    DWORD          dwAuthenticatorAttachment;
    DWORD          dwUserVerificationRequirement;
    DWORD          dwFlags;
    PCWSTR         pwszU2fAppId;
    BOOL          *pbU2fAppId;
    GUID          *pCancellationId;
} WN_GET_ASSERTION_OPTIONS;

typedef struct {
    DWORD         dwVersion;
    DWORD         cbAuthenticatorData;
    PBYTE         pbAuthenticatorData;
    DWORD         cbSignature;
    PBYTE         pbSignature;
    WN_CREDENTIAL Credential;
    DWORD         cbUserId;
    PBYTE         pbUserId;
} WN_ASSERTION, *PWN_ASSERTION;

/* The 32-bit layouts below are the API version 1 layouts from Microsoft's
 * webauthn.h (same ones the Delphi unit used). If a structure ever drifts, the
 * build fails here instead of at runtime on a user's machine. */
typedef char abi_check_client_data[sizeof(WN_CLIENT_DATA) == 16 ? 1 : -1];
typedef char abi_check_credential[sizeof(WN_CREDENTIAL) == 16 ? 1 : -1];
typedef char abi_check_credentials[sizeof(WN_CREDENTIALS) == 8 ? 1 : -1];
typedef char abi_check_extensions[sizeof(WN_EXTENSIONS) == 8 ? 1 : -1];
typedef char abi_check_assertion_opts[sizeof(WN_GET_ASSERTION_OPTIONS) == 48 ? 1 : -1];
typedef char abi_check_assertion[sizeof(WN_ASSERTION) == 44 ? 1 : -1];

/* enum values from webauthn.h */
#define WN_UV_REQUIRED     1
#define WN_UV_PREFERRED    2
#define WN_UV_DISCOURAGED  3
#define WN_ATTACHMENT_ANY  0

typedef HRESULT (WINAPI *fnGetAssertion)(HWND, LPCWSTR, const WN_CLIENT_DATA *,
                                         const WN_GET_ASSERTION_OPTIONS *, PWN_ASSERTION *);
typedef void    (WINAPI *fnFreeAssertion)(PWN_ASSERTION);
typedef PCWSTR  (WINAPI *fnGetErrorName)(HRESULT);

typedef struct {
    HMODULE         lib;
    fnGetAssertion  GetAssertion;
    fnFreeAssertion FreeAssertion;
    fnGetErrorName  GetErrorName;
    int             probed;
} wn_lib;

static wn_lib g_wn;

static void wn_load(void)
{
    if (g_wn.probed)
        return;
    g_wn.probed = 1;
    g_wn.lib = LoadLibraryW(L"webauthn.dll");
    if (!g_wn.lib)
        return;
    g_wn.GetAssertion = (fnGetAssertion)(void *)GetProcAddress(g_wn.lib,
                                                              "WebAuthNAuthenticatorGetAssertion");
    g_wn.FreeAssertion = (fnFreeAssertion)(void *)GetProcAddress(g_wn.lib,
                                                                "WebAuthNFreeAssertion");
    g_wn.GetErrorName = (fnGetErrorName)(void *)GetProcAddress(g_wn.lib,
                                                              "WebAuthNGetErrorName");
    if (!g_wn.GetAssertion || !g_wn.FreeAssertion) {
        FreeLibrary(g_wn.lib);
        g_wn.lib = NULL;
        g_wn.GetAssertion = NULL;
        g_wn.FreeAssertion = NULL;
    }
}

static int wn_available(void)
{
    wn_load();
    return g_wn.lib != NULL;
}

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

/* HRESULT -> sentence the user understands */
static void wn_error_text(HRESULT hr, char *err, size_t errlen)
{
    if (hr == (HRESULT)0x800704C7L /* ERROR_CANCELLED */ ) {
        snprintf(err, errlen, "Sign-in was cancelled.");
        return;
    }
    if (hr == (HRESULT)0x800705B4L /* ERROR_TIMEOUT */ ) {
        snprintf(err, errlen, "Timed out waiting for the security key / Hello prompt.");
        return;
    }
    if (g_wn.GetErrorName) {
        PCWSTR name = g_wn.GetErrorName(hr);
        if (name) {
            char *utf8 = NULL;
            int n = WideCharToMultiByte(CP_UTF8, 0, name, -1, NULL, 0, NULL, NULL);
            if (n > 0) {
                utf8 = (char *)p_malloc((size_t)n);
                WideCharToMultiByte(CP_UTF8, 0, name, -1, utf8, n, NULL, NULL);
                if (strcmp(utf8, "NotAllowedError") == 0)
                    snprintf(err, errlen,
                             "This passkey cannot be used here, or the prompt timed out.");
                else
                    snprintf(err, errlen, "Passkey error: %s", utf8);
                free(utf8);
                return;
            }
        }
    }
    snprintf(err, errlen, "Passkey error 0x%08lX", (unsigned long)hr);
}

/* ---------------- the ceremony ---------------- */

int passkey_sign_in(void *hwnd_owner, http_client *c, const char *rp_id,
                    const char *origin, const char *username, passkey_result *out)
{
    char err[512];
    http_resp begin = { 0 }, done = { 0 };
    json *opts = NULL, *j = NULL;
    sbuf body;
    char *req_body = NULL;
    const char *challenge, *challenge_id, *user_id, *rp;
    const json *allow;
    wchar_t *w_rp = NULL;
    WN_CREDENTIAL *creds = NULL;
    size_t cred_count = 0, i;
    WN_CLIENT_DATA client_data;
    WN_GET_ASSERTION_OPTIONS options;
    WN_ASSERTION *assertion = NULL;
    HRESULT hr;
    sbuf client_json;
    char *client_b64 = NULL, *auth_b64 = NULL, *sig_b64 = NULL, *user_b64 = NULL;
    char *id_b64 = NULL;
    int rc = -1;

    memset(out, 0, sizeof(*out));
    err[0] = 0;

    if (!wn_available()) {
        out->error = p_strdup("Passkeys need Windows 10 1903 or newer with Windows Hello "
                              "set up. Use password sign-in instead.");
        return -1;
    }
    if (!rp_id || !*rp_id) {
        out->error = p_strdup("launcher.ini has no RpId - passkeys cannot be used.");
        return -1;
    }

    /* 1. ask the server for a challenge */
    sb_init(&body);
    sb_adds(&body, "{\"username\":");
    sb_add_json_string(&body, username, strlen(username));
    sb_addc(&body, '}');
    req_body = sb_take(&body);
    if (http_post_json(c, "/api/passkey/authenticate/begin", req_body, NULL, &begin,
                       err, sizeof(err)) != 0) {
        out->error = p_strdup(err);
        goto cleanup;
    }
    opts = json_parse(begin.body, begin.len);
    if (!opts) {
        out->error = p_strdup("Invalid server response (passkey begin)");
        goto cleanup;
    }
    challenge = json_str(opts, "challenge", "");
    challenge_id = json_str(opts, "challengeId", "");
    user_id = json_str(opts, "userId", "");
    rp = json_str(opts, "rpId", rp_id);
    if (!*challenge || !*challenge_id || !*user_id) {
        out->error = p_strdup("The server did not return a passkey challenge");
        goto cleanup;
    }

    /* 2. build the client data exactly like the browser does */
    sb_init(&client_json);
    sb_adds(&client_json, "{\"type\":\"webauthn.get\",\"challenge\":");
    sb_add_json_string(&client_json, challenge, strlen(challenge));
    sb_adds(&client_json, ",\"origin\":");
    sb_add_json_string(&client_json, origin ? origin : "", strlen(origin ? origin : ""));
    sb_adds(&client_json, ",\"crossOrigin\":false}");
    memset(&client_data, 0, sizeof(client_data));
    client_data.dwVersion = 1;
    client_data.cbClientDataJSON = (DWORD)client_json.len;
    client_data.pbClientDataJSON = (PBYTE)client_json.p;
    client_data.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA256;

    /* 3. allowCredentials -> native credential list */
    allow = json_get(opts, "allowCredentials");
    if (allow && json_len(allow) > 0) {
        cred_count = json_len(allow);
        creds = (WN_CREDENTIAL *)p_malloc(cred_count * sizeof(WN_CREDENTIAL));
        memset(creds, 0, cred_count * sizeof(WN_CREDENTIAL));
        for (i = 0; i < cred_count; i++) {
            const json *item = json_at(allow, i);
            uint8_t *id = NULL;
            size_t idlen = 0;
            const char *idstr = json_str(item, "id", "");
            if (!*idstr || b64url_decode(idstr, &id, &idlen) != 0 || idlen == 0) {
                out->error = p_strdup("The server sent an invalid credential id");
                goto cleanup;
            }
            creds[i].dwVersion = 1;
            creds[i].cbId = (DWORD)idlen;
            creds[i].pbId = (PBYTE)id;
            creds[i].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
        }
    }

    w_rp = u2w(rp);
    if (!w_rp) {
        out->error = p_strdup("invalid RpId");
        goto cleanup;
    }

    {
        int timeout = (int)json_num(opts, "timeout", 60000);
        const char *uv = json_str(opts, "userVerification", "preferred");
        if (timeout <= 0)
            timeout = 60000;
        if (timeout > 180000)
            timeout = 180000;
        memset(&options, 0, sizeof(options));
        options.dwVersion = 1;
        options.dwTimeoutMilliseconds = (DWORD)timeout;
        options.CredentialList.cCredentials = (DWORD)cred_count;
        options.CredentialList.pCredentials = creds;
        options.dwAuthenticatorAttachment = WN_ATTACHMENT_ANY;
        options.dwUserVerificationRequirement = ascii_icmp(uv, "required") == 0
                                                    ? WN_UV_REQUIRED
                                                    : (ascii_icmp(uv, "discouraged") == 0
                                                           ? WN_UV_DISCOURAGED
                                                           : WN_UV_PREFERRED);
    }

    /* 4. the Windows Hello / security-key prompt */
    hr = g_wn.GetAssertion((HWND)hwnd_owner, w_rp, &client_data, &options, &assertion);
    if (FAILED(hr) || !assertion) {
        char msg[512];
        wn_error_text(hr, msg, sizeof(msg));
        out->error = p_strdup(msg);
        goto cleanup;
    }

    /* 5. POST the assertion back */
    client_b64 = b64url_encode((const uint8_t *)client_json.p, client_json.len);
    id_b64 = b64url_encode(assertion->Credential.pbId, assertion->Credential.cbId);
    auth_b64 = b64url_encode(assertion->pbAuthenticatorData, assertion->cbAuthenticatorData);
    sig_b64 = b64url_encode(assertion->pbSignature, assertion->cbSignature);
    if (assertion->cbUserId > 0)
        user_b64 = b64url_encode(assertion->pbUserId, assertion->cbUserId);

    sb_init(&body);
    sb_adds(&body, "{\"challengeId\":");
    sb_add_json_string(&body, challenge_id, strlen(challenge_id));
    sb_adds(&body, ",\"userId\":");
    sb_add_json_string(&body, user_id, strlen(user_id));
    sb_adds(&body, ",\"response\":{\"id\":");
    sb_add_json_string(&body, id_b64, strlen(id_b64));
    sb_adds(&body, ",\"rawId\":");
    sb_add_json_string(&body, id_b64, strlen(id_b64));
    sb_adds(&body, ",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":");
    sb_add_json_string(&body, client_b64, strlen(client_b64));
    sb_adds(&body, ",\"authenticatorData\":");
    sb_add_json_string(&body, auth_b64, strlen(auth_b64));
    sb_adds(&body, ",\"signature\":");
    sb_add_json_string(&body, sig_b64, strlen(sig_b64));
    if (user_b64) {
        sb_adds(&body, ",\"userHandle\":");
        sb_add_json_string(&body, user_b64, strlen(user_b64));
    }
    sb_adds(&body, "}}}");
    free(req_body);
    req_body = sb_take(&body);

    if (http_post_json(c, "/api/passkey/authenticate/complete", req_body, NULL, &done,
                       err, sizeof(err)) != 0) {
        out->error = p_strdup(err);
        goto cleanup;
    }
    j = json_parse(done.body, done.len);
    if (!j) {
        out->error = p_strdup("Invalid server response (passkey complete)");
        goto cleanup;
    }
    {
        const char *token = json_str(j, "token", "");
        const json *user = json_get(j, "user");
        if (!*token) {
            out->error = p_strdup("The server did not return a session");
            goto cleanup;
        }
        out->ok = 1;
        out->token = p_strdup(token);
        out->username = p_strdup(json_str(user, "username", username));
        out->display_name = p_strdup(json_str(user, "displayName",
                                              json_str(user, "username", username)));
    }
    rc = 0;

cleanup:
    if (assertion && g_wn.FreeAssertion)
        g_wn.FreeAssertion(assertion);
    if (creds) {
        for (i = 0; i < cred_count; i++)
            free(creds[i].pbId);
        free(creds);
    }
    free(w_rp);
    free(req_body);
    free(client_b64);
    free(id_b64);
    free(auth_b64);
    free(sig_b64);
    free(user_b64);
    json_free(j);
    json_free(opts);
    http_resp_free(&begin);
    http_resp_free(&done);
    sb_free(&client_json);   /* the buffer behind client_data.pbClientDataJSON */
    return rc;
}
