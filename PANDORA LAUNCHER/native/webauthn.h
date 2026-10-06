/*
 * webauthn.h - Windows WebAuthn API (webauthn.dll) declarations.
 *
 * Verified against Microsoft's webauthn.h; uses API version 1 structures,
 * which every Windows 10 build >= 1903 supports (Windows Hello, PIN,
 * fingerprint, security keys). The DLL is loaded dynamically, so the launcher
 * still starts on older systems and simply offers password sign-in.
 */
#ifndef PANDORA_WEBAUTHN_H
#define PANDORA_WEBAUTHN_H

#include <windows.h>
#include <stdlib.h>

#define WEBAUTHN_HASH_ALGORITHM_SHA_256 L"SHA-256"
#define WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY L"public-key"

#define WEBAUTHN_COSE_ES256 (-7)
#define WEBAUTHN_COSE_RS256 (-257)

#define WEBAUTHN_ATTACHMENT_ANY 0
#define WEBAUTHN_ATTACHMENT_PLATFORM 1
#define WEBAUTHN_ATTACHMENT_CROSS_PLATFORM 2

#define WEBAUTHN_UV_ANY 0
#define WEBAUTHN_UV_REQUIRED 1
#define WEBAUTHN_UV_PREFERRED 2
#define WEBAUTHN_UV_DISCOURAGED 3

#define WEBAUTHN_ATTESTATION_ANY 0
#define WEBAUTHN_ATTESTATION_NONE 1
#define WEBAUTHN_ATTESTATION_INDIRECT 2
#define WEBAUTHN_ATTESTATION_DIRECT 3

typedef struct _WEBAUTHN_CLIENT_DATA {
    DWORD dwVersion;
    DWORD cbClientDataJSON;
    PBYTE pbClientDataJSON;
    LPCWSTR pwszHashAlgId;
} WEBAUTHN_CLIENT_DATA, *PWEBAUTHN_CLIENT_DATA;

typedef struct _WEBAUTHN_RP_ENTITY_INFORMATION {
    DWORD dwVersion;
    LPCWSTR pwszId;
    LPCWSTR pwszName;
    LPCWSTR pwszIcon;
} WEBAUTHN_RP_ENTITY_INFORMATION, *PWEBAUTHN_RP_ENTITY_INFORMATION;

typedef struct _WEBAUTHN_USER_ENTITY_INFORMATION {
    DWORD dwVersion;
    DWORD cbId;
    PBYTE pbId;
    LPCWSTR pwszName;
    LPCWSTR pwszIcon;
    LPCWSTR pwszDisplayName;
} WEBAUTHN_USER_ENTITY_INFORMATION, *PWEBAUTHN_USER_ENTITY_INFORMATION;

typedef struct _WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
    DWORD dwVersion;
    LPCWSTR pwszCredentialType;
    LONG lAlg;
} WEBAUTHN_COSE_CREDENTIAL_PARAMETER, *PWEBAUTHN_COSE_CREDENTIAL_PARAMETER;

typedef struct _WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
    DWORD cCredentialParameters;
    PWEBAUTHN_COSE_CREDENTIAL_PARAMETER pCredentialParameters;
} WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, *PWEBAUTHN_COSE_CREDENTIAL_PARAMETERS;

typedef struct _WEBAUTHN_CREDENTIAL {
    DWORD dwVersion;
    DWORD cbId;
    PBYTE pbId;
    LPCWSTR pwszCredentialType;
} WEBAUTHN_CREDENTIAL, *PWEBAUTHN_CREDENTIAL;

typedef struct _WEBAUTHN_CREDENTIALS {
    DWORD cCredentials;
    PWEBAUTHN_CREDENTIAL pCredentials;
} WEBAUTHN_CREDENTIALS, *PWEBAUTHN_CREDENTIALS;

typedef struct _WEBAUTHN_EXTENSION {
    LPCSTR pwszExtensionIdentifier;
    DWORD cbExtension;
    PVOID pvExtension;
} WEBAUTHN_EXTENSION, *PWEBAUTHN_EXTENSION;

typedef struct _WEBAUTHN_EXTENSIONS {
    DWORD cExtensions;
    PWEBAUTHN_EXTENSION pExtensions;
} WEBAUTHN_EXTENSIONS, *PWEBAUTHN_EXTENSIONS;

/* v1 prefix of WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS */
typedef struct _WEBAUTHN_MAKE_CREDENTIAL_OPTIONS {
    DWORD dwVersion;
    DWORD dwTimeoutMilliseconds;
    WEBAUTHN_CREDENTIALS CredentialList; /* v1: exclude credentials */
    WEBAUTHN_EXTENSIONS Extensions;
    DWORD dwAuthenticatorAttachment;
    BOOL bRequireResidentKey;
    DWORD dwUserVerificationRequirement;
    DWORD dwAttestationConveyancePreference;
    DWORD dwFlags;
    GUID *pCancellationId;
} WEBAUTHN_MAKE_CREDENTIAL_OPTIONS, *PWEBAUTHN_MAKE_CREDENTIAL_OPTIONS;

/* v1 prefix of WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS */
typedef struct _WEBAUTHN_GET_ASSERTION_OPTIONS {
    DWORD dwVersion;
    DWORD dwTimeoutMilliseconds;
    WEBAUTHN_CREDENTIALS CredentialList; /* v1: allow credentials */
    WEBAUTHN_EXTENSIONS Extensions;
    DWORD dwAuthenticatorAttachment;
    DWORD dwUserVerificationRequirement;
    DWORD dwFlags;
    LPCWSTR pwszU2fAppId;
    BOOL *pbU2fAppId;
    GUID *pCancellationId;
} WEBAUTHN_GET_ASSERTION_OPTIONS, *PWEBAUTHN_GET_ASSERTION_OPTIONS;

/* v1 prefix of WEBAUTHN_CREDENTIAL_ATTESTATION */
typedef struct _WEBAUTHN_CREDENTIAL_ATTESTATION {
    DWORD dwVersion;
    LPCWSTR pwszFormatType;
    DWORD cbAuthenticatorData;
    PBYTE pbAuthenticatorData;
    DWORD cbAttestation;
    PBYTE pbAttestation;
    DWORD dwAttestationDecodeType;
    PVOID pvAttestationDecode;
    DWORD cbAttestationObject;
    PBYTE pbAttestationObject;
    DWORD cbCredentialId;
    PBYTE pbCredentialId;
} WEBAUTHN_CREDENTIAL_ATTESTATION, *PWEBAUTHN_CREDENTIAL_ATTESTATION;

/* v1 prefix of WEBAUTHN_ASSERTION */
typedef struct _WEBAUTHN_ASSERTION {
    DWORD dwVersion;
    DWORD cbAuthenticatorData;
    PBYTE pbAuthenticatorData;
    DWORD cbSignature;
    PBYTE pbSignature;
    WEBAUTHN_CREDENTIAL Credential;
    DWORD cbUserId;
    PBYTE pbUserId;
} WEBAUTHN_ASSERTION, *PWEBAUTHN_ASSERTION;

/* Dynamically loaded webauthn.dll entry points. */
typedef struct {
    HMODULE lib;
    DWORD (WINAPI *GetApiVersionNumber)(void);
    HRESULT (WINAPI *IsUserVerifyingPlatformAuthenticatorAvailable)(BOOL *out_available);
    HRESULT (WINAPI *AuthenticatorMakeCredential)(
        HWND hWnd,
        PWEBAUTHN_RP_ENTITY_INFORMATION pRpInformation,
        PWEBAUTHN_USER_ENTITY_INFORMATION pUserInformation,
        PWEBAUTHN_COSE_CREDENTIAL_PARAMETERS pPubKeyCredParams,
        PWEBAUTHN_CLIENT_DATA pWebAuthnClientData,
        PWEBAUTHN_MAKE_CREDENTIAL_OPTIONS pWebAuthnMakeCredentialOptions,
        PWEBAUTHN_CREDENTIAL_ATTESTATION *ppWebAuthnCredentialAttestation);
    HRESULT (WINAPI *AuthenticatorGetAssertion)(
        HWND hWnd,
        LPCWSTR pwszRpId,
        PWEBAUTHN_CLIENT_DATA pWebAuthnClientData,
        PWEBAUTHN_GET_ASSERTION_OPTIONS pWebAuthnGetAssertionOptions,
        PWEBAUTHN_ASSERTION *ppWebAuthnAssertion);
    VOID (WINAPI *FreeCredentialAttestation)(PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation);
    VOID (WINAPI *FreeAssertion)(PWEBAUTHN_ASSERTION pAssertion);
    PCWSTR (WINAPI *GetErrorName)(HRESULT hr);
} webauthn_api;

static webauthn_api *webauthn_load(void)
{
    webauthn_api *api = (webauthn_api *)calloc(1, sizeof(webauthn_api));
    if (!api)
        return NULL;
    api->lib = LoadLibraryW(L"webauthn.dll");
    if (!api->lib) {
        free(api);
        return NULL;
    }
#define PANDORA_LOAD(field, name)                                              \
    do {                                                                       \
        api->field = (void *)GetProcAddress(api->lib, name);                   \
    } while (0)
    PANDORA_LOAD(GetApiVersionNumber, "WebAuthNGetApiVersionNumber");
    PANDORA_LOAD(IsUserVerifyingPlatformAuthenticatorAvailable,
                 "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
    PANDORA_LOAD(AuthenticatorMakeCredential, "WebAuthNAuthenticatorMakeCredential");
    PANDORA_LOAD(AuthenticatorGetAssertion, "WebAuthNAuthenticatorGetAssertion");
    PANDORA_LOAD(FreeCredentialAttestation, "WebAuthNFreeCredentialAttestation");
    PANDORA_LOAD(FreeAssertion, "WebAuthNFreeAssertion");
    PANDORA_LOAD(GetErrorName, "WebAuthNGetErrorName");
#undef PANDORA_LOAD
    if (!api->AuthenticatorGetAssertion || !api->FreeAssertion) {
        FreeLibrary(api->lib);
        free(api);
        return NULL;
    }
    return api;
}

static void webauthn_unload(webauthn_api *api)
{
    if (!api)
        return;
    if (api->lib)
        FreeLibrary(api->lib);
    free(api);
}

/* Human-readable text for the common WebAuthn HRESULTs. */
static const wchar_t *webauthn_error_text(const webauthn_api *api, HRESULT hr)
{
    switch ((unsigned long)hr) {
    case 0x800704C7UL: /* ERROR_CANCELLED */
        return L"Sign-in was cancelled.";
    case 0x800705B4UL: /* ERROR_TIMEOUT */
        return L"Timed out waiting for the Windows Hello / security key prompt.";
    case 0x80090027UL: /* NTE_INVALID_PARAMETER */
    case 0x80070057UL: /* E_INVALIDARG */
        return L"The passkey prompt rejected the request parameters.";
    default:
        break;
    }
    if (api && api->GetErrorName) {
        PCWSTR name = api->GetErrorName(hr);
        if (name) {
            if (lstrcmpW(name, L"NotAllowedError") == 0)
                return L"This passkey cannot be used here, or the prompt timed out.";
            return name; /* e.g. "NotAllowedError" / "SecurityError" */
        }
    }
    return L"Passkey error.";
}

#endif /* PANDORA_WEBAUTHN_H */
