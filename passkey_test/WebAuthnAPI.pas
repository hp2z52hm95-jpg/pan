unit WebAuthnAPI;

{
  Delphi headers for Windows WebAuthn API (webauthn.dll)
  Requires Windows 10 version 1903 or later
  
  Reference: https://docs.microsoft.com/en-us/windows/win32/api/webauthn/
}

interface

uses
  Winapi.Windows, System.SysUtils;

const
  WEBAUTHN_API_VERSION_1 = 1;
  WEBAUTHN_API_VERSION_2 = 2;
  WEBAUTHN_API_VERSION_3 = 3;
  WEBAUTHN_API_VERSION_4 = 4;
  WEBAUTHN_API_VERSION_5 = 5;
  WEBAUTHN_API_VERSION_6 = 6;
  WEBAUTHN_API_CURRENT_VERSION = WEBAUTHN_API_VERSION_6;

  // Authenticator attachment
  WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY = 0;
  WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM = 1;
  WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 2;

  // User verification requirement
  WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY = 0;
  WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED = 1;
  WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED = 2;
  WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 3;

  // Attestation conveyance preference
  WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY = 0;
  WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 1;
  WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT = 2;
  WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 3;

  // Resident key requirement
  WEBAUTHN_RESIDENT_KEY_REQUIREMENT_ANY = 0;
  WEBAUTHN_RESIDENT_KEY_REQUIREMENT_DISCOURAGED = 1;
  WEBAUTHN_RESIDENT_KEY_REQUIREMENT_PREFERRED = 2;
  WEBAUTHN_RESIDENT_KEY_REQUIREMENT_REQUIRED = 3;

type
  // Byte buffer structure
  WEBAUTHN_CREDENTIAL_ID = record
    cbId: DWORD;
    pbId: PByte;
  end;
  PWEBAUTHN_CREDENTIAL_ID = ^WEBAUTHN_CREDENTIAL_ID;

  // Relying party entity
  WEBAUTHN_RP_ENTITY_INFORMATION = record
    cbSize: DWORD;
    pcwszId: PWideChar;
    pcwszName: PWideChar;
    pcwszIcon: PWideChar;
  end;
  PWEBAUTHN_RP_ENTITY_INFORMATION = ^WEBAUTHN_RP_ENTITY_INFORMATION;

  // User entity
  WEBAUTHN_USER_ENTITY_INFORMATION = record
    cbSize: DWORD;
    cbId: DWORD;
    pbId: PByte;
    pcwszDisplayName: PWideChar;
    pcwszIcon: PWideChar;
    pcwszName: PWideChar;
  end;
  PWEBAUTHN_USER_ENTITY_INFORMATION = ^WEBAUTHN_USER_ENTITY_INFORMATION;

  // Credential parameters
  WEBAUTHN_CREDENTIAL_PARAMETERS = record
    cbCount: DWORD;
    pCredentialParameters: Pointer;
  end;
  PWEBAUTHN_CREDENTIAL_PARAMETERS = ^WEBAUTHN_CREDENTIAL_PARAMETERS;

  // Credential list
  WEBAUTHN_CREDENTIAL_LIST = record
    cCredentials: DWORD;
    ppCredentials: Pointer;
  end;
  PWEBAUTHN_CREDENTIAL_LIST = ^WEBAUTHN_CREDENTIAL_LIST;

  // Make credential options
  WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = record
    cbSize: DWORD;
    dwTimeoutMilliseconds: DWORD;
    CredentialList: WEBAUTHN_CREDENTIAL_LIST;
    Extensions: Pointer;
    dwAuthenticatorAttachment: DWORD;
    bRequireResidentKey: BOOL;
    dwUserVerificationRequirement: DWORD;
    dwAttestationConveyancePreference: DWORD;
    dwFlags: DWORD;
    pU2fAppId: PWideChar;
    pbU2fAppId: PBOOL;
    pCancelId: Pointer;
    pPublicKeyCredentialDesired: Pointer;
    dwMinimumCachedTime: DWORD;
    hWnd: HWND;
  end;
  PWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = ^WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS;

  // Get assertion options
  WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = record
    cbSize: DWORD;
    dwTimeoutMilliseconds: DWORD;
    CredentialList: WEBAUTHN_CREDENTIAL_LIST;
    Extensions: Pointer;
    dwAuthenticatorAttachment: DWORD;
    dwUserVerificationRequirement: DWORD;
    dwFlags: DWORD;
    pU2fAppId: PWideChar;
    pbU2fAppId: PBOOL;
    pCancelId: Pointer;
    pPublicKeyCredentialDesired: Pointer;
    dwMinimumCachedTime: DWORD;
    hWnd: HWND;
  end;
  PWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = ^WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS;

  // Credential response
  WEBAUTHN_CREDENTIAL_ATTESTATION = record
    cbSize: DWORD;
    pwszFormatType: PWideChar;
    cbAuthData: DWORD;
    pbAuthData: PByte;
    cbAttestation: DWORD;
    pbAttestation: PByte;
    cbAttestationObject: DWORD;
    pbAttestationObject: PByte;
    CredentialId: WEBAUTHN_CREDENTIAL_ID;
  end;
  PWEBAUTHN_CREDENTIAL_ATTESTATION = ^WEBAUTHN_CREDENTIAL_ATTESTATION;

  // Assertion response
  WEBAUTHN_ASSERTION = record
    cbSize: DWORD;
    cbAuthenticatorData: DWORD;
    pbAuthenticatorData: PByte;
    cbSignature: DWORD;
    pbSignature: PByte;
    Credential: WEBAUTHN_CREDENTIAL_ID;
    cbUserId: DWORD;
    pbUserId: PByte;
  end;
  PWEBAUTHN_ASSERTION = ^WEBAUTHN_ASSERTION;

  // Common struct for COSE credential parameters
  WEBAUTHN_COSE_CREDENTIAL_PARAMETER = record
    pwszCredentialType: PWideChar;
    lAlg: Integer;
  end;
  PWEBAUTHN_COSE_CREDENTIAL_PARAMETER = ^WEBAUTHN_COSE_CREDENTIAL_PARAMETER;

  WEBAUTHN_COSE_CREDENTIAL_PARAMETERS = record
    cCredentialParameters: DWORD;
    pCredentialParameters: PWEBAUTHN_COSE_CREDENTIAL_PARAMETER;
  end;
  PWEBAUTHN_COSE_CREDENTIAL_PARAMETERS = ^WEBAUTHN_COSE_CREDENTIAL_PARAMETERS;

// API Functions
function WebAuthNGetApiVersionNumber: DWORD; stdcall; external 'webauthn.dll';

function WebAuthNAuthenticatorMakeCredential(
  hWnd: HWND;
  pRpInformation: PWEBAUTHN_RP_ENTITY_INFORMATION;
  pUserInformation: PWEBAUTHN_USER_ENTITY_INFORMATION;
  pPubKeyCredParams: PWEBAUTHN_COSE_CREDENTIAL_PARAMETERS;
  pMakeCredentialOptions: PWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS;
  out ppMakeCredentialResult: PWEBAUTHN_CREDENTIAL_ATTESTATION
): HRESULT; stdcall; external 'webauthn.dll';

function WebAuthNAuthenticatorGetAssertion(
  hWnd: HWND;
  pcwszRpId: PWideChar;
  pGetAssertionOptions: PWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS;
  out ppAssertion: PWEBAUTHN_ASSERTION
): HRESULT; stdcall; external 'webauthn.dll';

procedure WebAuthNFreeCredentialAttestation(
  pWebAuthNCredentialAttestation: PWEBAUTHN_CREDENTIAL_ATTESTATION
); stdcall; external 'webauthn.dll';

procedure WebAuthNFreeAssertion(
  pAssertion: PWEBAUTHN_ASSERTION
); stdcall; external 'webauthn.dll';

function WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
  out pbIsUserVerifyingPlatformAuthenticatorAvailable: BOOL
): HRESULT; stdcall; external 'webauthn.dll';

implementation

end.
