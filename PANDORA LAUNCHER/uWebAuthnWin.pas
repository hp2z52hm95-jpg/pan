unit uWebAuthnWin;

{
  Windows WebAuthn API (webauthn.dll) headers for Delphi.

  Verified against Microsoft webauthn.h. Uses API v1 structures, which every
  Windows 10 build >= 1903 supports.

  Loaded dynamically: if webauthn.dll is missing (old Windows), the launcher
  still starts and TWebAuthnLib.Available returns False, so the caller can
  fall back to password sign-in instead of crashing at startup.
}

interface

uses
  Winapi.Windows, System.SysUtils;

const
  WEBAUTHN_HASH_ALGORITHM_SHA_256 = 'SHA-256';
  WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = 'public-key';

  WEBAUTHN_COSE_ES256 = -7;
  WEBAUTHN_COSE_RS256 = -257;

  WEBAUTHN_ATTACHMENT_ANY = 0;
  WEBAUTHN_ATTACHMENT_PLATFORM = 1;
  WEBAUTHN_ATTACHMENT_CROSS_PLATFORM = 2;

  WEBAUTHN_UV_ANY = 0;
  WEBAUTHN_UV_REQUIRED = 1;
  WEBAUTHN_UV_PREFERRED = 2;
  WEBAUTHN_UV_DISCOURAGED = 3;

  WEBAUTHN_ATTESTATION_ANY = 0;
  WEBAUTHN_ATTESTATION_NONE = 1;
  WEBAUTHN_ATTESTATION_INDIRECT = 2;
  WEBAUTHN_ATTESTATION_DIRECT = 3;

type
  PWinBool = ^BOOL;

  PWEBAUTHN_CLIENT_DATA = ^WEBAUTHN_CLIENT_DATA;
  WEBAUTHN_CLIENT_DATA = record
    dwVersion: DWORD;
    cbClientDataJSON: DWORD;
    pbClientDataJSON: PByte;
    pwszHashAlgId: PWideChar;
  end;

  PWEBAUTHN_RP_ENTITY_INFORMATION = ^WEBAUTHN_RP_ENTITY_INFORMATION;
  WEBAUTHN_RP_ENTITY_INFORMATION = record
    dwVersion: DWORD;
    pwszId: PWideChar;
    pwszName: PWideChar;
    pwszIcon: PWideChar;
  end;

  PWEBAUTHN_USER_ENTITY_INFORMATION = ^WEBAUTHN_USER_ENTITY_INFORMATION;
  WEBAUTHN_USER_ENTITY_INFORMATION = record
    dwVersion: DWORD;
    cbId: DWORD;
    pbId: PByte;
    pwszName: PWideChar;
    pwszIcon: PWideChar;
    pwszDisplayName: PWideChar;
  end;

  PWEBAUTHN_COSE_CREDENTIAL_PARAMETER = ^WEBAUTHN_COSE_CREDENTIAL_PARAMETER;
  WEBAUTHN_COSE_CREDENTIAL_PARAMETER = record
    dwVersion: DWORD;
    pwszCredentialType: PWideChar;
    lAlg: LONG;
  end;

  PWEBAUTHN_COSE_CREDENTIAL_PARAMETERS = ^WEBAUTHN_COSE_CREDENTIAL_PARAMETERS;
  WEBAUTHN_COSE_CREDENTIAL_PARAMETERS = record
    cCredentialParameters: DWORD;
    pCredentialParameters: PWEBAUTHN_COSE_CREDENTIAL_PARAMETER;
  end;

  PWEBAUTHN_CREDENTIAL = ^WEBAUTHN_CREDENTIAL;
  WEBAUTHN_CREDENTIAL = record
    dwVersion: DWORD;
    cbId: DWORD;
    pbId: PByte;
    pwszCredentialType: PWideChar;
  end;

  PWEBAUTHN_CREDENTIALS = ^WEBAUTHN_CREDENTIALS;
  WEBAUTHN_CREDENTIALS = record
    cCredentials: DWORD;
    pCredentials: PWEBAUTHN_CREDENTIAL;
  end;

  PWEBAUTHN_EXTENSIONS = ^WEBAUTHN_EXTENSIONS;
  WEBAUTHN_EXTENSIONS = record
    cExtensions: DWORD;
    pExtensions: Pointer;
  end;

  // v1 prefix of WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
  PWEBAUTHN_MAKE_CREDENTIAL_OPTIONS = ^WEBAUTHN_MAKE_CREDENTIAL_OPTIONS;
  WEBAUTHN_MAKE_CREDENTIAL_OPTIONS = record
    dwVersion: DWORD;
    dwTimeoutMilliseconds: DWORD;
    CredentialList: WEBAUTHN_CREDENTIALS; // v1: exclude-credentials list
    Extensions: WEBAUTHN_EXTENSIONS;
    dwAuthenticatorAttachment: DWORD;
    bRequireResidentKey: BOOL;
    dwUserVerificationRequirement: DWORD;
    dwAttestationConveyancePreference: DWORD;
    dwFlags: DWORD;
    pCancellationId: PGUID;
  end;

  // v1 prefix of WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
  PWEBAUTHN_GET_ASSERTION_OPTIONS = ^WEBAUTHN_GET_ASSERTION_OPTIONS;
  WEBAUTHN_GET_ASSERTION_OPTIONS = record
    dwVersion: DWORD;
    dwTimeoutMilliseconds: DWORD;
    CredentialList: WEBAUTHN_CREDENTIALS; // v1: allow-credentials list
    Extensions: WEBAUTHN_EXTENSIONS;
    dwAuthenticatorAttachment: DWORD;
    dwUserVerificationRequirement: DWORD;
    dwFlags: DWORD;
    pwszU2fAppId: PWideChar;
    pbU2fAppId: PWinBool;
    pCancellationId: PGUID;
  end;

  // v1 prefix of WEBAUTHN_CREDENTIAL_ATTESTATION
  PWEBAUTHN_CREDENTIAL_ATTESTATION = ^WEBAUTHN_CREDENTIAL_ATTESTATION;
  WEBAUTHN_CREDENTIAL_ATTESTATION = record
    dwVersion: DWORD;
    pwszFormatType: PWideChar;
    cbAuthenticatorData: DWORD;
    pbAuthenticatorData: PByte;
    cbAttestation: DWORD;
    pbAttestation: PByte;
    dwAttestationDecodeType: DWORD;
    pvAttestationDecode: Pointer;
    cbAttestationObject: DWORD;
    pbAttestationObject: PByte;
    cbCredentialId: DWORD;
    pbCredentialId: PByte;
  end;

  // v1 prefix of WEBAUTHN_ASSERTION
  PWEBAUTHN_ASSERTION = ^WEBAUTHN_ASSERTION;
  WEBAUTHN_ASSERTION = record
    dwVersion: DWORD;
    cbAuthenticatorData: DWORD;
    pbAuthenticatorData: PByte;
    cbSignature: DWORD;
    pbSignature: PByte;
    Credential: WEBAUTHN_CREDENTIAL;
    cbUserId: DWORD;
    pbUserId: PByte;
  end;

type
  TFnGetApiVersion = function: DWORD; stdcall;
  TFnIsUVPlatformAvailable = function(out Available: BOOL): HRESULT; stdcall;
  TFnMakeCredential = function(hWnd: HWND;
    pRpInfo: PWEBAUTHN_RP_ENTITY_INFORMATION;
    pUserInfo: PWEBAUTHN_USER_ENTITY_INFORMATION;
    pPubKeyCredParams: PWEBAUTHN_COSE_CREDENTIAL_PARAMETERS;
    pClientData: PWEBAUTHN_CLIENT_DATA;
    pOptions: PWEBAUTHN_MAKE_CREDENTIAL_OPTIONS;
    out ppAttestation: PWEBAUTHN_CREDENTIAL_ATTESTATION): HRESULT; stdcall;
  TFnGetAssertion = function(hWnd: HWND;
    pwszRpId: PWideChar;
    pClientData: PWEBAUTHN_CLIENT_DATA;
    pOptions: PWEBAUTHN_GET_ASSERTION_OPTIONS;
    out ppAssertion: PWEBAUTHN_ASSERTION): HRESULT; stdcall;
  TFnFreeAttestation = procedure(p: PWEBAUTHN_CREDENTIAL_ATTESTATION); stdcall;
  TFnFreeAssertion = procedure(p: PWEBAUTHN_ASSERTION); stdcall;
  TFnGetErrorName = function(hr: HRESULT): PWideChar; stdcall;

  TWebAuthnLib = class
  private
    FLib: HMODULE;
  public
    GetApiVersion: TFnGetApiVersion;
    IsUVPlatformAvailable: TFnIsUVPlatformAvailable;
    MakeCredential: TFnMakeCredential;
    GetAssertion: TFnGetAssertion;
    FreeAttestation: TFnFreeAttestation;
    FreeAssertion: TFnFreeAssertion;
    GetErrorName: TFnGetErrorName;
    constructor Create;
    destructor Destroy; override;
    function Available: Boolean;
    function ErrorMessage(hr: HRESULT): string;
  end;

function HrFailed(hr: HRESULT): Boolean;

implementation

function HrFailed(hr: HRESULT): Boolean;
begin
  Result := hr < 0;
end;

{ TWebAuthnLib }

constructor TWebAuthnLib.Create;
begin
  inherited Create;
  FLib := LoadLibrary('webauthn.dll');
  if FLib = 0 then
    Exit;
  GetApiVersion := GetProcAddress(FLib, 'WebAuthNGetApiVersionNumber');
  IsUVPlatformAvailable := GetProcAddress(FLib, 'WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable');
  MakeCredential := GetProcAddress(FLib, 'WebAuthNAuthenticatorMakeCredential');
  GetAssertion := GetProcAddress(FLib, 'WebAuthNAuthenticatorGetAssertion');
  FreeAttestation := GetProcAddress(FLib, 'WebAuthNFreeCredentialAttestation');
  FreeAssertion := GetProcAddress(FLib, 'WebAuthNFreeAssertion');
  GetErrorName := GetProcAddress(FLib, 'WebAuthNGetErrorName');
end;

destructor TWebAuthnLib.Destroy;
begin
  if FLib <> 0 then
    FreeLibrary(FLib);
  inherited;
end;

function TWebAuthnLib.Available: Boolean;
begin
  Result :=
    Assigned(MakeCredential) and
    Assigned(GetAssertion) and
    Assigned(FreeAttestation) and
    Assigned(FreeAssertion);
end;

function TWebAuthnLib.ErrorMessage(hr: HRESULT): string;
var
  P: PWideChar;
begin
  if hr = HRESULT($800704C7) then // ERROR_CANCELLED: user pressed Cancel
    Exit('Sign-in was cancelled.');
  if hr = HRESULT($800705B4) then // ERROR_TIMEOUT
    Exit('Timed out waiting for the security key / Hello prompt.');
  if Assigned(GetErrorName) then
  begin
    P := GetErrorName(hr);
    if P <> nil then
    begin
      Result := string(P);
      if SameText(Result, 'NotAllowedError') then
        Exit('This passkey cannot be used here, or the prompt timed out.');
      Exit('Passkey error: ' + Result);
    end;
  end;
  Result := 'Passkey error $' + IntToHex(LongWord(hr), 8);
end;

end.
