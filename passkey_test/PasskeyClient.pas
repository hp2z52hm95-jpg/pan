unit PasskeyClient;

{
  Passkey Client - Wraps Windows WebAuthn API for easy use
  
  Provides high-level methods for:
  - Checking WebAuthn availability
  - Registering new passkeys
  - Authenticating with passkeys
}

interface

uses
  System.SysUtils, System.Classes, Winapi.Windows,
  WebAuthnAPI, CryptoUtils, MockServer;

type
  TPasskeyRegistrationResult = record
    Success: Boolean;
    CredentialId: TBytes;
    PublicKey: TBytes;
    AttestationObject: TBytes;
    ErrorMessage: string;
  end;

  TPasskeyAuthenticationResult = record
    Success: Boolean;
    CredentialId: TBytes;
    Signature: TBytes;
    AuthenticatorData: TBytes;
    ErrorMessage: string;
  end;

  TPasskeyClient = class
  private
    FServer: TMockServer;
    FUserId: string;
    FUserName: string;
    FWebAuthnAvailable: Boolean;
    FPlatformAuthenticatorAvailable: Boolean;
    procedure CheckWebAuthnAvailability;
  public
    constructor Create(Server: TMockServer; const UserId, UserName: string);
    destructor Destroy; override;

    // Properties
    property WebAuthnAvailable: Boolean read FWebAuthnAvailable;
    property PlatformAuthenticatorAvailable: Boolean read FPlatformAuthenticatorAvailable;
    property UserId: string read FUserId;
    property UserName: string read FUserName;

    // Passkey operations
    function RegisterPasskey(hWnd: HWND): TPasskeyRegistrationResult;
    function AuthenticatePasskey(hWnd: HWND): TPasskeyAuthenticationResult;
    
    // Utility
    function HasRegisteredPasskeys: Boolean;
    function GetRegisteredPasskeys: TArray<TStoredCredential>;
    function DeletePasskey(const CredentialId: TBytes): Boolean;
  end;

implementation

{ TPasskeyClient }

constructor TPasskeyClient.Create(Server: TMockServer; const UserId, UserName: string);
begin
  inherited Create;
  FServer := Server;
  FUserId := UserId;
  FUserName := UserName;
  
  CheckWebAuthnAvailability;
end;

destructor TPasskeyClient.Destroy;
begin
  inherited;
end;

procedure TPasskeyClient.CheckWebAuthnAvailability;
var
  IsAvailable: BOOL;
  HR: HRESULT;
begin
  FWebAuthnAvailable := False;
  FPlatformAuthenticatorAvailable := False;
  
  try
    // Check if WebAuthn API is available (Windows 10 1903+)
    if WebAuthNGetApiVersionNumber >= WEBAUTHN_API_VERSION_1 then
      FWebAuthnAvailable := True;
    
    // Check if platform authenticator (Windows Hello) is available
    if FWebAuthnAvailable then
    begin
      HR := WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(IsAvailable);
      if Succeeded(HR) then
        FPlatformAuthenticatorAvailable := IsAvailable;
    end;
  except
    // WebAuthn API not available (older Windows version)
    FWebAuthnAvailable := False;
    FPlatformAuthenticatorAvailable := False;
  end;
end;

function TPasskeyClient.RegisterPasskey(hWnd: HWND): TPasskeyRegistrationResult;
var
  RpInfo: WEBAUTHN_RP_ENTITY_INFORMATION;
  UserInfo: WEBAUTHN_USER_ENTITY_INFORMATION;
  Options: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS;
  CredAttestation: PWEBAUTHN_CREDENTIAL_ATTESTATION;
  Challenge: TBytes;
  UserIdBytes: TBytes;
  CoseParams: WEBAUTHN_COSE_CREDENTIAL_PARAMETERS;
  Param: WEBAUTHN_COSE_CREDENTIAL_PARAMETER;
  HR: HRESULT;
begin
  Result.Success := False;
  Result.ErrorMessage := '';
  
  if not FWebAuthnAvailable then
  begin
    Result.ErrorMessage := 'WebAuthn API not available. Requires Windows 10 version 1903 or later.';
    Exit;
  end;
  
  if not FPlatformAuthenticatorAvailable then
  begin
    Result.ErrorMessage := 'Platform authenticator (Windows Hello) not available. Please set up Windows Hello PIN.';
    Exit;
  end;
  
  try
    // Get challenge from server
    Challenge := FServer.BeginRegistration(FUserId, FUserName);
    
    // Prepare relying party info
    FillChar(RpInfo, SizeOf(RpInfo), 0);
    RpInfo.cbSize := SizeOf(RpInfo);
    RpInfo.pcwszId := PWideChar(FServer.RelyingPartyId);
    RpInfo.pcwszName := PWideChar(FServer.RelyingPartyName);
    RpInfo.pcwszIcon := nil;
    
    // Prepare user info
    UserIdBytes := TEncoding.UTF8.GetBytes(FUserId);
    FillChar(UserInfo, SizeOf(UserInfo), 0);
    UserInfo.cbSize := SizeOf(UserInfo);
    UserInfo.cbId := Length(UserIdBytes);
    UserInfo.pbId := @UserIdBytes[0];
    UserInfo.pcwszDisplayName := PWideChar(FUserName);
    UserInfo.pcwszIcon := nil;
    UserInfo.pcwszName := PWideChar(FUserId);
    
    // Prepare COSE parameters (request ES256 algorithm)
    Param.pwszCredentialType := 'public-key';
    Param.lAlg := -7; // ES256 (ECDSA with P-256 and SHA-256)
    CoseParams.cCredentialParameters := 1;
    CoseParams.pCredentialParameters := @Param;
    
    // Prepare options
    FillChar(Options, SizeOf(Options), 0);
    Options.cbSize := SizeOf(Options);
    Options.dwTimeoutMilliseconds := 60000; // 60 seconds
    Options.dwAuthenticatorAttachment := WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    Options.bRequireResidentKey := False;
    Options.dwUserVerificationRequirement := WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    Options.dwAttestationConveyancePreference := WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    Options.hWnd := hWnd;
    
    // Call WebAuthn API
    CredAttestation := nil;
    HR := WebAuthNAuthenticatorMakeCredential(
      hWnd,
      @RpInfo,
      @UserInfo,
      @CoseParams,
      @Options,
      CredAttestation
    );
    
    if Failed(HR) then
    begin
      case Cardinal(HR) of
        $800704C7: Result.ErrorMessage := 'User cancelled authentication';
        $80070005: Result.ErrorMessage := 'Access denied. Try running as administrator.';
        else Result.ErrorMessage := Format('WebAuthn error: 0x%.8X', [Cardinal(HR)]);
      end;
      Exit;
    end;
    
    try
      // Extract credential ID
      SetLength(Result.CredentialId, CredAttestation.CredentialId.cbId);
      if CredAttestation.CredentialId.cbId > 0 then
        Move(CredAttestation.CredentialId.pbId^, Result.CredentialId[0], CredAttestation.CredentialId.cbId);
      
      // Extract attestation object (contains public key)
      SetLength(Result.AttestationObject, CredAttestation.cbAttestationObject);
      if CredAttestation.cbAttestationObject > 0 then
        Move(CredAttestation.pbAttestationObject^, Result.AttestationObject[0], CredAttestation.cbAttestationObject);
      
      // For this mock, we'll use the attestation object as the "public key"
      // In a real implementation, we would parse the CBOR to extract the actual public key
      Result.PublicKey := Result.AttestationObject;
      
      // Send to server
      if FServer.CompleteRegistration(FUserId, FUserName, Result.CredentialId, Result.PublicKey) then
        Result.Success := True
      else
        Result.ErrorMessage := 'Server rejected registration (credential already exists)';
    finally
      WebAuthNFreeCredentialAttestation(CredAttestation);
    end;
    
  except
    on E: Exception do
      Result.ErrorMessage := 'Exception: ' + E.Message;
  end;
end;

function TPasskeyClient.AuthenticatePasskey(hWnd: HWND): TPasskeyAuthenticationResult;
var
  Options: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS;
  Assertion: PWEBAUTHN_ASSERTION;
  Challenge: TBytes;
  HR: HRESULT;
begin
  Result.Success := False;
  Result.ErrorMessage := '';
  
  if not FWebAuthnAvailable then
  begin
    Result.ErrorMessage := 'WebAuthn API not available';
    Exit;
  end;
  
  if not HasRegisteredPasskeys then
  begin
    Result.ErrorMessage := 'No passkeys registered. Please register a passkey first.';
    Exit;
  end;
  
  try
    // Get challenge from server
    Challenge := FServer.BeginAuthentication(FUserId);
    
    // Prepare options
    FillChar(Options, SizeOf(Options), 0);
    Options.cbSize := SizeOf(Options);
    Options.dwTimeoutMilliseconds := 60000;
    Options.dwAuthenticatorAttachment := WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    Options.dwUserVerificationRequirement := WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    Options.hWnd := hWnd;
    
    // Call WebAuthn API
    Assertion := nil;
    HR := WebAuthNAuthenticatorGetAssertion(
      hWnd,
      PWideChar(FServer.RelyingPartyId),
      @Options,
      Assertion
    );
    
    if Failed(HR) then
    begin
      case Cardinal(HR) of
        $800704C7: Result.ErrorMessage := 'User cancelled authentication';
        $80070005: Result.ErrorMessage := 'Access denied';
        else Result.ErrorMessage := Format('WebAuthn error: 0x%.8X', [Cardinal(HR)]);
      end;
      Exit;
    end;
    
    try
      // Extract credential ID
      SetLength(Result.CredentialId, Assertion.Credential.cbId);
      if Assertion.Credential.cbId > 0 then
        Move(Assertion.Credential.pbId^, Result.CredentialId[0], Assertion.Credential.cbId);
      
      // Extract signature
      SetLength(Result.Signature, Assertion.cbSignature);
      if Assertion.cbSignature > 0 then
        Move(Assertion.pbSignature^, Result.Signature[0], Assertion.cbSignature);
      
      // Extract authenticator data
      SetLength(Result.AuthenticatorData, Assertion.cbAuthenticatorData);
      if Assertion.cbAuthenticatorData > 0 then
        Move(Assertion.pbAuthenticatorData^, Result.AuthenticatorData[0], Assertion.cbAuthenticatorData);
      
      // Send to server for verification
      // For this mock, we pass empty clientDataJSON
      if FServer.CompleteAuthentication(FUserId, Result.CredentialId, Result.Signature, 
                                         Result.AuthenticatorData, nil) then
        Result.Success := True
      else
        Result.ErrorMessage := 'Server rejected authentication';
    finally
      WebAuthNFreeAssertion(Assertion);
    end;
    
  except
    on E: Exception do
      Result.ErrorMessage := 'Exception: ' + E.Message;
  end;
end;

function TPasskeyClient.HasRegisteredPasskeys: Boolean;
begin
  Result := Length(GetRegisteredPasskeys) > 0;
end;

function TPasskeyClient.GetRegisteredPasskeys: TArray<TStoredCredential>;
begin
  Result := FServer.GetCredentialsForUser(FUserId);
end;

function TPasskeyClient.DeletePasskey(const CredentialId: TBytes): Boolean;
begin
  Result := FServer.DeleteCredential(CredentialId);
end;

end.
