unit MockServer;

{
  Mock FIDO2 Server for Passkey Testing
  
  In a real implementation, this would be a remote server with:
  - Database of registered credentials
  - Challenge generation
  - Signature verification
  - Session management
  
  For this smoke test, we simulate it locally.
}

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections,
  CryptoUtils;

type
  TStoredCredential = record
    CredentialId: TBytes;
    PublicKey: TBytes;
    UserId: string;
    UserName: string;
    SignCount: Cardinal;
    CreatedAt: TDateTime;
    LastUsed: TDateTime;
  end;

  TChallengeSession = record
    Challenge: TBytes;
    UserId: string;
    CreatedAt: TDateTime;
    ExpiresAt: TDateTime;
  end;

  TMockServer = class
  private
    FCredentials: TList<TStoredCredential>;
    FChallenges: TDictionary<string, TChallengeSession>;
    FRelyingPartyId: string;
    FRelyingPartyName: string;
    FOrigin: string;
  public
    constructor Create;
    destructor Destroy; override;

    // Server configuration
    property RelyingPartyId: string read FRelyingPartyId;
    property RelyingPartyName: string read FRelyingPartyName;
    property Origin: string read FOrigin;

    // Registration flow
    function BeginRegistration(const UserId, UserName: string): TBytes;
    function CompleteRegistration(
      const UserId, UserName: string;
      const CredentialId, PublicKey: TBytes): Boolean;

    // Authentication flow
    function BeginAuthentication(const UserId: string): TBytes;
    function CompleteAuthentication(
      const UserId: string;
      const CredentialId, Signature, AuthenticatorData, ClientDataJSON: TBytes): Boolean;

    // Credential management
    function GetCredentialsForUser(const UserId: string): TArray<TStoredCredential>;
    function DeleteCredential(const CredentialId: TBytes): Boolean;
    function CredentialExists(const CredentialId: TBytes): Boolean;

    // Utility
    function ValidateChallenge(const Challenge: TBytes; const UserId: string): Boolean;
  end;

implementation

{ TMockServer }

constructor TMockServer.Create;
begin
  inherited Create;
  FCredentials := TList<TStoredCredential>.Create;
  FChallenges := TDictionary<string, TChallengeSession>.Create;
  
  // Configure relying party
  FRelyingPartyId := 'localhost';
  FRelyingPartyName := 'Pandora Tool Passkey Test';
  FOrigin := 'https://localhost';
end;

destructor TMockServer.Destroy;
begin
  FCredentials.Free;
  FChallenges.Free;
  inherited;
end;

function TMockServer.BeginRegistration(const UserId, UserName: string): TBytes;
var
  Session: TChallengeSession;
begin
  // Generate random challenge
  Result := TCryptoUtils.GenerateChallenge(32);
  
  // Store session
  Session.Challenge := Result;
  Session.UserId := UserId;
  Session.CreatedAt := Now;
  Session.ExpiresAt := Now + (5 / 1440); // 5 minutes
  
  FChallenges.AddOrSetValue('reg_' + UserId, Session);
end;

function TMockServer.CompleteRegistration(
  const UserId, UserName: string;
  const CredentialId, PublicKey: TBytes): Boolean;
var
  Cred: TStoredCredential;
begin
  // In a real server, we would:
  // 1. Verify attestation object
  // 2. Extract public key from CBOR
  // 3. Verify attestation certificate chain
  // 4. Check that credential ID is not already registered
  
  // For this mock, we just store the credential
  
  if CredentialExists(CredentialId) then
  begin
    Result := False;
    Exit;
  end;
  
  Cred.CredentialId := CredentialId;
  Cred.PublicKey := PublicKey;
  Cred.UserId := UserId;
  Cred.UserName := UserName;
  Cred.SignCount := 0;
  Cred.CreatedAt := Now;
  Cred.LastUsed := Now;
  
  FCredentials.Add(Cred);
  Result := True;
end;

function TMockServer.BeginAuthentication(const UserId: string): TBytes;
var
  Session: TChallengeSession;
begin
  // Generate random challenge
  Result := TCryptoUtils.GenerateChallenge(32);
  
  // Store session
  Session.Challenge := Result;
  Session.UserId := UserId;
  Session.CreatedAt := Now;
  Session.ExpiresAt := Now + (5 / 1440); // 5 minutes
  
  FChallenges.AddOrSetValue('auth_' + UserId, Session);
end;

function TMockServer.CompleteAuthentication(
  const UserId: string;
  const CredentialId, Signature, AuthenticatorData, ClientDataJSON: TBytes): Boolean;
var
  I: Integer;
  Cred: TStoredCredential;
  Found: Boolean;
begin
  // In a real server, we would:
  // 1. Find credential by ID
  // 2. Verify signature using stored public key
  // 3. Verify authenticator data (rpIdHash, flags, signCount)
  // 4. Verify clientDataJSON (challenge, origin, type)
  // 5. Update sign count
  
  // For this mock, we simulate verification
  
  Found := False;
  for I := 0 to FCredentials.Count - 1 do
  begin
    Cred := FCredentials[I];
    if TCryptoUtils.BytesEqual(Cred.CredentialId, CredentialId) and
       (Cred.UserId = UserId) then
    begin
      Found := True;
      
      // Update sign count and last used
      Inc(Cred.SignCount);
      Cred.LastUsed := Now;
      FCredentials[I] := Cred;
      
      Break;
    end;
  end;
  
  // In a real implementation, we would verify the signature
  // For this mock, we assume it's valid if credential exists
  Result := Found;
end;

function TMockServer.GetCredentialsForUser(const UserId: string): TArray<TStoredCredential>;
var
  I: Integer;
  List: TList<TStoredCredential>;
begin
  List := TList<TStoredCredential>.Create;
  try
    for I := 0 to FCredentials.Count - 1 do
      if FCredentials[I].UserId = UserId then
        List.Add(FCredentials[I]);
    
    Result := List.ToArray;
  finally
    List.Free;
  end;
end;

function TMockServer.DeleteCredential(const CredentialId: TBytes): Boolean;
var
  I: Integer;
begin
  for I := 0 to FCredentials.Count - 1 do
  begin
    if TCryptoUtils.BytesEqual(FCredentials[I].CredentialId, CredentialId) then
    begin
      FCredentials.Delete(I);
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

function TMockServer.CredentialExists(const CredentialId: TBytes): Boolean;
var
  I: Integer;
begin
  for I := 0 to FCredentials.Count - 1 do
    if TCryptoUtils.BytesEqual(FCredentials[I].CredentialId, CredentialId) then
      Exit(True);
  Result := False;
end;

function TMockServer.ValidateChallenge(const Challenge: TBytes; const UserId: string): Boolean;
var
  Session: TChallengeSession;
  Key: string;
begin
  // Check registration challenge
  Key := 'reg_' + UserId;
  if FChallenges.TryGetValue(Key, Session) then
  begin
    if TCryptoUtils.BytesEqual(Session.Challenge, Challenge) and
       (Now < Session.ExpiresAt) then
    begin
      FChallenges.Remove(Key);
      Exit(True);
    end;
  end;
  
  // Check authentication challenge
  Key := 'auth_' + UserId;
  if FChallenges.TryGetValue(Key, Session) then
  begin
    if TCryptoUtils.BytesEqual(Session.Challenge, Challenge) and
       (Now < Session.ExpiresAt) then
    begin
      FChallenges.Remove(Key);
      Exit(True);
    end;
  end;
  
  Result := False;
end;

end.
