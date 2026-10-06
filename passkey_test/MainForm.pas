unit MainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls,
  MockServer, PasskeyClient, CryptoUtils;

type
  TForm1 = class(TForm)
    PanelTop: TPanel;
    LabelTitle: TLabel;
    LabelSubtitle: TLabel;
    GroupStatus: TGroupBox;
    LabelWebAuthn: TLabel;
    LabelWebAuthnStatus: TLabel;
    LabelPlatform: TLabel;
    LabelPlatformStatus: TLabel;
    GroupUser: TGroupBox;
    LabelUserId: TLabel;
    LabelUserName: TLabel;
    EditUserId: TEdit;
    EditUserName: TEdit;
    GroupActions: TGroupBox;
    BtnRegister: TButton;
    BtnAuthenticate: TButton;
    BtnListCredentials: TButton;
    GroupLog: TGroupBox;
    MemoLog: TMemo;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure BtnRegisterClick(Sender: TObject);
    procedure BtnAuthenticateClick(Sender: TObject);
    procedure BtnListCredentialsClick(Sender: TObject);
  private
    FServer: TMockServer;
    FClient: TPasskeyClient;
    procedure Log(const Msg: string);
    procedure UpdateStatus;
    procedure InitializeClient;
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.FormCreate(Sender: TObject);
begin
  Log('=== Passkey Authentication Smoke Test ===');
  Log('');
  Log('Initializing...');
  
  // Create mock server
  FServer := TMockServer.Create;
  Log('[OK] Mock FIDO2 server created');
  Log('     Relying Party: ' + FServer.RelyingPartyName);
  Log('     RP ID: ' + FServer.RelyingPartyId);
  Log('');
  
  // Initialize client
  InitializeClient;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  if Assigned(FClient) then
    FClient.Free;
  if Assigned(FServer) then
    FServer.Free;
end;

procedure TForm1.InitializeClient;
begin
  // Create passkey client with current user
  if Assigned(FClient) then
    FClient.Free;
    
  FClient := TPasskeyClient.Create(
    FServer,
    EditUserId.Text,
    EditUserName.Text
  );
  
  UpdateStatus;
end;

procedure TForm1.UpdateStatus;
begin
  // Update WebAuthn API status
  if FClient.WebAuthnAvailable then
  begin
    LabelWebAuthnStatus.Caption := 'Available';
    LabelWebAuthnStatus.Font.Color := clGreen;
  end
  else
  begin
    LabelWebAuthnStatus.Caption := 'Not Available';
    LabelWebAuthnStatus.Font.Color := clRed;
  end;
  
  // Update platform authenticator status
  if FClient.PlatformAuthenticatorAvailable then
  begin
    LabelPlatformStatus.Caption := 'Available (PIN/Biometric)';
    LabelPlatformStatus.Font.Color := clGreen;
  end
  else
  begin
    LabelPlatformStatus.Caption := 'Not Available';
    LabelPlatformStatus.Font.Color := clRed;
  end;
end;

procedure TForm1.Log(const Msg: string);
begin
  MemoLog.Lines.Add(Msg);
  // Scroll to bottom
  SendMessage(MemoLog.Handle, WM_VSCROLL, SB_BOTTOM, 0);
  Application.ProcessMessages;
end;

procedure TForm1.BtnRegisterClick(Sender: TObject);
var
  Result: TPasskeyRegistrationResult;
begin
  Log('--- Register Passkey ---');
  Log('User ID: ' + EditUserId.Text);
  Log('User Name: ' + EditUserName.Text);
  Log('');
  
  // Reinitialize client with current user info
  InitializeClient;
  
  if not FClient.WebAuthnAvailable then
  begin
    Log('[ERROR] WebAuthn API not available');
    Log('        Requires Windows 10 version 1903 or later');
    ShowMessage('WebAuthn API not available. Requires Windows 10 1903+.');
    Exit;
  end;
  
  if not FClient.PlatformAuthenticatorAvailable then
  begin
    Log('[ERROR] Platform authenticator not available');
    Log('        Please set up Windows Hello (PIN, fingerprint, or face)');
    ShowMessage('Windows Hello not configured. Please set up a PIN first.');
    Exit;
  end;
  
  Log('[INFO] Requesting passkey registration...');
  Log('[INFO] Windows Hello prompt will appear');
  Log('[INFO] Please enter your PIN or use biometric');
  Log('');
  Application.ProcessMessages;
  
  // Register passkey
  Result := FClient.RegisterPasskey(Self.Handle);
  
  if Result.Success then
  begin
    Log('[SUCCESS] Passkey registered!');
    Log('          Credential ID: ' + TCryptoUtils.Base64URLEncode(Result.CredentialId));
    Log('          Public key size: ' + IntToStr(Length(Result.PublicKey)) + ' bytes');
    Log('          Attestation object: ' + IntToStr(Length(Result.AttestationObject)) + ' bytes');
    Log('');
    Log('[INFO] Credential stored on server');
    Log('       You can now authenticate with this passkey');
    
    ShowMessage('Passkey registered successfully!' + #13#10#13#10 +
                'Credential ID: ' + Copy(TCryptoUtils.Base64URLEncode(Result.CredentialId), 1, 40) + '...');
  end
  else
  begin
    Log('[ERROR] Registration failed');
    Log('        ' + Result.ErrorMessage);
    ShowMessage('Registration failed: ' + Result.ErrorMessage);
  end;
  
  Log('');
end;

procedure TForm1.BtnAuthenticateClick(Sender: TObject);
var
  Result: TPasskeyAuthenticationResult;
begin
  Log('--- Authenticate with Passkey ---');
  Log('User ID: ' + EditUserId.Text);
  Log('');
  
  // Reinitialize client with current user info
  InitializeClient;
  
  if not FClient.WebAuthnAvailable then
  begin
    Log('[ERROR] WebAuthn API not available');
    ShowMessage('WebAuthn API not available.');
    Exit;
  end;
  
  if not FClient.HasRegisteredPasskeys then
  begin
    Log('[ERROR] No passkeys registered for this user');
    Log('        Please register a passkey first');
    ShowMessage('No passkeys registered. Please click "Register Passkey" first.');
    Exit;
  end;
  
  Log('[INFO] Found ' + IntToStr(Length(FClient.GetRegisteredPasskeys)) + ' registered passkey(s)');
  Log('[INFO] Requesting authentication...');
  Log('[INFO] Windows Hello prompt will appear');
  Log('[INFO] Please enter your PIN or use biometric');
  Log('');
  Application.ProcessMessages;
  
  // Authenticate
  Result := FClient.AuthenticatePasskey(Self.Handle);
  
  if Result.Success then
  begin
    Log('[SUCCESS] Authentication successful!');
    Log('          Credential ID: ' + TCryptoUtils.Base64URLEncode(Result.CredentialId));
    Log('          Signature size: ' + IntToStr(Length(Result.Signature)) + ' bytes');
    Log('          Authenticator data: ' + IntToStr(Length(Result.AuthenticatorData)) + ' bytes');
    Log('');
    Log('[INFO] Server verified signature');
    Log('       Session established');
    Log('');
    Log('[INFO] User is now logged in!');
    Log('       In a real app, this would unlock features');
    
    ShowMessage('Authentication successful!' + #13#10#13#10 +
                'User authenticated with passkey.' + #13#10 +
                'Session established.');
  end
  else
  begin
    Log('[ERROR] Authentication failed');
    Log('        ' + Result.ErrorMessage);
    ShowMessage('Authentication failed: ' + Result.ErrorMessage);
  end;
  
  Log('');
end;

procedure TForm1.BtnListCredentialsClick(Sender: TObject);
var
  Credentials: TArray<TStoredCredential>;
  I: Integer;
  Cred: TStoredCredential;
begin
  Log('--- List Registered Passkeys ---');
  Log('User ID: ' + EditUserId.Text);
  Log('');
  
  // Reinitialize client with current user info
  InitializeClient;
  
  Credentials := FClient.GetRegisteredPasskeys;
  
  if Length(Credentials) = 0 then
  begin
    Log('[INFO] No passkeys registered for this user');
    ShowMessage('No passkeys registered for user: ' + EditUserId.Text);
  end
  else
  begin
    Log('[INFO] Found ' + IntToStr(Length(Credentials)) + ' passkey(s):');
    Log('');
    
    for I := 0 to Length(Credentials) - 1 do
    begin
      Cred := Credentials[I];
      Log('  Passkey #' + IntToStr(I + 1));
      Log('    Credential ID: ' + TCryptoUtils.Base64URLEncode(Cred.CredentialId));
      Log('    User: ' + Cred.UserName + ' (' + Cred.UserId + ')');
      Log('    Sign Count: ' + IntToStr(Cred.SignCount));
      Log('    Created: ' + DateTimeToStr(Cred.CreatedAt));
      Log('    Last Used: ' + DateTimeToStr(Cred.LastUsed));
      Log('');
    end;
    
    ShowMessage('Found ' + IntToStr(Length(Credentials)) + ' passkey(s). See log for details.');
  end;
  
  Log('');
end;

end.
