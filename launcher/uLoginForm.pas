unit uLoginForm;

{
  Sign-in dialog: password or passkey (Windows Hello / security key).
  Shown by the launcher before PandoraTool.exe starts.
}

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Classes,
  System.JSON, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.StdCtrls,
  uPandoraApi, uPasskeyAuth;

type
  TLoginForm = class(TForm)
    lblTitle: TLabel;
    lblUser: TLabel;
    edtUsername: TEdit;
    lblPass: TLabel;
    edtPassword: TEdit;
    btnLogin: TButton;
    btnPasskey: TButton;
    btnCancel: TButton;
    lblStatus: TLabel;
    procedure btnLoginClick(Sender: TObject);
    procedure btnPasskeyClick(Sender: TObject);
  private
    FApi: TPandoraApi;
    FRpId: string;
    FOrigin: string;
    FUserName: string;
    FDisplayName: string;
    procedure SetBusy(Busy: Boolean);
    procedure DoPasswordLogin;
    procedure DoPasskeyLogin;
  public
    property Api: TPandoraApi read FApi write FApi;
    property RpId: string read FRpId write FRpId;
    property Origin: string read FOrigin write FOrigin;
    property UserName: string read FUserName;
    property DisplayName: string read FDisplayName;
  end;

implementation

{$R *.dfm}

procedure TLoginForm.SetBusy(Busy: Boolean);
begin
  btnLogin.Enabled := not Busy;
  btnPasskey.Enabled := not Busy;
  btnCancel.Enabled := not Busy;
  edtUsername.Enabled := not Busy;
  edtPassword.Enabled := not Busy;
  if Busy then
    Screen.Cursor := crHourGlass
  else
    Screen.Cursor := crDefault;
end;

procedure TLoginForm.btnLoginClick(Sender: TObject);
begin
  DoPasswordLogin;
end;

procedure TLoginForm.DoPasswordLogin;
var
  Res: TJSONObject;
  U: TJSONObject;
begin
  if Trim(edtUsername.Text) = '' then
  begin
    lblStatus.Caption := 'Enter your username.';
    Exit;
  end;
  if edtPassword.Text = '' then
  begin
    lblStatus.Caption := 'Enter your password.';
    Exit;
  end;
  SetBusy(True);
  try
    lblStatus.Caption := 'Signing in...';
    Application.ProcessMessages;
    try
      Res := FApi.Login(Trim(edtUsername.Text), edtPassword.Text);
      try
        U := JsonObj(Res, 'user');
        FUserName := JsonStr(U, 'username');
        FDisplayName := JsonStr(U, 'displayName', FUserName);
        ModalResult := mrOk;
      finally
        Res.Free;
      end;
    except
      on E: Exception do
        lblStatus.Caption := E.Message;
    end;
  finally
    SetBusy(False);
  end;
end;

procedure TLoginForm.btnPasskeyClick(Sender: TObject);
begin
  DoPasskeyLogin;
end;

procedure TLoginForm.DoPasskeyLogin;
var
  Pk: TPandoraPasskey;
  R: TPasskeyResult;
begin
  if Trim(edtUsername.Text) = '' then
  begin
    lblStatus.Caption := 'Enter your username, then use your passkey.';
    Exit;
  end;
  SetBusy(True);
  try
    lblStatus.Caption := 'Waiting for fingerprint / PIN / security key...';
    Application.ProcessMessages;
    Pk := TPandoraPasskey.Create(FApi, FRpId, FOrigin);
    try
      R := Pk.SignInWithPasskey(Handle, Trim(edtUsername.Text));
    finally
      Pk.Free;
    end;
    if R.Success then
    begin
      FApi.Token := R.Token;
      FUserName := R.UserName;
      FDisplayName := R.DisplayName;
      ModalResult := mrOk;
    end
    else
      lblStatus.Caption := R.Error;
  finally
    SetBusy(False);
  end;
end;

end.
