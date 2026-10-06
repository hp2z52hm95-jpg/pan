program PasskeyTest;

uses
  Vcl.Forms,
  MainForm in 'MainForm.pas' {Form1},
  WebAuthnAPI in 'WebAuthnAPI.pas',
  CryptoUtils in 'CryptoUtils.pas',
  MockServer in 'MockServer.pas',
  PasskeyClient in 'PasskeyClient.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
