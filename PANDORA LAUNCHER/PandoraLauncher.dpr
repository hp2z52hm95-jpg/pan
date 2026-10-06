program PandoraLauncher;

uses
  Vcl.Forms,
  uMainForm in 'uMainForm.pas' {MainForm},
  uLoginForm in 'uLoginForm.pas' {LoginForm},
  uPandoraApi in 'uPandoraApi.pas',
  uPasskeyAuth in 'uPasskeyAuth.pas',
  uUpdateEngine in 'uUpdateEngine.pas',
  uWebAuthnWin in 'uWebAuthnWin.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.Title := 'Pandora Launcher';
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
