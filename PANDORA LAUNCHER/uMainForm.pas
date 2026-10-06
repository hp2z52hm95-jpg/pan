unit uMainForm;

{
  Launcher main window: sign in -> check updates -> apply -> run PandoraTool.

  Flow on start (automatic):
  1. Read launcher.ini (same folder as this .exe).
  2. Show the login dialog (password or passkey). No login = no updates, no run.
  3. Ask the server for updates; download + verify + apply if any.
  4. Start PandoraTool.exe, passing the session:
       PandoraTool.exe --pandora-session <jwt> --pandora-user "<name>"
     (Unknown switches are ignored by the current PandoraTool build; they are
     there for LoginGate-enabled builds, and prove which session started it.)
}

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Classes,
  System.JSON, System.IniFiles, Vcl.Graphics, Vcl.Controls, Vcl.Forms,
  Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls,
  uPandoraApi, uUpdateEngine, uLoginForm;

type
  TMainForm = class(TForm)
    memLog: TMemo;
    barProgress: TProgressBar;
    btnRun: TButton;
    btnExit: TButton;
    lblStatus: TLabel;
    tmrAuto: TTimer;
    procedure FormShow(Sender: TObject);
    procedure tmrAutoTimer(Sender: TObject);
    procedure btnRunClick(Sender: TObject);
    procedure btnExitClick(Sender: TObject);
  private
    FApi: TPandoraApi;
    FEngine: TUpdateEngine;
    FBaseURL, FRpId, FOrigin, FAppExe, FLaunchArgs: string;
    FAutoUpdate, FAutoLaunch: Boolean;
    FUserName: string;
    FDidAuto: Boolean;
    procedure LoadConfig;
    procedure AddLog(const Msg: string);
    procedure SetProgress(P: Integer);
    procedure RunFlow;
    function DoLogin: Boolean;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}

constructor TMainForm.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FDidAuto := False;
end;

destructor TMainForm.Destroy;
begin
  FEngine.Free;
  FApi.Free;
  inherited;
end;

procedure TMainForm.LoadConfig;
var
  Ini: TMemIniFile;
  Path: string;
begin
  Path := ExtractFilePath(ParamStr(0)) + 'launcher.ini';
  FBaseURL := 'http://localhost:3000';
  FRpId := 'localhost';
  FOrigin := 'http://localhost:3000';
  FAppExe := 'PandoraTool.exe';
  FLaunchArgs := '';
  FAutoUpdate := True;
  FAutoLaunch := True;
  Ini := TMemIniFile.Create(Path);
  try
    FBaseURL := Ini.ReadString('Server', 'BaseURL', FBaseURL);
    FRpId := Ini.ReadString('Server', 'RpId', FRpId);
    FOrigin := Ini.ReadString('Server', 'Origin', FOrigin);
    FAppExe := Ini.ReadString('App', 'Exe', FAppExe);
    FLaunchArgs := Ini.ReadString('App', 'LaunchArgs', '');
    FAutoUpdate := Ini.ReadBool('App', 'AutoUpdate', True);
    FAutoLaunch := Ini.ReadBool('App', 'AutoLaunch', True);
  finally
    Ini.Free;
  end;
end;

procedure TMainForm.AddLog(const Msg: string);
begin
  memLog.Lines.Add(Msg);
  Application.ProcessMessages;
end;

procedure TMainForm.SetProgress(P: Integer);
begin
  if P < barProgress.Min then
    P := barProgress.Min;
  if P > barProgress.Max then
    P := barProgress.Max;
  barProgress.Position := P;
  Application.ProcessMessages;
end;

procedure TMainForm.FormShow(Sender: TObject);
begin
  tmrAuto.Enabled := True; // kick off once, after the form has painted
end;

procedure TMainForm.tmrAutoTimer(Sender: TObject);
begin
  tmrAuto.Enabled := False;
  if FDidAuto then
    Exit;
  FDidAuto := True;
  RunFlow;
end;

procedure TMainForm.btnRunClick(Sender: TObject);
begin
  RunFlow;
end;

procedure TMainForm.btnExitClick(Sender: TObject);
begin
  Close;
end;

function TMainForm.DoLogin: Boolean;
var
  L: TLoginForm;
begin
  L := TLoginForm.Create(Self);
  try
    L.Api := FApi;
    L.RpId := FRpId;
    L.Origin := FOrigin;
    Result := L.ShowModal = mrOk;
    if Result then
      FUserName := L.UserName;
  finally
    L.Free;
  end;
end;

procedure TMainForm.RunFlow;
var
  Latest, Notes: string;
  Pkgs: TJSONArray;
  Args: string;
begin
  btnRun.Enabled := False;
  try
    LoadConfig;
    FreeAndNil(FEngine);
    FreeAndNil(FApi);
    FApi := TPandoraApi.Create(FBaseURL);
    FEngine := TUpdateEngine.Create(FApi, ExtractFilePath(ParamStr(0)), FAppExe);
    FEngine.OnLog := AddLog;
    FEngine.OnProgress := SetProgress;

    memLog.Clear;
    SetProgress(0);
    AddLog('Pandora Launcher');
    AddLog('Server: ' + FBaseURL);

    // 1. login (password or passkey) — required for update downloads
    lblStatus.Caption := 'Waiting for sign-in...';
    if not DoLogin then
    begin
      lblStatus.Caption := 'Sign-in cancelled.';
      Exit;
    end;
    AddLog('Signed in as ' + FUserName);

    // 2. update
    if FAutoUpdate then
    begin
      lblStatus.Caption := 'Checking for updates...';
      try
        if FEngine.CheckForUpdates(Latest, Notes, Pkgs) then
        begin
          try
            AddLog('Update found: ' + Latest);
            if Notes <> '' then
              AddLog(Notes);
            lblStatus.Caption := 'Updating to ' + Latest + '...';
            if not FEngine.DownloadAndApply(Pkgs, Latest) then
            begin
              lblStatus.Caption := 'Update failed — see log.';
              Exit;
            end;
          finally
            Pkgs.Free;
          end;
        end
        else
          AddLog('Already up to date (' + Latest + ').');
      except
        on E: Exception do
        begin
          AddLog('Update error: ' + E.Message);
          lblStatus.Caption := 'Update failed.';
          Exit;
        end;
      end;
    end;

    // 3. launch the tool with the login session
    Args := Trim(FLaunchArgs + ' --pandora-session ' + FApi.Token +
      ' --pandora-user "' + FUserName + '"');
    AddLog('Starting ' + FAppExe + ' ...');
    FEngine.LaunchApp(Args);
    lblStatus.Caption := 'Running.';
    if FAutoLaunch then
      Close;
  finally
    btnRun.Enabled := True;
  end;
end;

end.
