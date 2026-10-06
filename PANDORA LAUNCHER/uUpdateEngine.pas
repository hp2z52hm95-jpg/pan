unit uUpdateEngine;

{
  Package update engine.

  How a running app gets updated on Windows:
  1. All packages are downloaded + hash-verified FIRST (nothing is touched yet).
  2. The running app is asked to close (WM_CLOSE), waited on, then force-closed
     if needed — Windows cannot overwrite a running .exe, so this step is required.
  3. Files about to be replaced are copied to Backup\<old-version>\ (rollback).
  4. Packages are applied (zips extracted over the app folder).
  5. The app is relaunched, receiving the login session on its command line.

  If anything fails, the old Backup\ folder lets you restore by hand.
}

interface

uses
  Winapi.Windows, Winapi.TlHelp32, Winapi.ShellAPI,
  System.SysUtils, System.Classes, System.Math, System.JSON, System.Hash,
  System.Zip, System.IOUtils, System.Generics.Collections,
  uPandoraApi;

type
  TLogEvent = procedure(const Msg: string) of object;
  TProgressEvent = procedure(Percent: Integer) of object;

  TUpdateEngine = class
  private
    FApi: TPandoraApi;
    FAppDir: string; // with trailing backslash
    FAppExe: string; // e.g. PandoraTool.exe
    FOnLog: TLogEvent;
    FOnProgress: TProgressEvent;
    procedure Log(const Msg: string);
    procedure SetProgress(P: Integer);
    procedure OnHttpProgress(const Sender: TObject; AContentLength,
      AReadCount: Int64; var Abort: Boolean);
    function ExePath: string;
    function FindPIDs: TArray<DWORD>;
    function CloseRunningApp: Boolean;
    function Sha256OfFile(const Path: string): string;
    function BackupAndExtract(const ZipPath, BackupDir: string): Boolean;
  public
    constructor Create(Api: TPandoraApi; const AppDir, AppExe: string);
    function InstalledVersion: string;
    function CheckForUpdates(out Latest, Notes: string;
      out Packages: TJSONArray): Boolean;
    function DownloadAndApply(Packages: TJSONArray;
      const Latest: string): Boolean;
    procedure LaunchApp(const Args: string);
    class function CompareVersions(const A, B: string): Integer;
    property OnLog: TLogEvent read FOnLog write FOnLog;
    property OnProgress: TProgressEvent read FOnProgress write FOnProgress;
  end;

implementation

function EnumCloseProc(Wnd: HWND; Param: LPARAM): BOOL; stdcall;
var
  PID: DWORD;
begin
  Result := True;
  GetWindowThreadProcessId(Wnd, @PID);
  if PID = DWORD(Param) then
    if IsWindowVisible(Wnd) then
      PostMessage(Wnd, WM_CLOSE, 0, 0);
end;

{ TUpdateEngine }

constructor TUpdateEngine.Create(Api: TPandoraApi;
  const AppDir, AppExe: string);
begin
  inherited Create;
  FApi := Api;
  FAppDir := IncludeTrailingPathDelimiter(AppDir);
  FAppExe := AppExe;
  FApi.OnDownloadProgress := OnHttpProgress;
end;

procedure TUpdateEngine.Log(const Msg: string);
begin
  if Assigned(FOnLog) then
    FOnLog(FormatDateTime('hh:nn:ss ', Now) + Msg);
end;

procedure TUpdateEngine.SetProgress(P: Integer);
begin
  if Assigned(FOnProgress) then
    FOnProgress(P);
end;

procedure TUpdateEngine.OnHttpProgress(const Sender: TObject; AContentLength,
  AReadCount: Int64; var Abort: Boolean);
begin
  Abort := False;
  if AContentLength > 0 then
    SetProgress(Round(AReadCount * 100 / AContentLength));
end;

function TUpdateEngine.ExePath: string;
begin
  Result := FAppDir + FAppExe;
end;

class function TUpdateEngine.CompareVersions(const A, B: string): Integer;
var
  PA, PB: TArray<string>;
  i, X, Y: Integer;
begin
  PA := A.Split(['.']);
  PB := B.Split(['.']);
  for i := 0 to Max(Length(PA), Length(PB)) - 1 do
  begin
    if i < Length(PA) then
      X := StrToIntDef(PA[i], 0)
    else
      X := 0;
    if i < Length(PB) then
      Y := StrToIntDef(PB[i], 0)
    else
      Y := 0;
    if X < Y then
      Exit(-1);
    if X > Y then
      Exit(1);
  end;
  Result := 0;
end;

function TUpdateEngine.InstalledVersion: string;
var
  Size, Dummy: DWORD;
  Buf: Pointer;
  P: Pointer;
  Info: PVSFixedFileInfo;
  Len: UINT;
begin
  Result := '0.0.0.0';
  if not FileExists(ExePath) then
    Exit;
  Size := GetFileVersionInfoSize(PChar(ExePath), Dummy);
  if Size = 0 then
    Exit;
  GetMem(Buf, Size);
  try
    if GetFileVersionInfo(PChar(ExePath), 0, Size, Buf) and
      VerQueryValue(Buf, '\', P, Len) then
    begin
      Info := PVSFixedFileInfo(P);
      Result := Format('%d.%d.%d.%d', [HiWord(Info^.dwFileVersionMS),
        LoWord(Info^.dwFileVersionMS), HiWord(Info^.dwFileVersionLS),
        LoWord(Info^.dwFileVersionLS)]);
    end;
  finally
    FreeMem(Buf);
  end;
end;

function TUpdateEngine.CheckForUpdates(out Latest, Notes: string;
  out Packages: TJSONArray): Boolean;
var
  Res: TJSONObject;
  Cur: string;
  V: TJSONValue;
begin
  Result := False;
  Packages := nil;
  Latest := '';
  Notes := '';
  Cur := InstalledVersion;
  Log('Installed version: ' + Cur);
  Res := FApi.UpdatesCheck('PandoraTool', Cur);
  try
    Latest := JsonStr(Res, 'latest', Cur);
    Notes := JsonStr(Res, 'notes', '');
    Result := JsonBool(Res, 'updateAvailable', False);
    if Result then
    begin
      V := Res.GetValue('packages');
      if V is TJSONArray then
        Packages := TJSONArray(V.Clone) // caller owns, must Free
      else
        Result := False;
    end;
  finally
    Res.Free;
  end;
end;

function TUpdateEngine.FindPIDs: TArray<DWORD>;
var
  Snap: THandle;
  PE: TProcessEntry32;
begin
  Result := nil;
  Snap := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if Snap = THandle(INVALID_HANDLE_VALUE) then
    Exit;
  try
    PE.dwSize := SizeOf(PE);
    if Process32First(Snap, PE) then
      repeat
        if SameText(string(PE.szExeFile), FAppExe) then
          Result := Result + [PE.th32ProcessID];
      until not Process32Next(Snap, PE);
  finally
    CloseHandle(Snap);
  end;
end;

function TUpdateEngine.CloseRunningApp: Boolean;
var
  PIDs: TArray<DWORD>;
  PID: DWORD;
  H: THandle;
begin
  Result := True;
  PIDs := FindPIDs;
  if Length(PIDs) = 0 then
    Exit; // not running — nothing to do

  // 1. ask nicely: close its windows
  for PID in PIDs do
    EnumWindows(@EnumCloseProc, LPARAM(PID));

  // 2. wait, then force remaining processes
  for PID in PIDs do
  begin
    H := OpenProcess(SYNCHRONIZE or PROCESS_TERMINATE, False, PID);
    if H = 0 then
      Continue; // already gone
    try
      if WaitForSingleObject(H, 15000) = WAIT_TIMEOUT then
      begin
        Log('Process did not exit, force-closing...');
        TerminateProcess(H, 0);
        WaitForSingleObject(H, 5000);
      end;
    finally
      CloseHandle(H);
    end;
  end;

  Sleep(500);
  if Length(FindPIDs) > 0 then
    Result := False;
end;

function TUpdateEngine.Sha256OfFile(const Path: string): string;
var
  Digest: TBytes;
  i: Integer;
begin
  Digest := THashSHA2.GetHashBytesFromFile(Path);
  Result := '';
  for i := 0 to Length(Digest) - 1 do
    Result := Result + IntToHex(Digest[i], 2);
  Result := LowerCase(Result);
end;

function TUpdateEngine.BackupAndExtract(const ZipPath,
  BackupDir: string): Boolean;
var
  Z: TZipFile;
  i: Integer;
  Name, Src, Dst: string;
begin
  Result := False;
  Z := TZipFile.Create;
  try
    try
      Z.Open(ZipPath, zmRead);
    except
      on E: Exception do
      begin
        Log('Cannot open update package: ' + E.Message);
        Exit;
      end;
    end;
    try
      for i := 0 to Z.FileCount - 1 do
      begin
        Name := Z.FileNames[i];
        if Name = '' then
          Continue;
        if Name[Length(Name)] = '/' then
          Continue; // directory entry
        Src := FAppDir + StringReplace(Name, '/', PathDelim, [rfReplaceAll]);
        if FileExists(Src) then
        begin
          Dst := BackupDir + StringReplace(Name, '/', PathDelim, [rfReplaceAll]);
          ForceDirectories(ExtractFilePath(Dst));
          if not CopyFile(PChar(Src), PChar(Dst), True) then
          begin
            Log('Backup failed: ' + Name);
            Exit;
          end;
        end;
      end;
    finally
      Z.Close;
    end;
  finally
    Z.Free;
  end;

  try
    TZipFile.ExtractZipFile(ZipPath, FAppDir);
  except
    on E: Exception do
    begin
      Log('Extract failed: ' + E.Message + '. Restore from ' + BackupDir);
      Exit;
    end;
  end;
  Result := True;
end;

function TUpdateEngine.DownloadAndApply(Packages: TJSONArray;
  const Latest: string): Boolean;
var
  i: Integer;
  Pkg: TJSONObject;
  FileName, Kind, ExpectHash, LocalFile: string;
  ExpectSize: Int64;
  WorkDir, BackupDir: string;
begin
  Result := False;
  WorkDir := FAppDir + 'Update' + PathDelim;
  BackupDir := FAppDir + 'Backup' + PathDelim + InstalledVersion + PathDelim;
  ForceDirectories(WorkDir);

  // 1. download + verify everything BEFORE touching the install
  for i := 0 to Packages.Count - 1 do
  begin
    if not (Packages.Items[i] is TJSONObject) then
    begin
      Log('Bad manifest entry, update aborted');
      Exit;
    end;
    Pkg := TJSONObject(Packages.Items[i]);
    FileName := JsonStr(Pkg, 'file');
    Kind := LowerCase(JsonStr(Pkg, 'kind', 'zip'));
    ExpectHash := LowerCase(JsonStr(Pkg, 'sha256'));
    ExpectSize := StrToInt64Def(JsonStr(Pkg, 'size', '0'), 0);
    if FileName = '' then
    begin
      Log('Manifest entry without file name, update aborted');
      Exit;
    end;
    LocalFile := WorkDir + FileName;
    Log(Format('Downloading %s ...', [FileName]));
    SetProgress(0);
    FApi.DownloadFile(FileName, LocalFile); // raises EApiError on failure
    if (ExpectSize > 0) and (TFile.GetSize(LocalFile) <> ExpectSize) then
    begin
      Log('Size mismatch on ' + FileName + ', update aborted');
      Exit;
    end;
    if (ExpectHash <> '') and (Sha256OfFile(LocalFile) <> ExpectHash) then
    begin
      Log('SHA-256 mismatch on ' + FileName + ', update aborted');
      Exit;
    end;
    Log('Verified ' + FileName);
  end;
  SetProgress(100);

  // 2. close the running app (Windows cannot overwrite a running .exe)
  Log('Closing ' + FAppExe + ' ...');
  if not CloseRunningApp then
  begin
    Log('Could not close the running app, update aborted');
    Exit;
  end;

  // 3. apply packages
  ForceDirectories(BackupDir);
  for i := 0 to Packages.Count - 1 do
  begin
    Pkg := TJSONObject(Packages.Items[i]);
    FileName := JsonStr(Pkg, 'file');
    Kind := LowerCase(JsonStr(Pkg, 'kind', 'zip'));
    LocalFile := WorkDir + FileName;
    if Kind = 'zip' then
    begin
      if not BackupAndExtract(LocalFile, BackupDir) then
        Exit;
    end
    else
    begin
      // single file: back up the target, then replace it
      if FileExists(FAppDir + FileName) then
      begin
        ForceDirectories(ExtractFilePath(BackupDir + FileName));
        if not CopyFile(PChar(FAppDir + FileName), PChar(BackupDir + FileName), True) then
        begin
          Log('Backup failed for ' + FileName);
          Exit;
        end;
      end;
      if not CopyFile(PChar(LocalFile), PChar(FAppDir + FileName), False) then
      begin
        Log('Replace failed for ' + FileName + ' (code ' +
          IntToStr(GetLastError) + ')');
        Exit;
      end;
    end;
    Log('Applied ' + FileName);
    DeleteFile(LocalFile);
  end;

  Log('Updated to ' + Latest + '. Backup kept in ' + BackupDir);
  Result := True;
end;

procedure TUpdateEngine.LaunchApp(const Args: string);
var
  R: HINST;
begin
  R := ShellExecute(0, 'open', PChar(ExePath), PChar(Args), PChar(FAppDir),
    SW_SHOWNORMAL);
  if R <= 32 then
    Log('Could not start app (code ' + IntToStr(Integer(R)) + ')');
end;

end.
