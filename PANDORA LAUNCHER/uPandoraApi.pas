unit uPandoraApi;

{
  HTTP client for the Pandora passkey/update server.
  Uses RTL THTTPClient (WinHTTP on Windows) + System.JSON. No components needed.

  Ownership rules:
  - Functions returning TJSONObject: caller OWNS the result, must Free it.
  - Functions taking TJSONObject params: caller keeps ownership (we Clone).
  - JsonObj/JsonArr return INNER pointers: do NOT free them.
}

interface

uses
  System.SysUtils, System.Classes, System.JSON,
  System.Net.HttpClient, System.Net.URLClient;

type
  EApiError = class(Exception);

  TPandoraApi = class
  private
    FBaseURL: string;
    FToken: string;
    FOnProgress: TReceiveDataEvent;
    function URL(const Path: string): string;
    function AuthHeader: TNetHeaders;
    function JsonHeaders: TNetHeaders;
    function ParseObject(const S: string): TJSONObject;
    function HttpPost(const Path: string; Body: TJSONObject): TJSONObject;
    function HttpGet(const Path: string): TJSONObject;
  public
    constructor Create(const BaseURL: string);
    property Token: string read FToken write FToken;
    property OnDownloadProgress: TReceiveDataEvent read FOnProgress write FOnProgress;

    function Login(const Username, Password: string): TJSONObject;
    function PasskeyAuthBegin(const Username: string): TJSONObject;
    function PasskeyAuthComplete(const ChallengeId, UserId: string;
      Assertion: TJSONObject): TJSONObject;
    function PasskeyRegBegin: TJSONObject;
    function PasskeyRegComplete(const ChallengeId, DeviceName: string;
      Attestation: TJSONObject): TJSONObject;
    function UpdatesCheck(const App, Current: string): TJSONObject;
    procedure DownloadFile(const RemoteFile, LocalPath: string);
  end;

function JsonStr(Obj: TJSONObject; const Name: string;
  const Default: string = ''): string;
function JsonBool(Obj: TJSONObject; const Name: string;
  Default: Boolean = False): Boolean;
function JsonObj(Obj: TJSONObject; const Name: string): TJSONObject;
function JsonArr(Obj: TJSONObject; const Name: string): TJSONArray;

implementation

function QEncode(const S: string): string;
begin
  // Manifest file names are server-validated (word chars, dots, dashes,
  // spaces); only spaces need encoding for the URL path.
  Result := StringReplace(S, ' ', '%20', [rfReplaceAll]);
end;

{ JSON helpers }

function JsonStr(Obj: TJSONObject; const Name: string;
  const Default: string): string;
var
  V: TJSONValue;
begin
  Result := Default;
  if Obj = nil then
    Exit;
  V := Obj.GetValue(Name);
  if V <> nil then
    Result := V.Value;
end;

function JsonBool(Obj: TJSONObject; const Name: string;
  Default: Boolean): Boolean;
var
  V: TJSONValue;
begin
  Result := Default;
  if Obj = nil then
    Exit;
  V := Obj.GetValue(Name);
  if V is TJSONBool then
    Result := TJSONBool(V).AsBoolean
  else if V is TJSONNumber then
    Result := TJSONNumber(V).AsInt <> 0
  else if V <> nil then
    Result := SameText(V.Value, 'true');
end;

function JsonObj(Obj: TJSONObject; const Name: string): TJSONObject;
var
  V: TJSONValue;
begin
  if Obj = nil then
    raise EApiError.Create('Bad server response (no ' + Name + ')');
  V := Obj.GetValue(Name);
  if not (V is TJSONObject) then
    raise EApiError.Create('Bad server response (no ' + Name + ')');
  Result := TJSONObject(V);
end;

function JsonArr(Obj: TJSONObject; const Name: string): TJSONArray;
var
  V: TJSONValue;
begin
  if Obj = nil then
    raise EApiError.Create('Bad server response (no ' + Name + ')');
  V := Obj.GetValue(Name);
  if not (V is TJSONArray) then
    raise EApiError.Create('Bad server response (no ' + Name + ')');
  Result := TJSONArray(V);
end;

{ TPandoraApi }

constructor TPandoraApi.Create(const BaseURL: string);
begin
  inherited Create;
  FBaseURL := BaseURL;
  while (FBaseURL <> '') and (FBaseURL[Length(FBaseURL)] = '/') do
    Delete(FBaseURL, Length(FBaseURL), 1);
end;

function TPandoraApi.URL(const Path: string): string;
begin
  Result := FBaseURL + Path;
end;

function TPandoraApi.AuthHeader: TNetHeaders;
begin
  SetLength(Result, 1);
  Result[0] := TNameValuePair.Create('Authorization', 'Bearer ' + FToken);
end;

function TPandoraApi.JsonHeaders: TNetHeaders;
begin
  if FToken <> '' then
  begin
    SetLength(Result, 2);
    Result[0] := TNameValuePair.Create('Content-Type', 'application/json');
    Result[1] := TNameValuePair.Create('Authorization', 'Bearer ' + FToken);
  end
  else
  begin
    SetLength(Result, 1);
    Result[0] := TNameValuePair.Create('Content-Type', 'application/json');
  end;
end;

function TPandoraApi.ParseObject(const S: string): TJSONObject;
var
  V: TJSONValue;
begin
  V := TJSONObject.ParseJSONValue(S);
  if not (V is TJSONObject) then
  begin
    V.Free;
    raise EApiError.Create('Invalid server response');
  end;
  Result := TJSONObject(V);
end;

function TPandoraApi.HttpPost(const Path: string; Body: TJSONObject): TJSONObject;
var
  Http: THTTPClient;
  SS: TStringStream;
  Resp: IHTTPResponse;
  Err: string;
  ErrObj: TJSONObject;
begin
  Http := THTTPClient.Create;
  try
    Http.ConnectionTimeout := 15000;
    Http.ResponseTimeout := 60000;
    SS := TStringStream.Create(Body.ToJSON, TEncoding.UTF8);
    try
      Resp := Http.Post(URL(Path), SS, nil, JsonHeaders);
    finally
      SS.Free;
    end;
    if Resp.StatusCode >= 400 then
    begin
      Err := 'Request failed (HTTP ' + Resp.StatusCode.ToString + ')';
      try
        ErrObj := ParseObject(Resp.ContentAsString);
        try
          Err := JsonStr(ErrObj, 'error', Err);
        finally
          ErrObj.Free;
        end;
      except
        // keep generic message
      end;
      raise EApiError.Create(Err);
    end;
    Result := ParseObject(Resp.ContentAsString);
  finally
    Http.Free;
  end;
end;

function TPandoraApi.HttpGet(const Path: string): TJSONObject;
var
  Http: THTTPClient;
  Resp: IHTTPResponse;
begin
  Http := THTTPClient.Create;
  try
    Http.ConnectionTimeout := 15000;
    Http.ResponseTimeout := 60000;
    Resp := Http.Get(URL(Path), nil, JsonHeaders);
    if Resp.StatusCode >= 400 then
      raise EApiError.Create('Request failed (HTTP ' +
        Resp.StatusCode.ToString + ')');
    Result := ParseObject(Resp.ContentAsString);
  finally
    Http.Free;
  end;
end;

function TPandoraApi.Login(const Username, Password: string): TJSONObject;
var
  B: TJSONObject;
begin
  B := TJSONObject.Create;
  try
    B.AddPair('username', Username);
    B.AddPair('password', Password);
    Result := HttpPost('/api/auth/login', B);
    FToken := JsonStr(Result, 'token');
  finally
    B.Free;
  end;
end;

function TPandoraApi.PasskeyAuthBegin(const Username: string): TJSONObject;
var
  B: TJSONObject;
begin
  B := TJSONObject.Create;
  try
    B.AddPair('username', Username);
    Result := HttpPost('/api/passkey/authenticate/begin', B);
  finally
    B.Free;
  end;
end;

function TPandoraApi.PasskeyAuthComplete(const ChallengeId, UserId: string;
  Assertion: TJSONObject): TJSONObject;
var
  B: TJSONObject;
begin
  B := TJSONObject.Create;
  try
    B.AddPair('challengeId', ChallengeId);
    B.AddPair('userId', UserId);
    B.AddPair('response', TJSONObject(Assertion.Clone));
    Result := HttpPost('/api/passkey/authenticate/complete', B);
    FToken := JsonStr(Result, 'token', FToken);
  finally
    B.Free;
  end;
end;

function TPandoraApi.PasskeyRegBegin: TJSONObject;
var
  B: TJSONObject;
begin
  B := TJSONObject.Create;
  try
    Result := HttpPost('/api/passkey/register/begin', B);
  finally
    B.Free;
  end;
end;

function TPandoraApi.PasskeyRegComplete(const ChallengeId, DeviceName: string;
  Attestation: TJSONObject): TJSONObject;
var
  B: TJSONObject;
begin
  B := TJSONObject.Create;
  try
    B.AddPair('challengeId', ChallengeId);
    B.AddPair('deviceName', DeviceName);
    B.AddPair('response', TJSONObject(Attestation.Clone));
    Result := HttpPost('/api/passkey/register/complete', B);
  finally
    B.Free;
  end;
end;

function TPandoraApi.UpdatesCheck(const App, Current: string): TJSONObject;
begin
  Result := HttpGet('/api/updates/check?app=' + QEncode(App) +
    '&current=' + QEncode(Current));
end;

procedure TPandoraApi.DownloadFile(const RemoteFile, LocalPath: string);
var
  Http: THTTPClient;
  FS: TFileStream;
  Resp: IHTTPResponse;
  Msg: string;
  ErrObj: TJSONObject;
  SS: TStringStream;
begin
  ForceDirectories(ExtractFilePath(LocalPath));
  if FileExists(LocalPath) then
    DeleteFile(LocalPath);

  Http := THTTPClient.Create;
  try
    Http.ConnectionTimeout := 15000;
    Http.ResponseTimeout := 1800000; // 30 min — packages can be large
    if Assigned(FOnProgress) then
      Http.OnReceiveData := FOnProgress;
    FS := TFileStream.Create(LocalPath, fmCreate);
    try
      Resp := Http.Get(URL('/api/updates/download/' + QEncode(RemoteFile)),
        FS, AuthHeader);
    finally
      FS.Free;
    end;

    if Resp.StatusCode <> 200 then
    begin
      Msg := 'Download failed (HTTP ' + Resp.StatusCode.ToString + ')';
      // The server's JSON error was written into the file — read it back.
      try
        SS := TStringStream.Create('', TEncoding.UTF8);
        try
          if FileExists(LocalPath) then
          begin
            SS.LoadFromFile(LocalPath);
            if SS.Size < 4096 then
            begin
              ErrObj := ParseObject(SS.DataString);
              try
                Msg := JsonStr(ErrObj, 'error', Msg);
              finally
                ErrObj.Free;
              end;
            end;
          end;
        finally
          SS.Free;
        end;
      except
        // keep generic message
      end;
      DeleteFile(LocalPath);
      raise EApiError.Create(Msg);
    end;
  finally
    Http.Free;
  end;
end;

end.
