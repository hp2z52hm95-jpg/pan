unit LoginGate;

{
  Drop-in login gate for a future PandoraTool rebuild (or any Delphi VCL app).

  1. Add these units to your project:
       LoginGate, uLoginForm (+ .dfm), uPandoraApi, uPasskeyAuth, uWebAuthnWin
  2. At the top of your .dpr, AFTER Application.Initialize but BEFORE the
     main form is created:

       if not PandoraLogin('https://updates.example.com',
                           'updates.example.com',
                           'https://updates.example.com') then Halt(0);

  3. After login, LastSessionToken / LastUserName hold the session.

  Until PandoraTool itself is rebuilt with this gate, use PandoraLauncher.exe:
  it shows this same login dialog, applies updates, then starts PandoraTool.
}

interface

function PandoraLogin(const ServerURL, RpId, Origin: string): Boolean;
function LastSessionToken: string;
function LastUserName: string;
procedure PandoraLogout;

implementation

uses
  System.SysUtils, Vcl.Forms, uPandoraApi, uLoginForm;

var
  GToken: string = '';
  GUser: string = '';

function PandoraLogin(const ServerURL, RpId, Origin: string): Boolean;
var
  Api: TPandoraApi;
  L: TLoginForm;
begin
  Result := False;
  Api := TPandoraApi.Create(ServerURL);
  try
    L := TLoginForm.Create(nil);
    try
      L.Api := Api;
      L.RpId := RpId;
      L.Origin := Origin;
      if L.ShowModal = mrOk then
      begin
        GToken := Api.Token;
        GUser := L.UserName;
        Result := True;
      end;
    finally
      L.Free;
    end;
  finally
    Api.Free;
  end;
end;

function LastSessionToken: string;
begin
  Result := GToken;
end;

function LastUserName: string;
begin
  Result := GUser;
end;

procedure PandoraLogout;
begin
  GToken := '';
  GUser := '';
end;

end.
