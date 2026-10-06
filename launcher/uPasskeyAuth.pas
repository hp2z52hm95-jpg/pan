unit uPasskeyAuth;

{
  Desktop passkey sign-in / registration against the Pandora server.

  Uses the real Windows WebAuthn API (Windows Hello prompt, security keys),
  so the SAME passkeys work in the browser login page and in this launcher.

  IMPORTANT: RpId and Origin must EXACTLY match the server's RP_ID and
  WEBAUTHN_ORIGIN settings (see launcher.ini), otherwise the server rejects
  the ceremony. This is what makes passkeys phishing-resistant.
}

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.JSON,
  System.NetEncoding,
  uWebAuthnWin, uPandoraApi;

type
  TPasskeyResult = record
    Success: Boolean;
    Token: string;
    UserName: string;
    DisplayName: string;
    Error: string;
  end;

  TPandoraPasskey = class
  private
    FApi: TPandoraApi;
    FRpId: string;
    FOrigin: string;
    function B64UrlEncode(const Data: TBytes): string;
    function B64UrlEncodePtr(P: PByte; Len: DWORD): string;
    function B64UrlDecode(const S: string): TBytes;
    function UvRequirement(const S: string): DWORD;
    function ClientDataBytes(const Ceremony, Challenge: string): TBytes;
  public
    constructor Create(Api: TPandoraApi; const RpId, Origin: string);
    function SignInWithPasskey(hWnd: HWND; const Username: string): TPasskeyResult;
    function RegisterPasskey(hWnd: HWND; const DeviceName: string): TPasskeyResult;
  end;

implementation

{ TPandoraPasskey }

constructor TPandoraPasskey.Create(Api: TPandoraApi;
  const RpId, Origin: string);
begin
  inherited Create;
  FApi := Api;
  FRpId := RpId;
  FOrigin := Origin;
end;

function TPandoraPasskey.B64UrlEncode(const Data: TBytes): string;
begin
  Result := TNetEncoding.Base64.EncodeBytesToString(Data);
  Result := StringReplace(Result, '+', '-', [rfReplaceAll]);
  Result := StringReplace(Result, '/', '_', [rfReplaceAll]);
  Result := StringReplace(Result, '=', '', [rfReplaceAll]);
end;

function TPandoraPasskey.B64UrlEncodePtr(P: PByte; Len: DWORD): string;
var
  B: TBytes;
begin
  SetLength(B, Len);
  if Len > 0 then
    Move(P^, B[0], Len);
  Result := B64UrlEncode(B);
end;

function TPandoraPasskey.B64UrlDecode(const S: string): TBytes;
var
  T: string;
begin
  T := StringReplace(S, '-', '+', [rfReplaceAll]);
  T := StringReplace(T, '_', '/', [rfReplaceAll]);
  while Length(T) mod 4 <> 0 do
    T := T + '=';
  Result := TNetEncoding.Base64.DecodeStringToBytes(T);
end;

function TPandoraPasskey.UvRequirement(const S: string): DWORD;
begin
  if SameText(S, 'required') then
    Result := WEBAUTHN_UV_REQUIRED
  else if SameText(S, 'discouraged') then
    Result := WEBAUTHN_UV_DISCOURAGED
  else
    Result := WEBAUTHN_UV_PREFERRED;
end;

function TPandoraPasskey.ClientDataBytes(const Ceremony,
  Challenge: string): TBytes;
var
  J: string;
begin
  J := '{"type":"' + Ceremony + '","challenge":"' + Challenge +
    '","origin":"' + FOrigin + '","crossOrigin":false}';
  Result := TEncoding.UTF8.GetBytes(J);
end;

function TPandoraPasskey.SignInWithPasskey(hWnd: HWND;
  const Username: string): TPasskeyResult;
var
  Lib: TWebAuthnLib;
  Opts, RespObj, R, DoneObj, UserObj: TJSONObject;
  Challenge, ChallengeId, UserId, RpId, Uv: string;
  Timeout: Integer;
  Allow: TJSONArray;
  Item: TJSONValue;
  ClientData: TBytes;
  ClientDataRec: WEBAUTHN_CLIENT_DATA;
  Options: WEBAUTHN_GET_ASSERTION_OPTIONS;
  Creds: PWEBAUTHN_CREDENTIAL;
  CredCount, i: Integer;
  IdBytes: TBytes;
  HashAlg, CredTypeW, RpIdW: WideString;
  hr: HRESULT;
  Assertion: PWEBAUTHN_ASSERTION;
begin
  Result.Success := False;
  Result.Error := '';
  Assertion := nil;
  Creds := nil;
  Opts := nil;
  Lib := TWebAuthnLib.Create;
  try
    if not Lib.Available then
    begin
      Result.Error := 'Passkeys need Windows 10 1903+ with Windows Hello set up. ' +
        'Use password sign-in instead.';
      Exit;
    end;

    try
      Opts := FApi.PasskeyAuthBegin(Username);
    except
      on E: Exception do
      begin
        Result.Error := E.Message;
        Exit;
      end;
    end;

    try
      Challenge := JsonStr(Opts, 'challenge');
      ChallengeId := JsonStr(Opts, 'challengeId');
      UserId := JsonStr(Opts, 'userId');
      RpId := JsonStr(Opts, 'rpId', FRpId);
      Uv := JsonStr(Opts, 'userVerification', 'preferred');
      Timeout := StrToIntDef(JsonStr(Opts, 'timeout', '60000'), 60000);
      if Timeout <= 0 then
        Timeout := 60000;
      if Timeout > 180000 then
        Timeout := 180000;
      if Challenge = '' then
        raise EApiError.Create('Server did not return a challenge');

      // --- build allow-credentials list ---
      Allow := JsonArr(Opts, 'allowCredentials');
      CredCount := Allow.Count;
      CredTypeW := WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
      if CredCount > 0 then
      begin
        GetMem(Creds, CredCount * SizeOf(WEBAUTHN_CREDENTIAL));
        FillChar(Creds^, CredCount * SizeOf(WEBAUTHN_CREDENTIAL), 0);
        for i := 0 to CredCount - 1 do
        begin
          Item := Allow.Items[i];
          if not (Item is TJSONObject) then
            raise EApiError.Create('Bad allowCredentials from server');
          IdBytes := B64UrlDecode(JsonStr(TJSONObject(Item), 'id'));
          if Length(IdBytes) = 0 then
            raise EApiError.Create('Bad credential id from server');
          Creds[i].dwVersion := 1;
          Creds[i].cbId := DWORD(Length(IdBytes));
          GetMem(Creds[i].pbId, Length(IdBytes));
          Move(IdBytes[0], Creds[i].pbId^, Length(IdBytes));
          Creds[i].pwszCredentialType := PWideChar(CredTypeW);
        end;
      end;

      try
        // --- client data ---
        ClientData := ClientDataBytes('webauthn.get', Challenge);
        HashAlg := WEBAUTHN_HASH_ALGORITHM_SHA_256;
        FillChar(ClientDataRec, SizeOf(ClientDataRec), 0);
        ClientDataRec.dwVersion := 1;
        ClientDataRec.cbClientDataJSON := DWORD(Length(ClientData));
        ClientDataRec.pbClientDataJSON := @ClientData[0];
        ClientDataRec.pwszHashAlgId := PWideChar(HashAlg);

        // --- options ---
        RpIdW := WideString(RpId);
        FillChar(Options, SizeOf(Options), 0);
        Options.dwVersion := 1;
        Options.dwTimeoutMilliseconds := DWORD(Timeout);
        Options.CredentialList.cCredentials := DWORD(CredCount);
        Options.CredentialList.pCredentials := Creds;
        Options.dwAuthenticatorAttachment := WEBAUTHN_ATTACHMENT_ANY;
        Options.dwUserVerificationRequirement := UvRequirement(Uv);

        // --- ceremony (Windows shows the Hello / security-key prompt) ---
        hr := Lib.GetAssertion(hWnd, PWideChar(RpIdW), @ClientDataRec,
          @Options, Assertion);
        if HrFailed(hr) then
        begin
          Result.Error := Lib.ErrorMessage(hr);
          Exit;
        end;
        if Assertion = nil then
        begin
          Result.Error := 'Empty response from authenticator';
          Exit;
        end;

        // --- send assertion to server ---
        RespObj := TJSONObject.Create;
        try
          RespObj.AddPair('id', B64UrlEncodePtr(Assertion^.Credential.pbId,
            Assertion^.Credential.cbId));
          RespObj.AddPair('rawId', B64UrlEncodePtr(Assertion^.Credential.pbId,
            Assertion^.Credential.cbId));
          RespObj.AddPair('type', 'public-key');
          R := TJSONObject.Create;
          R.AddPair('clientDataJSON', B64UrlEncode(ClientData));
          R.AddPair('authenticatorData', B64UrlEncodePtr(
            Assertion^.pbAuthenticatorData, Assertion^.cbAuthenticatorData));
          R.AddPair('signature', B64UrlEncodePtr(Assertion^.pbSignature,
            Assertion^.cbSignature));
          if Assertion^.cbUserId > 0 then
            R.AddPair('userHandle', B64UrlEncodePtr(Assertion^.pbUserId,
              Assertion^.cbUserId));
          RespObj.AddPair('response', R);

          try
            DoneObj := FApi.PasskeyAuthComplete(ChallengeId, UserId, RespObj);
          except
            on E: Exception do
            begin
              Result.Error := E.Message;
              Exit;
            end;
          end;
          try
            Result.Token := JsonStr(DoneObj, 'token');
            UserObj := JsonObj(DoneObj, 'user');
            Result.UserName := JsonStr(UserObj, 'username');
            Result.DisplayName := JsonStr(UserObj, 'displayName',
              Result.UserName);
            Result.Success := Result.Token <> '';
            if not Result.Success then
              Result.Error := 'Server did not return a session';
          finally
            DoneObj.Free;
          end;
        finally
          RespObj.Free;
        end;
      finally
        if Assertion <> nil then
          Lib.FreeAssertion(Assertion);
        if Creds <> nil then
        begin
          for i := 0 to CredCount - 1 do
            if Creds[i].pbId <> nil then
              FreeMem(Creds[i].pbId);
          FreeMem(Creds);
          Creds := nil;
        end;
      end;
    except
      on E: Exception do
        Result.Error := E.Message;
    end;
  finally
    Opts.Free;
    Lib.Free;
  end;
end;

function TPandoraPasskey.RegisterPasskey(hWnd: HWND;
  const DeviceName: string): TPasskeyResult;
var
  Lib: TWebAuthnLib;
  Opts, RespObj, R, DoneObj, RpJson, UserJson, SelJson: TJSONObject;
  Challenge, ChallengeId, RpName, UserName, UserDisplay, Uv, Att: string;
  Timeout, i: Integer;
  UserIdBytes, ClientData: TBytes;
  ClientDataRec: WEBAUTHN_CLIENT_DATA;
  RpInfo: WEBAUTHN_RP_ENTITY_INFORMATION;
  UserInfo: WEBAUTHN_USER_ENTITY_INFORMATION;
  CoseParams: WEBAUTHN_COSE_CREDENTIAL_PARAMETERS;
  CoseArr: PWEBAUTHN_COSE_CREDENTIAL_PARAMETER;
  CoseJson, ExclJson: TJSONArray;
  Options: WEBAUTHN_MAKE_CREDENTIAL_OPTIONS;
  Excl: PWEBAUTHN_CREDENTIAL;
  ExclCount: Integer;
  ExclIds: TArray<string>;
  IdStr: string;
  IdBytes: TBytes;
  Item: TJSONValue;
  HashAlg, CredTypeW, RpIdW, RpNameW, UserNameW, UserDisplayW: WideString;
  hr: HRESULT;
  Attest: PWEBAUTHN_CREDENTIAL_ATTESTATION;
begin
  Result.Success := False;
  Result.Error := '';
  Attest := nil;
  Excl := nil;
  CoseArr := nil;
  Opts := nil;
  Lib := TWebAuthnLib.Create;
  try
    if not Lib.Available then
    begin
      Result.Error := 'Passkeys need Windows 10 1903+ with Windows Hello set up.';
      Exit;
    end;

    try
      Opts := FApi.PasskeyRegBegin;
    except
      on E: Exception do
      begin
        Result.Error := E.Message;
        Exit;
      end;
    end;

    try
      Challenge := JsonStr(Opts, 'challenge');
      ChallengeId := JsonStr(Opts, 'challengeId');
      RpJson := JsonObj(Opts, 'rp');
      RpName := JsonStr(RpJson, 'name', 'Pandora Tool');
      UserJson := JsonObj(Opts, 'user');
      UserName := JsonStr(UserJson, 'name');
      UserDisplay := JsonStr(UserJson, 'displayName', UserName);
      UserIdBytes := B64UrlDecode(JsonStr(UserJson, 'id'));
      Timeout := StrToIntDef(JsonStr(Opts, 'timeout', '60000'), 60000);
      if Timeout <= 0 then
        Timeout := 60000;
      if Timeout > 180000 then
        Timeout := 180000;
      Att := LowerCase(JsonStr(Opts, 'attestation', 'none'));
      Uv := 'preferred';
      SelJson := nil;
      if Opts.GetValue('authenticatorSelection') is TJSONObject then
      begin
        SelJson := TJSONObject(Opts.GetValue('authenticatorSelection'));
        Uv := JsonStr(SelJson, 'userVerification', 'preferred');
      end;
      if (Challenge = '') or (Length(UserIdBytes) = 0) then
        raise EApiError.Create('Bad registration options from server');

      // --- wide-string buffers (must stay alive during the call) ---
      CredTypeW := WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
      RpIdW := WideString(FRpId);
      RpNameW := WideString(RpName);
      UserNameW := WideString(UserName);
      UserDisplayW := WideString(UserDisplay);
      HashAlg := WEBAUTHN_HASH_ALGORITHM_SHA_256;

      // --- credential parameters (ES256, RS256, ...) ---
      CoseJson := JsonArr(Opts, 'pubKeyCredParams');
      if CoseJson.Count = 0 then
        raise EApiError.Create('Server sent no credential parameters');
      GetMem(CoseArr, CoseJson.Count * SizeOf(WEBAUTHN_COSE_CREDENTIAL_PARAMETER));
      FillChar(CoseArr^, CoseJson.Count * SizeOf(WEBAUTHN_COSE_CREDENTIAL_PARAMETER), 0);
      for i := 0 to CoseJson.Count - 1 do
      begin
        Item := CoseJson.Items[i];
        if not (Item is TJSONObject) then
          raise EApiError.Create('Bad pubKeyCredParams from server');
        CoseArr[i].dwVersion := 1;
        CoseArr[i].pwszCredentialType := PWideChar(CredTypeW);
        CoseArr[i].lAlg := StrToIntDef(JsonStr(TJSONObject(Item), 'alg', '-7'), -7);
      end;
      CoseParams.cCredentialParameters := DWORD(CoseJson.Count);
      CoseParams.pCredentialParameters := CoseArr;

      // --- exclude list (already-registered passkeys) ---
      // Pre-filter to valid ids so the native array has no blank entries.
      ExclIds := nil;
      if Opts.GetValue('excludeCredentials') is TJSONArray then
      begin
        ExclJson := TJSONArray(Opts.GetValue('excludeCredentials'));
        for i := 0 to ExclJson.Count - 1 do
        begin
          Item := ExclJson.Items[i];
          if not (Item is TJSONObject) then
            Continue;
          IdStr := JsonStr(TJSONObject(Item), 'id');
          if IdStr <> '' then
            ExclIds := ExclIds + [IdStr];
        end;
      end;
      ExclCount := Length(ExclIds);
      if ExclCount > 0 then
      begin
        GetMem(Excl, ExclCount * SizeOf(WEBAUTHN_CREDENTIAL));
        FillChar(Excl^, ExclCount * SizeOf(WEBAUTHN_CREDENTIAL), 0);
        for i := 0 to ExclCount - 1 do
        begin
          IdBytes := B64UrlDecode(ExclIds[i]);
          Excl[i].dwVersion := 1;
          Excl[i].cbId := DWORD(Length(IdBytes));
          GetMem(Excl[i].pbId, Length(IdBytes));
          Move(IdBytes[0], Excl[i].pbId^, Length(IdBytes));
          Excl[i].pwszCredentialType := PWideChar(CredTypeW);
        end;
      end;

      try
        FillChar(RpInfo, SizeOf(RpInfo), 0);
        RpInfo.dwVersion := 1;
        RpInfo.pwszId := PWideChar(RpIdW);
        RpInfo.pwszName := PWideChar(RpNameW);

        FillChar(UserInfo, SizeOf(UserInfo), 0);
        UserInfo.dwVersion := 1;
        UserInfo.cbId := DWORD(Length(UserIdBytes));
        UserInfo.pbId := @UserIdBytes[0];
        UserInfo.pwszName := PWideChar(UserNameW);
        UserInfo.pwszDisplayName := PWideChar(UserDisplayW);

        ClientData := ClientDataBytes('webauthn.create', Challenge);
        FillChar(ClientDataRec, SizeOf(ClientDataRec), 0);
        ClientDataRec.dwVersion := 1;
        ClientDataRec.cbClientDataJSON := DWORD(Length(ClientData));
        ClientDataRec.pbClientDataJSON := @ClientData[0];
        ClientDataRec.pwszHashAlgId := PWideChar(HashAlg);

        FillChar(Options, SizeOf(Options), 0);
        Options.dwVersion := 1;
        Options.dwTimeoutMilliseconds := DWORD(Timeout);
        Options.CredentialList.cCredentials := DWORD(ExclCount);
        Options.CredentialList.pCredentials := Excl;
        Options.dwAuthenticatorAttachment := WEBAUTHN_ATTACHMENT_ANY;
        Options.bRequireResidentKey := False;
        Options.dwUserVerificationRequirement := UvRequirement(Uv);
        if Att = 'direct' then
          Options.dwAttestationConveyancePreference := WEBAUTHN_ATTESTATION_DIRECT
        else if Att = 'indirect' then
          Options.dwAttestationConveyancePreference := WEBAUTHN_ATTESTATION_INDIRECT
        else
          Options.dwAttestationConveyancePreference := WEBAUTHN_ATTESTATION_NONE;

        hr := Lib.MakeCredential(hWnd, @RpInfo, @UserInfo, @CoseParams,
          @ClientDataRec, @Options, Attest);
        if HrFailed(hr) then
        begin
          Result.Error := Lib.ErrorMessage(hr);
          Exit;
        end;
        if Attest = nil then
        begin
          Result.Error := 'Empty response from authenticator';
          Exit;
        end;

        RespObj := TJSONObject.Create;
        try
          RespObj.AddPair('id', B64UrlEncodePtr(Attest^.pbCredentialId,
            Attest^.cbCredentialId));
          RespObj.AddPair('rawId', B64UrlEncodePtr(Attest^.pbCredentialId,
            Attest^.cbCredentialId));
          RespObj.AddPair('type', 'public-key');
          R := TJSONObject.Create;
          R.AddPair('clientDataJSON', B64UrlEncode(ClientData));
          R.AddPair('attestationObject', B64UrlEncodePtr(
            Attest^.pbAttestationObject, Attest^.cbAttestationObject));
          R.AddPair('transports', TJSONArray.Create);
          RespObj.AddPair('response', R);

          try
            DoneObj := FApi.PasskeyRegComplete(ChallengeId, DeviceName, RespObj);
          except
            on E: Exception do
            begin
              Result.Error := E.Message;
              Exit;
            end;
          end;
          try
            Result.Success := JsonBool(DoneObj, 'success', False);
            if not Result.Success then
              Result.Error := JsonStr(DoneObj, 'error',
                'Server rejected the new passkey');
          finally
            DoneObj.Free;
          end;
        finally
          RespObj.Free;
        end;
      finally
        if Attest <> nil then
          Lib.FreeAttestation(Attest);
      end;
    except
      on E: Exception do
        Result.Error := E.Message;
    end;
  finally
    if Excl <> nil then
    begin
      for i := 0 to ExclCount - 1 do
        if Excl[i].pbId <> nil then
          FreeMem(Excl[i].pbId);
      FreeMem(Excl);
    end;
    if CoseArr <> nil then
      FreeMem(CoseArr);
    Opts.Free;
    Lib.Free;
  end;
end;

end.
