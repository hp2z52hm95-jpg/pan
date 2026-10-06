unit CryptoUtils;

{
  Cryptographic utilities for Passkey authentication
  - Base64 encoding/decoding
  - Random challenge generation
  - SHA-256 hashing
  - COSE key parsing
}

interface

uses
  System.SysUtils, System.Classes, Winapi.Windows, System.NetEncoding;

type
  TCryptoUtils = class
  public
    // Base64 URL encoding (WebAuthn standard)
    class function Base64URLEncode(const Data: TBytes): string;
    class function Base64URLDecode(const Base64: string): TBytes;
    
    // Random challenge generation
    class function GenerateChallenge(Size: Integer = 32): TBytes;
    
    // SHA-256 hashing
    class function SHA256(const Data: TBytes): TBytes;
    
    // Byte array utilities
    class function BytesToHex(const Data: TBytes): string;
    class function HexToBytes(const Hex: string): TBytes;
    class function BytesEqual(const A, B: TBytes): Boolean;
    
    // COSE key utilities
    class function ExtractPublicKeyFromAuthData(const AuthData: TBytes): TBytes;
  end;

implementation

uses
  Winapi.WinCrypt;

{ TCryptoUtils }

class function TCryptoUtils.Base64URLEncode(const Data: TBytes): string;
var
  Base64: string;
begin
  Base64 := TNetEncoding.Base64.EncodeBytesToString(Data);
  // Convert to URL-safe Base64
  Result := StringReplace(Base64, '+', '-', [rfReplaceAll]);
  Result := StringReplace(Result, '/', '_', [rfReplaceAll]);
  Result := StringReplace(Result, '=', '', [rfReplaceAll]);
end;

class function TCryptoUtils.Base64URLDecode(const Base64: string): TBytes;
var
  StdBase64: string;
  Padding: Integer;
begin
  // Convert from URL-safe to standard Base64
  StdBase64 := StringReplace(Base64, '-', '+', [rfReplaceAll]);
  StdBase64 := StringReplace(StdBase64, '_', '/', [rfReplaceAll]);
  
  // Add padding if needed
  Padding := Length(StdBase64) mod 4;
  if Padding > 0 then
    StdBase64 := StdBase64 + StringOfChar('=', 4 - Padding);
  
  Result := TNetEncoding.Base64.DecodeStringToBytes(StdBase64);
end;

class function TCryptoUtils.GenerateChallenge(Size: Integer): TBytes;
var
  hProv: HCRYPTPROV;
begin
  SetLength(Result, Size);
  
  if not CryptAcquireContext(hProv, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) then
    raise Exception.CreateFmt('CryptAcquireContext failed: %d', [GetLastError]);
  
  try
    if not CryptGenRandom(hProv, Size, @Result[0]) then
      raise Exception.CreateFmt('CryptGenRandom failed: %d', [GetLastError]);
  finally
    CryptReleaseContext(hProv, 0);
  end;
end;

class function TCryptoUtils.SHA256(const Data: TBytes): TBytes;
var
  hProv: HCRYPTPROV;
  hHash: HCRYPTHASH;
  HashSize: DWORD;
begin
  HashSize := 32; // SHA-256 = 32 bytes
  SetLength(Result, HashSize);
  
  if not CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
    raise Exception.CreateFmt('CryptAcquireContext failed: %d', [GetLastError]);
  
  try
    if not CryptCreateHash(hProv, CALG_SHA_256, 0, 0, hHash) then
      raise Exception.CreateFmt('CryptCreateHash failed: %d', [GetLastError]);
    
    try
      if not CryptHashData(hHash, @Data[0], Length(Data), 0) then
        raise Exception.CreateFmt('CryptHashData failed: %d', [GetLastError]);
      
      if not CryptGetHashParam(hHash, HP_HASHVAL, @Result[0], HashSize, 0) then
        raise Exception.CreateFmt('CryptGetHashParam failed: %d', [GetLastError]);
    finally
      CryptDestroyHash(hHash);
    end;
  finally
    CryptReleaseContext(hProv, 0);
  end;
end;

class function TCryptoUtils.BytesToHex(const Data: TBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Length(Data) - 1 do
    Result := Result + IntToHex(Data[I], 2);
end;

class function TCryptoUtils.HexToBytes(const Hex: string): TBytes;
var
  I: Integer;
begin
  SetLength(Result, Length(Hex) div 2);
  for I := 0 to Length(Result) - 1 do
    Result[I] := StrToInt('$' + Copy(Hex, I * 2 + 1, 2));
end;

class function TCryptoUtils.BytesEqual(const A, B: TBytes): Boolean;
var
  I: Integer;
begin
  if Length(A) <> Length(B) then
    Exit(False);
  
  for I := 0 to Length(A) - 1 do
    if A[I] <> B[I] then
      Exit(False);
  
  Result := True;
end;

class function TCryptoUtils.ExtractPublicKeyFromAuthData(const AuthData: TBytes): TBytes;
var
  CredIdLen: Word;
  PubKeyOffset: Integer;
begin
  {
    Authenticator data structure:
    - rpIdHash (32 bytes)
    - flags (1 byte)
    - signCount (4 bytes)
    - attestedCredentialData (variable):
      - aaguid (16 bytes)
      - credentialIdLength (2 bytes, big-endian)
      - credentialId (credentialIdLength bytes)
      - credentialPublicKey (CBOR encoded, variable)
  }
  
  if Length(AuthData) < 37 then
    raise Exception.Create('Authenticator data too short');
  
  // Read credential ID length (big-endian at offset 53)
  CredIdLen := (AuthData[53] shl 8) or AuthData[54];
  
  // Public key starts after credential ID
  PubKeyOffset := 55 + CredIdLen;
  
  if PubKeyOffset >= Length(AuthData) then
    raise Exception.Create('Invalid authenticator data structure');
  
  // Extract public key (CBOR encoded)
  SetLength(Result, Length(AuthData) - PubKeyOffset);
  Move(AuthData[PubKeyOffset], Result[0], Length(Result));
end;

end.
