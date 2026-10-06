# Passkey Authentication Smoke Test

## Overview
This is a proof-of-concept Delphi application demonstrating FIDO2/WebAuthn passkey authentication using Windows Hello PIN as the authenticator.

## What This Demonstrates
- Passkey registration (creating a new credential)
- Passkey authentication (signing in with biometric/PIN)
- Windows WebAuthn API integration
- Server-side verification (mock server included)

## Requirements
- Windows 10 version 1903 or later (for WebAuthn API)
- Windows Hello configured (PIN, fingerprint, or face)
- Delphi 10.4+ (for compilation)
- Administrator privileges (for some WebAuthn operations)

## Files
```
passkey_test/
├── README.md                      (this file)
├── PasskeyTest.dpr                (Delphi project file)
├── MainForm.pas                   (main form with UI)
├── MainForm.dfm                   (form layout)
├── WebAuthnAPI.pas                (Delphi headers for webauthn.dll)
├── PasskeyClient.pas              (client-side passkey logic)
├── MockServer.pas                 (mock FIDO2 server for testing)
├── CryptoUtils.pas                (cryptographic utilities)
└── build_and_run.bat              (build script)
```

## How to Run

### Option 1: Build with Delphi IDE
1. Open `PasskeyTest.dpr` in Delphi
2. Build (F9)
3. Run (F5)

### Option 2: Use Build Script
```cmd
cd passkey_test
build_and_run.bat
```

### Option 3: Pre-built Binary
If you have a pre-built `PasskeyTest.exe`, just run it.

## Usage

### 1. Register a Passkey
- Click "Register Passkey" button
- Windows Hello prompt appears (enter PIN/fingerprint/face)
- Credential created and stored
- Public key sent to mock server

### 2. Authenticate with Passkey
- Click "Authenticate" button
- Windows Hello prompt appears
- Credential used to sign challenge
- Server verifies signature
- Success/failure displayed

### 3. View Stored Credentials
- Shows credential ID, public key, creation time
- Demonstrates what server stores

## Expected Behavior

### Successful Registration:
```
[INFO] Starting passkey registration...
[INFO] Calling WebAuthNAuthenticatorMakeCredential...
[WINDOWS HELLO PROMPT APPEARS]
[USER ENTERS PIN]
[SUCCESS] Passkey registered!
[INFO] Credential ID: <base64>
[INFO] Public key stored on server
```

### Successful Authentication:
```
[INFO] Starting passkey authentication...
[INFO] Generating challenge...
[INFO] Calling WebAuthNAuthenticatorGetAssertion...
[WINDOWS HELLO PROMPT APPEARS]
[USER ENTERS PIN]
[SUCCESS] Authentication successful!
[INFO] Signature verified by server
[INFO] Session token: <token>
```

### Failure Cases:
```
[ERROR] WebAuthn API not available (requires Windows 10 1903+)
[ERROR] User cancelled authentication
[ERROR] No passkey registered yet
[ERROR] Signature verification failed
```

## Technical Details

### WebAuthn Flow

**Registration:**
1. Client requests registration from server
2. Server returns challenge + relying party info
3. Client calls `WebAuthNAuthenticatorMakeCredential`
4. Windows Hello prompts user (PIN/biometric)
5. Authenticator generates key pair
6. Private key stored in TPM (secure hardware)
7. Public key + attestation returned to client
8. Client sends public key to server
9. Server stores credential

**Authentication:**
1. Client requests authentication from server
2. Server returns challenge + allowed credentials
3. Client calls `WebAuthNAuthenticatorGetAssertion`
4. Windows Hello prompts user (PIN/biometric)
5. Authenticator signs challenge with private key
6. Signature returned to client
7. Client sends signature to server
8. Server verifies signature with stored public key
9. If valid, user authenticated

### Windows APIs Used
- `webauthn.dll` (WebAuthn API)
- `Windows.Security.Credentials.UI` (biometric prompts)
- `NCrypt` (key storage)

### Security Features
- Private key never leaves device (stored in TPM)
- Biometric/PIN required for each use
- Cryptographic challenge-response (no password transmitted)
- Phishing-resistant (bound to relying party)
- Replay protection (sign counter)

## Troubleshooting

### "WebAuthn API not available"
- Requires Windows 10 version 1903 or later
- Check: Settings → System → About → Version (should be 1903+)

### "User cancelled authentication"
- User clicked Cancel on Windows Hello prompt
- Try again and complete authentication

### "No passkey registered"
- Click "Register Passkey" first before authenticating

### "Signature verification failed"
- Should not happen in normal flow
- Indicates tampering or bug
- Check mock server logs

### Windows Hello prompt doesn't appear
- Ensure Windows Hello is configured
- Settings → Accounts → Sign-in options
- Set up PIN, fingerprint, or face recognition

## Next Steps

After this smoke test:
1. Integrate with real Pandora server
2. Add credential management (list, delete, backup)
3. Implement cross-device authentication (phone as authenticator)
4. Add passkey + BOX hybrid mode
5. User-friendly error messages
6. Localization support

## References
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [FIDO2 Documentation](https://fidoalliance.org/fido2/)
- [Windows WebAuthn API](https://docs.microsoft.com/en-us/windows/win32/api/webauthn/)
- [Passkeys Introduction](https://fidoalliance.org/passkeys/)

## License
Proof of concept for Pandora Tool authentication enhancement.
