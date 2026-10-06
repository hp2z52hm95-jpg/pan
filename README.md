# pan — Pandora Tool launcher & login

Repository for the Pandora Tool desktop launcher: password + passkey
(WebAuthn / Windows Hello) sign-in and automatic updates for `PandoraTool.exe`.

## I just want the launcher

**`PANDORA LAUNCHER/PandoraLauncher.exe`** — prebuilt, committed, nothing to compile.

```
C:\Pandora\                     (the folder with PandoraTool.exe)
├── PandoraTool.exe
├── PandoraLauncher.exe         ← copy from PANDORA LAUNCHER/ in this repo
├── launcher.ini                ← copy of PANDORA LAUNCHER/launcher.ini.example, edited
└── launcher.ini.example
```

Point the Desktop/Start-menu shortcut at `PandoraLauncher.exe` instead of
`PandoraTool.exe`. On start it shows the sign-in dialog (password or
🔑 passkey), applies any update published on your server, then starts
`PandoraTool.exe` with the session.

`launcher.ini` must point at your server, e.g.

```ini
[Server]
BaseURL=https://updates.example.com
RpId=updates.example.com        ; must equal the server's RP_ID
Origin=https://updates.example.com  ; must equal the server's WEBAUTHN_ORIGIN

[App]
Exe=PandoraTool.exe
AutoUpdate=1
AutoLaunch=1
```

## What's in here

| Path | What it is |
|---|---|
| `PANDORA LAUNCHER/` | The launcher: prebuilt `.exe`, its C source (`native/`), the original Delphi project (`PandoraLauncher.dpr`, `u*.pas`) and the README |
| `PANDORA LAUNCHER/native/` | Plain-C implementation + build scripts + tests (`native/README.md`) |
| `passkey_test/server/` | Node/Express API server: web login page, FIDO2/WebAuthn passkey endpoints, update distribution (`/api/updates/*`) |
| `passkey_test/` | Delphi passkey test app, mock server and the WebAuthn integration guide |
| `RE_work/` | Reverse-engineering notes and security analysis of the tool |

## Build & test

```sh
# rebuild the launcher from C (no Delphi needed)
pip install ziglang
sh "PANDORA LAUNCHER/native/build.sh"          # -> PANDORA LAUNCHER/native/PandoraLauncher.exe

# portable core unit tests (JSON, SHA-256, deflate, ZIP)
sh "PANDORA LAUNCHER/native/tests/run_tests.sh"

# live API contract test against the Node server
cd passkey_test/server && npm install && cd -
python3 "PANDORA LAUNCHER/native/tests/api_contract_test.py"
```

See `PANDORA LAUNCHER/README.md` (behaviour, configuration, publishing
updates, rollback) and `PANDORA LAUNCHER/native/README.md` (implementation
notes, build options, tests).
