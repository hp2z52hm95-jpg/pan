# Pandora Launcher — login (password + passkey) + package updater

`PandoraLauncher.exe` sits **in the same folder as `PandoraTool.exe`**.
Users start the launcher instead of the tool directly. It:

1. shows a **login dialog with password + 🔑 passkey** (Windows Hello / security key),
2. checks the server for updates and **updates the running app**,
3. starts `PandoraTool.exe` with the login session.

```
User double-clicks PandoraLauncher.exe
        │
        ▼
┌───────────────────┐
│  LOGIN (required) │  password  ──► POST /api/auth/login
│  passkey button   │  passkey   ──► WebAuthn ceremony + /api/passkey/...
└────────┬──────────┘  (same passkeys as the web login page)
         │ JWT session
         ▼
┌───────────────────┐
│  UPDATE CHECK     │  GET /api/updates/check?current=10.2.20.0
└────────┬──────────┘
         │ update available?
         ▼
┌───────────────────┐
│  DOWNLOAD (auth)  │  GET /api/updates/download/:file + JWT
│  verify SHA-256   │  nothing is touched until ALL files verify ✔
└────────┬──────────┘
         ▼
┌───────────────────┐
│  CLOSE running    │  WM_CLOSE → wait 15 s → force-close if needed
│  PandoraTool.exe  │  (Windows CANNOT overwrite a running .exe — this is why
└────────┬──────────┘   the updater closes it first, then relaunches it)
         ▼
┌───────────────────┐
│  BACKUP + APPLY   │  replaced files → Backup\<old-version>\
│                   │  .zip packages extracted over the app folder
└────────┬──────────┘
         ▼
   PandoraTool.exe --pandora-session <jwt> --pandora-user "<name>"
```

## Why a launcher? (login "when we run PandoraTool.exe")

`PandoraTool.exe` is a closed binary — there is no source to add a login
dialog into it. So the login lives in the launcher, which runs **first**:

- Replace the Desktop/Start-menu shortcut target with `PandoraLauncher.exe`.
- The launcher shows login (with the passkey button), updates if needed,
  then runs `PandoraTool.exe` automatically. From the user's view, pressing
  the Pandora icon = login page → tool. ✔
- The session (`--pandora-session <jwt>`) is passed on the command line.
  The current tool ignores unknown switches; `LoginGate.pas` in this folder
  is the 3-line drop-in for a future rebuild that enforces the session.

## Files

| File | Purpose |
|---|---|
| `PandoraLauncher.dpr` | Project (Delphi 10.4+, VCL, Win32) |
| `uMainForm.pas/.dfm` | Launcher window: log + progress + auto flow |
| `uLoginForm.pas/.dfm` | Login dialog: password + passkey buttons |
| `uPandoraApi.pas` | Server client (login, passkey, updates, download) |
| `uPasskeyAuth.pas` | WebAuthn ceremony → server JWT |
| `uWebAuthnWin.pas` | **Correct** `webauthn.dll` headers (verified vs `webauthn.h`, dynamically loaded) |
| `uUpdateEngine.pas` | Version check, download+verify, close app, backup, apply, relaunch |
| `LoginGate.pas` | Drop-in gate for a future tool rebuild (see header comment) |
| `launcher.ini.example` | Config template |
| `build.bat` | Command-line build script |

Needs only RTL/VCL units (`System.Net.HttpClient`, `System.JSON`,
`System.Hash`, `System.Zip`, `TlHelp32`) — no third-party components.

## Build

1. Open `PandoraLauncher.dpr` in Delphi (10.4 Sydney or newer), press **Save All**
   (generates `.dproj`/`.res`), then **Run** — or run `build.bat`.
2. **Important:** Project → Options → Application → Manifest →
   set **"Require Administrator"** if the tool lives in `Program Files`
   (updating files there needs elevation — same as PandoraTool itself).
3. Copy to the tool folder:
   ```
   C:\Pandora\
   ├── PandoraTool.exe
   ├── PandoraLauncher.exe   ← build output
   └── launcher.ini           ← from launcher.ini.example, edited
   ```
4. Point the user's shortcut at `PandoraLauncher.exe`.

## Configure

`launcher.ini`:

```ini
[Server]
BaseURL=https://updates.example.com   ; where the Node server runs
RpId=updates.example.com              ; MUST equal server RP_ID
Origin=https://updates.example.com    ; MUST equal server WEBAUTHN_ORIGIN

[App]
Exe=PandoraTool.exe
LaunchArgs=                           ; extra switches for the tool
AutoUpdate=1
AutoLaunch=1
```

> `RpId`/`Origin` must **exactly** match the server, or passkey ceremonies
> fail (this exact-match is what makes passkeys phishing-proof).

## Publish an update (server side)

```bash
cd passkey_test/server
# 1. put the new files in a zip (paths relative to the app folder):
#      PandoraTool-10.2.21.0.zip  →  PandoraTool.exe, MetaCore.dll, ...
cp /path/to/PandoraTool-10.2.21.0.zip packages/

# 2. generate the signed manifest (sizes + SHA-256):
node scripts/make-manifest.js --version 10.2.21.0 --notes "What changed"

# 3. done — launchers on 10.2.20.0 will now offer the update after login.
```

Downloads require a valid login (password **or** passkey session) and are
audit-logged on the server.

## Rollback

Every update copies replaced files to `Backup\<old-version>\`. If a release
is bad: close the tool, copy the backup files back over the app folder.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "Passkeys need Windows 10 1903+" | Old Windows or `webauthn.dll` missing — password login still works |
| Passkey ceremony fails | `RpId`/`Origin` in `launcher.ini` don't match server `.env` |
| "Could not close the running app" | Tool is hung as admin / in use — close it manually, retry |
| Replace failed (code 5) | Access denied — enable "Require Administrator" manifest, or install outside `Program Files` |
| SmartScreen warning | Normal for unsigned builds — sign the `.exe` (Authenticode) for production |
| Server shows "Invalid session" on download | JWT expired (24 h) — sign in again |
