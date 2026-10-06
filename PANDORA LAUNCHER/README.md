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
| `build.bat` | Command-line build script (Delphi / MSBuild) |
| **`PandoraLauncher.exe`** | **Ready-to-use launcher (prebuilt — see below)** |
| `native/` | Same launcher written in plain C, builds with free tools (see `native/README.md`) |

Needs only RTL/VCL units (`System.Net.HttpClient`, `System.JSON`,
`System.Hash`, `System.Zip`, `TlHelp32`) — no third-party components.

The `native/` C build needs only Win32, WinHTTP and `webauthn.dll`; see
`native/README.md` for its tests (portable unit tests + a live API contract
test against the Node server).

## Install (no compiler needed)

`PandoraLauncher.exe` is **already built and committed** in this folder —
there is nothing to compile to get started:

```
C:\Pandora\
├── PandoraTool.exe
├── PandoraLauncher.exe   ← committed in this repo, 32-bit, runs on any Windows
└── launcher.ini          ← copy launcher.ini.example, then edit
```

Then point the user's shortcut at `PandoraLauncher.exe`.

The version committed here is the C build in `native/` (369 KB, x86, built
with `sh native/build.sh`). It is functionally identical to the Delphi
launcher described in this file and uses the same `launcher.ini`.

## Build (if you want to rebuild)

Two interchangeable sources — pick whichever toolchain you have:

| Source | Toolchain | Command |
|---|---|---|
| `native/launcher.c` | **free**: Visual Studio Build Tools, MinGW-w64, LLVM — or cross-compiled from Linux with `zig cc` | `native\build.bat` &nbsp;/&nbsp; `sh native/build.sh` |
| `PandoraLauncher.dpr` | Delphi 10.4+ (commercial) | open the project → Save All → Run, or `build.bat` |

The C build needs no third-party libraries (Win32 + WinHTTP + `webauthn.dll`)
and compiles the icon, DPI-aware manifest and version info from
`native/launcher.rc`. For Delphi:

1. Open `PandoraLauncher.dpr` in Delphi (10.4 Sydney or newer), press **Save All**
   (generates `.dproj`/`.res`), then **Run** — or run `build.bat`.
2. **Important:** Project → Options → Application → Manifest →
   set **"Require Administrator"** if the tool lives in `Program Files`
   (updating files there needs elevation — same as PandoraTool itself).
   (The C build does this automatically: it probes the folder and elevates
   itself only when an update must actually be written.)
3. Copy the resulting `PandoraLauncher.exe` into the tool folder as above.

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
