# Pandora Launcher — sign in (password + passkey) → update → start PandoraTool

`PandoraLauncher.exe` is **already built and committed in this folder** — you do
not need Delphi or Visual Studio to use it.

```
C:\Pandora\                      (the folder that has PandoraTool.exe)
├── PandoraTool.exe
├── PandoraLauncher.exe          ← copy this from PANDORA LAUNCHER\
└── launcher.ini                 ← copy from launcher.ini.example, edit BaseURL
```

The launcher sits **next to `PandoraTool.exe`**. Users start the launcher instead
of the tool:

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
│  UPDATE CHECK     │  GET /api/updates/check?app=PandoraTool&current=10.2.20.0
└────────┬──────────┘
         │ update available?
         ▼
┌───────────────────┐
│  DOWNLOAD (auth)  │  GET /api/updates/download/<file> + JWT
│  verify SHA-256   │  nothing is touched until ALL files verify ✔
│  verify CRC-32    │  (also checked while unpacking the .zip)
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  CLOSE running    │  WM_CLOSE → wait 15 s → force-close if needed
│  PandoraTool.exe  │  (Windows CANNOT overwrite a running .exe — that is why
└────────┬──────────┘   the updater closes it first, then relaunches it)
         ▼
┌───────────────────┐
│  BACKUP + APPLY   │  replaced files → Backup\<old-version>\
│                   │  .zip packages unpacked over the app folder
└────────┬──────────┘
         ▼
   PandoraTool.exe --pandora-session <jwt> --pandora-user "<name>"
```

## Why a launcher? ("show a login when PandoraTool.exe runs")

`PandoraTool.exe` is a closed binary — there is no source to add a login dialog
into it. The login therefore lives in the launcher, which runs **first**:

- Point the Desktop/Start-menu shortcut at `PandoraLauncher.exe`.
- The launcher signs the user in (with the passkey button), updates if needed,
  then starts `PandoraTool.exe`. From the user's view: press the Pandora icon →
  login page → tool. ✔
- The session (`--pandora-session <jwt>`) is passed on the command line. The
  current tool ignores unknown switches; `LoginGate.pas` in this folder is the
  3-line drop-in for a future rebuild that enforces the session.

## Files

| File | Purpose |
|---|---|
| **`PandoraLauncher.exe`** | **the built 32-bit Windows launcher (committed, ready to copy)** |
| `src/` | C sources of that .exe (see `src/README.md`) |
| `src/build.sh` | rebuilds the .exe with zig — no Delphi, no Visual Studio |
| `src/tests/` | host test suite + `make -C src/tests` |
| `src/app.rc`, `src/icon.ico` | icon (same as PandoraTool), version info, manifest |
| `launcher.ini.example` | config template |
| `PandoraLauncher.dpr`, `u*.pas`, `LoginGate.pas` | the same launcher written in Delphi (reference source; see "Delphi version" below) |
| `build.bat` | command-line build of the Delphi version (needs Delphi 10.4+) |

## Configure

`launcher.ini` — copied next to `PandoraLauncher.exe`:

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

Without a `launcher.ini` the built-in defaults are used
(`http://localhost:3000`, `PandoraTool.exe`, auto update/launch on).

> `RpId`/`Origin` must **exactly** match the server's `.env`, or passkey
> ceremonies fail (that exact match is what makes passkeys phishing-proof).
> Passkeys can be used for **sign-in** here; registering a *new* passkey is done
> once in the web login page (the register endpoint requires a signed-in
> session).

## What happens on failure (nothing is left half-updated)

| Step | On failure |
|---|---|
| Sign-in | nothing is downloaded and `PandoraTool.exe` is not started |
| Update check | the launcher stops with the server's error in the log |
| Download / SHA-256 / CRC-32 | the install folder is untouched, the tool is **not** started |
| Closing the running tool | the update is aborted (nothing replaced) |
| Unpacking | the files that were already replaced can be restored from `Backup\<old-version>\` |

## Verify the build

The launcher can test itself (SHA-256 vectors, base64url, version compare,
launcher.ini, JSON, DEFLATE, ZIP unpacking of a real package incl. non-ASCII
names and a hostile `../` package, backup/rollback behaviour):

```bat
PandoraLauncher.exe --self-test
```

It writes `pandora-launcher-selftest.txt` next to the .exe and shows PASS/FAIL.
`--self-test --quiet` skips the message box (used by CI).

The same suite, plus a byte-for-byte comparison of an unpacked package against
its source files, runs on any machine with a C compiler:

```bash
make -C "PANDORA LAUNCHER/src/tests"      # -> ALL TESTS PASSED (68 checks)
```

## Rebuild PandoraLauncher.exe (no Delphi needed)

```bash
pip install ziglang                       # or grab zig from ziglang.org
cd "PANDORA LAUNCHER/src"
./build.sh                                # -> ../PandoraLauncher.exe
```

`build.sh` uses zig as a drop-in C compiler with the bundled mingw-w64 headers,
targets 32-bit Windows (`x86-windows-gnu`, like PandoraTool.exe itself), embeds
`icon.ico` + version info + an `asInvoker` manifest, and links WinHTTP, comctl32,
shell32, version and advapi32. Output is a single self-contained
`PandoraLauncher.exe` (~415 KB, no DLLs to ship).
Requires Windows 10/11 (the universal runtime is part of the OS there).

CI does exactly this on every push (`.github/workflows/launcher.yml`) and uploads
the fresh `.exe` as an artifact.

## Privileges (Program Files, "Access denied")

The launcher starts with normal user rights. If an update hits an access-denied
error the launcher offers to **restart itself as administrator** (Run as
administrator) and continues. Two alternatives:

- install the Pandora folder somewhere writable (e.g. `C:\Pandora`), or
- always start elevated: in `src/app.manifest` change
  `requestedExecutionLevel level="asInvoker"` to `requireAdministrator`, then
  rebuild (or set it in the Delphi project options if you build the Delphi
  version).

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

Every update copies replaced files to `Backup\<old-version>\`. If a release is
bad: close the tool, copy the backup files back over the app folder.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "Passkeys need Windows 10 1903+" | Old Windows or `webauthn.dll` missing — password sign-in still works |
| Passkey ceremony fails | `RpId`/`Origin` in `launcher.ini` don't match the server `.env` |
| "Invalid username or password" | Wrong credentials, or the user does not exist on that server |
| "Cannot reach the update server" | Wrong `BaseURL`, server down, firewall, or a bad TLS certificate |
| "Could not close the running app" | The tool is hung (or elevated) — close it by hand, run the launcher again |
| "Replace failed … access denied" | Enable the elevated restart (see *Privileges*), or install outside `Program Files` |
| "SHA-256 mismatch" | The package on the server is not the one the manifest was built from — rebuild the manifest |
| SmartScreen warning | Normal for unsigned builds — sign the `.exe` (Authenticode) for production |
| Server shows "Invalid session" on download | JWT expired (24 h) — sign in again |

## Delphi version (reference source)

`PandoraLauncher.dpr` + `u*.pas` are the original Delphi source of the same
launcher (RTL/VCL only, `build.bat` builds it with MSBuild). The C sources in
`src/` implement the same flow and are what produces the committed
`PandoraLauncher.exe`, because the .exe had to be buildable and testable without
a Delphi installation. If you have Delphi 10.4+ you can keep using the Delphi
project — both produce the same behaviour, the same `launcher.ini`, the same
server API calls and the same `--pandora-session` hand-off.
