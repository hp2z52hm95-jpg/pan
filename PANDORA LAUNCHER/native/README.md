# PandoraLauncher.exe — native build (C, no Delphi needed)

This folder contains a **complete, self-contained implementation of the
launcher as plain C**, so a working `PandoraLauncher.exe` can be built with
free tools (or committed to the repo as a binary, which the Delphi project
cannot do — there is no free Delphi command-line compiler).

It is a drop-in replacement for the Delphi launcher in the parent folder:
same `launcher.ini`, same server endpoints, same behaviour.

```
PANDORA LAUNCHER/
├── PandoraLauncher.exe        <- the built launcher (this folder)
├── PandoraLauncher.dpr        <- original Delphi project (kept)
├── uMainForm.pas ... etc.     <- original Delphi sources (kept)
└── native/
    ├── launcher.c             <- UI, sign-in, update flow, WinHTTP client
    ├── util.c / util.h        <- portable core: JSON, SHA-256, base64url,
    │                             inflate, ZIP, buffers
    ├── webauthn.h             <- Windows WebAuthn API (webauthn.dll)
    ├── launcher.rc / .manifest / pandora.ico
    ├── build.bat              <- Windows build (MSVC / MinGW / clang)
    ├── build.sh               <- Linux/macOS cross build (zig cc / mingw)
    └── tests/                 <- unit tests + live API contract test
```

## What it does (identical to the Delphi version)

1. Reads `launcher.ini` next to the exe.
2. Shows the sign-in dialog — **password** or **passkey** (Windows Hello,
   fingerprint, PIN or a security key) through the real Windows WebAuthn API.
3. Calls `GET /api/updates/check?app=PandoraTool&current=<installed version>`.
4. Downloads every package from `GET /api/updates/download/:file` **with the
   session token**, and verifies size + SHA-256 *before* touching anything.
5. Closes a running `PandoraTool.exe` (WM_CLOSE, then 15 s, then force).
6. Copies replaced files to `Backup\<old version>\`, applies the packages.
7. Starts `PandoraTool.exe --pandora-session <jwt> --pandora-user "<name>"`.

Extras that the Delphi version does not have:

* **Looks like the tool** — the application icon and version info are
  extracted from `PandoraTool.exe`, so launcher and tool match in Explorer,
  the taskbar and Task Manager.
* **Windows 11 / high-DPI clean** — per-monitor DPI awareness is declared in
  the embedded manifest, fonts follow the user's system font and DPI.
* **Program Files handled** — probing the install folder; if it is not
  writable, the launcher re-launches itself elevated (one UAC prompt, only
  when an update really has to be installed).
* **Single instance** — double-clicking the icon again focuses the running
  launcher instead of starting a second copy.
* **`PandoraLauncher.version`** — records the last installed version as a
  fallback for tools whose `.exe` carries no version resource.

## Build

### Windows

```bat
build.bat            :: 32-bit, runs on every Windows (recommended)
build.bat 64         :: 64-bit
build.bat debug      :: -O0 build with symbols
```

Works with any one of: Visual Studio Build Tools (`cl.exe`), MinGW-w64
(`gcc.exe`) or LLVM (`clang.exe`). The script picks what it finds and also
compiles the resources (icon, manifest, version info). If no resource
compiler is installed the exe still builds, just without the icon.

### Linux / macOS (cross-compile)

```sh
pip install ziglang          # free, no root needed
sh build.sh                  # -> native/PandoraLauncher.exe (32-bit)
sh build.sh 64               # -> 64-bit
sh build.sh 32 dist          # + copy to ../PandoraLauncher.exe (the shipped
                             #   launcher) and refresh PandoraLauncher.exe.sha256
```

`zig cc` is a full C compiler + MinGW-w64 headers/libs and `zig rc` compiles
the `.rc`, so the resulting exe is identical in features to the MSVC one.
With MinGW-w64 installed instead, `sh build.sh` uses
`i686-w64-mingw32-gcc` + `windres`.

## Tests

```sh
sh tests/run_tests.sh                       # portable core unit tests
python3 tests/api_contract_test.py          # live server contract test
```

* `tests/run_tests.sh` builds `util.c` with the host compiler and checks
  base64url, SHA-256 (NIST vectors), CRC-32, JSON parsing/paths, DEFLATE
  inflate, ZIP extraction, CRC corruption detection and path-traversal
  rejection — using real ZIPs (stored *and* deflated) and a 2 MiB payload.
* `tests/api_contract_test.py` boots the Node server from `passkey_test/`
  with a throwaway database, generates a signed manifest with the repo's own
  `make-manifest.js`, then replays the launcher's exact request sequence
  (password login, passkey *authenticate/begin*, update check, authenticated
  download) and verifies every field the C code reads.

Both are runnable on any machine and are wired into CI.

## Notes / limitations

* Passkeys need Windows 10 1903+ with Windows Hello set up; on older systems
  the launcher says so and password sign-in still works.
* `webauthn.dll` is loaded dynamically, so the launcher never fails to start
  because of it.
* `RpId` and `Origin` in `launcher.ini` must match the server's `RP_ID` /
  `WEBAUTHN_ORIGIN` exactly, otherwise the server rejects the ceremony
  (that is what makes passkeys phishing-proof).
* The binary is unsigned; SmartScreen may warn on first run for downloads
  from the internet. Sign it with Authenticode for production releases.
* The committed `PANDORA LAUNCHER/PandoraLauncher.exe` is this build; its
  SHA-256 is kept in `PANDORA LAUNCHER/PandoraLauncher.exe.sha256`.
