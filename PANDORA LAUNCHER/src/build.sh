#!/usr/bin/env bash
#
# Builds PandoraLauncher.exe (32-bit Windows GUI) from the C sources.
#
# No Delphi and no Visual Studio needed - the build uses zig as a drop-in
# C compiler with the bundled mingw-w64 headers and import libraries:
#
#   pip install ziglang            (or download zig from ziglang.org)
#   ./build.sh                     -> ../PandoraLauncher.exe
#
# On Windows the same command works from Git Bash / WSL:
#   python -m ziglang cc ...       (see the command below)
#
# Optional environment variables:
#   ZIG="python3 -m ziglang"   how to call zig (default: python3 -m ziglang, or
#                              plain `zig` when it is on PATH)
#   OUT=...                    output .exe path
set -euo pipefail

cd "$(dirname "$0")"

if [ -z "${ZIG:-}" ]; then
  if command -v zig >/dev/null 2>&1; then
    ZIG="zig"
  else
    ZIG="python3 -m ziglang"
  fi
fi

OUT="${OUT:-../PandoraLauncher.exe}"

CC_OPTS=(
  -target x86-windows-gnu
  -std=c99
  -Os
  -Wall
  -Wextra
  -Wno-unused-parameter
  -DUNICODE
  -D_UNICODE
  -ffunction-sections
  -fdata-sections
  -I.
  -Isrc
  -Itests
)

LIBS=(
  -lwinhttp -lcomctl32 -lshell32 -lversion -ladvapi32 -luser32 -lgdi32 -lole32
)

SOURCES=(
  util.c json.c inflate.c zip.c fs.c url.c
  http.c webauthn.c update.c ui.c main.c
  tests/selftest.c
)

echo "==> compiling the icon/version resources"
$ZIG rc /fo app.res app.rc

echo "==> compiling and linking $OUT"
$ZIG cc "${CC_OPTS[@]}" \
  "${SOURCES[@]}" app.res \
  -Wl,--subsystem,windows \
  -Wl,--gc-sections \
  -s \
  -o "$OUT" \
  "${LIBS[@]}"

echo "==> done"
ls -la "$OUT"
