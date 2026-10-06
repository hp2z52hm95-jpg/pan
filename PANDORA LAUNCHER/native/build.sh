#!/bin/sh
# ======================================================================
#  build.sh - cross-compile PandoraLauncher.exe from Linux/macOS
#
#  Toolchains (first one found wins):
#    1. zig        ->  pip install ziglang     (no root needed)
#                      `zig cc` builds Windows PE files out of the box and
#                      `zig rc` compiles the icon/manifest resources
#    2. MinGW-w64  ->  apt install mingw-w64   (win32 threads)
#
#  Usage:  sh build.sh [32|64] [dist]
#                32 = default, runs on every Windows
#                dist = also copy the exe next to the Delphi sources
#                       (PANDORA LAUNCHER/PandoraLauncher.exe) and refresh
#                       the .sha256 file - that is the shipped launcher
#
#  Output: PandoraLauncher.exe in this folder, ready to copy next to
#          PandoraTool.exe together with a launcher.ini.
# ======================================================================
set -e
cd "$(dirname "$0")"

ARCH="${1:-32}"
case "$ARCH" in
  32|86|x86)    TARGET=x86-windows-gnu ;;
  64|x64|amd64) TARGET=x86_64-windows-gnu ;;
  *) echo "usage: sh build.sh [32|64]"; exit 2 ;;
esac

find_zig() {
  if command -v zig >/dev/null 2>&1; then command -v zig; return; fi
  for p in "$HOME/.local/bin/zig" /usr/local/bin/zig /opt/zig/zig; do
    [ -x "$p" ] && { echo "$p"; return; }
  done
  p=$(python3 -c 'import os,ziglang;print(os.path.join(os.path.dirname(ziglang.__file__),"zig"))' 2>/dev/null || true)
  [ -n "$p" ] && [ -x "$p" ] && { echo "$p"; return; }
  echo ""
}

ZIG=$(find_zig)
LIBS="-lwinhttp -lcomctl32 -lversion -lshell32 -luser32 -lgdi32 -ladvapi32"
CFLAGS="-std=c99 -O2 -Wall -Wextra -DUNICODE -D_UNICODE"

echo "=== Pandora Launcher build ($TARGET) ==="

# --- 1. resources (icon + manifest + version info) --------------------
DIST=0
for a in "$@"; do
  [ "$a" = "dist" ] && DIST=1
done

rm -f launcher.res launcher_res.o
RES=""
if [ -n "$ZIG" ]; then
  "$ZIG" rc launcher.rc launcher.res
  RES=launcher.res
elif command -v windres >/dev/null 2>&1; then
  windres launcher.rc -O coff -o launcher_res.o
  RES=launcher_res.o
else
  echo "WARNING: no resource compiler (zig rc / windres) - building without icon/manifest"
fi

# --- 2. compile + link -------------------------------------------------
if [ -n "$ZIG" ]; then
  echo "Using zig cc ($("$ZIG" version))"
  "$ZIG" cc -target "$TARGET" $CFLAGS -Wl,--subsystem,windows \
      -o PandoraLauncher.exe launcher.c util.c $RES $LIBS
elif [ "$ARCH" = "64" ] && command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
  echo "Using x86_64-w64-mingw32-gcc"
  x86_64-w64-mingw32-gcc $CFLAGS -Wl,--subsystem,windows \
      -o PandoraLauncher.exe launcher.c util.c $RES $LIBS
elif command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
  echo "Using i686-w64-mingw32-gcc"
  i686-w64-mingw32-gcc $CFLAGS -Wl,--subsystem,windows \
      -o PandoraLauncher.exe launcher.c util.c $RES $LIBS
else
  echo "ERROR: no cross compiler found."
  echo "       Install zig (pip install ziglang) or mingw-w64, then rerun."
  exit 1
fi

rm -f $RES
echo
echo "BUILD OK: $(pwd)/PandoraLauncher.exe"
ls -l PandoraLauncher.exe

if [ "$DIST" = "1" ]; then
  # Ship it: the committed launcher lives next to the Delphi sources.
  cp PandoraLauncher.exe ../PandoraLauncher.exe
  ( cd .. && python3 -c "
import hashlib
h = hashlib.sha256(open('PandoraLauncher.exe','rb').read()).hexdigest()
open('PandoraLauncher.exe.sha256','w').write(h + '  PandoraLauncher.exe\n')
print('sha256', h)
" )
  echo "Copied to $(cd .. && pwd)/PandoraLauncher.exe"
fi
