#!/bin/sh
# run_tests.sh - build and run the portable launcher-core unit tests.
#
# Creates a scratch dir with realistic ZIP packages (stored + deflated),
# then builds tests/test_util.c with the host compiler and runs it.
#
# Usage: sh tests/run_tests.sh [cc]

set -e

CC="${1:-${CC:-cc}}"
HERE=$(cd "$(dirname "$0")" && pwd)
BUILD="$HERE/build"

rm -rf "$BUILD"
mkdir -p "$BUILD/ref" "$BUILD/pkg"

echo "== creating test fixtures =="
python3 - "$BUILD" <<'PY'
import hashlib, os, random, sys, zipfile

build = sys.argv[1]
ref = os.path.join(build, "ref")

# A ~2 MiB stand-in for PandoraTool.exe (compressible, so deflate matters)
random.seed(1234)
payload = bytearray()
while len(payload) < 2 * 1024 * 1024:
    payload += b"PANDORA-TOOL-PAYLOAD-" + bytes(random.getrandbits(8) % 32 + 65 for _ in range(48))
payload = bytes(payload)
open(os.path.join(ref, "PandoraTool.exe"), "wb").write(payload)
open(os.path.join(ref, "PandoraTool.exe.sha256"), "w").write(
    hashlib.sha256(payload).hexdigest() + "\n")

# store.zip: kind = stored (method 0), like a "no recompression" package
with zipfile.ZipFile(os.path.join(build, "store.zip"), "w", zipfile.ZIP_STORED) as z:
    z.writestr("PandoraTool.exe", b"PANDORA-TOOL-STORE-PAYLOAD")
    z.writestr("MetaCore.dll", b"stub dll for the updater test")
    z.writestr("README.txt", b"readme\n")

# deflate.zip: kind = deflate (method 8), several entries incl. nested dirs
with zipfile.ZipFile(os.path.join(build, "deflate.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("PandoraTool.exe", payload)
    z.writestr("MetaCore.dll", b"stub dll for the updater test\n" * 200)
    z.writestr("sub/dir/deep.txt", b"deep file inside a subdirectory\n")
    z.writestr("passkey_test/server/x.txt", b"nested path with a second level\n")
print("fixtures written to", build)
PY

echo "== compiling test binary =="
"$CC" -std=c99 -O2 -Wall -Wextra -o "$BUILD/test_util" "$HERE/test_util.c" "$HERE/../util.c"

echo "== running tests =="
"$BUILD/test_util" "$BUILD"
echo "ALL TESTS PASSED"
