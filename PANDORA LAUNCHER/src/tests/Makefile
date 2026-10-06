# Host tests for the launcher.
#
# Runs the same checks that PandoraLauncher.exe --self-test runs (SHA-256,
# base64url, version compare, launcher.ini, JSON, DEFLATE, ZIP, paths, URLs)
# plus a byte-for-byte comparison of the extracted fixture package against
# fixtures/tree.
#
#   make -C "PANDORA LAUNCHER/src/tests"        # build + run
#   make -C "PANDORA LAUNCHER/src/tests" clean
#
# The fixtures are committed and can be rebuilt with:
#   python3 "PANDORA LAUNCHER/src/tools/make-fixtures.py"

CC      ?= cc
CFLAGS  ?= -std=c99 -Wall -Wextra -O1 -g
CPPFLAGS?= -I.. -I.

SOURCES = ../util.c ../json.c ../inflate.c ../fs.c ../url.c ../zip.c selftest.c run.c
BIN     = pandora-tests

all: check

check: $(BIN)
	./$(BIN) fixtures/tree fixtures/packages.zip

$(BIN): $(SOURCES) ../pandora.h selftest.c run.c testzip.h expected.h deflate.h hostilezip.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $(BIN) $(SOURCES)

clean:
	rm -f $(BIN)
	rm -rf fixtures/tree.extracted

.PHONY: all check clean
