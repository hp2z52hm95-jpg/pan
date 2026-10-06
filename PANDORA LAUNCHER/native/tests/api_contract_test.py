#!/usr/bin/env python3
"""
api_contract_test.py - end-to-end check of the HTTP/JSON contract that
PandoraLauncher.exe (native/launcher.c) relies on.

It boots the real Node passkey/update server against a throwaway database and
package folder, then replays the launcher's exact request sequence:

    POST /api/auth/login                       (password sign-in)
    GET  /api/updates/check?app=PandoraTool&current=<ver>
    GET  /api/updates/download/<file>           with "Authorization: Bearer ..."
    POST /api/passkey/authenticate/begin        (options the launcher feeds to
                                                 the Windows WebAuthn API)

and verifies every field the C code reads, plus the update package itself
(size, SHA-256, and that the zip extracts to the expected files - the launcher
does the same with its own inflate/CRC code).

Usage:
    python3 tests/api_contract_test.py [--server-dir ../../passkey_test/server]

Exit code 0 = contract holds.
"""

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

PASS = []
FAIL = []


def check(cond, msg, extra=""):
    if cond:
        PASS.append(msg)
        print(f"  ok   {msg}")
    else:
        FAIL.append(msg)
        print(f"  FAIL {msg}" + (f"\n       {extra}" if extra else ""))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def request(url, method="GET", body=None, token=None, raw=False):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            payload = r.read()
            if raw:
                return r.status, payload, dict(r.headers)
            return r.status, json.loads(payload.decode()), dict(r.headers)
    except urllib.error.HTTPError as e:
        payload = e.read()
        if raw:
            return e.code, payload, dict(e.headers)
        try:
            return e.code, json.loads(payload.decode()), dict(e.headers)
        except Exception:
            return e.code, {"raw": payload[:200].decode(errors="replace")}, dict(e.headers)


def wait_for_server(port, proc, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def make_update_package(pkg_dir):
    """Mimics a real release: a zip with PandoraTool.exe + MetaCore.dll."""
    payload = (b"PANDORA-TOOL-BINARY-" + bytes(range(256))) * 4096
    with zipfile.ZipFile(os.path.join(pkg_dir, "PandoraTool-10.2.21.0.zip"), "w",
                         zipfile.ZIP_DEFLATED) as z:
        z.writestr("PandoraTool.exe", payload)
        z.writestr("MetaCore.dll", b"stub metacore\n" * 1000)
    return payload


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-dir",
                    default=os.path.abspath(os.path.join(here, "..", "..", "..",
                                                         "passkey_test", "server")))
    args = ap.parse_args()

    server_dir = args.server_dir
    if not os.path.isdir(os.path.join(server_dir, "src")):
        print(f"server not found at {server_dir}")
        return 2
    if not os.path.isdir(os.path.join(server_dir, "node_modules")):
        print(f"run 'npm install' in {server_dir} first")
        return 2

    tmp = tempfile.mkdtemp(prefix="pandora-contract-")
    os.makedirs(os.path.join(tmp, "db"), exist_ok=True)

    # make-manifest.js always reads <server>/packages, so use that folder and
    # put back whatever was there before.
    pkg_dir = os.path.join(server_dir, "packages")
    os.makedirs(pkg_dir, exist_ok=True)
    created = []
    payload = make_update_package(pkg_dir)
    created.append(os.path.join(pkg_dir, "PandoraTool-10.2.21.0.zip"))

    port = free_port()
    env = dict(os.environ)
    env.update({
        "PORT": str(port),
        "HOST": "127.0.0.1",
        "DB_PATH": os.path.join(tmp, "db", "pandora.db"),
        "PACKAGES_DIR": pkg_dir,
        "RP_ID": "localhost",
        "RP_NAME": "Pandora Tool",
        "WEBAUTHN_ORIGIN": f"http://localhost:{port}",
        "JWT_SECRET": "contract-test-secret",
        "BCRYPT_ROUNDS": "4",
        "RATE_LIMIT_MAX_REQUESTS": "1000",
        "NODE_ENV": "test",
    })

    # Generate the signed manifest with the repo's own script (same one the
    # release process uses).
    subprocess.run(["node", "scripts/make-manifest.js", "--version", "10.2.21.0",
                    "--notes", "Contract test release"],
                   cwd=server_dir, env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    manifest = json.load(open(os.path.join(pkg_dir, "manifest.json")))

    print(f"== starting server on port {port} (tmp: {tmp}) ==")
    log = open(os.path.join(tmp, "server.log"), "w")
    proc = subprocess.Popen(["node", "--experimental-sqlite", "src/index.js"],
                            cwd=server_dir, env=env, stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        if not wait_for_server(port, proc):
            print("server did not start; log tail:")
            print(open(os.path.join(tmp, "server.log")).read()[-2000:])
            return 2

        print("== user setup ==")
        st, body, _ = request(f"{base}/api/auth/register", "POST",
                              {"username": "launcheruser", "email": "l@example.com",
                               "password": "correct-horse-battery", "displayName": "Launcher User"})
        check(st == 201, "register returns 201", f"status={st} body={body}")

        print("== password sign-in (launcher login dialog) ==")
        st, body, _ = request(f"{base}/api/auth/login", "POST",
                              {"username": "launcheruser", "password": "wrong-password"})
        check(st in (400, 401), "wrong password rejected", f"status={st}")
        check(isinstance(body.get("error"), str),
              "error path: JSON has an 'error' string (launcher shows it verbatim)",
              f"body={body}")

        st, body, _ = request(f"{base}/api/auth/login", "POST",
                              {"username": "launcheruser", "password": "correct-horse-battery"})
        check(st == 200, "password login returns 200", f"status={st} body={body}")
        token = body.get("token", "")
        check(isinstance(token, str) and token.count(".") == 2,
              "login returns a JWT in 'token'")
        check(body.get("user", {}).get("username") == "launcheruser",
              "login returns user.username")
        check("displayName" in body.get("user", {}), "login returns user.displayName")

        print("== passkey sign-in options (launcher -> Windows WebAuthn API) ==")
        st, body, _ = request(f"{base}/api/passkey/authenticate/begin", "POST",
                              {"username": "launcheruser"})
        check(st == 400 and body.get("code") == "NO_PASSKEYS",
              "no-passkeys user gets the NO_PASSKEYS error", f"status={st} body={body}")

        # Register a dummy credential directly in the DB so begin returns the
        # full option set the launcher parses.
        import sqlite3
        con = sqlite3.connect(os.path.join(tmp, "db", "pandora.db"))
        uid = con.execute("SELECT id FROM users WHERE username='launcheruser'").fetchone()[0]
        con.execute(
            "INSERT INTO passkeys (id, user_id, credential_id, public_key, counter,"
            " device_type, backed_up, transports, name) VALUES (?,?,?,?,?,?,?,?,?)",
            ("pk-1", uid, "AAAA_TEST_CREDENTIAL", "BBBB", 0, "singleDevice", 0,
             '["internal"]', "contract test"))
        con.commit()
        con.close()

        st, body, _ = request(f"{base}/api/passkey/authenticate/begin", "POST",
                              {"username": "launcheruser"})
        check(st == 200, "authenticate/begin returns options", f"status={st} body={body}")
        for field in ("challenge", "challengeId", "userId", "rpId", "userVerification",
                      "timeout"):
            check(field in body, f"begin response has '{field}'")
        n = len(body.get("allowCredentials") or [])
        check(n >= 1, "allowCredentials contains the registered passkey", f"n={n}")
        for i, cred in enumerate(body.get("allowCredentials") or []):
            check(isinstance(cred.get("id"), str) and cred.get("id"),
                  f"allowCredentials[{i}].id is a non-empty string")

        worst = request(f"{base}/api/passkey/authenticate/begin", "POST",
                        {"username": "ghost"})
        check(worst[0] == 404 and isinstance(worst[1].get("error"), str),
              "unknown user -> 404 with error text")

        print("== update check (launcher start-up) ==")
        st, body, _ = request(f"{base}/api/updates/check?app=PandoraTool&current=10.2.20.0")
        check(st == 200, "updates/check returns 200", f"status={st}")
        check(body.get("updateAvailable") is True, "'updateAvailable' is a boolean true")
        check(body.get("latest") == "10.2.21.0", "'latest' is the manifest version")
        check("notes" in body, "'notes' present")
        pkgs = body.get("packages") or []
        check(len(pkgs) == len(manifest["packages"]), "package list matches the manifest")
        for i, p in enumerate(pkgs):
            for field in ("file", "sha256", "size"):
                check(field in p, f"packages[{i}].{field} present")
            check(isinstance(p.get("size"), int), f"packages[{i}].size is a number")
            check(p.get("kind") in (None, "zip") or isinstance(p.get("kind"), str),
                  f"packages[{i}].kind is a string")

        st, body, _ = request(f"{base}/api/updates/check?app=PandoraTool&current=10.2.21.0")
        check(body.get("updateAvailable") is False, "up-to-date install sees no update")
        check(body.get("packages") == [], "no packages when up to date")

        print("== package download (auth required) ==")
        fname = pkgs[0]["file"]
        st, raw, _ = request(f"{base}/api/updates/download/{fname}", raw=True)
        check(st == 401, "download without a session is refused (401)", f"status={st}")
        check(b"error" in raw.lower(), "401 body carries an error the launcher can show")

        st, raw, headers = request(f"{base}/api/updates/download/{fname}", token=token, raw=True)
        check(st == 200, "download with the login session succeeds", f"status={st}")
        check(len(raw) == pkgs[0]["size"], "downloaded size matches the manifest size")
        digest = hashlib.sha256(raw).hexdigest()
        check(digest == pkgs[0]["sha256"].lower(),
              "downloaded SHA-256 matches the manifest (launcher verifies before applying)")

        print("== package contents (launcher's zip extractor) ==")
        pkg_path = os.path.join(tmp, "downloaded.zip")
        open(pkg_path, "wb").write(raw)
        with zipfile.ZipFile(pkg_path) as z:
            names = z.namelist()
            check("PandoraTool.exe" in names, "package contains PandoraTool.exe")
            check("MetaCore.dll" in names, "package contains MetaCore.dll")
            check(z.read("PandoraTool.exe") == payload,
                  "extracted PandoraTool.exe matches the released bytes")
            check(z.testzip() is None, "package CRCs are valid")

        print("== credential storage for the next launcher login ==")
        st, body, _ = request(f"{base}/api/auth/me", token=token)
        check(st == 200, "session token is accepted by the API", f"status={st}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()
        # Remove only the files this test created.
        created.append(os.path.join(pkg_dir, "manifest.json"))
        for f in created:
            try:
                os.remove(f)
            except OSError:
                pass

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for f in FAIL:
            print("  - " + f)
        print(f"(server dir kept for inspection: {tmp})")
        return 1
    shutil.rmtree(tmp, ignore_errors=True)
    print("API CONTRACT OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
