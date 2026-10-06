# Pandora Tool — How Login / Approval Works, and How to Make a Login Bypass Useless

**Repository:** `hp2z52hm95-jpg/pan`
**Analysis date:** 2026-10-06
**Inputs used:** `Languages/*.json` (639 GUI strings + 2,952 log strings, English keys), the PE headers of `PandoraTool.exe` / `PandoraUpdater.exe`, the three SQLite databases, `Data/DA/*`, `unins000.dat`, and the earlier `REVERSE_ENGINEERING_REPORT.md` / `RE_work/DEEP_REFERENCE.md`.

**Scope / boundary:** this document explains *how the protection is built* and *how to make it stronger*. It contains **no** bypass recipe, no key recovery, and no patched-client instructions. The interesting engineering question here is not "how do I remove the login form", it is "**why does removing the login form not open the application** — and how do I guarantee that stays true".

---

## PART 0 — QUICK ANSWERS

| Your question | Short answer |
|---|---|
| Is it a compiled program? | **Yes.** Native 32-bit Windows PE, written in **Delphi (Object Pascal)** with the VCL GUI. There is no source code in this repo — only the finished binaries. |
| Does it connect to a database? | **Yes, but locally.** It ships **three SQLite databases** (firmware catalog, EMI/DRAM table, encrypted model catalog) that it reads with `sqlite3.dll`. **These databases do not contain accounts, passwords, or licenses** — no such table exists in any of them. |
| Where does "login / approve" happen? | **On Pandora's remote server over HTTPS** (WinHTTP/WinINet), and additionally on the **hardware BOX/CARD** (which performs ECDH + nonce/hash authentication). The local SQLite DBs are *content*, not *authority*. |
| Does the login page protect the app? | **No — and it was never designed to.** The login form is a *router*; the real locks are (a) per-operation server sessions, (b) server-issued signed loaders/keys, (c) the model-DB decryption key, (d) the BOX's challenge–response. |
| So if someone deletes the login page, is everything open? | **No — most of the app dies, but not all of it.** Evidence: the program's own log strings (`Not signed in: cannot decrypt models DB`, `Operation refused: session is not authorized`, `No authenticated server session (neither online nor box)`, `Job id not found`, `Loader link received` …). See Part 5 for the exact "what still works" analysis, and Part 6 for the remaining holes. |
| What is the correct defence? | **Never put authority in the client.** The client must only ever *relay* an authorisation that it cannot compute itself: server-signed short-lived operation tokens, keys the client never stores, and a hardware challenge–response. Full blueprint in **Part 6**. |

---

## PART 1 — WHAT KIND OF PROGRAM THIS IS (COMPILED, AND HOW WE KNOW)

### 1.1 Facts measured directly from the binary

| Measurement | Result | What it means |
|---|---|---|
| PE machine | `0x014C` | 32-bit x86 Windows executable |
| Section layout | `.text .itext .data .bss .idata .didata .edata .tls .rdata` **all with `raw size = 0`**, then `.upx0` (19.7 MB, empty), `.upx1` (1.5 KB), `.upx2` (29.2 MB of data) | Classic **packer layout**: the real code/data sections exist in the header but have no bytes on disk; everything lives inside the packer sections |
| Entropy of `.upx2` | **8.000** (maximum) for the first ~21 MB | The payload is **encrypted**, not merely compressed (compressed Delphi code would be ~6.5–7.3) |
| `UPX!` magic | **Not present anywhere in the file** | It is a modified/hardened UPX-style packer, or the magic was deliberately wiped so a stock `upx -d` refuses to unpack it |
| Import table | Valid, but **exactly 1 function per DLL** for 30 DLLs (`kernel32.dll → GetVersion`, `wininet.dll → InternetCloseHandle`, `bcrypt.dll → BCryptGenRandom`, `winscard.dll → SCardIsValidContext`, `MetaCore.dll → SP_META_NVRAM_Init_rW`, …) | Authentic packer behaviour: the loader resolves the *real* imports at runtime through `GetProcAddress`; the on-disk table is a shim |
| `.rsrc` | Intact (manifest + 16 icons, ~74 KB) | Resources are not compressed — ordinary for this packer layout |
| Internal module name | `PND.RELEASE.exe` (found in the packer stub area) | The original build artefact name |
| Compiler | Delphi, VCL, `Vcl.Themes`, `System.JSON`, PerMonitorV2 DPI, `requireAdministrator` | Delphi VCL app; **not** .NET, not C++, not Electron |

**Consequence for this analysis:** because the body is encrypted at entropy 8.0, the login code itself **cannot be read statically**. Everything below is reconstructed from hard, readable evidence: the app's own **UI strings**, its own **log lines** (2,952 of them — these are the program's own internal event names, and they are extremely revealing), the **import table**, and the **database schemas**. Where something is an inference it is marked *(inferred)*.

### 1.2 The packer already tells you the authors' security posture
Two conclusions worth keeping in mind for Part 6:

1. They **already** pack + encrypt the EXE and strip the packer magic. That raises the cost of *static* analysis, but it does **not** stop a determined person from patching the running program (they patch the *decision*, not the *crypto*).
2. Packing protects **secrets in the binary**, not **logic**. This is the core lesson for the hardening plan.

---

## PART 2 — THE DATABASES: WHAT THEY ARE, AND WHAT THEY ARE **NOT**

The application uses `sqlite3.dll` (SQLite 3.30.1) and ships three databases:

| File | Real format | Tables (verified) | Purpose | Does it gate access? |
|---|---|---|---|---|
| `Firmwares.db3` | SQLite | `Files`, `Version` | Catalog of 7,307 stock firmware archives on Pandora's servers (name, size, hits, active/new flags) | **No** |
| `emi_base.db3` | SQLite | `EmiInfo`, `meta` | 29,941 EMI/DRAM initialisation records (eMMC ID + memory type + binary blob) used when bringing a phone up in BROM mode | **No** |
| `models.mdb` | **SQLite** (despite the `.mdb` extension) | `db_meta`, `models` (11,652 rows), `catalogs` (6 rows) | The brand/model tree plus **per-model payloads** that describe protocol parameters, which loader to use, whether device auth bypass is needed, and which operations are allowed | **Yes — it is encrypted with a key that is only issued after sign-in** |

### 2.1 The crucial detail

`models.mdb` metadata is self-describing:

```
db_meta:  db_version=1
          payload_crypto   = soft_magic_v1     ← per-model payloads
          catalog_crypto   = aes_softkey_v1    ← per-platform catalogs
          crypto_migrated_at = 1780377062
```

* Every one of the 11,652 `models.payload` blobs starts with the magic `PNDMODEL1` followed by high-entropy data.
* Every `catalogs.data` blob starts with `PNDCAT01` (AES).
* The app's own log line: **`Not signed in: cannot decrypt models DB`**.

**This is the single most important architectural fact in this repository:**

> The phone-model intelligence (how to talk to each model, which loader, which operation is allowed) is **encrypted at rest**, and the key is **not in the binary** — it is obtained from the server after a successful sign-in (or from the BOX in offline mode).

That is what turns the login form from "a screen you can delete" into "the door you cannot walk past without the key". A person who patches away the login form still holds 11,652 opaque blobs.

### 2.2 And the negative evidence

None of the three databases contains a table for **accounts, users, passwords, sessions, licenses, activations, or credits**. Search the schemas yourself — they are printed in the appendix. The strings `Could not create activation (DB error)`, `Renewal activation id was not found in activations`, `Could not find the associated credit account`, `Job id not found` all describe **server-side** database operations reported back to the client. **The accounts live on Pandora's server, not on your PC.** That is good design and it is the reason the login page is not the real security boundary.

---

## PART 3 — THE GATE CHAIN (STARTUP ORDER AND WHO CAN SAY "YES")

### 3.1 The gates, reconstructed from the app's own strings

```
  PandoraTool.exe starts (packer decrypts body, Administrator)
        │
        ├─(1) EULA gate ................. "Checking EULA..."  "Confirming EULA..."
        │        • EULA text is downloaded/verified: "EULA URL is missing",
        │          "EULA checksum mismatch", "EULA version mismatch",
        │          "Cannot verify saved EULA text", "saved data verification failed"
        │        • Result is stored as signed/verifiable local state
        │          ("Cannot build EULA acceptance JSON", "Cannot write EULA state: %s")
        │
        ├─(2) BOX / CARD presence gate ... "Checking Box..."  "Box connected"
        │        • "Box not found", "Box SN is empty", "Card not activated",
        │          "Card verification failed", "Activation card removed.
        │           The application will now close."
        │        • Cryptographic, not cosmetic: "Box: authentication error (hash
        │          mismatch)", "ECDH gen (box)", "ECDH compute (box)",
        │          "Box: client nonce repeated", "CryptNonceByCard failed"
        │
        ├─(3) Sign-in gate ............... "Sign in" / "Enter login and password"
        │        • Server call: "Login successful" / "Login or password is incorrect"
        │          "Login is banned", "IP banned", "Login server error %d"
        │        • Credentials are protected in transit: "Could not decrypt login
        │          data", "Failed to RSA-encrypt session data", "Could not load RSA key"
        │        • Email verification + reset-code flow:
        │          "We've sent a 6-digit verification code to %s."
        │        • The server returns a **session**: "Missing session_id field",
        │          "Could not increase session counter", "Session lifetime expired,
        │          please login again", "Portal token received"
        │
        ├─(4) Activation / binding gate .. "Activate BOX", "Linking card...",
        │        "This computer is not linked to the account. Link it now?",
        │        "Your BOX already binded to another CARD",
        │        "Card fingerprint does not match the one generated by the server",
        │        "Activation period has expired at %s", "Box is banned"
        │        → binds: account ↔ box SN ↔ card SN ↔ machine fingerprint
        │
        ├─(5) Content unlock ............. "Activated. Restarting..."
        │        • models DB decrypts, platform engines become usable
        │
        └─(6) Per-operation gate ......... EVERY privileged action, again:
                 "Operation refused: session is not authorized"
                 "No authenticated server session (neither online nor box)"
                 "Response missing operation/job_id"   → "Job started" / "Job finished"
                 "You do not have enough credits"      → "Credits info received"
                 "Loader link received" / "Server loader not found: %s"
                 "VIP: signed hash authentication failed"
```

### 3.2 What the strings prove about the *approval* model

This is not "log in once, then the app is trusted". It is a **leased, per-operation authorisation** model:

| Mechanism | Evidence strings | Meaning |
|---|---|---|
| **Job / lease per operation** | `Job started`, `Job finished`, `No active job`, `Job id is used by another login`, `Online job finish skipped: no active job`, `Response missing operation/job_id` | The server *opens a job* and returns an id; the operation is tied to that job. This is an "approval" in the literal sense. |
| **Session, not boolean** | `Operation refused: session is not authorized`, `No authenticated server session (neither online nor box)`, `Session lifetime expired, please login again`, `Could not update session data` | The client holds a *session*, with a server-side lifetime and counter. |
| **Quota / credits** | `Credits`, `Read Codes (credits)`, `Unlock Network (credits)`, `Could not get remaining changes for the current quarter`, `Response missing left_credits field` | Metered features are checked against the server balance, not a local counter. |
| **Server-issued binaries** | `Loader link received`, `Cannot get loader link: %s`, `Server loader not found: %s`, `MTK server loader link: %s`, `Discarded stale loader cache` | The DA/preloader needed for the work is fetched per session, not taken from disk forever. |
| **Signed data** | `VIP: signed hash authentication failed`, `SLA bypass: no key for brand [%s], skipped`, `%s HMAC key unavailable (HRID missing)`, `Server proof (M2) verification failed`, `ECDH handshake exception: %s` | The server/BOX signs things; the client verifies. This is the part a patched client cannot forge. |
| **Hardware authority** | `ECDH gen (box)`, `ECDH compute (box)`, `Box: could not create a new session`, `Box: session not found`, `No server session available for "%s" (not logged in, box server unavailable)`, `Not logged in and box server is not authenticated` | The BOX is an **offline authorisation authority** with its own sessions and a shared secret — that is why the tool works without internet. |
| **Revocation** | `Box is banned`, `Login is banned`, `IP banned`, `Too many activation code entry attempts, please try again in 24 hours` | Authority can be withdrawn remotely. |
| **Bound identity** | `This computer is not linked to the account. Link it now?`, `Machine fingerprint is empty`, `Fingerprint can be changed after %s`, `No more attempts to change fingerprint`, `Card fingerprint does not match the one generated by the server` | The licence is bound to account + box + card + machine, with limits on changes. |

---

## PART 4 — THE FOUR AUTHORITIES (WHO ACTUALLY DECIDES)

This is the mental model to keep. There are four places a "yes" can come from, in descending order of strength:

| # | Authority | Where it lives | Can a client patch defeat it? | Evidence |
|---|---|---|---|---|
| 1 | **Remote server (HTTPS)** | Pandora's servers | **No.** The client can lie to itself, but the server will not issue the job id / loader link / credits / session it needs. | `No server session available for "%s"`, `Operation refused: session is not authorized`, `Server returned error: %s`, `No online session` |
| 2 | **Hardware BOX / CARD** | USB dongle with its own firmware and secrets | **No** (only spoofing the hardware could, which is a much bigger attack). | `ECDH gen (box)`, `Box: authentication error (hash mismatch)`, `Box: client nonce repeated`, `Box decrypt failed (status=%d)` |
| 3 | **Local crypto (keys not in the binary)** | Server/BOX-issued keys unlocking `models.mdb`, `.crp` DAs, loaders, security blobs | **No**, as long as the key really is not in the binary or derivable from it. | `Not signed in: cannot decrypt models DB`, `FDL1: AES decrypt failed`, `Catalog cipher length invalid`, `%s HMAC key unavailable (HRID missing)` |
| 4 | **The GUI itself (login form, menus, buttons)** | Inside `PandoraTool.exe` | **Yes — trivially.** Any check made in the same process you control is patchable. | Everything in `Languages/*.json` `gui` section |

**The whole point of a well-built licensed tool is that layer 4 carries no authority.** It only *routes* the user to the work. If a feature can be unlocked by making the GUI skip a check, then that feature was never protected by layer 1, 2 or 3 — and that is a bug you can find and fix *before* someone else does.

---

## PART 5 — "IF SOMEONE REMOVES THE LOGIN PAGE, IS THE APP OPEN?"

### 5.1 What would still be blocked (because the lock is not the form)

| Feature | What blocks it even with a patched login form |
|---|---|
| Model selection / any per-model work | `models.mdb` payloads stay encrypted (`Not signed in: cannot decrypt models DB`) |
| Loading DA / preloader / FDL | `.crp` blobs are crypted and per-session loader links come from the server (`Cannot get loader link`) |
| Credits features (unlock network, read codes) | Server-side balance (`Response missing left_credits field`) |
| Anything needing an online job | `No active job`, `Job id not found` |
| Offline operation without a logged-in account | Only the BOX can authorise, and it authenticates cryptographically (`Not logged in and box server is not authenticated`) |
| Signed/hash-protected data flows | `VIP: signed hash authentication failed`, `%s HMAC key unavailable (HRID missing)` |

### 5.2 What would *not* be blocked (the real risk list)

These are the areas where a patched client would gain something, i.e. **where your own code decides locally instead of forwarding a decision**:

1. **Pure-local / cosmetic features** — UI, log views, file explorer over ADB, firmware browsing, `Firmwares.db3` browsing. Low value, unavoidable.
2. **Anything that reads a local flag** rather than asking the authority — e.g. if "is activated?" is a boolean in memory or a local file, all features behind that single boolean collapse at once. Strings like `Activation status %d`, `Cannot verify saved EULA text`, `saved data verification failed` suggest at least some *local* state exists; whichever feature trusts that state without re-asking the server is a hole.
3. **Client-side permission checks** — `Permissions`, `Permissions changed: %s`, `Invalid permissions value` show a permission set exists. If the client *enforces* those permissions itself for any operation, patching that one comparison unlocks it.
4. **Locally validated activation codes** — `Activation code failed local validation`, `Incorrect activation code`, `Too many activation code entry attempts` → there is an **offline activation-code** path. Any code path that is validated *entirely* on the client can be re-implemented by an attacker who studies the response format. (The 24-hour attempt limiter also lives locally, so it is patchable.)
5. **A configurable server address / API key** — `Server address not configured`, `API key not configured (fill the "API key" field on the form)`, `config.txt: %d byte(s), deflate mode %d`. If the endpoint is user-editable and the updater trusts what the "server" says, a patched client can point itself at a **fake server** that answers `done=1` to everything. This is the most dangerous class of hole because it neutralises authority #1 entirely.
6. **Trusting the update channel** — `PandoraUpdater.exe` runs `asInvoker` and applies downloaded files in place. If it does not verify signatures, a patched updater/rogue manifest is a delivery mechanism for a modified client.

### 5.3 The honest conclusion

> Removing the login form does **not** open the app — it breaks most of it, because the design already puts the "yes" in three places the patcher does not control (server, BOX, crypto keys).
>
> The residual risk is **not** the deleted form. It is **any single code path that decides "allowed" locally**. One such path = one free feature. Twenty such paths = a fully "open" application, reached without ever touching the login form.

That is the correct framing of your question, and it is exactly what Part 6 fixes.

---

## PART 6 — HARDENING BLUEPRINT: MAKING A LOGIN BYPASS WORTHLESS

### 6.1 The three principles

1. **The client proposes, the authority decides.** The client never computes "allowed"; it only *relays* a proof produced elsewhere (server signature / BOX response / secret key).
2. **Authorise the capability, not the user.** "Is user X allowed in?" is a Boolean an attacker can flip. "Here is a key/token that only the server can mint for *this* operation on *this* box for the next 120 seconds" is not.
3. **Every privileged path must be able to answer: "what does the attacker still not have if he patches this exact line?"** If the answer is "nothing", that path is unprotected.

### 6.2 Architecture rule #1 — a single choke point

Put one function between the GUI and every engine call, and make it impossible to reach the engines without it:

```
UI form / button
      │
      ▼
AuthorizationService.Authorize(Operation, Params)   ← ONE place only
      │   ├── check session (online or BOX), not an in-memory boolean
      │   ├── request/verify an operation token from the authority
      │   ├── bind token to: session_id, box SN, card SN, machine fingerprint,
      │   │                  operation id, hash(params), nonce, short expiry
      │   └── on failure → return error, never "continue anyway"
      ▼
Engine (MTK / SPRD / QCOM / …)   ← must refuse to run without a valid token object
```

Practical implementation details that make it bite:

* The engine APIs should **require** an authorisation object as a parameter (a value the caller cannot construct — a private-constructor class, or a handle the engine validates against a server-signed blob). If the engine can be called with `nil`/empty and still work, the choke point is decorative.
* Keep the "am I allowed" decision in **one module** and mark it as security-critical in code review, so a patch to that module is a single, detectable point.
* Never let a form compare strings/booleans for authority. Forms pass a request; the service decides.

### 6.3 Architecture rule #2 — server-signed, short-lived, operation-scoped tokens

Replace any "logged-in flag" with a token that the **server signs with a private key**, and the client **verifies with a public key**:

| Token field | Why it must be there |
|---|---|
| `session_id` | Ties the token to one signed-in session; the server can kill it. |
| `account_id`, `permissions[]` | Permissions come *from the server*, signed — so patching the client's permission table changes nothing. |
| `operation` + `hash(params)` | A token for "read info" cannot be replayed for "write IMEI" or for a different model/region. |
| `box_sn`, `card_sn`, `machine_fingerprint` | Stops token sharing between users/machines. |
| `nonce` (single use) + `issued_at` / `expires_at` (short, e.g. 2–10 min) | Kills replay. The app already has the vocabulary for this: `Nonce already exists`, `Box: client nonce repeated`. |
| `credits_cost` / `job_id` | Connects the authorisation to the server-side job and balance. |
| `signature` | The only part the attacker cannot produce. |

Client-side verification must be with an **embedded public key** (or a pinned server certificate), and the client must **fail closed** if verification fails.

### 6.4 Architecture rule #3 — the "signing oracle" pattern (the strongest single idea)

For every operation that the licence is supposed to sell, make the **server** do a piece of the work that cannot be faked locally. Concretely, these devices generally need one of:

* a **challenge-response signature** (server holds the private key; client relays the signature to the phone/BOX),
* a **key** (device auth key, NVRAM key, RPMB key, loader AES key),
* a **signed blob** (loader, preloader, security config, `auth_profiles`, model payload).

Your own strings show this pattern is already partly used: `SLA bypass: no key for brand [%s], skipped`, `Server loader not found: %s`, `MTK server loader link: %s`, `VIP: signed hash authentication failed`, `FDL1: AES decrypt failed`. **Push more of the tool into this category.** The test is simple:

> If I patch the client so that it always believes it is authorised, can I still complete this operation?
> If yes → the operation is unprotected, no matter how good the login screen is.

### 6.5 Architecture rule #4 — protect the payloads, not just the door

* `models.mdb`: keep the per-sign-in key **and** move from a "soft magic" obfuscation to **authenticated encryption** (AES-GCM or ChaCha20-Poly1305). A name like `soft_magic_v1` implies a reversible obfuscation/XOR-style scheme — the moment one user obtains the scheme, the whole 11,652-model catalog becomes readable and the client's remaining checks are the only barrier. Authenticated encryption also gives you tamper-detection (`Catalog PKCS7 padding invalid` is the current hint that the catalog format is hand-rolled; a MAC makes this robust).
* Loaders/DAs (`.crp`, `.da`, `preloader*.crp`): keep them AES-encrypted, decrypt only in memory, and — critically — **deliver them per session with a short validity**, as the strings already suggest (`Loader link received`, `Discarded stale loader cache`). A cached loader on disk is a loader an attacker can reuse forever.
* Local state files (EULA acceptance, fingerprint, activation cache, log): store them with a **MAC keyed by a secret the client does not have** (derived from the BOX via the existing ECDH/HMAC(HRID) path). Then `saved data verification failed` becomes a real wall instead of a self-check an attacker rewrites.

### 6.6 Architecture rule #5 — verify the *server*, not just the user

This closes the biggest hole listed in Part 5.2:

* **TLS with certificate pinning** (or public-key pinning) — the client must refuse a server whose key is not yours. Without pinning, a patched client + fake server + hosts-file entry can be crafted, and every "server-side" decision evaporates.
* **Mutual authentication**: client certificate and/or a signed challenge from the client, so your server knows it is talking to your client, and can rate-limit per box/account.
* **Sign every server response payload** (job id, loader link, credits, permissions) with a key the client verifies against an embedded public key. If the client accepts unsigned JSON, then whoever controls the endpoint controls the licence.
* **Do not expose a user-editable "server address" / "API key" in the shipped client.** If a build must have it (e.g. for internal/staging), gate it to a debug build, not the release binary.

### 6.7 Architecture rule #6 — offline mode must still be an authority

The BOX path is the correct model (`ECDH`, nonces, sessions, `Box is banned`). Keep these invariants:

* Offline authorisation **only** through the BOX, never through local files.
* Offline **time limits must be signed/box-derived**, not `Now()`. Detect clock rollback (monotonic counters, last-seen timestamps, `Could not get remaining changes for the current quarter` style server counters).
* Monotonic **session counter** kept server-side (the strings already hint at it: `Could not increase session counter`) — this is what makes state rollback detectable.
* Bind differently for online vs offline (`No authenticated server session (neither online nor box)`), and never fall back from "offline denied" to "allowed".

### 6.8 Architecture rule #7 — anti-tamper as **detection + revocation**, never as the wall

You already pack + encrypt the EXE and strip the packer magic. That is worth keeping, but treat it as a smoke detector, not a vault door:

* Self-integrity checks (hash of the code section, checksum of loaded modules), anti-debug checks, detection of patched jump instructions — but **only** to *report* and to *degrade*, not as the sole protection.
* Report tamper signals to the server with the session (`version`, `hash`, `box_sn`, `card_sn`, `machine_fingerprint`). The server then decides: warn, throttle, expire the session, ban the box (`Box is banned` already exists).
* Add a **kill switch**: patched-clients must not be able to keep talking to your API. Give each session a nonce/quorum the server can revoke, and require periodic re-authorisation so a stolen token dies quickly.
* Ship a **server-enforced minimum client version** (the strings `Server requires an update, but no newer update is available` show this exists — keep it and make it blocking for auth endpoints).

### 6.9 Architecture rule #8 — abuse detection and business rules

* Log every sign-in, activation, fingerprint change, job start/finish with box + card + machine + IP; alert on impossible patterns (same card, many machines; many accounts, one box; activation churn).
* Keep the existing limits and make them **server-side**: fingerprint change windows (`Fingerprint can be changed after %s` — the "after N days" must be evaluated on the server), attempt limits (`Too many activation code entry attempts` — the 24-hour lockout must be a server counter keyed to the account/box, not a local one), one-login-per-job (`Job id is used by another login`).
* Rate-limit and CAPTCHA-protect the login/reset endpoints; make e-mail reset codes single-use and short-lived.

### 6.10 Anti-pattern table (what a bypass normally targets)

| Anti-pattern | Why it is weak | Replace with |
|---|---|---|
| `if IsLoggedIn then EnableFeatures` | One boolean to patch | Per-operation signed token |
| Login form hidden/disabled after success | Cosmetic | Feature unreachable without a valid authorisation object |
| Permissions table held in the client | Attacker edits the table | Permissions inside the server-signed token |
| Local "activation" file / registry value | Attacker writes the file | Server-signed / BOX-MAC'd state, or nothing local at all |
| XOR / "soft magic" payload obfuscation | Scheme recovered once, catalog public forever | AES-GCM / ChaCha20-Poly1305 with per-session keys |
| Endpoint + API key in a config file | Fake server answers "allowed" | Pinned TLS + signed responses + embedded public key |
| Unpacked/unsigned updater applying files | Modified client delivered by the vendor's own updater | Signed manifest + signature verification + pinned download host |
| All checks at startup only | Session expiry and revocation never applied | Re-authorise per operation/job, short TTL, server-side counters |

### 6.11 Gate audit checklist (run this over the codebase)

For **every** feature that the licence sells or restricts, fill in one row:

| Question | Why |
|---|---|
| Where is the yes/no decided? (file + line) | Makes the attack surface explicit |
| Is the decision based on: session/list/Boolean/file, or a signed token? | The first group is patchable |
| What does the operation need that the client cannot compute? (key, signature, loader, credits) | If the answer is "nothing", it is unprotected |
| What happens if that check is removed by a patch — does anything else still refuse? | Defence in depth test |
| Is the request traceable to a server-side job/credit/quota? | Prevents free use |
| Is it logged (account/box/card/machine/version/IP)? | Enables detection and banning |

### 6.12 Red-team your own client (acceptance tests)

These are safe, self-directed tests to run on your **own** product to prove the design holds:

1. **Bypass simulation:** build a test client with the login form replaced by a "skip" button (in a controlled test build). Then attempt every paid operation. **Pass = every one of them fails** with a session/authority error, not a UI error.
2. **Fake server test:** point the client at a stub server that answers `done=1` to everything. **Pass = the client rejects the responses** (signature/pinning failure) — nothing unlocks.
3. **Key-absence test:** confirm by inspection that no key capable of decrypting `models.mdb`, loaders, or security blobs exists anywhere in the shipped tree (binary, DB, config, logs, temp files).
4. **Rollback test:** restore an old local state/DB snapshot and confirm the server/BOX notices the counter going backwards.
5. **Token replay test:** capture an operation token and replay it later / on another box / for another operation. **Pass = all three replays are refused.**
6. **Revocation test:** ban a test box/account mid-session and confirm the running client loses capability within the intended window.
7. **Time test:** move the system clock forward/back and confirm offline grace does not extend.
8. **Update test:** serve a modified manifest/file from a non-pinned host and confirm the updater refuses it.

Automate tests 1, 2, 4, 5, 7 in CI as "authorisation regression tests" — these are the tests that stop a future refactor from accidentally reintroducing a local-only check.

---

## PART 7 — WHAT CANNOT BE PROTECTED ON A WINDOWS PC (BE REALISTIC)

* Any decision made **inside** the client process can be patched, no matter how obfuscated or packed. Packing raises cost; it does not create safety.
* A determined attacker will always be able to unlock **cosmetic** and **data-browsing** features.
* The only durable protections are: (a) a **remote** authority, (b) **private keys the client never holds**, (c) a **hardware** element, (d) **authenticated encryption** of the valuable assets.
* Therefore the goal is not "nobody can patch my client". The goal is: **"patching my client gives them nothing they could not get anyway."**

---

## PART 8 — EVIDENCE APPENDIX

### 8.1 Where each conclusion came from

| Claim | Evidence |
|---|---|
| Delphi/VCL Win32, packed, encrypted body | PE section table (`raw=0` for all original sections + `.upx0/.upx1/.upx2`), `.upx2` entropy **8.000**, no `UPX!` magic, 1-function-per-DLL import shim, `PND.RELEASE.exe` string in the stub area |
| Uses SQLite databases | `sqlite3.dll` (3.30.1) shipped; three DBs open as SQLite with the schemas shown below |
| No accounts/licences stored locally | `models.mdb` = `db_meta, models, catalogs`; `Firmwares.db3` = `Files, Version`; `emi_base.db3` = `EmiInfo, meta`. No user/account/licence/activation/credit table anywhere |
| Model catalog is encrypted with a non-local key | `models.payload` = 11,652/11,652 blobs starting `PNDMODEL1`; `db_meta.payload_crypto = soft_magic_v1`, `catalog_crypto = aes_softkey_v1`; client log: `Not signed in: cannot decrypt models DB` |
| Server-authoritative sessions/jobs/credits | `No authenticated server session (neither online nor box)`, `Operation refused: session is not authorized`, `Job started/finished`, `No active job`, `Response missing left_credits field`, `Credits info received` |
| Hardware BOX is a crypto authority | `ECDH gen (box)`, `ECDH compute (box)`, `Box: client nonce repeated`, `Box: authentication error (hash mismatch)`, `No server session available for "%s" (not logged in, box server unavailable)` |
| EULA gate is verifiable state | `Checking EULA...`, `EULA checksum mismatch`, `Confirming EULA...`, `Cannot verify saved EULA text` |
| Local offline activation-code path exists | `Activation code failed local validation`, `Incorrect activation code`, `Too many activation code entry attempts, please try again in 24 hours`, `Activation period has expired at %s` |
| Server address / API key are configurable fields | `Server address not configured`, `API key not configured (fill the "API key" field on the form)`, `config.txt: %d byte(s), deflate mode %d` |
| Network stack | Imports: `winhttp.dll` (`WinHttpGetIEProxyConfigForCurrentUser`), `wininet.dll` (`InternetCloseHandle`), `bcrypt.dll` (`BCryptGenRandom`), `ncrypt.dll`, `iphlpapi.dll`, `netapi32.dll`; updater additionally uses `Reg*` registry APIs and file APIs (WinInet-based installer) |
| Crypto primitives in use | `AES init failed`, `Could not load RSA key`, `Failed to RSA-encrypt session data`, `ECDH handshake exception`, `%s HMAC key unavailable (HRID missing)`, `AES decrypt failed`, `Decrypt security...` |
| Installer / provenance | `unins000.dat` header `Inno Setup Uninstall Log (b)`, app name `Pandora Tool Ultra`, install path `D:\pandd\Pandora`, machine `DESKTOP-EIQ7K6O`, user `Ahmed`; distributed with .NET prerequisite checks |

### 8.2 Database schemas (verbatim, from `sqlite_master`)

```sql
-- models.mdb
CREATE TABLE models (id INTEGER PRIMARY KEY AUTOINCREMENT, brand TEXT NOT NULL,
    name TEXT NOT NULL, code_name TEXT, platform TEXT, cpu TEXT,
    payload BLOB NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE catalogs (platform TEXT PRIMARY KEY, data BLOB NOT NULL, json_mtime INTEGER NOT NULL);
-- db_meta: db_version=1, created_at=1777335075, payload_crypto=soft_magic_v1,
--          catalog_crypto=aes_softkey_v1, crypto_migrated_at=1780377062

-- Firmwares.db3
CREATE TABLE `Files` (id BIGINT PRIMARY KEY, file_name TEXT, file_size BIGINT DEFAULT 0,
    hits INTEGER DEFAULT 0, active TINYINT DEFAULT 1, new TINYINT DEFAULT 1,
    created_at TIMESTAMP, updated_at TIMESTAMP);
CREATE TABLE `Version` (id INTEGER PRIMARY KEY, ver TEXT);   -- '2026_02_19_05_00_07'

-- emi_base.db3
CREATE TABLE EmiInfo (id INTEGER PRIMARY KEY AUTOINCREMENT, version INTEGER NOT NULL,
    brand TEXT NOT NULL, model TEXT NOT NULL, emmc_id TEXT NOT NULL, sub_ver INTEGER,
    m_type INTEGER, id_len INTEGER, emi_crc INTEGER NOT NULL, data BLOB NOT NULL,
    data_size INTEGER NOT NULL, src_name TEXT, src_path TEXT, created INTEGER);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
```

### 8.3 How to reproduce the measurements

```bash
# PE facts + entropy of the packed section
python3 - <<'PY'
import pefile, collections, math
pe = pefile.PE('PandoraTool.exe')
for s in pe.sections:
    d = s.get_data() if s.SizeOfRawData else b''
    e = 0.0
    if d:
        c = collections.Counter(d); n = len(d)
        e = -sum((v/n) * math.log2(v/n) for v in c.values())
    print(s.Name.rstrip(b'\0').decode(), hex(s.Misc_VirtualSize), hex(s.SizeOfRawData), round(e, 3))
print('UPX! present:', b'UPX!' in open('PandoraTool.exe','rb').read())
PY

# UI + log vocabulary used throughout this document
python3 -c "import json;d=json.load(open('Languages/DEU.json'));print(len(d['gui']),'gui /',len(d['log']),'log strings')"
```

---

## PART 9 — BOUNDARY NOTE

This workspace deliberately does **not** recover `soft_magic_v1` / `aes_softkey_v1` keys, does not defeat the packer, and contains no instruction for removing, patching, or spoofing the login, activation, BOX or credit checks. The purpose here is architectural understanding and **defensive** design: to show that the login page is not (and must not be) the lock, and to describe what has to be true for a client-side bypass to remain worthless.
