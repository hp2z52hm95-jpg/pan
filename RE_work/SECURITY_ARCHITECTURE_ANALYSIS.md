# Pandora Tool — Security Architecture & Login Bypass Analysis

**Purpose:** Understand how the compiled program works, how it connects to
databases, how login/approval works, and **what happens if someone bypasses or
removes the login page** — would the entire app become open and unprotected?

---

## 1. HOW THE COMPILED PROGRAM WORKS (HIGH-LEVEL FLOW)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PandoraTool.exe STARTS                           │
│  (Delphi VCL Win32 app, UPX-packed, requires Administrator)         │
└─────────────────────────┬───────────────────────────────────────────┘
                          │
                          ▼
         ┌────────────────────────────────┐
         │  LAYER 1: HARDWARE CHECK       │  ← FIRST GATE
         │  ─────────────────────────────  │
         │  • Is Pandora BOX connected?   │  (Smart card / USB dongle)
         │  • Is Activation Card present? │  (Physical card with SN)
         │  • WinSCard API reads card     │
         │  • libusb detects BOX via USB  │
         │                                │
         │  FAIL → "Activation card       │
         │   removed. App will close."    │
         │  FAIL → "Box disconnected.     │
         │   App will close."             │
         └────────────┬───────────────────┘
                      │ PASS
                      ▼
         ┌────────────────────────────────┐
         │  LAYER 2: EULA CHECK           │  ← SECOND GATE
         │  ─────────────────────────────  │
         │  • Has user accepted EULA?     │
         │  • EULA version matches?       │
         │  • Checksum verified?          │
         │                                │
         │  FAIL → Show EULA dialog       │
         │  FAIL → "Cannot confirm EULA"  │
         └────────────┬───────────────────┘
                      │ PASS
                      ▼
         ┌────────────────────────────────┐
         │  LAYER 3: SERVER LOGIN         │  ← THIRD GATE
         │  ─────────────────────────────  │     (THIS IS THE LOGIN PAGE)
         │  • Login + Password (PND_xxx)  │
         │  • HTTPS to Pandora servers    │
         │  • WinInet API                 │
         │  • Server validates account    │
         │  • Returns session token       │
         │                                │
         │  FAIL → "Login failed"         │
         │  FAIL → "Sign in first"        │
         └────────────┬───────────────────┘
                      │ PASS
                      ▼
         ┌────────────────────────────────┐
         │  LAYER 4: ACTIVATION STATUS    │  ← FOURTH GATE
         │  ─────────────────────────────  │
         │  • BOX SN linked to account?   │
         │  • Card activated?             │
         │  • BOX not banned?             │
         │  • Activation valid?           │
         │  • Server confirms all of this │
         │                                │
         │  FAIL → "Box is banned"        │
         │  FAIL → "Card not activated"   │
         │  FAIL → "Activation missing"   │
         └────────────┬───────────────────┘
                      │ PASS
                      ▼
         ┌────────────────────────────────┐
         │  LAYER 5: MAIN APP UNLOCKED    │
         │  ─────────────────────────────  │
         │  GUI shows all operations      │
         │  BUT each operation ALSO       │
         │  checks authorization:         │
         │                                │
         │  • "Operation not authorized"  │
         │  • Credit balance check        │
         │  • Server-side validation      │
         │  • Per-operation permission    │
         └────────────────────────────────┘
```

---

## 2. HOW IT CONNECTS TO DATABASES

The program uses **3 local SQLite databases** + **1 remote server connection**:

### 2.1 Local Databases (via sqlite3.dll — direct C API calls from Delphi)

```
┌──────────────────────────────────────────────────────────────────┐
│  PandoraTool.exe                                                 │
│                                                                  │
│  sqlite3_open() ──→ emi_base.db3     (29,941 EMI/DRAM records)   │
│  sqlite3_open() ──→ Firmwares.db3    (7,307 firmware entries)    │
│  sqlite3_open() ──→ models.mdb       (11,652 phone models)       │
│                     ↑ ENCRYPTED with soft_magic_v1 + AES         │
│                     ↑ Key is INSIDE the compiled EXE binary      │
│                     ↑ Cannot be read without the EXE's key       │
└──────────────────────────────────────────────────────────────────┘
```

**Key point:** The `models.mdb` database is **encrypted**. The decryption key
is **hardcoded inside PandoraTool.exe** (called `soft_magic_v1` for model
payloads and `aes_softkey_v1` for catalogs). Without the running EXE to decrypt
it, the database is **unreadable garbage**.

### 2.2 Remote Server Connection (via WinInet HTTPS)

```
PandoraTool.exe ──HTTPS──→ Pandora Servers
                             │
                             ├── /api/login        (authenticate user)
                             ├── /api/activate     (activate BOX+card)
                             ├── /api/credits      (check/purchase credits)
                             ├── /api/authorize    (per-operation auth)
                             ├── /api/firmwares    (firmware catalog sync)
                             ├── /api/update       (software updates)
                             └── /api/eula         (EULA version check)
```

**Every paid/sensitive operation** contacts the server for authorization.
The server checks:
- Is the user logged in?
- Does the user have enough credits?
- Is the BOX not banned?
- Is this operation allowed for this account?

---

## 3. HOW THE LOGIN + APPROVAL SYSTEM WORKS

### 3.1 Login Flow (Step by Step)

```
Step 1: User enters Login (PND_xxxxx) + Password
        │
        ▼
Step 2: EXE sends HTTPS POST to Pandora server
        { login: "PND_xxxxx", password: "<hashed>" }
        │
        ▼
Step 3: Server validates credentials
        ├── Valid → Returns session token + account info
        │           (credits balance, linked BOX SN, card SN)
        │
        └── Invalid → "Login failed. Please try again."
        │
        ▼
Step 4: EXE stores session token in memory
        │
        ▼
Step 5: EXE checks BOX activation status with server
        ├── BOX linked to this account? ✓
        ├── Card activated? ✓
        ├── BOX not banned? ✓
        ├── Activation valid? ✓
        │
        └── All pass → Main GUI unlocked
```

### 3.2 Per-Operation Authorization

Even after login, **each operation** may require additional server checks:

| Operation | Authorization Type |
|---|---|
| Read Info | Free (local check only) |
| Flash Firmware | Free (local check only) |
| Repair IMEI | Server auth (needs active account) |
| Unlock Network | **CREDITS** (server deducts credits) |
| Read Codes | **CREDITS** (server deducts credits) |
| Reset FRP | Server auth check |
| Unlock Bootloader | Server auth check |

Strings like `"Operation not authorized"` and `"Sign in first"` confirm
that the EXE checks authorization status before allowing operations.

### 3.3 Hardware Dongle (Pandora BOX) — The Physical Lock

The BOX is a **smart card / USB dongle** that:
- Must be physically connected via USB at all times
- Is detected by `WinSCard` (smart card API) + `libusb`
- Has a unique Serial Number (SN) linked to the user's account
- Can be **remotely banned** by Pandora ("Box is banned")
- Has **updatable firmware** (the BOX itself runs firmware)
- Performs **challenge-response crypto** ("Box decrypt failed")
- If removed → **"Activation card removed. The application will now close."**
- If disconnected → **"Box disconnected. The application will now close."**

The app **actively monitors** the BOX connection and will **force-close**
if it disappears.

---

## 4. WHAT HAPPENS IF SOMEONE BYPASSES THE LOGIN PAGE?

### 4.1 Your Concern: "If bypass happens / login page removed → app becomes open?"

**SHORT ANSWER: NO — the app would NOT become fully open/usable.**

Here's why:

### 4.2 The Login Page is Only ONE of FIVE Security Layers

```
Security Layer          │ What Happens if Bypassed
────────────────────────┼──────────────────────────────────────────
1. Hardware BOX check   │ App force-closes if BOX not connected.
                        │ Cannot be bypassed by removing login.
                        │ The check is in a DIFFERENT code path.
────────────────────────┼──────────────────────────────────────────
2. EULA check           │ Minor — can be skipped, but doesn't
                        │ unlock any operations.
────────────────────────┼──────────────────────────────────────────
3. Login page           │ ⚠️ If bypassed (patched NOP):
   (YOUR CONCERN)       │ • GUI might show, BUT...
                        │ • No valid session token in memory
                        │ • Server won't authorize operations
                        │ • Credit operations impossible
                        │ • "Operation not authorized" errors
────────────────────────┼──────────────────────────────────────────
4. Activation status    │ Server-side check. Even without login,
                        │ the BOX must be activated+not banned.
                        │ Cannot be bypassed locally.
────────────────────────┼──────────────────────────────────────────
5. Per-operation auth   │ Every paid/sensitive operation contacts
                        │ the server. No token = no authorization.
                        │ Credits cannot be deducted = blocked.
```

### 4.3 Detailed Analysis: What Works vs. What Doesn't After Login Bypass

#### ✅ COULD WORK (offline/local-only operations):
- **Local database queries** — viewing the model list, firmware catalog
- **UI navigation** — browsing tabs, selecting brand/model
- **Reading local files** — EMI database, firmware references
- **Basic USB detection** — seeing connected devices

#### ❌ WOULD NOT WORK (server-dependent operations):
- **Repair IMEI** — needs server authorization
- **Unlock Network** — needs credits (server-side)
- **Read Codes** — needs credits (server-side)
- **Any credit-based operation** — server must deduct credits
- **Activation/Reactivation** — server-side
- **Firmware downloads** — server provides URLs
- **Software updates** — server provides manifests

#### ❌ WOULD NOT WORK (hardware-dependent):
- **ANY operation if BOX is disconnected** — app force-closes
- **Any operation if BOX is banned** — server rejects
- **Any crypto operation** — BOX does challenge-response decryption

#### ❌ WOULD NOT WORK (encrypted data):
- **models.mdb payloads** — encrypted with key inside EXE; even if you
  bypass login, the model configuration blobs (DA selection, auth bypass
  flags, operation permissions) remain encrypted. The decryption happens
  in a separate code path from login.
- **.crp files** — encrypted DA/preloader files decrypted in memory

### 4.4 The Real Risk: What a Skilled Attacker Could Do

A sophisticated reverse engineer who unpacks the UPX'd EXE could potentially:

| Attack | Difficulty | Impact |
|---|---|---|
| Patch the login form to skip | Medium | GUI shows, but operations fail |
| Patch the BOX detection check | Hard | App doesn't close without BOX, but server still blocks |
| Extract the models.mdb decryption key | Hard | Can read model configs (DA selection, etc.) |
| Patch per-operation auth checks | Very Hard | Would need to find and NOP every server call |
| Emulate the Pandora server | Very Hard | Would need to reverse all API endpoints |
| Clone the entire tool | Extremely Hard | BOX hardware crypto is not in the EXE |

**The hardware BOX is the strongest protection** because:
1. It's a physical device — can't be copied from the binary
2. It does cryptographic challenge-response — keys are in the hardware
3. The app force-closes without it — this check runs continuously
4. Even if all software checks are bypassed, BOX crypto operations
   (decryption of .crp files, model payloads) won't work without it

---

## 5. SECURITY ARCHITECTURE DIAGRAM (COMPLETE)

```
                    ┌─────────────────────────┐
                    │   PANDORA SERVER (HTTPS) │
                    │                         │
                    │  • User accounts        │
                    │  • Session tokens       │
                    │  • Credit balances      │
                    │  • BOX ban list         │
                    │  • Per-op authorization │
                    │  • Firmware hosting     │
                    │  • Update manifests     │
                    └────────────┬────────────┘
                                 │ WinInet HTTPS
                                 │
┌────────────────────────────────┼────────────────────────────────┐
│  LOCAL PC                     │                                  │
│                                ▼                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  PandoraTool.exe (Delphi VCL, UPX-packed)                │   │
│  │                                                          │   │
│  │  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  │   │
│  │  │  LOGIN  │→ │  ACTIVATE│→ │  AUTHORIZE│→ │OPERATION│  │   │
│  │  │  FORM   │  │  CHECK   │  │  CHECK    │  │ EXECUTE │  │   │
│  │  └────┬────┘  └────┬─────┘  └────┬──────┘  └────┬────┘  │   │
│  │       │             │             │              │        │   │
│  │  Layer 3       Layer 4       Layer 5        Layer 5      │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────────────────────────┐  │   │
│  │  │  LOCAL DATA (encrypted)                            │  │   │
│  │  │  • models.mdb (AES + XOR encrypted)                │  │   │
│  │  │  • .crp files (encrypted DAs/preloaders)           │  │   │
│  │  │  • emi_base.db3 (plaintext SQLite)                 │  │   │
│  │  │  • Firmwares.db3 (plaintext SQLite)                │  │   │
│  │  └────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────┬───────────────────────────────┘   │
│                              │                                   │
│                              │ USB (libusb + WinSCard)           │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  PANDORA BOX (Hardware Dongle)         ← LAYER 1        │   │
│  │                                                          │   │
│  │  • Smart card with unique SN                             │   │
│  │  • Cryptographic challenge-response                      │   │
│  │  • Firmware (updatable)                                  │   │
│  │  • USB passthrough for phone connection                  │   │
│  │  • Actively monitored — removal = app crash              │   │
│  └──────────────────────────┬───────────────────────────────┘   │
│                              │                                   │
│                              │ USB                               │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  PHONE (MTK / SPD / QCOM / Exynos / Kirin)              │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 6. SECURITY RECOMMENDATIONS (HOW TO KEEP IT SAFE)

### 6.1 Current Protections (Already Strong)

| Protection | Strength | Why |
|---|---|---|
| Hardware BOX dongle | ★★★★★ | Physical device, can't be cloned from binary |
| Server-side authorization | ★★★★☆ | Operations need server token |
| Credit system | ★★★★☆ | Paid ops need server-side credit deduction |
| Encrypted databases | ★★★★☆ | models.mdb unreadable without EXE key |
| UPX packing | ★★☆☆☆ | Easily unpacked, but slows casual RE |
| BOX ban system | ★★★★☆ | Compromised BOXes can be remotely disabled |

### 6.2 Risks to Be Aware Of

1. **Login bypass alone is NOT dangerous** — server auth blocks operations
2. **BOX removal is the real concern** — if someone patches the BOX check
   AND the server auth, operations could run. But this requires:
   - Unpacking UPX
   - Finding BOX detection code (multiple code paths)
   - Finding every server auth call (dozens of operations)
   - Emulating BOX crypto (challenge-response)
   - This is **extremely difficult** and time-consuming

3. **Soft-coded encryption keys** — the `soft_magic_v1` and `aes_softkey_v1`
   keys are inside the EXE binary. A determined reverse engineer can extract
   them and decrypt the model database. This gives them knowledge of DA
   selection and protocol parameters, but not the ability to run operations.

4. **Shared BOX credentials** — if users share their login + BOX, another
   person could use the tool legitimately. The server could detect concurrent
   sessions from different IPs.

### 6.3 Additional Hardening Suggestions

| Recommendation | Impact |
|---|---|
| **Add session heartbeat** — periodic server check every N minutes | Catches patched/stale sessions |
| **Bind session to BOX SN** — token only valid with specific BOX | Prevents token sharing |
| **Obfuscate BOX check code** — multiple checks, not one obvious one | Harder to patch out |
| **Code signing verification** — EXE checks its own integrity at runtime | Detects binary patching |
| **Anti-debug / anti-dump** — detect debuggers, prevent memory dumps | Slows reverse engineering |
| **Move crypto keys to BOX** — store decryption keys in hardware, not EXE | Makes models.mdb truly unreadable |
| **Concurrent session detection** — ban accounts logged in from 2+ IPs | Prevents credential sharing |
| **Operation logging** — server logs every operation with BOX SN + IP | Forensic trail |

---

## 7. SUMMARY: YOUR QUESTION ANSWERED

### "If someone bypasses/removes the login page, would the whole app become open?"

**NO.** Here's why:

1. **The login page is Layer 3 of 5.** Even without it, Layers 1 (BOX hardware),
   4 (activation status), and 5 (per-operation server auth) still block everything.

2. **Server authorization is required** for every sensitive operation. Without a
   valid login session token, the server returns "Operation not authorized."

3. **The BOX must be physically connected.** The app actively monitors this and
   force-closes if the BOX is removed. This cannot be bypassed by removing just
   the login form.

4. **Encrypted data stays encrypted.** The model database and DA files are
   encrypted independently of the login system. Bypassing login does NOT
   decrypt these files.

5. **Credit operations are impossible** without server-side credit deduction.

### The only real risk is:
A **very skilled reverse engineer** who patches ALL five layers simultaneously:
BOX detection + EULA + login + activation + per-operation auth. This is
extremely difficult (weeks/months of work) and each new version of the tool
would require re-patching.

**The hardware BOX is the ultimate safety net** — even if all software
protections are defeated, the cryptographic operations that the BOX performs
(challenge-response, file decryption) cannot be replicated without the
physical hardware.

---

*This analysis is for educational/security audit purposes. No DRM circumvention
was performed — all findings come from static binary inspection of publicly
visible structures, PE headers, string tables, and SQLite metadata.*
