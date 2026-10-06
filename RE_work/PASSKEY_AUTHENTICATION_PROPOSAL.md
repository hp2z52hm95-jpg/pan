# Passkey Authentication System for Pandora Tool

## What Are Passkeys? (Like Google/Apple/Microsoft Use)

Passkeys are **FIDO2/WebAuthn standard** credentials that replace passwords with:
- **Public-key cryptography** (like SSH keys but for web/app auth)
- **Biometric authentication** (fingerprint, face, PIN)
- **Device-bound credentials** (stored in secure hardware: TPM, Secure Enclave, security keys)
- **Phishing-resistant** (cryptographically bound to the domain/app)

---

## How Passkeys Work:

```
REGISTRATION (One-time setup):
┌──────────────────────────────────────────────────────────────┐
│  User → "Create Passkey"                                     │
│    ↓                                                         │
│  Device generates key pair:                                  │
│    • Private key (stays on device, in TPM/Secure Enclave)   │
│    • Public key (sent to server)                             │
│    ↓                                                         │
│  User authenticates with biometric/PIN:                      │
│    • Fingerprint / Face ID / Windows Hello / PIN            │
│    ↓                                                         │
│  Server stores: {user_id, public_key, device_info}          │
└──────────────────────────────────────────────────────────────┘

LOGIN (Every time):
┌──────────────────────────────────────────────────────────────┐
│  User → "Sign in with Passkey"                               │
│    ↓                                                         │
│  Server sends challenge (random bytes)                       │
│    ↓                                                         │
│  Device prompts biometric/PIN                                │
│    ↓                                                         │
│  User authenticates (fingerprint/face/PIN)                   │
│    ↓                                                         │
│  Device signs challenge with private key                     │
│    ↓                                                         │
│  Server verifies signature with stored public key            │
│    ↓                                                         │
│  ✓ Authenticated (no password transmitted!)                  │
└──────────────────────────────────────────────────────────────┘
```

---

## How Passkeys Could Fit Into Pandora's Architecture:

### Option 1: Passkey as THIRD Authentication Path

```
Current:
  PATH A: Login (username + password)
  PATH B: BOX (hardware dongle)

With Passkeys:
  PATH A: Login (username + password)
  PATH B: BOX (hardware dongle)
  PATH C: Passkey (biometric/device-bound)  ← NEW
```

**Pros:**
- Users can choose their preferred method
- Passkey more secure than password
- Works offline (like BOX) if device has cached credentials
- No hardware to buy (unlike BOX)
- Phishing-resistant

**Cons:**
- Requires device with biometric/TPM support
- Device loss = need recovery method
- Implementation complexity

### Option 2: Passkey REPLACES Password (2FA Enhancement)

```
Current Login:
  Username + Password → Session token

Enhanced Login:
  Username + Passkey → Session token
  (biometric instead of typing password)
```

**Pros:**
- Stronger than passwords
- Faster login (biometric vs typing)
- Phishing-resistant
- No password to forget/leak

**Cons:**
- Requires biometric device support
- Need fallback for devices without biometrics

### Option 3: Passkey + BOX Hybrid (Strongest)

```
BOX + Passkey Required:
  BOX hardware + Biometric confirmation
  (Something you have + Something you are)
```

**Pros:**
- Maximum security (2FA)
- BOX can't be used if stolen (needs biometric)
- Prevents BOX sharing (biometric is person-specific)

**Cons:**
- More friction for users
- Requires biometric support

---

## Implementation Architecture:

```
┌─────────────────────────────────────────────────────────────┐
│  Pandora Tool (Delphi VCL)                                  │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Authentication Manager                            │    │
│  │                                                     │    │
│  │  ├─ BOX Auth (existing)                            │    │
│  │  │   └─ WinSCard + libusb + crypto challenge       │    │
│  │  │                                                 │    │
│  │  ├─ Password Auth (existing)                       │    │
│  │  │   └─ WinInet HTTPS + username/password          │    │
│  │  │                                                 │    │
│  │  └─ Passkey Auth (NEW)                             │    │
│  │      ├─ Windows WebAuthn API (Win10 1903+)         │    │
│  │      ├─ Biometric prompt (Windows Hello)           │    │
│  │      ├─ FIDO2 security key support (YubiKey, etc.) │    │
│  │      └─ Platform authenticator (TPM)               │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
│  Windows APIs needed:                                        │
│  • webauthn.dll (Windows 10 1903+)                          │
│  • Windows.Security.Credentials.UI (biometric prompts)      │
│  • NCrypt (key storage in TPM)                               │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ HTTPS
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Pandora Server                                              │
│                                                              │
│  New endpoints:                                              │
│  • POST /api/passkey/register                               │
│  • POST /api/passkey/authenticate                           │
│  • GET  /api/passkey/credentials                            │
│                                                              │
│  Database:                                                   │
│  • users_passkeys table:                                    │
│    - user_id                                                │
│    - credential_id (public key ID)                          │
│    - public_key                                             │
│    - sign_count (replay protection)                         │
│    - device_info                                            │
│    - created_at                                             │
│    - last_used                                              │
│                                                              │
│  FIDO2 server library:                                       │
│  • fido2-net-lib (C#) or                                    │
│  • webauthn-lib (Node.js) or                                │
│  • java-webauthn-server (Java)                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Delphi Implementation Challenges:

### Challenge 1: WebAuthn API in Delphi
**Problem:** Delphi doesn't have built-in WebAuthn support

**Solutions:**
1. **Use Windows WebAuthn API directly:**
   - `webauthn.dll` (Win10 1903+)
   - Need to write Delphi headers for the C API
   - Call `WebAuthNGetApiVersionNumber`, `WebAuthNAuthenticatorMakeCredential`, etc.

2. **Use a DLL wrapper:**
   - Write C/C++ DLL that wraps WebAuthn API
   - Delphi calls the wrapper DLL
   - Easier than direct API calls

3. **Use external authenticator:**
   - Launch browser for WebAuthn flow
   - Communicate via localhost HTTP or named pipes
   - More complex UX

### Challenge 2: Biometric Prompts
**Problem:** Need to show Windows Hello / biometric dialog

**Solution:**
- Windows handles this automatically via WebAuthn API
- `WebAuthNAuthenticatorGetAssertion` triggers the prompt
- User sees native Windows Hello UI

### Challenge 3: Key Storage
**Problem:** Where to store private keys?

**Solution:**
- **Platform authenticator:** Keys stored in TPM (Windows Hello)
- **Roaming authenticator:** Keys on FIDO2 security key (YubiKey)
- Server never sees private keys (by design)

---

## Security Benefits:

### vs Passwords:
| Attack | Password | Passkey |
|---|---|---|
| Phishing | ❌ Vulnerable | ✅ Immune (domain-bound) |
| Credential stuffing | ❌ Vulnerable | ✅ Immune (no password) |
| Password leaks | ❌ Vulnerable | ✅ Immune (no password) |
| Brute force | ❌ Vulnerable | ✅ Immune (rate-limited) |
| Keyloggers | ❌ Vulnerable | ✅ Immune (biometric) |

### vs BOX:
| Feature | BOX | Passkey |
|---|---|---|
| Hardware cost | $$$ (buy dongle) | Free (device TPM) |
| Loss recovery | Buy new BOX | Revoke + re-register |
| Sharing prevention | ❌ Can share BOX | ✅ Biometric = person-specific |
| Offline operation | ✅ Yes | ⚠️ Limited (needs cached creds) |
| Platform support | Windows only | Cross-platform |

---

## Recommended Implementation:

### Phase 1: Passkey as Password Replacement (Easiest)

```
User flow:
1. Login with username + password (one-time)
2. "Enable Passkey for faster login?"
3. Register passkey (biometric prompt)
4. Future logins: username + passkey (no password)
```

**Benefits:**
- Stronger than passwords
- Faster login
- Phishing-resistant
- Minimal code changes

**Implementation effort:** Medium (2-4 weeks)

### Phase 2: Passkey + BOX Hybrid (Strongest)

```
User flow:
1. Insert BOX
2. Biometric prompt (Windows Hello)
3. Authenticate with both
4. Full access
```

**Benefits:**
- Maximum security
- Prevents BOX sharing
- Person-specific (biometric)
- Can't use stolen BOX

**Implementation effort:** High (4-8 weeks)

### Phase 3: Cross-Platform Passkey (Future)

```
User flow:
1. Register passkey on phone
2. Use phone as authenticator for PC
3. QR code or Bluetooth proximity
```

**Benefits:**
- Works on any device
- No BOX needed
- Cross-platform

**Implementation effort:** Very High (8-12 weeks)

---

## Security Considerations:

### What Passkeys Protect Against:
✅ Phishing attacks
✅ Password database breaches
✅ Credential stuffing
✅ Keyloggers
✅ Password reuse attacks
✅ Man-in-the-middle attacks

### What Passkeys DON'T Protect Against:
❌ Device theft (if device unlocked)
❌ Malware on authenticated device
❌ Server-side attacks
❌ Social engineering
❌ Insider threats

### Mitigations:
- **Device theft:** Require biometric for every operation (not just login)
- **Malware:** Code signing, anti-tamper, sandboxing
- **Server attacks:** Standard web security (HTTPS, input validation, etc.)
- **Social engineering:** User education
- **Insider threats:** Audit logs, least privilege

---

## Business Model Impact:

### Current Model:
- BOX users: Buy hardware ($$$), use offline
- Login users: Buy credits, use online

### With Passkeys:
- **Option A:** Passkey users pay subscription (like Netflix)
  - Monthly fee for unlimited operations
  - No hardware needed
  - Biometric security
  
- **Option B:** Passkey replaces password (free enhancement)
  - Same credit system
  - Just better security
  
- **Option C:** Passkey + BOX hybrid (premium tier)
  - Maximum security
  - Exclusive operations
  - Higher price point

---

## Implementation Roadmap:

### Week 1-2: Research & Design
- Evaluate WebAuthn libraries for Delphi
- Design server API endpoints
- Database schema for passkey storage
- UX flow design

### Week 3-4: Server Implementation
- Implement FIDO2 server library
- API endpoints for registration/authentication
- Database migrations
- Testing with FIDO2 test tools

### Week 5-6: Client Implementation (Delphi)
- WebAuthn API integration
- Biometric prompt handling
- Key management
- Error handling

### Week 7-8: Testing & Deployment
- Security audit
- Penetration testing
- Beta testing with users
- Rollout plan

### Week 9+: Monitoring & Iteration
- Monitor adoption
- Gather feedback
- Fix issues
- Add features (cross-platform, etc.)

---

## Cost Estimate:

### Development:
- Server-side: $10,000 - $20,000 (2-4 weeks)
- Client-side (Delphi): $15,000 - $30,000 (4-6 weeks)
- Security audit: $5,000 - $10,000
- Testing: $5,000 - $10,000

**Total: $35,000 - $70,000**

### Ongoing:
- Server infrastructure: $500 - $2,000/month
- Maintenance: $2,000 - $5,000/month
- Support: $1,000 - $3,000/month

**Total: $3,500 - $10,000/month**

### ROI:
- Reduced support costs (no password resets)
- Higher security (fewer breaches)
- Competitive advantage
- Premium pricing for passkey tier

---

## Comparison: Passkey vs Current System

| Feature | Password | BOX | Passkey |
|---|---|---|---|
| Security | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Convenience | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ |
| Cost | Free | $$$ | Free |
| Offline | ❌ | ✅ | ⚠️ |
| Phishing-proof | ❌ | ✅ | ✅ |
| Sharing-proof | ❌ | ❌ | ✅ |
| Cross-platform | ✅ | ❌ | ✅ |
| Implementation | Easy | Done | Medium |

---

## Recommendation:

**Implement Passkey as Phase 1 enhancement:**

1. **Keep existing systems** (password + BOX)
2. **Add passkey as optional upgrade** for password users
3. **Market as "Biometric Login"** (user-friendly term)
4. **Offer as premium feature** or free security enhancement
5. **Future:** Add passkey + BOX hybrid for maximum security

**Why this approach:**
- Minimal disruption to existing users
- Gradual adoption
- Prove value before full migration
- Lower risk

---

## Next Steps:

1. **Proof of Concept:**
   - Build simple Delphi app that calls WebAuthn API
   - Test on Windows 10/11
   - Verify biometric prompts work

2. **Server Prototype:**
   - Implement FIDO2 endpoints
   - Test with FIDO2 conformance tools
   - Security review

3. **User Research:**
   - Survey users about biometric login
   - Understand concerns (privacy, device support)
   - Price sensitivity

4. **Business Case:**
   - Cost-benefit analysis
   - Pricing model
   - Marketing strategy

---

## Summary:

**Passkeys would be a STRONG security enhancement for Pandora:**

✅ More secure than passwords
✅ Phishing-resistant
✅ Biometric convenience
✅ No hardware cost (unlike BOX)
✅ Person-specific (prevents sharing)
✅ Industry standard (Google, Apple, Microsoft)

**Challenges:**
- Delphi WebAuthn integration (needs custom work)
- Device support requirements (TPM/biometric)
- User education (new concept)

**Recommendation:**
Implement as optional enhancement alongside existing password + BOX system. Start with password replacement, then add BOX hybrid for maximum security.

**This would make Pandora one of the FIRST professional tools with passkey authentication** - a significant competitive advantage.

---

*Passkey implementation would follow FIDO2/WebAuthn standards.*
*Compatible with Windows Hello, Touch ID, Android biometrics, and FIDO2 security keys.*
