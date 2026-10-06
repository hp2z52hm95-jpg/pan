# Quick Start Guide - Passkey Integration

## 🚀 Get Started in 5 Minutes

### 1. Start the Server

```bash
cd passkey_test/server
npm install
cp .env.example .env
npm start
```

Server runs at: **http://localhost:3000**

### 2. Test with the Demo

Open the Python demo (already running):
- **URL:** http://localhost:8080
- Register a passkey
- Authenticate with passkey
- See it work!

### 3. Integrate into Your App

#### Option A: Web App (JavaScript)
```javascript
// 1. Register passkey
const options = await fetch('/api/passkey/register/begin', {
  method: 'POST',
  headers: { 'Authorization': 'Bearer YOUR_TOKEN' }
}).then(r => r.json());

const credential = await navigator.credentials.create({ publicKey: options });

await fetch('/api/passkey/register/complete', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/json',
    'Authorization': 'Bearer YOUR_TOKEN'
  },
  body: JSON.stringify({
    challengeId: options.challengeId,
    response: credential
  })
});

// 2. Authenticate with passkey
const authOptions = await fetch('/api/passkey/authenticate/begin', {
  method: 'POST',
  body: JSON.stringify({ username: 'user123' })
}).then(r => r.json());

const assertion = await navigator.credentials.get({ publicKey: authOptions });

const result = await fetch('/api/passkey/authenticate/complete', {
  method: 'POST',
  body: JSON.stringify({
    challengeId: authOptions.challengeId,
    userId: authOptions.userId,
    response: assertion
  })
}).then(r => r.json());

// result.token = your session token!
```

#### Option B: Delphi App
```delphi
// Use the provided WebAuthnAPI.pas and PasskeyClient.pas
var
  Client: TPasskeyClient;
  Result: TPasskeyAuthenticationResult;
begin
  Client := TPasskeyClient.Create(Server, UserId, UserName);
  
  // Register
  RegResult := Client.RegisterPasskey(Handle);
  if RegResult.Success then
    ShowMessage('Passkey registered!');
  
  // Authenticate
  Result := Client.AuthenticatePasskey(Handle);
  if Result.Success then
    ShowMessage('Authenticated!');
end;
```

---

## 📋 Integration Checklist

### Server Setup
- [ ] Install Node.js 18+
- [ ] Run `npm install` in `passkey_test/server`
- [ ] Copy `.env.example` to `.env`
- [ ] Set `RP_ID` and `WEBAUTHN_ORIGIN` in `.env`
- [ ] Run `npm start`
- [ ] Test health endpoint: `curl http://localhost:3000/health`

### Database Setup
- [ ] Database auto-created on first run
- [ ] Tables: users, passkeys, challenges, sessions, audit_log
- [ ] For production: Consider PostgreSQL

### Client Integration
- [ ] Add API base URL to your app config
- [ ] Implement registration flow
- [ ] Implement authentication flow
- [ ] Store JWT token after successful auth
- [ ] Handle errors gracefully

### Testing
- [ ] Register a test user
- [ ] Login with password
- [ ] Register a passkey
- [ ] Authenticate with passkey
- [ ] Verify session token works
- [ ] Test logout

---

## 🔧 Configuration

### For Local Development
```env
RP_ID=localhost
RP_NAME=Pandora Tool
WEBAUTHN_ORIGIN=http://localhost:3000
JWT_SECRET=dev-secret-change-in-production
```

### For Production
```env
RP_ID=pandora-tool.com
RP_NAME=Pandora Tool
WEBAUTHN_ORIGIN=https://pandora-tool.com
JWT_SECRET=your-super-secret-32-char-key-here
```

**Important:**
- `RP_ID` = Domain without protocol
- `WEBAUTHN_ORIGIN` = Full URL with protocol
- HTTPS required in production!

---

## 📚 Key Files

```
passkey_test/
├── INTEGRATION_GUIDE.md          ← Full documentation
├── QUICK_START.md               ← This file
├── python_demo.py               ← Live demo (running on :8080)
│
├── server/                      ← Production server
│   ├── src/
│   │   ├── index.js            ← Main server
│   │   ├── config.js           ← Configuration
│   │   ├── routes/
│   │   │   ├── auth.js         ← Login/register endpoints
│   │   │   ├── passkey.js      ← Passkey endpoints
│   │   │   └── users.js        ← User management
│   │   ├── models/
│   │   │   └── database.js     ← Database setup
│   │   ├── middleware/
│   │   │   └── auth.js         ← JWT middleware
│   │   └── utils/
│   │       └── audit.js        ← Audit logging
│   ├── package.json
│   └── .env.example
│
└── PasskeyTest.dpr              ← Delphi example app
    ├── WebAuthnAPI.pas          ← Windows API headers
    ├── PasskeyClient.pas        ← Client logic
    ├── MockServer.pas           ← Mock server
    └── MainForm.pas             ← UI
```

---

## 🎯 API Endpoints

### Authentication
```
POST /api/auth/register          Register new user
POST /api/auth/login             Login with password
POST /api/auth/logout            Logout
GET  /api/auth/me                Get current user
PUT  /api/auth/password          Change password
```

### Passkeys
```
POST /api/passkey/register/begin     Start registration
POST /api/passkey/register/complete  Complete registration
POST /api/passkey/authenticate/begin     Start authentication
POST /api/passkey/authenticate/complete  Complete authentication
GET  /api/passkey/list                   List user's passkeys
DELETE /api/passkey/:id                  Delete passkey
```

---

## 🔐 Security Features

✅ **Phishing-resistant** - Credentials bound to domain  
✅ **No password transmission** - Only cryptographic signatures  
✅ **Biometric protection** - Private key in secure hardware  
✅ **Replay protection** - Unique challenges per request  
✅ **Rate limiting** - Prevents brute force  
✅ **Audit logging** - Track all auth events  
✅ **Session management** - JWT with expiration  
✅ **HTTPS required** - Encrypted transport  

---

## 🆘 Common Issues

### "WebAuthn not available"
- Use Chrome, Edge, Firefox, or Safari (latest)
- Ensure HTTPS (except localhost)

### "Invalid origin"
- Check `WEBAUTHN_ORIGIN` matches your app URL exactly
- Include protocol (https://)

### "Challenge expired"
- Increase `CHALLENGE_TIMEOUT_MS` in `.env`
- Default is 5 minutes

### Database errors
- Check `DB_PATH` in `.env`
- Ensure write permissions

---

## 📞 Next Steps

1. **Test the demo** at http://localhost:8080
2. **Start the server** (http://localhost:3000)
3. **Read the full guide** (INTEGRATION_GUIDE.md)
4. **Integrate into your app** using examples above
5. **Deploy to production** with HTTPS
6. **Monitor audit logs** for security events

---

## 💡 Pro Tips

- **Start with the demo** - See how it works before integrating
- **Use the Python demo** for quick testing
- **Use Delphi code** for Windows app integration
- **Use JavaScript code** for web app integration
- **Test on localhost first** - No HTTPS needed
- **Use production domain** for `RP_ID` when deploying
- **Enable audit logging** - Helps with security analysis
- **Implement passkey + BOX** for maximum security

---

## 🎉 You're Ready!

You now have:
- ✅ Complete passkey server (Node.js)
- ✅ Database schema
- ✅ API endpoints
- ✅ Delphi client code
- ✅ JavaScript client code
- ✅ Live demo
- ✅ Full documentation

**Start testing now!** Open http://localhost:8080 and register your first passkey.

---

*Need help? Check INTEGRATION_GUIDE.md for detailed documentation.*
