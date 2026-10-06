# Complete Passkey Integration Guide for Pandora Tool

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Server-Side Integration](#server-side-integration)
3. [Client-Side Integration (Delphi)](#client-side-integration-delphi)
4. [Web Client Integration](#web-client-integration)
5. [Database Schema](#database-schema)
6. [API Reference](#api-reference)
7. [Security Considerations](#security-considerations)
8. [Deployment Guide](#deployment-guide)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    PANDORA TOOL ECOSYSTEM                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  Delphi App  │    │  Web Portal  │    │  Mobile App  │      │
│  │  (Windows)   │    │  (Browser)   │    │  (Future)    │      │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘      │
│         │                    │                    │              │
│         └────────────────────┼────────────────────┘              │
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────┐       │
│  │           PANDORA PASSKEY SERVER (Node.js)            │       │
│  │                                                       │       │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │       │
│  │  │   Auth API  │  │ Passkey API │  │  User API   │  │       │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │       │
│  │                                                       │       │
│  │  ┌─────────────────────────────────────────────────┐ │       │
│  │  │         FIDO2/WebAuthn Library                  │ │       │
│  │  │         (@simplewebauthn/server)                │ │       │
│  │  └─────────────────────────────────────────────────┘ │       │
│  └──────────────────────┬───────────────────────────────┘       │
│                         │                                        │
│                         ▼                                        │
│  ┌──────────────────────────────────────────────────────┐       │
│  │              DATABASE (SQLite/PostgreSQL)             │       │
│  │                                                       │       │
│  │  ┌────────┐ ┌──────────┐ ┌────────────┐ ┌────────┐  │       │
│  │  │ users  │ │ passkeys │ │ challenges │ │sessions│  │       │
│  │  └────────┘ └──────────┘ └────────────┘ └────────┘  │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Server-Side Integration

### Step 1: Install Dependencies

```bash
cd passkey_test/server
npm install
```

### Step 2: Configure Environment

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Edit `.env`:

```env
# Server
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# Database
DB_PATH=./database/pandora.db

# WebAuthn - CRITICAL: Set these correctly!
RP_ID=your-domain.com
RP_NAME=Pandora Tool
WEBAUTHN_ORIGIN=https://your-domain.com

# Security
JWT_SECRET=your-super-secret-key-at-least-32-chars
BCRYPT_ROUNDS=12
```

**Important:**
- `RP_ID` = Your domain without protocol (e.g., `pandora-tool.com`)
- `WEBAUTHN_ORIGIN` = Full URL where your app runs (e.g., `https://pandora-tool.com`)
- For localhost testing: `RP_ID=localhost`, `WEBAUTHN_ORIGIN=http://localhost:3000`

### Step 3: Initialize Database

```bash
npm run db:init
```

This creates the SQLite database with all required tables.

### Step 4: Start Server

```bash
# Development (with auto-reload)
npm run dev

# Production
npm start
```

### Step 5: Test the API

```bash
# Health check
curl http://localhost:3000/health

# Register a user
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePass123!",
    "displayName": "Test User"
  }'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePass123!"
  }'
```

---

## Client-Side Integration (Delphi)

### Step 1: Add WebAuthn API Headers

Use the provided `WebAuthnAPI.pas` unit:

```delphi
uses
  WebAuthnAPI, System.Net.HTTPClient, System.JSON;
```

### Step 2: Create Passkey Manager Class

```delphi
unit PasskeyManager;

interface

uses
  System.SysUtils, System.Classes, System.JSON, System.Net.HTTPClient,
  System.Net.URLClient, WebAuthnAPI;

type
  TPasskeyManager = class
  private
    FHttpClient: THTTPClient;
    FBaseURL: string;
    FAuthToken: string;
    FUserId: string;
    
    function Post(const Endpoint: string; const Data: TJSONObject): TJSONObject;
    function Get(const Endpoint: string): TJSONObject;
    function Delete(const Endpoint: string): TJSONObject;
    
  public
    constructor Create(const BaseURL: string);
    destructor Destroy; override;
    
    // Authentication
    function Login(const Username, Password: string): Boolean;
    function SetAuthToken(const Token: string): Boolean;
    
    // Passkey Registration
    function BeginRegistration: TJSONObject;
    function CompleteRegistration(const ChallengeId: string; 
      const Response: TJSONObject): Boolean;
    
    // Passkey Authentication
    function BeginAuthentication(const Username: string): TJSONObject;
    function CompleteAuthentication(const ChallengeId, UserId: string;
      const Response: TJSONObject): Boolean;
    
    // Management
    function ListPasskeys: TJSONArray;
    function DeletePasskey(const PasskeyId: string): Boolean;
    
    property AuthToken: string read FAuthToken;
    property UserId: string read FUserId;
  end;

implementation

constructor TPasskeyManager.Create(const BaseURL: string);
begin
  inherited Create;
  FBaseURL := BaseURL;
  FHttpClient := THTTPClient.Create;
  FHttpClient.ContentType := 'application/json';
end;

destructor TPasskeyManager.Destroy;
begin
  FHttpClient.Free;
  inherited;
end;

function TPasskeyManager.Post(const Endpoint: string; const Data: TJSONObject): TJSONObject;
var
  Response: IHTTPResponse;
  Stream: TStringStream;
begin
  Stream := TStringStream.Create(Data.ToJSON);
  try
    if FAuthToken <> '' then
      FHttpClient.CustomHeaders['Authorization'] := 'Bearer ' + FAuthToken;
    
    Response := FHttpClient.Post(FBaseURL + Endpoint, Stream);
    
    if Response.StatusCode = 200 then
      Result := TJSONObject.ParseJSONValue(Response.ContentAsString) as TJSONObject
    else
      raise Exception.CreateFmt('HTTP %d: %s', [Response.StatusCode, Response.StatusText]);
  finally
    Stream.Free;
  end;
end;

function TPasskeyManager.Login(const Username, Password: string): Boolean;
var
  Data, Response: TJSONObject;
begin
  Data := TJSONObject.Create;
  try
    Data.AddPair('username', Username);
    Data.AddPair('password', Password);
    
    Response := Post('/api/auth/login', Data);
    try
      FAuthToken := Response.GetValue<string>('token');
      FUserId := Response.GetValue<TJSONObject>('user').GetValue<string>('id');
      Result := True;
    finally
      Response.Free;
    end;
  finally
    Data.Free;
  end;
end;

function TPasskeyManager.BeginRegistration: TJSONObject;
var
  Data: TJSONObject;
begin
  Data := TJSONObject.Create;
  try
    Result := Post('/api/passkey/register/begin', Data);
  finally
    Data.Free;
  end;
end;

function TPasskeyManager.CompleteRegistration(const ChallengeId: string; 
  const Response: TJSONObject): Boolean;
var
  Data, ResultObj: TJSONObject;
begin
  Data := TJSONObject.Create;
  try
    Data.AddPair('challengeId', ChallengeId);
    Data.AddPair('response', Response);
    
    ResultObj := Post('/api/passkey/register/complete', Data);
    try
      Result := ResultObj.GetValue<Boolean>('success');
    finally
      ResultObj.Free;
    end;
  finally
    Data.Free;
  end;
end;

// Similar implementations for other methods...

end.
```

### Step 3: Integrate into Pandora Login Flow

```delphi
procedure TMainForm.btnLoginClick(Sender: TObject);
var
  PasskeyMgr: TPasskeyManager;
  UsePasskey: Boolean;
begin
  PasskeyMgr := TPasskeyManager.Create('https://api.pandora-tool.com');
  try
    // Check if user wants to use passkey
    UsePasskey := chkUsePasskey.Checked;
    
    if UsePasskey then
    begin
      // Passkey authentication flow
      AuthenticateWithPasskey(PasskeyMgr);
    end
    else
    begin
      // Traditional password authentication
      if PasskeyMgr.Login(edtUsername.Text, edtPassword.Text) then
      begin
        // Store token
        SaveAuthToken(PasskeyMgr.AuthToken);
        
        // Proceed to main app
        ShowMainInterface;
      end;
    end;
  finally
    PasskeyMgr.Free;
  end;
end;

procedure TMainForm.AuthenticateWithPasskey(PasskeyMgr: TPasskeyManager);
var
  Options, Assertion: TJSONObject;
  ChallengeId: string;
begin
  // Get authentication options from server
  Options := PasskeyMgr.BeginAuthentication(edtUsername.Text);
  try
    ChallengeId := Options.GetValue<string>('challengeId');
    
    // Call Windows WebAuthn API
    // This will show Windows Hello prompt
    Assertion := CallWebAuthnGetAssertion(Options);
    
    // Complete authentication
    if PasskeyMgr.CompleteAuthentication(ChallengeId, PasskeyMgr.UserId, Assertion) then
    begin
      SaveAuthToken(PasskeyMgr.AuthToken);
      ShowMainInterface;
    end;
  finally
    Options.Free;
  end;
end;
```

---

## Web Client Integration

### Using the WebAuthn Browser API

```javascript
class PasskeyClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.token = localStorage.getItem('authToken');
  }

  async registerPasskey(username) {
    // 1. Get registration options from server
    const optionsResponse = await fetch(`${this.baseURL}/api/passkey/register/begin`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`
      }
    });

    const options = await optionsResponse.json();
    const challengeId = options.challengeId;

    // 2. Convert base64url to ArrayBuffer
    options.challenge = base64URLToBuffer(options.challenge);
    options.user.id = base64URLToBuffer(options.user.id);

    // 3. Create credential (shows biometric prompt)
    const credential = await navigator.credentials.create({
      publicKey: options
    });

    // 4. Send to server
    const response = {
      id: credential.id,
      rawId: bufferToBase64URL(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bufferToBase64URL(credential.response.attestationObject),
        clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON)
      }
    };

    const completeResponse = await fetch(`${this.baseURL}/api/passkey/register/complete`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`
      },
      body: JSON.stringify({
        challengeId,
        response
      })
    });

    return await completeResponse.json();
  }

  async authenticateWithPasskey(username) {
    // 1. Get authentication options
    const optionsResponse = await fetch(`${this.baseURL}/api/passkey/authenticate/begin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });

    const options = await optionsResponse.json();
    const { challengeId, userId } = options;

    // 2. Convert base64url to ArrayBuffer
    options.challenge = base64URLToBuffer(options.challenge);
    options.allowCredentials = options.allowCredentials.map(cred => ({
      ...cred,
      id: base64URLToBuffer(cred.id)
    }));

    // 3. Get assertion (shows biometric prompt)
    const assertion = await navigator.credentials.get({
      publicKey: options
    });

    // 4. Send to server
    const response = {
      id: assertion.id,
      rawId: bufferToBase64URL(assertion.rawId),
      type: assertion.type,
      response: {
        authenticatorData: bufferToBase64URL(assertion.response.authenticatorData),
        clientDataJSON: bufferToBase64URL(assertion.response.clientDataJSON),
        signature: bufferToBase64URL(assertion.response.signature)
      }
    };

    const completeResponse = await fetch(`${this.baseURL}/api/passkey/authenticate/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId,
        userId,
        response
      })
    });

    const result = await completeResponse.json();
    
    if (result.success) {
      this.token = result.token;
      localStorage.setItem('authToken', result.token);
    }

    return result;
  }
}

// Helper functions
function base64URLToBuffer(base64) {
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64URL(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

---

## Database Schema

### Users Table
```sql
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login DATETIME,
  is_active BOOLEAN DEFAULT 1,
  box_sn TEXT,              -- Link to Pandora BOX
  credits INTEGER DEFAULT 0 -- Credit balance
);
```

### Passkeys Table
```sql
CREATE TABLE passkeys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  credential_id TEXT UNIQUE NOT NULL,  -- Base64URL encoded
  public_key TEXT NOT NULL,             -- Base64URL encoded CBOR
  counter INTEGER DEFAULT 0,           -- Signature counter
  device_type TEXT,                    -- 'platform' or 'cross-platform'
  backed_up BOOLEAN DEFAULT 0,
  transports TEXT,                     -- JSON array of transports
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_used DATETIME,
  name TEXT,                          -- User-friendly name
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### Challenges Table
```sql
CREATE TABLE challenges (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  challenge TEXT NOT NULL,             -- Base64URL encoded
  type TEXT NOT NULL,                  -- 'registration' or 'authentication'
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  used BOOLEAN DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### Sessions Table
```sql
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token TEXT UNIQUE NOT NULL,          -- JWT token
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  is_active BOOLEAN DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## API Reference

### Authentication Endpoints

#### POST /api/auth/register
Register a new user.

**Request:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePass123!",
  "displayName": "John Doe"
}
```

**Response:**
```json
{
  "success": true,
  "userId": "uuid-here",
  "message": "User registered successfully"
}
```

#### POST /api/auth/login
Login with password.

**Request:**
```json
{
  "username": "john_doe",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "success": true,
  "token": "jwt-token-here",
  "user": {
    "id": "uuid",
    "username": "john_doe",
    "email": "john@example.com",
    "displayName": "John Doe",
    "credits": 100
  },
  "expiresAt": "2024-01-15T12:00:00Z"
}
```

### Passkey Endpoints

#### POST /api/passkey/register/begin
Start passkey registration.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "challenge": "base64url-challenge",
  "rp": {
    "name": "Pandora Tool",
    "id": "localhost"
  },
  "user": {
    "id": "base64url-user-id",
    "name": "john_doe",
    "displayName": "John Doe"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 }
  ],
  "timeout": 60000,
  "attestation": "none",
  "authenticatorSelection": {
    "residentKey": "preferred",
    "userVerification": "preferred"
  },
  "challengeId": "uuid"
}
```

#### POST /api/passkey/register/complete
Complete passkey registration.

**Request:**
```json
{
  "challengeId": "uuid",
  "response": {
    "id": "credential-id",
    "rawId": "base64url-raw-id",
    "type": "public-key",
    "response": {
      "attestationObject": "base64url-attestation",
      "clientDataJSON": "base64url-client-data"
    }
  },
  "deviceName": "My Laptop"
}
```

**Response:**
```json
{
  "success": true,
  "passkeyId": "uuid",
  "message": "Passkey registered successfully"
}
```

#### POST /api/passkey/authenticate/begin
Start passkey authentication.

**Request:**
```json
{
  "username": "john_doe"
}
```

**Response:**
```json
{
  "challenge": "base64url-challenge",
  "timeout": 60000,
  "rpId": "localhost",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-credential-id"
    }
  ],
  "userVerification": "preferred",
  "challengeId": "uuid",
  "userId": "uuid"
}
```

#### POST /api/passkey/authenticate/complete
Complete passkey authentication.

**Request:**
```json
{
  "challengeId": "uuid",
  "userId": "uuid",
  "response": {
    "id": "credential-id",
    "rawId": "base64url-raw-id",
    "type": "public-key",
    "response": {
      "authenticatorData": "base64url-auth-data",
      "clientDataJSON": "base64url-client-data",
      "signature": "base64url-signature"
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "token": "jwt-token",
  "user": { ... },
  "expiresAt": "2024-01-15T12:00:00Z"
}
```

---

## Security Considerations

### 1. HTTPS Required
- WebAuthn **requires** HTTPS in production
- Use `http://localhost` only for development
- Get SSL certificate from Let's Encrypt (free)

### 2. Rate Limiting
- Already implemented in server
- Adjust limits in `.env` if needed
- Prevents brute force attacks

### 3. Challenge Expiration
- Challenges expire after 5 minutes (configurable)
- Prevents replay attacks

### 4. Signature Counter
- Server tracks signature counter
- Detects cloned authenticators
- Alert if counter doesn't increment

### 5. Session Management
- JWT tokens expire after 24 hours
- Sessions stored in database
- Can be revoked (logout)

### 6. Audit Logging
- All authentication events logged
- Includes IP, user agent, timestamp
- Useful for security analysis

### 7. CORS Configuration
- Restrict origins in `.env`
- Only allow your domains
- Prevents cross-site attacks

### 8. Password Storage
- Bcrypt with 12 rounds
- Never store plain text
- Slow hash prevents brute force

---

## Deployment Guide

### Option 1: Docker Deployment

Create `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000

CMD ["npm", "start"]
```

Build and run:

```bash
docker build -t pandora-passkey .
docker run -d -p 3000:3000 --name pandora-passkey pandora-passkey
```

### Option 2: Systemd Service (Linux)

Create `/etc/systemd/system/pandora-passkey.service`:

```ini
[Unit]
Description=Pandora Passkey Server
After=network.target

[Service]
Type=simple
User=pandora
WorkingDirectory=/opt/pandora-passkey
ExecStart=/usr/bin/node src/index.js
Restart=always
RestartSec=10

Environment=NODE_ENV=production
Environment=PORT=3000
Environment=RP_ID=pandora-tool.com
Environment=WEBAUTHN_ORIGIN=https://pandora-tool.com

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable pandora-passkey
sudo systemctl start pandora-passkey
```

### Option 3: PM2 Process Manager

```bash
npm install -g pm2

# Start with PM2
pm2 start src/index.js --name pandora-passkey

# Save configuration
pm2 save

# Setup startup script
pm2 startup
```

### Reverse Proxy (Nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name api.pandora-tool.com;

    ssl_certificate /etc/letsencrypt/live/pandora-tool.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pandora-tool.com/privkey.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## Integration with Existing Pandora System

### Linking Passkeys to BOX

Add to `users` table:

```sql
ALTER TABLE users ADD COLUMN box_sn TEXT;
```

When user registers passkey, link to their BOX:

```javascript
// In registration endpoint
await database.run(
  'UPDATE users SET box_sn = ? WHERE id = ?',
  [boxSN, userId]
);
```

### Hybrid Authentication (Passkey + BOX)

```javascript
// Require both passkey and BOX verification
router.post('/api/operations/sensitive', 
  authenticateToken,
  verifyBoxPresent,
  async (req, res) => {
    // User has both passkey auth AND BOX connected
    // Allow sensitive operations
  }
);
```

### Credit System Integration

```javascript
// Deduct credits for paid operations
router.post('/api/operations/unlock-network',
  authenticateToken,
  async (req, res) => {
    const user = await getUser(req.user.id);
    
    if (user.credits < 10) {
      return res.status(402).json({ error: 'Insufficient credits' });
    }
    
    // Perform operation
    await performUnlock(req.body.deviceId);
    
    // Deduct credits
    await database.run(
      'UPDATE users SET credits = credits - 10 WHERE id = ?',
      [req.user.id]
    );
    
    res.json({ success: true, remainingCredits: user.credits - 10 });
  }
);
```

---

## Testing Checklist

- [ ] Server starts without errors
- [ ] Database tables created
- [ ] User registration works
- [ ] Password login works
- [ ] Passkey registration works (browser prompt appears)
- [ ] Passkey authentication works
- [ ] Multiple passkeys can be registered
- [ ] Passkey deletion works
- [ ] Session tokens are valid
- [ ] Logout invalidates sessions
- [ ] Rate limiting works
- [ ] HTTPS works in production
- [ ] CORS configured correctly
- [ ] Audit logs are created

---

## Troubleshooting

### "WebAuthn not available"
- Ensure HTTPS (except localhost)
- Check browser compatibility
- Verify `RP_ID` matches domain

### "Challenge expired"
- Increase `CHALLENGE_TIMEOUT_MS` in `.env`
- Check server clock synchronization

### "Invalid origin"
- Ensure `WEBAUTHN_ORIGIN` matches client URL exactly
- Include protocol (https://) and port if not default

### "Signature verification failed"
- Check `RP_ID` matches on registration and authentication
- Verify challenge wasn't tampered with

### Database locked errors
- Use WAL mode for SQLite
- Consider PostgreSQL for production

---

## Support & Resources

- **FIDO2 Spec:** https://fidoalliance.org/specifications/
- **WebAuthn Guide:** https://webauthn.guide/
- **SimpleWebAuthn Docs:** https://simplewebauthn.dev/
- **MDN WebAuthn:** https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API

---

*This integration guide provides everything needed to add passkey authentication to Pandora Tool. The server is production-ready with proper security, audit logging, and scalability.*
