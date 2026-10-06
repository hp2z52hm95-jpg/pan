#!/usr/bin/env python3
"""
Passkey Authentication Smoke Test - Python Simulation

This is a Python-based simulation of the WebAuthn/FIDO2 passkey flow
that demonstrates the concept without requiring actual Windows hardware.

For the real implementation, use the Delphi code with Windows WebAuthn API.
"""

import os
import json
import base64
import secrets
import hashlib
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import html

# Mock FIDO2 Server
class MockFIDO2Server:
    def __init__(self):
        self.credentials = {}  # user_id -> list of credentials
        self.challenges = {}   # session_id -> challenge data
        self.rp_id = "localhost"
        self.rp_name = "Pandora Tool Passkey Test"
        self.origin = "http://localhost:8080"
    
    def begin_registration(self, user_id, user_name):
        """Start passkey registration - return challenge"""
        challenge = secrets.token_bytes(32)
        session_id = f"reg_{user_id}_{secrets.token_hex(8)}"
        
        self.challenges[session_id] = {
            'challenge': challenge,
            'user_id': user_id,
            'user_name': user_name,
            'type': 'registration',
            'expires': datetime.now() + timedelta(minutes=5)
        }
        
        return {
            'session_id': session_id,
            'challenge': base64.urlsafe_b64encode(challenge).decode('ascii'),
            'rp': {
                'id': self.rp_id,
                'name': self.rp_name
            },
            'user': {
                'id': base64.urlsafe_b64encode(user_id.encode()).decode('ascii'),
                'name': user_id,
                'displayName': user_name
            },
            'pubKeyCredParams': [
                {'type': 'public-key', 'alg': -7},  # ES256
                {'type': 'public-key', 'alg': -257} # RS256
            ],
            'authenticatorSelection': {
                'authenticatorAttachment': 'platform',
                'userVerification': 'required',
                'residentKey': 'preferred'
            },
            'attestation': 'none',
            'timeout': 60000
        }
    
    def complete_registration(self, session_id, credential_data):
        """Complete registration - verify and store credential"""
        if session_id not in self.challenges:
            return {'success': False, 'error': 'Invalid session'}
        
        session = self.challenges[session_id]
        
        if datetime.now() > session['expires']:
            del self.challenges[session_id]
            return {'success': False, 'error': 'Challenge expired'}
        
        user_id = session['user_id']
        
        # In a real implementation, we would:
        # 1. Parse attestation object (CBOR)
        # 2. Verify attestation statement
        # 3. Extract public key
        # 4. Verify authenticator data
        
        # For this simulation, we just store the credential
        credential = {
            'credential_id': credential_data['credential_id'],
            'public_key': credential_data['public_key'],
            'user_id': user_id,
            'user_name': session['user_name'],
            'sign_count': 0,
            'created_at': datetime.now().isoformat(),
            'last_used': datetime.now().isoformat()
        }
        
        if user_id not in self.credentials:
            self.credentials[user_id] = []
        
        self.credentials[user_id].append(credential)
        
        del self.challenges[session_id]
        
        return {'success': True, 'credential_id': credential['credential_id']}
    
    def begin_authentication(self, user_id):
        """Start authentication - return challenge"""
        if user_id not in self.credentials or len(self.credentials[user_id]) == 0:
            return {'success': False, 'error': 'No credentials registered'}
        
        challenge = secrets.token_bytes(32)
        session_id = f"auth_{user_id}_{secrets.token_hex(8)}"
        
        self.challenges[session_id] = {
            'challenge': challenge,
            'user_id': user_id,
            'type': 'authentication',
            'expires': datetime.now() + timedelta(minutes=5)
        }
        
        # Build allowCredentials list
        allow_credentials = []
        for cred in self.credentials[user_id]:
            allow_credentials.append({
                'type': 'public-key',
                'id': cred['credential_id']
            })
        
        return {
            'success': True,
            'session_id': session_id,
            'challenge': base64.urlsafe_b64encode(challenge).decode('ascii'),
            'rpId': self.rp_id,
            'allowCredentials': allow_credentials,
            'userVerification': 'required',
            'timeout': 60000
        }
    
    def complete_authentication(self, session_id, assertion_data):
        """Complete authentication - verify signature"""
        if session_id not in self.challenges:
            return {'success': False, 'error': 'Invalid session'}
        
        session = self.challenges[session_id]
        
        if datetime.now() > session['expires']:
            del self.challenges[session_id]
            return {'success': False, 'error': 'Challenge expired'}
        
        user_id = session['user_id']
        credential_id = assertion_data['credential_id']
        
        # Find credential
        credential = None
        for cred in self.credentials.get(user_id, []):
            if cred['credential_id'] == credential_id:
                credential = cred
                break
        
        if not credential:
            return {'success': False, 'error': 'Credential not found'}
        
        # In a real implementation, we would:
        # 1. Verify signature using stored public key
        # 2. Verify authenticator data
        # 3. Check sign count (replay protection)
        # 4. Verify clientDataJSON
        
        # For this simulation, we assume it's valid
        credential['sign_count'] += 1
        credential['last_used'] = datetime.now().isoformat()
        
        del self.challenges[session_id]
        
        return {
            'success': True,
            'user_id': user_id,
            'user_name': credential['user_name'],
            'credential_id': credential_id
        }
    
    def get_credentials(self, user_id):
        """Get all credentials for a user"""
        return self.credentials.get(user_id, [])


# Global server instance
fido2_server = MockFIDO2Server()


# HTTP Request Handler
class PasskeyHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Custom logging
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {format % args}")
    
    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_html().encode('utf-8'))
        
        elif parsed.path == '/api/credentials':
            params = parse_qs(parsed.query)
            user_id = params.get('user_id', [''])[0]
            
            credentials = fido2_server.get_credentials(user_id)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(credentials, indent=2).encode('utf-8'))
        
        else:
            self.send_error(404)
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        data = json.loads(body) if body else {}
        
        parsed = urlparse(self.path)
        
        if parsed.path == '/api/register/begin':
            user_id = data.get('user_id', '')
            user_name = data.get('user_name', '')
            
            result = fido2_server.begin_registration(user_id, user_name)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
        
        elif parsed.path == '/api/register/complete':
            session_id = data.get('session_id', '')
            credential_data = data.get('credential', {})
            
            result = fido2_server.complete_registration(session_id, credential_data)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
        
        elif parsed.path == '/api/authenticate/begin':
            user_id = data.get('user_id', '')
            
            result = fido2_server.begin_authentication(user_id)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
        
        elif parsed.path == '/api/authenticate/complete':
            session_id = data.get('session_id', '')
            assertion_data = data.get('assertion', {})
            
            result = fido2_server.complete_authentication(session_id, assertion_data)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
        
        else:
            self.send_error(404)
    
    def get_html(self):
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passkey Authentication - Smoke Test</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 14px;
        }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .section h2 {
            color: #333;
            margin-bottom: 15px;
            font-size: 18px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 600;
            font-size: 14px;
        }
        
        .form-group input {
            width: 100%;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        button {
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        
        .btn-secondary:hover {
            background: #5a6268;
        }
        
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .log {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .log-entry {
            margin-bottom: 5px;
            line-height: 1.5;
        }
        
        .log-info { color: #4fc3f7; }
        .log-success { color: #81c784; }
        .log-error { color: #e57373; }
        .log-warn { color: #ffb74d; }
        
        .status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .status-available {
            background: #c8e6c9;
            color: #2e7d32;
        }
        
        .status-unavailable {
            background: #ffcdd2;
            color: #c62828;
        }
        
        .credential-list {
            list-style: none;
            margin-top: 15px;
        }
        
        .credential-item {
            background: white;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 6px;
            border: 1px solid #ddd;
        }
        
        .credential-item strong {
            color: #667eea;
        }
        
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        
        .info-box strong {
            color: #1976d2;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Passkey Authentication Smoke Test</h1>
            <p>FIDO2/WebAuthn Demo using Browser's Platform Authenticator</p>
        </div>
        
        <div class="content">
            <div class="info-box">
                <strong>ℹ️ About this demo:</strong><br>
                This demonstrates passkey authentication using your browser's built-in 
                platform authenticator (Windows Hello, Touch ID, Android biometrics). 
                You'll be prompted to use your PIN, fingerprint, or face recognition.
            </div>
            
            <div class="section">
                <h2>System Status</h2>
                <p>
                    WebAuthn API: <span id="webauthn-status" class="status">Checking...</span>
                </p>
                <p style="margin-top: 10px;">
                    Platform Authenticator: <span id="platform-status" class="status">Checking...</span>
                </p>
            </div>
            
            <div class="section">
                <h2>User Configuration</h2>
                <div class="form-group">
                    <label for="userId">User ID:</label>
                    <input type="text" id="userId" value="user123" placeholder="Enter user ID">
                </div>
                <div class="form-group">
                    <label for="userName">User Name:</label>
                    <input type="text" id="userName" value="Test User" placeholder="Enter display name">
                </div>
            </div>
            
            <div class="section">
                <h2>Passkey Operations</h2>
                <div class="button-group">
                    <button class="btn-primary" id="btnRegister" onclick="registerPasskey()">
                        🔑 Register Passkey
                    </button>
                    <button class="btn-primary" id="btnAuthenticate" onclick="authenticatePasskey()">
                        ✓ Authenticate
                    </button>
                    <button class="btn-secondary" onclick="listCredentials()">
                        📋 List Passkeys
                    </button>
                    <button class="btn-secondary" onclick="clearLog()">
                        🗑️ Clear Log
                    </button>
                </div>
            </div>
            
            <div class="section">
                <h2>Activity Log</h2>
                <div class="log" id="log"></div>
            </div>
        </div>
    </div>
    
    <script>
        // Check WebAuthn availability
        async function checkWebAuthnSupport() {
            const webauthnStatus = document.getElementById('webauthn-status');
            const platformStatus = document.getElementById('platform-status');
            
            if (window.PublicKeyCredential) {
                webauthnStatus.textContent = 'Available';
                webauthnStatus.className = 'status status-available';
                log('✓ WebAuthn API available', 'success');
                
                try {
                    const available = await PublicKeyCredential
                        .isUserVerifyingPlatformAuthenticatorAvailable();
                    
                    if (available) {
                        platformStatus.textContent = 'Available (PIN/Biometric)';
                        platformStatus.className = 'status status-available';
                        log('✓ Platform authenticator available', 'success');
                    } else {
                        platformStatus.textContent = 'Not Available';
                        platformStatus.className = 'status status-unavailable';
                        log('⚠ Platform authenticator not available', 'warn');
                        log('  Please set up Windows Hello, Touch ID, or Android biometrics', 'warn');
                    }
                } catch (err) {
                    platformStatus.textContent = 'Error';
                    platformStatus.className = 'status status-unavailable';
                    log('✗ Error checking platform authenticator: ' + err.message, 'error');
                }
            } else {
                webauthnStatus.textContent = 'Not Available';
                webauthnStatus.className = 'status status-unavailable';
                log('✗ WebAuthn API not available in this browser', 'error');
                log('  Please use a modern browser (Chrome, Edge, Firefox, Safari)', 'error');
            }
        }
        
        // Logging
        function log(message, type = 'info') {
            const logDiv = document.getElementById('log');
            const entry = document.createElement('div');
            entry.className = 'log-entry log-' + type;
            
            const timestamp = new Date().toLocaleTimeString();
            entry.textContent = `[${timestamp}] ${message}`;
            
            logDiv.appendChild(entry);
            logDiv.scrollTop = logDiv.scrollHeight;
        }
        
        function clearLog() {
            document.getElementById('log').innerHTML = '';
            log('Log cleared', 'info');
        }
        
        // Helper functions
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
        
        function base64URLToBuffer(base64) {
            const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
            const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }
        
        // Register passkey
        async function registerPasskey() {
            const userId = document.getElementById('userId').value;
            const userName = document.getElementById('userName').value;
            
            if (!userId || !userName) {
                log('✗ Please enter User ID and User Name', 'error');
                return;
            }
            
            log('--- Register Passkey ---', 'info');
            log(`User ID: ${userId}`, 'info');
            log(`User Name: ${userName}`, 'info');
            log('', 'info');
            
            try {
                log('[INFO] Requesting registration options from server...', 'info');
                
                // Get registration options from server
                const beginResponse = await fetch('/api/register/begin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({user_id: userId, user_name: userName})
                });
                
                const options = await beginResponse.json();
                log('[OK] Received registration options', 'success');
                log(`     Challenge: ${options.challenge.substring(0, 20)}...`, 'info');
                log('', 'info');
                
                // Convert challenge and user ID to ArrayBuffer
                options.challenge = base64URLToBuffer(options.challenge);
                options.user.id = base64URLToBuffer(options.user.id);
                
                log('[INFO] Calling navigator.credentials.create()...', 'info');
                log('[INFO] Browser will prompt for PIN/biometric', 'info');
                log('[INFO] Please complete authentication...', 'info');
                log('', 'info');
                
                // Create credential
                const credential = await navigator.credentials.create({
                    publicKey: options
                });
                
                log('[OK] Credential created!', 'success');
                log(`     Credential ID: ${bufferToBase64URL(credential.rawId).substring(0, 20)}...`, 'info');
                log('', 'info');
                
                // Send to server
                log('[INFO] Sending credential to server...', 'info');
                
                const completeResponse = await fetch('/api/register/complete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        session_id: options.session_id,
                        credential: {
                            credential_id: bufferToBase64URL(credential.rawId),
                            public_key: bufferToBase64URL(credential.response.attestationObject),
                            client_data: bufferToBase64URL(credential.response.clientDataJSON)
                        }
                    })
                });
                
                const result = await completeResponse.json();
                
                if (result.success) {
                    log('[SUCCESS] Passkey registered!', 'success');
                    log(`          Credential ID: ${result.credential_id.substring(0, 30)}...`, 'success');
                    log('', 'info');
                    log('[INFO] You can now authenticate with this passkey', 'info');
                    alert('✓ Passkey registered successfully!\\n\\nYou can now click "Authenticate" to test it.');
                } else {
                    log(`[ERROR] Registration failed: ${result.error}`, 'error');
                    alert('✗ Registration failed: ' + result.error);
                }
                
            } catch (err) {
                if (err.name === 'NotAllowedError') {
                    log('[ERROR] User cancelled or timeout', 'error');
                } else {
                    log(`[ERROR] ${err.name}: ${err.message}`, 'error');
                }
                alert('Registration failed: ' + err.message);
            }
            
            log('', 'info');
        }
        
        // Authenticate with passkey
        async function authenticatePasskey() {
            const userId = document.getElementById('userId').value;
            
            if (!userId) {
                log('✗ Please enter User ID', 'error');
                return;
            }
            
            log('--- Authenticate with Passkey ---', 'info');
            log(`User ID: ${userId}`, 'info');
            log('', 'info');
            
            try {
                log('[INFO] Requesting authentication options from server...', 'info');
                
                // Get authentication options from server
                const beginResponse = await fetch('/api/authenticate/begin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({user_id: userId})
                });
                
                const options = await beginResponse.json();
                
                if (!options.success) {
                    log(`[ERROR] ${options.error}`, 'error');
                    alert('Error: ' + options.error);
                    return;
                }
                
                log('[OK] Received authentication options', 'success');
                log(`     Challenge: ${options.challenge.substring(0, 20)}...`, 'info');
                log(`     Allowed credentials: ${options.allowCredentials.length}`, 'info');
                log('', 'info');
                
                // Convert challenge and credential IDs to ArrayBuffer
                options.challenge = base64URLToBuffer(options.challenge);
                options.allowCredentials = options.allowCredentials.map(cred => ({
                    ...cred,
                    id: base64URLToBuffer(cred.id)
                }));
                
                log('[INFO] Calling navigator.credentials.get()...', 'info');
                log('[INFO] Browser will prompt for PIN/biometric', 'info');
                log('[INFO] Please complete authentication...', 'info');
                log('', 'info');
                
                // Get assertion
                const assertion = await navigator.credentials.get({
                    publicKey: options
                });
                
                log('[OK] Assertion created!', 'success');
                log(`     Credential ID: ${bufferToBase64URL(assertion.rawId).substring(0, 20)}...`, 'info');
                log('', 'info');
                
                // Send to server
                log('[INFO] Sending assertion to server for verification...', 'info');
                
                const completeResponse = await fetch('/api/authenticate/complete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        session_id: options.session_id,
                        assertion: {
                            credential_id: bufferToBase64URL(assertion.rawId),
                            authenticator_data: bufferToBase64URL(assertion.response.authenticatorData),
                            client_data: bufferToBase64URL(assertion.response.clientDataJSON),
                            signature: bufferToBase64URL(assertion.response.signature)
                        }
                    })
                });
                
                const result = await completeResponse.json();
                
                if (result.success) {
                    log('[SUCCESS] Authentication successful!', 'success');
                    log(`          User: ${result.user_name} (${result.user_id})`, 'success');
                    log(`          Credential: ${result.credential_id.substring(0, 30)}...`, 'success');
                    log('', 'info');
                    log('[INFO] Session established', 'info');
                    log('[INFO] User is now logged in!', 'success');
                    alert('✓ Authentication successful!\\n\\nUser: ' + result.user_name + '\\nUser ID: ' + result.user_id);
                } else {
                    log(`[ERROR] Authentication failed: ${result.error}`, 'error');
                    alert('✗ Authentication failed: ' + result.error);
                }
                
            } catch (err) {
                if (err.name === 'NotAllowedError') {
                    log('[ERROR] User cancelled or timeout', 'error');
                } else {
                    log(`[ERROR] ${err.name}: ${err.message}`, 'error');
                }
                alert('Authentication failed: ' + err.message);
            }
            
            log('', 'info');
        }
        
        // List credentials
        async function listCredentials() {
            const userId = document.getElementById('userId').value;
            
            if (!userId) {
                log('✗ Please enter User ID', 'error');
                return;
            }
            
            log('--- List Registered Passkeys ---', 'info');
            log(`User ID: ${userId}`, 'info');
            log('', 'info');
            
            try {
                const response = await fetch(`/api/credentials?user_id=${encodeURIComponent(userId)}`);
                const credentials = await response.json();
                
                if (credentials.length === 0) {
                    log('[INFO] No passkeys registered for this user', 'info');
                    alert('No passkeys registered for user: ' + userId);
                } else {
                    log(`[INFO] Found ${credentials.length} passkey(s):`, 'success');
                    log('', 'info');
                    
                    credentials.forEach((cred, i) => {
                        log(`  Passkey #${i + 1}`, 'info');
                        log(`    Credential ID: ${cred.credential_id.substring(0, 40)}...`, 'info');
                        log(`    User: ${cred.user_name} (${cred.user_id})`, 'info');
                        log(`    Sign Count: ${cred.sign_count}`, 'info');
                        log(`    Created: ${cred.created_at}`, 'info');
                        log(`    Last Used: ${cred.last_used}`, 'info');
                        log('', 'info');
                    });
                    
                    alert(`Found ${credentials.length} passkey(s). See log for details.`);
                }
                
            } catch (err) {
                log(`[ERROR] ${err.message}`, 'error');
                alert('Error: ' + err.message);
            }
            
            log('', 'info');
        }
        
        // Initialize
        window.addEventListener('load', () => {
            log('=== Passkey Authentication Smoke Test ===', 'info');
            log('', 'info');
            checkWebAuthnSupport();
            log('', 'info');
        });
    </script>
</body>
</html>'''


# Main
if __name__ == '__main__':
    print('=== Passkey Authentication Smoke Test ===')
    print()
    print('Starting server on http://localhost:8080')
    print()
    print('Open your browser and navigate to:')
    print('  http://localhost:8080')
    print()
    print('The demo will use your browser\'s built-in WebAuthn API')
    print('and prompt for PIN/biometric authentication.')
    print()
    print('Press Ctrl+C to stop the server')
    print()
    
    server = HTTPServer(('0.0.0.0', 8080), PasskeyHandler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print('Server stopped')
        server.shutdown()
