/* Pandora Tool — Login + Passkey frontend (no dependencies, pure WebAuthn) */
'use strict';

const $ = (id) => document.getElementById(id);
const API = ''; // same origin — page is served by the API server

/* ---------------- base64url helpers ---------------- */
function b64urlToBuffer(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), '='));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function bufferToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* ---------------- state ---------------- */
const store = {
  get token() { return localStorage.getItem('pandora_token'); },
  get user() { try { return JSON.parse(localStorage.getItem('pandora_user')); } catch { return null; } },
  save(token, user) {
    localStorage.setItem('pandora_token', token);
    localStorage.setItem('pandora_user', JSON.stringify(user));
  },
  clear() { localStorage.removeItem('pandora_token'); localStorage.removeItem('pandora_user'); },
};

async function api(path, { method = 'GET', body, auth = false } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth) headers['Authorization'] = 'Bearer ' + store.token;
  const res = await fetch(API + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (res.status === 401 && auth) { logout(true); throw new Error('Session expired — please sign in again.'); }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

/* ---------------- ui helpers ---------------- */
function toast(msg, type = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 350); }, 4200);
}
function setLoading(btn, on) {
  btn.disabled = on;
  btn.classList.toggle('loading', on);
}
function showError(el, msg) { el.textContent = msg || ''; }

function showView(name) {
  $('authView').classList.toggle('hidden', name !== 'auth');
  $('dashView').classList.toggle('hidden', name !== 'dash');
}

function switchTab(which) {
  const login = which === 'login';
  $('tabLogin').classList.toggle('active', login);
  $('tabRegister').classList.toggle('active', !login);
  $('tabLogin').setAttribute('aria-selected', login);
  $('tabRegister').setAttribute('aria-selected', !login);
  $('loginForm').classList.toggle('hidden', !login);
  $('registerForm').classList.toggle('hidden', login);
  showError($('loginError')); showError($('registerError'));
}

/* ---------------- webauthn support check ---------------- */
(function checkSupport() {
  const el = $('webauthnStatus');
  const ok = window.isSecureContext && window.PublicKeyCredential;
  if (ok) {
    el.textContent = '✅ This browser supports passkeys (WebAuthn).';
    el.classList.add('ok');
  } else if (!window.isSecureContext) {
    el.textContent = '⚠️ Passkeys need a secure context (HTTPS or localhost). Password sign-in still works.';
    el.classList.add('no');
  } else {
    el.textContent = '⚠️ This browser does not support passkeys. Password sign-in still works.';
    el.classList.add('no');
  }
})();

/* ---------------- auth flows ---------------- */
async function onPasswordLogin(e) {
  e.preventDefault();
  const username = $('loginUsername').value.trim();
  const password = $('loginPassword').value;
  showError($('loginError'));
  if (!username || !password) return showError($('loginError'), 'Enter your username and password.');
  setLoading($('loginBtn'), true);
  try {
    const data = await api('/api/auth/login', { method: 'POST', body: { username, password } });
    enterDashboard(data.token, data.user, 'password');
    toast(`Welcome back, ${data.user.displayName || data.user.username}! 👋`, 'ok');
  } catch (err) {
    showError($('loginError'), err.message);
  } finally {
    setLoading($('loginBtn'), false);
  }
}

async function onPasskeyLogin() {
  const username = $('loginUsername').value.trim();
  showError($('loginError'));
  if (!username) return showError($('loginError'), 'Enter your username first, then use your passkey.');
  if (!window.PublicKeyCredential) return showError($('loginError'), 'Passkeys are not supported in this browser.');
  setLoading($('passkeyLoginBtn'), true);
  try {
    // 1. Begin — get challenge from server
    const opts = await api('/api/passkey/authenticate/begin', { method: 'POST', body: { username } });

    // 2. Ask the authenticator to sign (browser shows fingerprint / PIN / security-key prompt)
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: b64urlToBuffer(opts.challenge),
        rpId: opts.rpId,
        timeout: opts.timeout,
        userVerification: opts.userVerification || 'preferred',
        allowCredentials: (opts.allowCredentials || []).map((c) => ({
          id: b64urlToBuffer(c.id),
          type: c.type,
        })),
      },
    });

    // 3. Complete — send assertion to server for verification
    const data = await api('/api/passkey/authenticate/complete', {
      method: 'POST',
      body: {
        challengeId: opts.challengeId,
        userId: opts.userId,
        response: credentialToJSON(credential),
      },
    });
    enterDashboard(data.token, data.user, 'passkey');
    toast(`Signed in with passkey as ${data.user.displayName || data.user.username}! 🔑`, 'ok');
  } catch (err) {
    showError($('loginError'), friendlyWebAuthnError(err));
  } finally {
    setLoading($('passkeyLoginBtn'), false);
  }
}

async function onRegister(e) {
  e.preventDefault();
  const displayName = $('regDisplayName').value.trim();
  const username = $('regUsername').value.trim();
  const email = $('regEmail').value.trim();
  const password = $('regPassword').value;
  showError($('registerError'));
  if (!username || username.length < 3) return showError($('registerError'), 'Username must be at least 3 characters.');
  if (!email || !email.includes('@')) return showError($('registerError'), 'Enter a valid email address.');
  if (!password || password.length < 8) return showError($('registerError'), 'Password must be at least 8 characters.');
  setLoading($('registerBtn'), true);
  try {
    await api('/api/auth/register', { method: 'POST', body: { username, email, password, displayName: displayName || username } });
    // Auto sign-in with the new credentials
    const data = await api('/api/auth/login', { method: 'POST', body: { username, password } });
    enterDashboard(data.token, data.user, 'password');
    toast('Account created! 🎉 Now add a passkey for one-tap sign-in.', 'ok');
  } catch (err) {
    showError($('registerError'), err.message);
  } finally {
    setLoading($('registerBtn'), false);
  }
}

/* ---------------- dashboard ---------------- */
function enterDashboard(token, user, method) {
  store.save(token, user);
  renderUser(user, method);
  showView('dash');
  loadPasskeys();
}

function renderUser(user, method) {
  const name = user.displayName || user.display_name || user.username;
  $('avatar').textContent = (name[0] || '?').toUpperCase();
  $('dashName').textContent = name;
  $('dashEmail').textContent = `${user.username} · ${user.email || ''}`;
  $('dashCredits').textContent = user.credits ?? 0;
  const pill = $('sessionPill');
  if (method === 'passkey') {
    pill.textContent = '🔑 passkey session';
    pill.classList.remove('password');
  } else {
    pill.textContent = '● password session';
    pill.classList.add('password');
  }
}

async function loadPasskeys() {
  showError($('dashError'));
  try {
    const { passkeys = [] } = await api('/api/passkey/list', { auth: true });
    const list = $('passkeyList');
    list.innerHTML = '';
    $('passkeyEmpty').classList.toggle('hidden', passkeys.length > 0);
    for (const pk of passkeys) {
      const li = document.createElement('li');
      const created = pk.created_at ? new Date(pk.created_at).toLocaleDateString() : '—';
      const used = pk.last_used ? new Date(pk.last_used).toLocaleString() : 'never';
      li.innerHTML = `
        <span class="pk-icon">🔑</span>
        <div class="pk-info"><strong></strong><span>Added ${created} · Last used ${used}</span></div>
      `;
      li.querySelector('strong').textContent = pk.name || 'Unnamed passkey';
      const del = document.createElement('button');
      del.className = 'btn danger small';
      del.textContent = 'Delete';
      del.onclick = () => deletePasskey(pk.id, pk.name);
      li.appendChild(del);
      list.appendChild(li);
    }
  } catch (err) {
    showError($('dashError'), err.message);
  }
}

async function onAddPasskey() {
  showError($('dashError'));
  if (!window.PublicKeyCredential) return showError($('dashError'), 'Passkeys are not supported in this browser.');
  const deviceName = $('deviceName').value.trim() || 'My device';
  setLoading($('addPasskeyBtn'), true);
  try {
    // 1. Begin — get creation options from server
    const opts = await api('/api/passkey/register/begin', { method: 'POST', auth: true });

    // 2. Create the credential (browser shows fingerprint / PIN / security-key prompt)
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: b64urlToBuffer(opts.challenge),
        rp: opts.rp,
        user: {
          id: b64urlToBuffer(opts.user.id),
          name: opts.user.name,
          displayName: opts.user.displayName,
        },
        pubKeyCredParams: opts.pubKeyCredParams,
        timeout: opts.timeout,
        attestation: opts.attestation || 'none',
        authenticatorSelection: opts.authenticatorSelection,
        excludeCredentials: (opts.excludeCredentials || []).map((c) => ({
          id: b64urlToBuffer(c.id),
          type: c.type,
        })),
      },
    });

    // 3. Complete — send attestation to server
    await api('/api/passkey/register/complete', {
      method: 'POST',
      auth: true,
      body: { challengeId: opts.challengeId, deviceName, response: credentialToJSON(credential) },
    });
    $('deviceName').value = '';
    toast(`Passkey "${deviceName}" added! 🎉`, 'ok');
    loadPasskeys();
  } catch (err) {
    showError($('dashError'), friendlyWebAuthnError(err));
  } finally {
    setLoading($('addPasskeyBtn'), false);
  }
}

async function deletePasskey(id, name) {
  if (!confirm(`Delete passkey "${name || 'Unnamed'}"?`)) return;
  try {
    await api(`/api/passkey/${id}`, { method: 'DELETE', auth: true });
    toast('Passkey deleted.', 'ok');
    loadPasskeys();
  } catch (err) {
    showError($('dashError'), err.message);
  }
}

async function logout(silent = false) {
  try { if (store.token) await api('/api/auth/logout', { method: 'POST', auth: true }); } catch { /* ignore */ }
  store.clear();
  showView('auth');
  if (!silent) toast('Signed out. See you soon! 👋');
}

/* Serialize a WebAuthn credential for transport (base64url) */
function credentialToJSON(cred) {
  const out = { id: cred.id, rawId: bufferToB64url(cred.rawId), type: cred.type, response: {} };
  const r = cred.response;
  for (const k of ['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
    if (r[k]) out.response[k] = bufferToB64url(r[k]);
  }
  if (typeof cred.getClientExtensionResults === 'function') {
    out.clientExtensionResults = cred.getClientExtensionResults();
  }
  if (typeof r.getTransports === 'function') {
    out.response.transports = r.getTransports();
  }
  return out;
}

function friendlyWebAuthnError(err) {
  if (err?.name === 'NotAllowedError') return 'Passkey prompt was cancelled or timed out. Try again.';
  if (err?.name === 'InvalidStateError') return 'This passkey is already registered on this device.';
  if (err?.name === 'NotSupportedError') return 'This device does not support passkeys.';
  if (err?.name === 'SecurityError') return 'Security error — passkeys require HTTPS or localhost.';
  return err.message || 'Passkey operation failed.';
}

/* ---------------- wire up ---------------- */
$('tabLogin').onclick = () => switchTab('login');
$('tabRegister').onclick = () => switchTab('register');
$('loginForm').addEventListener('submit', onPasswordLogin);
$('registerForm').addEventListener('submit', onRegister);
$('passkeyLoginBtn').onclick = onPasskeyLogin;
$('addPasskeyBtn').onclick = onAddPasskey;
$('refreshBtn').onclick = loadPasskeys;
$('logoutBtn').onclick = () => logout(false);
document.querySelectorAll('.peek').forEach((btn) => {
  btn.onclick = () => {
    const input = $(btn.dataset.peek);
    input.type = input.type === 'password' ? 'text' : 'password';
  };
});

/* Restore session on load */
(async function init() {
  if (!store.token || !store.user) return;
  try {
    const data = await api('/api/auth/me', { auth: true });
    const user = data.user || data;
    enterDashboard(store.token, user, user.sessionType || 'password');
  } catch {
    store.clear();
  }
})();
