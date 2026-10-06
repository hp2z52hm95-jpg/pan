# Pandora Login — Password + Passkey

Web login page + FIDO2/WebAuthn API server for Pandora Tool.
The login page is served by the API server itself (same origin, no CORS issues).

## Quick start

```bash
cd passkey_test/server
npm install
cp .env.example .env   # then edit RP_ID / WEBAUTHN_ORIGIN for your domain
npm start              # -> http://localhost:3000  (login page)
```

> **WebAuthn rule:** `RP_ID` must be the domain serving the page (no protocol),
> and `WEBAUTHN_ORIGIN` the full origin. Passkeys require HTTPS or localhost.
> Example for local dev: `RP_ID=localhost`, `WEBAUTHN_ORIGIN=http://localhost:3000`.

## What the login page does

- **Sign in tab** — username + password, or **🔑 Sign in with a passkey**
  (fingerprint / face / PIN / security key via the browser's WebAuthn prompt).
- **Create account tab** — register, auto sign-in, then get prompted to add a passkey.
- **Dashboard** — session info, passkey list (add with a device name, delete),
  credits, logout. Session survives page reload via JWT in `localStorage`.

Pure HTML/CSS/JS in `public/` — zero frontend dependencies, no CDN required.

## API (used by the page)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/register` | – | Create account |
| POST | `/api/auth/login` | – | Password login → JWT |
| GET | `/api/auth/me` | JWT | Current user |
| POST | `/api/auth/logout` | JWT | Invalidate session |
| POST | `/api/passkey/register/begin` | JWT | WebAuthn creation options |
| POST | `/api/passkey/register/complete` | JWT | Store new passkey |
| POST | `/api/passkey/authenticate/begin` | – | WebAuthn request options |
| POST | `/api/passkey/authenticate/complete` | – | Verify assertion → JWT |
| GET | `/api/passkey/list` | JWT | List user's passkeys |
| DELETE | `/api/passkey/:id` | JWT | Delete a passkey |
| GET | `/api/updates/check?app=&current=` | – | Check for updates (launcher) |
| GET | `/api/updates/download/:file` | JWT | Download update package (launcher) |

The Delphi launcher/updater source is in `/launcher` (login + passkey +
auto-update, runs `PandoraTool.exe` after login).

## Notes

- Database is SQLite via Node's built-in `node:sqlite` (no native modules).
  File lives at `DB_PATH` (default `./database/pandora.db`), auto-created.
- Requires Node 22+ (`--experimental-sqlite` flag is already in `npm start`).
- Any authenticator works: platform (Windows Hello, Touch ID), password
  managers (1Password, Bitwarden, …), and cross-platform security keys.
