/**
 * Database Models and Initialization
 *
 * SQLite database for storing users, passkeys, and challenges.
 * Uses Node.js built-in `node:sqlite` (no native dependencies).
 * Run node with `--experimental-sqlite` on Node 22.
 */

const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');
const config = require('../config');

class Database {
  constructor() {
    this.db = null;
  }

  async initialize() {
    const dbPath = path.resolve(config.database.path);
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    // Sensible defaults
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    await this.createTables();
  }

  async createTables() {
    const queries = [
      // Users table
      `CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        is_active BOOLEAN DEFAULT 1,
        box_sn TEXT,
        credits INTEGER DEFAULT 0
      )`,

      // Passkeys table
      `CREATE TABLE IF NOT EXISTS passkeys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        credential_id TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        counter INTEGER DEFAULT 0,
        device_type TEXT,
        backed_up BOOLEAN DEFAULT 0,
        transports TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used DATETIME,
        name TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`,

      // Challenges table (for WebAuthn flows)
      `CREATE TABLE IF NOT EXISTS challenges (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        challenge TEXT NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('registration', 'authentication')),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        used BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`,

      // Sessions table
      `CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`,

      // Audit log
      `CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      )`,

      // Indexes for performance
      `CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
      `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
      `CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_passkeys_credential_id ON passkeys(credential_id)`,
      `CREATE INDEX IF NOT EXISTS idx_challenges_challenge ON challenges(challenge)`,
      `CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)`
    ];

    for (const query of queries) {
      await this.run(query);
    }

    console.log('✓ Database tables created');
  }

  run(sql, params = []) {
    const stmt = this.db.prepare(sql);
    const info = stmt.run(...params);
    return Promise.resolve({ lastID: Number(info.lastInsertRowid), changes: Number(info.changes) });
  }

  get(sql, params = []) {
    const stmt = this.db.prepare(sql);
    return Promise.resolve(stmt.get(...params));
  }

  all(sql, params = []) {
    const stmt = this.db.prepare(sql);
    return Promise.resolve(stmt.all(...params));
  }

  close() {
    if (this.db) this.db.close();
    return Promise.resolve();
  }
}

module.exports = new Database();
