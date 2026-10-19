const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

// Ensure data directory exists
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'app.db');
const db = new DatabaseSync(dbPath);

// Enable WAL mode & Foreign Keys
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

// ── Schema ──
db.exec(`
  CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    company TEXT,
    phone TEXT,
    message TEXT NOT NULL,
    source TEXT DEFAULT 'contact_form',
    status TEXT DEFAULT 'new',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS newsletter_subscribers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    subscribed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'viewer',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS site_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stat_key TEXT UNIQUE NOT NULL,
    stat_value TEXT NOT NULL,
    stat_label TEXT NOT NULL,
    display_order INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expired_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS email_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    token_expiry INTEGER,
    connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_scanned_at DATETIME,
    status TEXT DEFAULT 'connected',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS email_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER,
    message_id TEXT UNIQUE,
    thread_id TEXT,
    sender TEXT NOT NULL,
    sender_name TEXT,
    recipient TEXT,
    subject TEXT,
    date DATETIME,
    snippet TEXT,
    body_text TEXT,
    summary TEXT,
    threat_score INTEGER DEFAULT 0,
    threat_level TEXT DEFAULT 'safe',
    is_phishing INTEGER DEFAULT 0,
    phishing_reasons TEXT,
    malicious_links TEXT,
    suspicious_attachments TEXT,
    leaked_secrets TEXT,
    auth_issues TEXT,
    classification_category TEXT DEFAULT 'legitimate',
    classification_confidence REAL DEFAULT 0,
    classification_details TEXT,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES email_accounts(id) ON DELETE CASCADE
  );

  CREATE TRIGGER IF NOT EXISTS trg_contacts_updated_at
  AFTER UPDATE OF name, email, company, phone, message, source, status ON contacts
  FOR EACH ROW
  BEGIN
    UPDATE contacts SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
  END;

  CREATE TRIGGER IF NOT EXISTS trg_site_stats_updated_at
  AFTER UPDATE OF stat_key, stat_value, stat_label, display_order ON site_stats
  FOR EACH ROW
  BEGIN
    UPDATE site_stats SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
  END;

  CREATE TABLE IF NOT EXISTS scanner_daemon (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    is_enabled INTEGER DEFAULT 1,
    interval_minutes INTEGER DEFAULT 5,
    last_run_at DATETIME,
    last_status TEXT DEFAULT 'idle',
    last_items_scanned INTEGER DEFAULT 0,
    last_threats_detected INTEGER DEFAULT 0
  );

  INSERT OR IGNORE INTO scanner_daemon (id, is_enabled, interval_minutes, last_status) VALUES (1, 1, 5, 'idle');
`);

// Safe runtime migration for existing databases
try {
  db.exec("ALTER TABLE email_scans ADD COLUMN classification_category TEXT DEFAULT 'legitimate';");
} catch (_) {}

try {
  db.exec("ALTER TABLE email_scans ADD COLUMN classification_confidence REAL DEFAULT 0;");
} catch (_) {}

try {
  db.exec("ALTER TABLE email_scans ADD COLUMN classification_details TEXT;");
} catch (_) {}

module.exports = db;
