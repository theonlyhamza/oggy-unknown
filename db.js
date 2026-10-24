'use strict';

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

// Prefer DB_PATH from env, else fall back to ./data/app.db next to the app.
// On Render Free tier, /data is read-only — only a paid disk makes it writable.
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'app.db');

try {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
} catch (e) {
  if (e.code !== 'EEXIST') {
    console.error(`[db] cannot create dir for ${DB_PATH}: ${e.message}`);
    console.error('[db] tip: unset DB_PATH or set it to ./data/app.db on Free tier,');
    console.error('[db]      or attach a persistent disk mounted at /data (paid plan).');
    process.exit(1);
  }
}

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    redirect_url TEXT NOT NULL DEFAULT 'https://example.com',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    ip TEXT,
    forwarded_for TEXT,
    real_ip TEXT,
    cf_country TEXT,
    user_agent TEXT,
    accept_language TEXT,
    referer TEXT,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_visits_user ON visits(user_id, id DESC);
`);

console.log(`[db] using ${DB_PATH}`);
module.exports = db;
