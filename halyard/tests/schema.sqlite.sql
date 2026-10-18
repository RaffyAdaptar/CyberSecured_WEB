-- Test-only schema so the smoke test can run without a MySQL server.
-- Mirrors database/schema.sql.
CREATE TABLE users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL,
  username_key  TEXT NOT NULL UNIQUE,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  last_login_at TEXT NULL
);

CREATE TABLE auth_attempts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  kind         TEXT NOT NULL,
  ip           TEXT NOT NULL,
  subject_hash TEXT NOT NULL,
  attempted_at INTEGER NOT NULL
);
CREATE INDEX idx_attempts_ip ON auth_attempts (kind, ip, attempted_at);
CREATE INDEX idx_attempts_subject ON auth_attempts (kind, ip, subject_hash, attempted_at);
