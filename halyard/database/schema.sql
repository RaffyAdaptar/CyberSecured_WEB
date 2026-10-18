-- Halyard database schema (MySQL 5.7+ / MariaDB 10.3+)
-- Run once:  mysql -u root -p < database/schema.sql

CREATE DATABASE IF NOT EXISTS halyard
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE halyard;

CREATE TABLE IF NOT EXISTS users (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username      VARCHAR(24)  NOT NULL,            -- as typed, used for display
  username_key  VARCHAR(24)  NOT NULL,            -- lowercase copy, used for uniqueness and lookup
  email         VARCHAR(254) NOT NULL,            -- stored lowercase
  password_hash VARCHAR(255) NOT NULL,            -- Argon2id (or bcrypt) hash, never the password
  created_at    DATETIME     NOT NULL,            -- UTC
  last_login_at DATETIME     NULL,                -- UTC
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username_key (username_key),
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Failed sign-ins and sign-up attempts, used for rate limiting.
-- subject_hash is a SHA-256 of the identifier, so no raw emails or usernames are stored here.
CREATE TABLE IF NOT EXISTS auth_attempts (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  kind         VARCHAR(16)  NOT NULL,             -- 'login' or 'register'
  ip           VARCHAR(45)  NOT NULL,
  subject_hash CHAR(64)     NOT NULL,
  attempted_at INT UNSIGNED NOT NULL,             -- unix time
  PRIMARY KEY (id),
  KEY idx_attempts_ip (kind, ip, attempted_at),
  KEY idx_attempts_subject (kind, ip, subject_hash, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Least-privilege database account for the app (do NOT run the app as root).
-- Change the password, then uncomment and run as a MySQL admin:
--
-- CREATE USER 'halyard_app'@'localhost' IDENTIFIED BY 'change-this-long-random-password';
-- GRANT SELECT, INSERT, UPDATE ON halyard.users         TO 'halyard_app'@'localhost';
-- GRANT SELECT, INSERT, DELETE ON halyard.auth_attempts TO 'halyard_app'@'localhost';
-- FLUSH PRIVILEGES;
-- ---------------------------------------------------------------------------
