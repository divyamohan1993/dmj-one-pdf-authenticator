PRAGMA foreign_keys = ON;

-- Admins (password hash stored in env as requested; this table links sessions/audit)
CREATE TABLE IF NOT EXISTS admins (
  id           TEXT PRIMARY KEY,
  username     TEXT UNIQUE NOT NULL,
  totp_enc     BLOB,
  created_at   INTEGER NOT NULL
);

-- Server-managed sessions (opaque id cookie)
CREATE TABLE IF NOT EXISTS sessions (
  id           TEXT PRIMARY KEY,
  admin_id     TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  csrf_token   BLOB NOT NULL,
  iat          INTEGER NOT NULL,
  exp          INTEGER NOT NULL,
  ip_hash      BLOB NOT NULL,
  ua_hash      BLOB NOT NULL
);

-- Signature metadata (what key, alg, etc.)
CREATE TABLE IF NOT EXISTS signatures (
  id                TEXT PRIMARY KEY,
  cert_serial       TEXT NOT NULL,
  cert_spki_sha256  BLOB NOT NULL,
  name              TEXT NOT NULL,
  reason            TEXT NOT NULL,
  subfilter         TEXT NOT NULL,
  alg               TEXT NOT NULL,
  created_at        INTEGER NOT NULL
);

-- Documents (store only the final signed PDF hash)
-- status: 1=issued, 2=revoked
CREATE TABLE IF NOT EXISTS documents (
  id             TEXT PRIMARY KEY,
  sha256         BLOB UNIQUE NOT NULL,
  size_bytes     INTEGER NOT NULL,
  filename       TEXT,
  status         INTEGER NOT NULL,
  issued_at      INTEGER NOT NULL,
  signature_id   TEXT NOT NULL REFERENCES signatures(id),
  CHECK (status IN (1,2))
);
CREATE INDEX IF NOT EXISTS idx_docs_status ON documents(status);
CREATE INDEX IF NOT EXISTS idx_docs_issued_at ON documents(issued_at DESC);

-- Revocations
CREATE TABLE IF NOT EXISTS revocations (
  id            TEXT PRIMARY KEY,
  document_id   TEXT NOT NULL REFERENCES documents(id),
  revoked_by    TEXT NOT NULL REFERENCES admins(id),
  reason        TEXT,
  revoked_at    INTEGER NOT NULL
);

-- Replay-guard nonces used in Worker→Signer HMAC
CREATE TABLE IF NOT EXISTS gateway_nonces (
  nonce     TEXT PRIMARY KEY,
  ts        INTEGER NOT NULL
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
  id        TEXT PRIMARY KEY,
  who       TEXT,
  action    TEXT NOT NULL,
  doc_sha   BLOB,
  ts        INTEGER NOT NULL,
  ip_hash   BLOB,
  ua_hash   BLOB
);

-- Simple rate limits (leaky bucket per key)
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket     TEXT PRIMARY KEY,
  window_s   INTEGER NOT NULL,
  count      INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Config store (e.g., 'signer_spki_sha256')
CREATE TABLE IF NOT EXISTS config (
  key    TEXT PRIMARY KEY,
  value  TEXT NOT NULL
);
