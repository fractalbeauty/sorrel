CREATE TABLE IF NOT EXISTS users (
  id BLOB PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  user_id BLOB NOT NULL,
  PRIMARY KEY (provider, subject),
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS keys (
  public_key BLOB PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  user_id BLOB NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS device_codes (
  device_code_hash BLOB PRIMARY KEY NOT NULL,
  user_code_hash BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  user_id BLOB,
  is_used BOOLEAN NOT NULL DEFAULT 0,
  device_name_hint TEXT,
  device_ip_hint TEXT,
  FOREIGN KEY (user_id) REFERENCES users (id)
);
