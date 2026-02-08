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

CREATE TABLE IF NOT EXISTS auth_codes (
  auth_code_hash BLOB PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  user_id BLOB NOT NULL,
  is_used BOOLEAN NOT NULL DEFAULT 0,
  device_name TEXT,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- TODO: split into user_codes and device_codes tables
CREATE TABLE IF NOT EXISTS device_codes (
  device_code_hash BLOB PRIMARY KEY NOT NULL,
  user_code_hash BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  user_id BLOB,
  is_used BOOLEAN NOT NULL DEFAULT 0,
  device_name_hint TEXT,
  device_ip_hint TEXT,
  UNIQUE (user_code_hash),
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id BLOB PRIMARY KEY NOT NULL,
  token_hash BLOB NOT NULL,
  last_used_at INTEGER NOT NULL,
  user_id BLOB NOT NULL,
  device_name TEXT,
  UNIQUE (token_hash),
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS keys (
  public_key BLOB PRIMARY KEY NOT NULL,
  app TEXT NOT NULL,
  session_id BLOB NOT NULL,
  FOREIGN KEY (session_id) REFERENCES sessions (id)
);
