CREATE TABLE IF NOT EXISTS users (
  id BLOB PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS credentials (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  user_id BLOB NOT NULL,
  PRIMARY KEY (provider, subject),
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS keys (
  public_key BLOB PRIMARY KEY,
  name TEXT NOT NULL,
  user_id BLOB NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users (id)
);
