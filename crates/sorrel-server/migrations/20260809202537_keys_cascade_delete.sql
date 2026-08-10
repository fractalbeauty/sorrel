CREATE TABLE keys_new (
  public_key BLOB PRIMARY KEY NOT NULL,
  app TEXT NOT NULL,
  session_id BLOB NOT NULL,
  FOREIGN KEY (session_id) REFERENCES sessions (id) ON DELETE CASCADE
);

INSERT INTO keys_new SELECT public_key, app, session_id FROM keys;

DROP TABLE keys;

ALTER TABLE keys_new RENAME TO keys;
