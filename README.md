# sorrel

Device management server for use with Iroh

- Authenticate using a configured OpenID Connect provider
- Receive a long-lived session token
- Set a public key for an application
- List public keys for an application
- List and revoke sessions

## Developing

- Add `DATABASE_URL="sqlite://./local/database.sqlite"` to `.env` for sqlx
- Create `./local/config.toml`. See `config.example.toml`
- `cargo run -p sorrel-server -- --config ./local/config.toml`
- `cargo run -p sorrel-cli -- auth`
- `cargo run -p sorrel-cli -- list-sessions`
- `cargo run -p sorrel-cli -- revoke-session <session id>`
- `cargo run -p sorrel-cli -- list-keys`
- `cargo run -p sorrel-cli -- set-key <application> <public key>`
