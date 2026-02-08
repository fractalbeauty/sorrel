use anyhow::Context;
use axum::extract::Query;
use axum::response::Html;
use axum::{Router, routing::get};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use clap::{Args, Parser, Subcommand};
use figment::Figment;
use figment::providers::{Env, Serialized};
use rand::{Rng, distributions::Alphanumeric};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sorrel_api::sessions::{
    SessionInfoResponse, SessionListResponse, SessionRevokeRequest, SessionRevokeResponse,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "sorrel-cli")]
#[command(about = "CLI for sorrel", long_about = None)]
struct Cli {
    #[command(flatten)]
    config: Config,

    #[command(subcommand)]
    command: Command,
}

#[derive(Serialize, Deserialize, Args)]
struct Config {
    /// Open the browser automatically
    #[clap(long, default_value_t = true, default_missing_value = "true", num_args = 0..=1)]
    open: bool,

    /// Session token to use
    #[clap(long)]
    token: Option<String>,

    /// Base URL of the API to use (default: http://localhost:3000)
    #[clap(long)]
    base_url: Option<String>,

    /// Client ID to use for authentication (default: sorrel-cli)
    #[clap(long)]
    client_id: Option<String>,

    /// Address to listen on for the local server for authentication (default: 127.0.0.1)
    #[clap(long)]
    listen_address: Option<String>,

    /// Port to listen on for the local server for authentication (default: 8080)
    #[clap(long)]
    listen_port: Option<u16>,

    /// Base URL to use for redirects during authentication (default: http://localhost:8080)
    #[clap(long)]
    redirect_base_url: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Authenticate
    Auth,
    /// List sessions
    ListSessions,
    /// Revoke a session
    RevokeSession(RevokeSessionArgs),
    /// List keys
    ListKeys,
    /// Set key for an application
    SetKey(SetKeyArgs),
}

#[derive(Args)]
struct RevokeSessionArgs {
    /// ID of the session to revoke
    session_id: Uuid,
}

#[derive(Args)]
struct SetKeyArgs {
    /// Application name to set the key for
    app: String,
    /// Public key (hex)
    public_key: String,
}

const ENV_PREFIX: &str = "APP_";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    let Cli {
        config: cli_config,
        command,
    } = Cli::parse();

    let config = Figment::new()
        .merge(Serialized::defaults(cli_config))
        .merge(Env::prefixed(ENV_PREFIX))
        .extract::<Config>()?;

    let base_url = config
        .base_url
        .as_deref()
        .unwrap_or("http://localhost:3000")
        .trim_end_matches('/');

    match command {
        Command::Auth => {
            let token = auth(&config).await?;

            let response = Client::new()
                .get(format!("{base_url}/api/sessions/info"))
                .bearer_auth(&token)
                .send()
                .await
                .context("Failed to send request to session info endpoint")?
                .json::<Value>()
                .await
                .context("Failed to get session info response")?;

            log::info!("Session info raw response: {:?}", response);

            let session_info: SessionInfoResponse = serde_json::from_value(response)
                .context("Failed to parse session info response")?;

            log::info!("Session info: {:?}", session_info);
        }
        Command::ListSessions => {
            let token = auth(&config).await?;

            let response = Client::new()
                .get(format!("{base_url}/api/sessions/list"))
                .bearer_auth(&token)
                .send()
                .await
                .context("Failed to send request to session list endpoint")?
                .json::<Value>()
                .await
                .context("Failed to get session list response")?;

            log::info!("Session list raw response: {:?}", response);

            let response: SessionListResponse = serde_json::from_value(response)
                .context("Failed to parse session list response")?;

            log::info!("Session list response: {:?}", response);
        }
        Command::RevokeSession(RevokeSessionArgs { session_id }) => {
            let token = auth(&config).await?;

            let response = Client::new()
                .post(format!("{base_url}/api/sessions/revoke"))
                .bearer_auth(&token)
                .json(&SessionRevokeRequest { session_id })
                .send()
                .await
                .context("Failed to send request to session revoke endpoint")?
                .json::<Value>()
                .await
                .context("Failed to get session revoke response")?;

            log::info!("Session revoke raw response: {:?}", response);

            let response: SessionRevokeResponse = serde_json::from_value(response)
                .context("Failed to parse session revoke response")?;

            log::info!("Session revoke response: {:?}", response);
        }
        Command::ListKeys => {
            let token = auth(&config).await?;

            let response = Client::new()
                .get(format!("{base_url}/api/keys"))
                .bearer_auth(&token)
                .send()
                .await
                .context("Failed to send request to list keys endpoint")?
                .json::<Value>()
                .await
                .context("Failed to get list keys response")?;

            log::info!("List keys raw response: {:?}", response);

            let response: sorrel_api::keys::ListKeysResponse =
                serde_json::from_value(response).context("Failed to parse list keys response")?;

            log::info!("List keys response: {:?}", response);
        }
        Command::SetKey(SetKeyArgs { app, public_key }) => {
            let token = auth(&config).await?;

            let public_key = match hex::decode(public_key) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("Failed to decode public key: {:?}", e);
                    return Err(anyhow::anyhow!("Invalid public key"));
                }
            };

            if public_key.len() != 32 {
                log::error!("Public key must be 32 bytes, got {}", public_key.len());
                return Err(anyhow::anyhow!("Invalid public key length"));
            }

            let response = Client::new()
                .post(format!("{base_url}/api/keys"))
                .bearer_auth(&token)
                .json(&sorrel_api::keys::SetKeyRequest {
                    app,
                    public_key: public_key.try_into().unwrap(),
                })
                .send()
                .await
                .context("Failed to send request to set key endpoint")?
                .json::<Value>()
                .await
                .context("Failed to get set key response")?;

            log::info!("Set key raw response: {:?}", response);

            let response: sorrel_api::keys::SetKeyResponse =
                serde_json::from_value(response).context("Failed to parse set key response")?;

            log::info!("Set key response: {:?}", response);
        }
    }

    Ok(())
}

async fn auth(config: &Config) -> anyhow::Result<Cow<'_, str>> {
    match &config.token {
        Some(token) => {
            log::info!("Using provided token");

            Ok(token.into())
        }
        None => {
            log::info!("No token provided, starting authentication flow");

            let token = auth_with_code(config).await?;

            log::info!(
                "To reuse authentication, use:\n\n--token {token}\n\nor\n\nexport {ENV_PREFIX}TOKEN={token}"
            );

            Ok(token.into())
        }
    }
}

async fn auth_with_code(config: &Config) -> anyhow::Result<String> {
    let base_url = config
        .base_url
        .as_deref()
        .unwrap_or("http://localhost:3000")
        .trim_end_matches('/')
        .to_owned();

    let client_id = config
        .client_id
        .as_deref()
        .unwrap_or("sorrel-cli")
        .to_owned();

    let listen_address = config
        .listen_address
        .as_deref()
        .unwrap_or("127.0.0.1")
        .parse::<IpAddr>()
        .context("Invalid listen address")?;

    let listen_port = config.listen_port.unwrap_or(8080);

    let redirect_base_url = config
        .redirect_base_url
        .as_deref()
        .unwrap_or("http://localhost:8080")
        .trim_end_matches('/')
        .to_owned();

    // Generate PKCE code verifier and challenge
    let code_verifier: [u8; 32] = rand::random::<[u8; 32]>();
    let code_challenge = BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier));

    // Generate CSRF token
    let csrf_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let redirect_uri = format!("{}/callback", redirect_base_url);

    // Generate the authorization URL
    let device_name = "sorrel-cli";
    let auth_url = format!(
        "{}/api/oauth/authorize?client_id={}&response_type=code&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&device_name={}",
        base_url, client_id, redirect_uri, code_challenge, csrf_token, device_name
    );

    if config.open {
        log::info!("Opening {}", auth_url);
        let _ = webbrowser::open(&auth_url);
    } else {
        log::info!("To authenticate, open {}", auth_url);
    }

    // Channel to signal shutdown
    let result = Arc::new(Mutex::new(None));
    let shutdown = Arc::new(Notify::new());

    let app = Router::new().route(
        "/callback",
        get({
            let result = result.clone();
            let shutdown = shutdown.clone();
            move |Query(params): Query<HashMap<String, String>>| {
                async move {
                    let state = params.get("state");
                    let code = params.get("code");

                    if state != Some(&csrf_token) {
                        let mut result = result.lock().unwrap();
                        *result = Some(Err(anyhow::anyhow!("Invalid CSRF token")));
                        shutdown.notify_waiters();
                        return Html("Authentication failed. You can close this tab.");
                    }

                    let Some(code) = code else {
                        let mut result = result.lock().unwrap();
                        *result = Some(Err(anyhow::anyhow!("Missing code parameter")));
                        shutdown.notify_waiters();
                        return Html("Authentication failed. You can close this tab.");
                    };

                    let code_verifier = BASE64_URL_SAFE_NO_PAD.encode(code_verifier);

                    // Exchange the code for a token
                    let client = Client::new();
                    let req = HashMap::from([
                        ("client_id", &*client_id),
                        ("code", code),
                        ("grant_type", "authorization_code"),
                        ("redirect_uri", &redirect_uri),
                        ("code_verifier", &code_verifier),
                    ]);
                    let token_response = match client
                        .post(format!("{}/api/oauth/token", base_url))
                        .json(&req)
                        .send()
                        .await
                    {
                        Ok(res) => res,
                        Err(e) => {
                            let mut result = result.lock().unwrap();
                            *result = Some(Err(e).context("Failed to send token request"));
                            shutdown.notify_waiters();
                            return Html("Authentication failed. You can close this tab.");
                        }
                    };

                    let mut token_response =
                        match token_response.json::<HashMap<String, String>>().await {
                            Ok(res) => res,
                            Err(e) => {
                                let mut result = result.lock().unwrap();
                                *result = Some(Err(e).context("Failed to receive token response"));
                                shutdown.notify_waiters();
                                return Html("Authentication failed. You can close this tab.");
                            }
                        };

                    let Some(token) = token_response.remove("access_token") else {
                        let mut result = result.lock().unwrap();
                        *result = Some(Err(anyhow::anyhow!("Token response missing access_token")));
                        shutdown.notify_waiters();
                        return Html("Authentication failed. You can close this tab.");
                    };

                    let mut result = result.lock().unwrap();
                    *result = Some(Ok(token));
                    shutdown.notify_waiters();

                    Html("Authentication success. You can close this tab.")
                }
            }
        }),
    );

    // Start the Axum server
    let addr = SocketAddr::from((listen_address, listen_port));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("Failed to bind to address")?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.notified().await;
    })
    .await?;

    let token = match result.lock().unwrap().take() {
        Some(Ok(token)) => token.clone(),
        Some(Err(e)) => return Err(e),
        None => return Err(anyhow::anyhow!("Authentication failed")),
    };

    Ok(token)
}
