use anyhow::Context;
use axum::extract::Query;
use axum::response::Html;
use axum::{Router, routing::get};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use clap::{Parser, Subcommand};
use rand::{Rng, distributions::Alphanumeric};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Parser)]
#[command(name = "iroh-keyserver-cli")]
#[command(about = "CLI for iroh-keyserver", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate
    Auth,
    /// List keys
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Auth => {
            let token = auth_with_code(true).await?;

            let session_info = Client::new()
                .get("http://localhost:3000/api/session/info")
                .bearer_auth(&token)
                .send()
                .await
                .context("Failed to send request to session info endpoint")?
                .json::<HashMap<String, String>>()
                .await
                .context("Failed to parse session info response")?;

            println!(
                "Authenticated successfully. Session info: {:?}",
                session_info
            );
        }
        Commands::List => {
            println!("List command executed");
        }
    }

    Ok(())
}

async fn auth_with_code(open: bool) -> anyhow::Result<String> {
    // Generate PKCE code verifier and challenge
    let code_verifier: [u8; 32] = rand::random::<[u8; 32]>();
    let code_challenge = BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier));

    // Generate CSRF token
    let csrf_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let bind_port = 8080;
    let redirect_uri = format!("http://localhost:{}/callback", bind_port);

    // Generate the authorization URL
    let base_url = "http://localhost:3000";
    let client_id = "iroh-keyserver-cli";
    let auth_url = format!(
        "{}/api/oauth/authorize?client_id=iroh-keyserver-cli&response_type=code&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}",
        base_url, redirect_uri, code_challenge, csrf_token
    );

    if open {
        println!("Opening {}", auth_url);
        let _ = webbrowser::open(&auth_url);
    } else {
        println!("To authenticate, open {}", auth_url);
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
                        ("client_id", client_id),
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
    let addr = SocketAddr::from(([127, 0, 0, 1], bind_port));

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
