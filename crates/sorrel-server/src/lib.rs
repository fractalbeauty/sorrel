pub mod api;
mod database;
mod session;

use crate::database::Database;
use axum::extract::{FromRef, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use axum::{Form, Json};
use axum::{Router, routing::get};
use axum_client_ip::{ClientIp, ClientIpSource};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use figment::Figment;
use figment::providers::Format;
use hmac::{Hmac, Mac};
use maud::{DOCTYPE, Markup, html};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::url::Url;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse as _,
};
use openidconnect::{EndpointMaybeSet, reqwest};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use serde_with::serde_as;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower_sessions::cookie::time::Duration;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};

const SESSION_KEY_AUTH: &str = "auth";
const SESSION_KEY_OIDC: &str = "oidc";

#[derive(Debug, Serialize, Deserialize)]
enum AuthState {
    /// State set when starting authorization code grant flow.
    AuthCode {
        client_id: String,
        redirect_url: String,
        redirect_state: String,
        code_challenge: Vec<u8>,
        device_name: Option<String>,
    },
    /// State used in device authorization grant flow.
    /// Set after user enters user code and confirms login.
    /// Used after OIDC flow to link device code to user.
    DeviceAuth { device_code_hash: Vec<u8> },
}

#[derive(Debug, Serialize, Deserialize)]
struct OidcState {
    provider_id: String,
    pkce_verifier: PkceCodeVerifier,
    csrf_state: String,
    nonce: String,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
struct Config {
    /// Path to SQLite database file.
    ///
    /// Example: "sqlite://./local/database.sqlite"
    database_path: String,

    listen_address: IpAddr,
    listen_port: u16,
    base_url: String,

    /// Source of client IP for device code requests.
    ///
    /// See https://docs.rs/axum-client-ip/latest/axum_client_ip
    ip_source: ClientIpSource,

    /// 32-byte secret, formatted as hex.
    #[serde_as(as = "serde_with::hex::Hex")]
    user_code_secret: [u8; 32],

    providers: HashMap<String, ProviderConfig>,

    clients: Vec<ClientConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct ProviderConfig {
    issuer_url: String,
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    #[serde(default)]
    dangerously_fix_token_hash_len: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientConfig {
    name: String,
    client_id: String,
    redirect_urls: Vec<String>,
}

#[derive(Debug, Clone)]
struct Provider {
    http_client: reqwest::Client,
    oidc_client: CoreClient<
        EndpointSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointMaybeSet,
        EndpointMaybeSet,
    >,
    scopes: Vec<String>,
    dangerously_fix_token_hash_len: bool,
}

#[derive(Debug, Clone, FromRef)]
pub struct AppState {
    config: Arc<Config>,
    database: Database,
    providers: Arc<HashMap<String, Provider>>,
}

// TODO: remove
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

pub async fn run(config_files: Vec<PathBuf>) -> anyhow::Result<()> {
    env_logger::init();

    let config = {
        let mut config =
            Figment::new().merge(figment::providers::Toml::file("config.default.toml"));

        for config_file in config_files {
            config = config.merge(figment::providers::Toml::file(config_file));
        }

        config
            .merge(figment::providers::Env::prefixed("APP_"))
            .extract::<Config>()?
    };
    let config = Arc::new(config);

    let database = database::Database::open_file(&config.database_path).await?;

    let providers = init_providers(&config.base_url, &config.providers).await?;

    let state = AppState {
        config: config.clone(),
        database,
        providers: Arc::new(providers),
    };

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_expiry(tower_sessions::session::Expiry::OnInactivity(
            Duration::days(30),
        ));

    let app = Router::new()
        .route("/code", get(get_code_form))
        .route("/code/confirm", get(get_confirm_form))
        .route("/code/confirm", post(post_confirm_form))
        .route("/code/done", get(get_done_page))
        .route("/provider", get(get_provider_form))
        .route("/api/oauth/authorize", get(oauth_authorize))
        .route("/api/oauth/token", post(oauth_token))
        .route("/api/oauth/device", post(oauth_device))
        .route("/api/oauth/device/poll", post(oauth_device_poll))
        .route("/api/sessions/info", get(api::api_session_info))
        .route("/api/sessions/list", get(api::api_session_list))
        .route("/api/sessions/revoke", post(api::api_session_revoke))
        .route("/api/keys", get(api::api_list_keys))
        .route("/api/keys", post(api::api_set_key))
        .route("/oidc/redirect/{provider_id}", get(oidc_redirect))
        .route("/oidc/callback/{provider_id}", get(oidc_callback))
        .layer(session_layer)
        .layer(config.ip_source.clone().into_extension())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind((config.listen_address, config.listen_port))
        .await
        .unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();

    Ok(())
}

async fn init_providers(
    base_url: &str,
    configs: &HashMap<String, ProviderConfig>,
) -> anyhow::Result<HashMap<String, Provider>> {
    let mut providers = HashMap::new();

    for (id, config) in configs {
        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        // Use OpenID Connect Discovery to fetch the provider metadata.
        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(config.issuer_url.clone())?,
            &http_client,
        )
        .await?;

        // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
        // and token URL.
        let oidc_client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new(format!("{base_url}/oidc/callback/{id}"))?);

        let provider = Provider {
            http_client,
            oidc_client,
            scopes: config.scopes.clone(),
            dangerously_fix_token_hash_len: config.dangerously_fix_token_hash_len,
        };

        providers.insert(id.clone(), provider);
    }

    Ok(providers)
}

async fn get_code_form() -> Result<Markup, AppError> {
    Ok(html! {
        (DOCTYPE)
        h1 { "Log in by entering code shown on device" }
        form method="get" action="/code/confirm" {
            label { "Code: " }
            input type="text" name="c";
            br;
            input type="submit" value="Submit";
        }
    })
}

#[derive(Deserialize)]
struct ConfirmQuery {
    c: String,
}

async fn get_confirm_form(
    State(state): State<AppState>,
    Query(query): Query<ConfirmQuery>,
) -> Result<Markup, AppError> {
    let user_code = UserCode(query.c.to_ascii_uppercase());
    let user_code_hash = user_code.hash(&state.config.user_code_secret)?;
    let device_code = state
        .database
        .get_device_code_by_user_code(&user_code_hash)
        .await?;

    let Some(device_code) = device_code else {
        return Err(anyhow::anyhow!("invalid code").into());
    };

    if device_code.is_used {
        return Err(anyhow::anyhow!("invalid code").into());
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    if device_code.expires_at < now {
        return Err(anyhow::anyhow!("invalid code").into());
    }

    Ok(html! {
        (DOCTYPE)
        h1 { "Confirm login" }
        @if let Some(name) = &device_code.device_name_hint {
            p { "Device name: " (name) }
        }
        @if let Some(ip) = &device_code.device_ip_hint {
            p { "Device IP: " (ip) }
        }
        form method="post" action="/code/confirm" {
            input type="hidden" name="code" value={ (user_code.0) };
            input type="submit" value="Continue";
        }
    })
}

#[derive(Deserialize)]
struct ConfirmForm {
    code: String,
}

async fn post_confirm_form(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<ConfirmForm>,
) -> Result<Redirect, AppError> {
    let user_code = UserCode(form.code);
    let user_code_hash = user_code.hash(&state.config.user_code_secret)?;
    let device_code = state
        .database
        .get_device_code_by_user_code(&user_code_hash)
        .await?;

    let Some(device_code) = device_code else {
        return Err(anyhow::anyhow!("invalid code").into());
    };

    if device_code.is_used {
        return Err(anyhow::anyhow!("invalid code").into());
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    if device_code.expires_at < now {
        return Err(anyhow::anyhow!("invalid code").into());
    }

    // Set session auth state
    session
        .insert(
            SESSION_KEY_AUTH,
            AuthState::DeviceAuth {
                device_code_hash: device_code.device_code_hash,
            },
        )
        .await?;

    // Redirect to provider selection
    Ok(Redirect::to("/provider"))
}

async fn get_provider_form(State(state): State<AppState>) -> Result<Markup, AppError> {
    Ok(html! {
        (DOCTYPE)
        h1 { "Choose a provider" }
        ul {
            @for provider_id in state.providers.keys() {
                li {
                    a href={ "/oidc/redirect/" (provider_id) } { (provider_id) }
                }
            }
        }
    })
}

async fn get_done_page() -> Result<Markup, AppError> {
    Ok(html! {
        (DOCTYPE)
        h1 { "Login complete" }
        p { "You can close this page." }
    })
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    device_name: Option<String>,
}

fn make_error_redirect(
    redirect_uri: &str,
    state: &str,
    error: &str,
    error_description: &str,
) -> Result<Redirect, AppError> {
    Ok(Redirect::to(
        Url::parse_with_params(
            redirect_uri,
            &[
                ("error", error),
                ("error_description", error_description),
                ("state", state),
            ],
        )?
        .as_str(),
    ))
}

async fn oauth_authorize(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
    session: Session,
) -> Result<Redirect, AppError> {
    let client = state
        .config
        .clients
        .iter()
        .find(|c| c.client_id == query.client_id);
    let Some(client) = client else {
        // do not redirect to invalid redirect_uri
        return Err(anyhow::anyhow!("unknown client_id").into());
    };
    if !client.redirect_urls.contains(&query.redirect_uri) {
        // do not redirect to invalid redirect_uri
        return Err(anyhow::anyhow!("invalid redirect_uri").into());
    }

    if query.response_type != "code" {
        return make_error_redirect(
            &query.redirect_uri,
            &query.state,
            "unsupported_response_type",
            "only 'code' response_type is supported",
        );
    }
    if query.code_challenge_method != "S256" {
        return make_error_redirect(
            &query.redirect_uri,
            &query.state,
            "invalid_request",
            "only 'S256' code_challenge_method is supported",
        );
    }
    if query.code_challenge.len() != 43 {
        return make_error_redirect(
            &query.redirect_uri,
            &query.state,
            "invalid_request",
            "invalid code_challenge length",
        );
    }
    let code_challenge = BASE64_URL_SAFE_NO_PAD
        .decode(&query.code_challenge)
        .map_err(|_e| anyhow::anyhow!("invalid code_challenge encoding"))?;

    // Set session auth state
    session
        .insert(
            SESSION_KEY_AUTH,
            AuthState::AuthCode {
                client_id: query.client_id,
                redirect_url: query.redirect_uri,
                redirect_state: query.state,
                code_challenge,
                device_name: query.device_name.clone(),
            },
        )
        .await?;

    // Redirect to provider selection
    Ok(Redirect::to("/provider"))
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: String,
}

async fn oauth_token(
    State(state): State<AppState>,
    Json(request): Json<TokenRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    // validate client_id
    let client = state
        .config
        .clients
        .iter()
        .find(|c| c.client_id == request.client_id);
    let Some(client) = client else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_client"
            })),
        ));
    };

    if request.grant_type != "authorization_code" {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported_grant_type"
            })),
        ));
    }

    let auth_code_hash = {
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(&request.code)
            .map_err(|_e| anyhow::anyhow!("invalid code encoding"))?;
        let mut arr = [0u8; 32];
        if decoded.len() != 32 {
            log::trace!("invalid code length: {}", decoded.len());
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_grant"
                })),
            ));
        }
        arr.copy_from_slice(&decoded);
        Sha256::digest(&arr)
    };

    let auth_code = state
        .database
        .get_auth_code_by_hash(&auth_code_hash)
        .await?;
    let Some(auth_code) = auth_code else {
        log::trace!("auth code not found for hash: {:x?}", auth_code_hash);
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_grant"
            })),
        ));
    };

    if request.client_id != auth_code.client_id {
        log::trace!(
            "client_id mismatch: {} != {}",
            request.client_id,
            auth_code.client_id
        );
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_grant"
            })),
        ));
    }
    if request.redirect_uri != auth_code.redirect_uri {
        log::trace!(
            "redirect_uri mismatch: {} != {}",
            request.redirect_uri,
            auth_code.redirect_uri
        );
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_grant"
            })),
        ));
    }

    let code_verifier_hash = {
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(&request.code_verifier)
            .map_err(|_e| anyhow::anyhow!("invalid code_verifier encoding"))?;
        log::trace!("code_verifier decoded: {:x?}", decoded);
        Sha256::digest(&decoded).to_vec()
    };
    log::trace!("code_verifier_hash: {:x?}", code_verifier_hash);
    log::trace!("expected code_challenge: {:x?}", auth_code.code_challenge);
    if code_verifier_hash.as_slice() != auth_code.code_challenge.as_slice() {
        log::trace!(
            "code_verifier mismatch: {:x?} != {:x?}",
            code_verifier_hash,
            auth_code.code_challenge
        );
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_grant"
            })),
        ));
    }

    let create_success = match session::create_session(
        &state.database,
        auth_code.user_id,
        auth_code.device_name.as_deref(),
    )
    .await
    {
        Ok(create_success) => create_success,
        Err(e) => {
            log::error!("failed to create session: {}", e);
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                })),
            ));
        }
    };

    Ok((
        StatusCode::OK,
        Json(json!({
            "access_token": create_success.plain_token,
            "token_type": "Bearer",
        })),
    ))
}

const DEVICE_CODE_TTL: Duration = Duration::minutes(10);
const DEVICE_POLL_INTERVAL: Duration = Duration::seconds(5);

const AUTH_CODE_TTL: Duration = Duration::minutes(5);

#[derive(Serialize, Deserialize)]
struct AuthCode([u8; 32]);

impl AuthCode {
    fn new() -> Self {
        Self(rand::random::<[u8; 32]>())
    }

    fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

impl AsRef<[u8]> for AuthCode {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for AuthCode {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err(anyhow::anyhow!("invalid authorization code length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&value);
        Ok(AuthCode(arr))
    }
}

#[derive(Serialize, Deserialize)]
struct DeviceCode([u8; 32]);

impl DeviceCode {
    fn new() -> Self {
        Self(rand::random::<[u8; 32]>())
    }

    fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

impl AsRef<[u8]> for DeviceCode {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for DeviceCode {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err(anyhow::anyhow!("invalid device code length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&value);
        Ok(DeviceCode(arr))
    }
}

#[derive(Serialize)]
struct UserCode(String);

impl UserCode {
    fn new() -> Self {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const CODE_LEN: usize = 6;

        let mut rng = rand::thread_rng();

        let user_code: String = (0..CODE_LEN)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        Self(user_code)
    }

    fn hash(&self, secret: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret).expect("HMAC can take key of any size");
        mac.update(self.0.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

#[derive(Deserialize)]
struct DeviceStartRequest {
    device_name: String,
}

#[serde_as]
#[derive(Serialize)]
struct DeviceStartResponse {
    #[serde_as(as = "serde_with::hex::Hex")]
    device_code: DeviceCode,
    user_code: UserCode,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i64,
}

#[axum::debug_handler]
async fn oauth_device(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    Json(request): Json<DeviceStartRequest>,
) -> Result<Json<DeviceStartResponse>, AppError> {
    let device_code = DeviceCode::new();
    let device_code_hash = device_code.hash();

    let (user_code, user_code_hash) = {
        let mut user_code = UserCode::new();
        loop {
            let user_code_hash = user_code.hash(&state.config.user_code_secret)?;
            if !state.database.exists_user_code(&user_code_hash).await? {
                break (user_code, user_code_hash);
            }

            user_code = UserCode::new();
        }
    };

    let expires_at = (SystemTime::now() + DEVICE_CODE_TTL)
        .duration_since(UNIX_EPOCH)?
        .as_secs() as i64;

    state
        .database
        .create_device_code(
            &device_code_hash,
            &user_code_hash,
            expires_at,
            Some(&request.device_name),
            Some(&client_ip.to_string()),
        )
        .await?;

    let verification_uri = format!("{}/code", state.config.base_url);
    let verification_uri_complete =
        format!("{}/code/confirm?c={}", state.config.base_url, user_code.0);

    Ok(Json(DeviceStartResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: DEVICE_CODE_TTL.whole_seconds(),
        interval: DEVICE_POLL_INTERVAL.whole_seconds(),
    }))
}

#[serde_as]
#[derive(Deserialize)]
struct DevicePollRequest {
    #[serde_as(as = "serde_with::hex::Hex")]
    device_code: DeviceCode,
    // grant_type: String,
    // client_id: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum DevicePollResponse {
    Success {
        access_token: String,
        // token_type: String,
        // expires_in: i64,
        // refresh_token: String,
    },
    Error {
        error: String,
    },
}

async fn oauth_device_poll(
    State(state): State<AppState>,
    Json(request): Json<DevicePollRequest>,
) -> Result<Json<DevicePollResponse>, AppError> {
    let device_code_hash = request.device_code.hash();
    let device_code = state
        .database
        .get_device_code_by_device_code(&device_code_hash)
        .await?
        .ok_or_else(|| anyhow::anyhow!("device code not found"))?;
    if device_code.is_used {
        return Err(anyhow::anyhow!("device code already used").into());
    }
    if device_code.expires_at < SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64 {
        return Err(anyhow::anyhow!("device code expired").into());
    }

    let user_id = match device_code.user_id {
        Some(user_id) => user_id,
        None => {
            return Ok(Json(DevicePollResponse::Error {
                error: "authorization_pending".to_string(),
            }));
        }
    };

    state
        .database
        .set_device_code_used(&device_code_hash)
        .await?;

    let create_success = match session::create_session(
        &state.database,
        user_id,
        device_code.device_name_hint.as_deref(),
    )
    .await
    {
        Ok(create_success) => create_success,
        Err(e) => {
            log::error!("failed to create session: {}", e);
            return Ok(Json(DevicePollResponse::Error {
                error: "server_error".to_string(),
            }));
        }
    };

    Ok(Json(DevicePollResponse::Success {
        access_token: create_success.plain_token,
    }))
}

async fn oidc_redirect(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    session: Session,
) -> Result<Redirect, AppError> {
    let Some(provider) = state.providers.get(&provider_id) else {
        return Err(anyhow::anyhow!("unknown provider").into());
    };

    let auth_state = session
        .get::<AuthState>(SESSION_KEY_AUTH)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing auth state in session"))?;

    match auth_state {
        AuthState::AuthCode { .. } => {
            // return Err(anyhow::anyhow!("authorization code flow not implemented").into());
        }
        AuthState::DeviceAuth { device_code_hash } => {
            let device_code = state
                .database
                .get_device_code_by_device_code(&device_code_hash)
                .await?
                .ok_or_else(|| anyhow::anyhow!("device code not found"))?;
            if device_code.user_id.is_some() {
                return Err(anyhow::anyhow!("device code already used").into());
            }
            if device_code.expires_at
                < SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64
            {
                return Err(anyhow::anyhow!("device code expired").into());
            }
        }
    }

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token, nonce) = {
        let mut builder = provider
            .oidc_client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge);

        for scope in &provider.scopes {
            builder = builder.add_scope(Scope::new(scope.clone()));
        }

        builder.url()
    };

    session
        .insert(
            SESSION_KEY_OIDC,
            OidcState {
                provider_id: provider_id.clone(),
                pkce_verifier,
                csrf_state: csrf_token.secret().clone(),
                nonce: nonce.secret().clone(),
            },
        )
        .await?;

    Ok(Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

async fn oidc_callback(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Query(query): Query<CallbackQuery>,
    session: Session,
) -> Result<Redirect, AppError> {
    let Some(provider) = state.providers.get(&provider_id) else {
        return Err(anyhow::anyhow!("unknown provider").into());
    };

    let auth_state = session
        .get::<AuthState>(SESSION_KEY_AUTH)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing auth state in session"))?;

    match &auth_state {
        AuthState::AuthCode { .. } => {
            // return Err(anyhow::anyhow!("authorization code flow not implemented").into());
        }
        AuthState::DeviceAuth { device_code_hash } => {
            let device_code = state
                .database
                .get_device_code_by_device_code(device_code_hash)
                .await?
                .ok_or_else(|| anyhow::anyhow!("device code not found"))?;
            if device_code.user_id.is_some() {
                return Err(anyhow::anyhow!("device code already used").into());
            }
            if device_code.expires_at
                < SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64
            {
                return Err(anyhow::anyhow!("device code expired").into());
            }
        }
    }

    let OidcState {
        provider_id: stored_provider_id,
        pkce_verifier,
        csrf_state,
        nonce,
    } = session
        .get::<OidcState>(SESSION_KEY_OIDC)
        .await
        .map_err(|_e| anyhow::anyhow!("failed to get session"))?
        .ok_or_else(|| anyhow::anyhow!("missing login state in session"))?;

    if stored_provider_id != provider_id {
        return Err(anyhow::anyhow!("provider ID mismatch").into());
    }

    if query.state != csrf_state {
        return Err(anyhow::anyhow!("CSRF state mismatch").into());
    }

    let token_response = provider
        .oidc_client
        .exchange_code(AuthorizationCode::new(query.code))?
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(&provider.http_client)
        .await?;

    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow::anyhow!("server did not return ID token"))?;
    let id_token_verifier = provider.oidc_client.id_token_verifier();
    let claims = id_token
        .claims(&id_token_verifier, &Nonce::new(nonce))
        .map_err(|e| anyhow::anyhow!("failed to verify ID token: {}", e))?;

    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            id_token.signing_alg()?,
            id_token.signing_key(&id_token_verifier)?,
        )?;

        // Workaround for https://github.com/graze-social/aip/issues/60
        let expected_access_token_hash = if provider.dangerously_fix_token_hash_len {
            let bytes = BASE64_URL_SAFE_NO_PAD.decode(expected_access_token_hash.as_str())?;
            let string = if bytes.len() == 32 {
                BASE64_URL_SAFE_NO_PAD.encode(&bytes[0..16])
            } else {
                expected_access_token_hash.as_str().to_string()
            };
            AccessTokenHash::new(string)
        } else {
            expected_access_token_hash.clone()
        };

        if actual_access_token_hash != expected_access_token_hash {
            return Err(anyhow::anyhow!("Invalid access token").into());
        }
    }

    let user = state
        .database
        .authenticate(&provider_id, claims.subject().as_str())
        .await?;

    match auth_state {
        AuthState::AuthCode {
            client_id,
            redirect_url,
            redirect_state,
            code_challenge,
            device_name,
        } => {
            let auth_code = AuthCode::new();
            let auth_code_hash = auth_code.hash();

            let expires_at = (SystemTime::now() + AUTH_CODE_TTL)
                .duration_since(UNIX_EPOCH)?
                .as_secs() as i64;

            state
                .database
                .create_auth_code(
                    &auth_code_hash,
                    &client_id,
                    &redirect_url,
                    &code_challenge,
                    expires_at,
                    user.id,
                    device_name.as_deref(),
                )
                .await?;

            Ok(Redirect::to(
                Url::parse_with_params(
                    &redirect_url,
                    &[
                        ("code", BASE64_URL_SAFE_NO_PAD.encode(auth_code.as_ref())),
                        ("state", redirect_state),
                    ],
                )?
                .as_str(),
            ))
        }
        AuthState::DeviceAuth { device_code_hash } => {
            state
                .database
                .set_device_code_user_id(&device_code_hash, user.id)
                .await?;

            Ok(Redirect::to("/code/done"))
        }
    }
}
