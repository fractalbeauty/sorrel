use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Router, routing::get};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use figment::Figment;
use figment::providers::Format;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope,
    TokenResponse,
};
use openidconnect::{EndpointMaybeSet, reqwest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use tower_sessions::cookie::time::Duration;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer, session};

const SESSION_KEY_PKCE_VERIFIER: &str = "pkce_verifier";
const SESSION_KEY_CSRF_STATE: &str = "csrf_state";
const SESSION_KEY_NONCE: &str = "nonce";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    listen_address: IpAddr,
    listen_port: u16,
    base_url: String,
    providers: HashMap<String, ProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderConfig {
    issuer_url: String,
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    #[serde(default)]
    dangerously_fix_token_hash_len: bool,
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

#[derive(Debug, Clone)]
struct AppState {
    providers: HashMap<String, Provider>,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Figment::new()
        .merge(figment::providers::Toml::file("config.local.toml"))
        .merge(figment::providers::Env::prefixed("APP_"))
        .join(figment::providers::Toml::file("config.default.toml"))
        .extract::<Config>()?;

    let providers = init_providers(&config.base_url, config.providers).await?;

    let state = AppState { providers };

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_expiry(session::Expiry::OnInactivity(Duration::days(30)));

    let app = Router::new()
        .route("/api/auth/login/{provider_id}", get(api_login))
        .route("/api/auth/callback/{provider_id}", get(api_callback))
        .layer(session_layer)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind((config.listen_address, config.listen_port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

async fn init_providers(
    base_url: &str,
    configs: HashMap<String, ProviderConfig>,
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
            ClientId::new(config.client_id),
            Some(ClientSecret::new(config.client_secret)),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new(format!(
            "{base_url}/api/auth/callback/{id}"
        ))?);

        let provider = Provider {
            http_client,
            oidc_client,
            scopes: config.scopes,
            dangerously_fix_token_hash_len: config.dangerously_fix_token_hash_len,
        };

        providers.insert(id, provider);
    }

    Ok(providers)
}

async fn api_login(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    session: Session,
) -> Result<Redirect, AppError> {
    let Some(provider) = state.providers.get(&provider_id) else {
        return Err(anyhow::anyhow!("unknown provider").into());
    };

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
        .insert(SESSION_KEY_PKCE_VERIFIER, pkce_verifier.into_secret())
        .await?;
    session
        .insert(SESSION_KEY_CSRF_STATE, csrf_token.into_secret())
        .await?;
    session.insert(SESSION_KEY_NONCE, nonce.secret()).await?;

    Ok(Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

async fn api_callback(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Query(query): Query<CallbackQuery>,
    session: Session,
) -> Result<String, AppError> {
    let Some(provider) = state.providers.get(&provider_id) else {
        return Err(anyhow::anyhow!("unknown provider").into());
    };

    let pkce_verifier = session
        .get(SESSION_KEY_PKCE_VERIFIER)
        .await
        .map_err(|_e| anyhow::anyhow!("failed to get session"))?
        .ok_or_else(|| anyhow::anyhow!("missing PKCE verifier in session"))?;

    let csrf_state = session
        .get::<String>(SESSION_KEY_CSRF_STATE)
        .await
        .map_err(|_e| anyhow::anyhow!("failed to get session"))?
        .ok_or_else(|| anyhow::anyhow!("missing CSRF state in session"))?;

    let nonce = session
        .get::<String>(SESSION_KEY_NONCE)
        .await
        .map_err(|_e| anyhow::anyhow!("failed to get session"))?
        .ok_or_else(|| anyhow::anyhow!("missing nonce in session"))?;

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

        dbg!(&actual_access_token_hash, &expected_access_token_hash);
        if actual_access_token_hash != expected_access_token_hash {
            return Err(anyhow::anyhow!("Invalid access token").into());
        }
    }

    println!(
        "User {} with e-mail address {} has authenticated successfully",
        claims.subject().as_str(),
        claims
            .email()
            .map(|email| email.as_str())
            .unwrap_or("<not provided>"),
    );

    Ok("meow".to_string())
}
