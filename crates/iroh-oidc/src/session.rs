use crate::{AppState, database::Database};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use monostate::MustBe;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::Snafu;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const SESSION_TTL: Duration = Duration::from_hours(24 * 30);

fn generate_token() -> (String, [u8; 32]) {
    let random_bytes = rand::random::<[u8; 32]>();
    let hashed_token = hash_token(random_bytes);
    let plain_token = URL_SAFE_NO_PAD.encode(random_bytes);
    (plain_token, hashed_token)
}

fn hash_token(token: [u8; 32]) -> [u8; 32] {
    Sha256::digest(token).into()
}

#[derive(Debug, Snafu)]
pub enum CreateSessionFatalError {
    #[snafu(transparent)]
    Database { source: sqlx::Error },
}

/// Creates a new session for the given user ID and returns the plain token.
pub async fn create_session(
    database: &Database,
    user_id: Uuid,
) -> Result<(Uuid, String), CreateSessionFatalError> {
    let id = Uuid::new_v4();
    let (plain_token, hashed_token) = generate_token();

    database.create_session(id, &hashed_token, user_id).await?;

    Ok((id, plain_token))
}

#[derive(Debug, Snafu)]
pub enum ValidateSessionFatalError {
    #[snafu(transparent)]
    Database { source: sqlx::Error },
    #[snafu(display("Last used time is in the future"))]
    InvalidLastUsed,
}

pub enum ValidateSessionLocalError {
    Expired,
    Invalid,
}

/// Validates and renews a session for the given plain token.
pub async fn validate_session(
    database: &Database,
    token: &str,
) -> Result<Result<Uuid, ValidateSessionLocalError>, ValidateSessionFatalError> {
    let token = match URL_SAFE_NO_PAD.decode(token) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Err(ValidateSessionLocalError::Invalid)),
    };
    let token: [u8; 32] = match token.try_into() {
        Ok(arr) => arr,
        Err(_) => return Ok(Err(ValidateSessionLocalError::Invalid)),
    };

    let hashed_token = hash_token(token);

    let session = database.get_session_by_token_hash(&hashed_token).await?;
    let Some(session) = session else {
        return Ok(Err(ValidateSessionLocalError::Invalid));
    };

    let last_used_at = UNIX_EPOCH + Duration::from_secs(session.last_used_at as u64);
    let session_age = SystemTime::now()
        .duration_since(last_used_at)
        .map_err(|_| ValidateSessionFatalError::InvalidLastUsed)?;

    if session_age > SESSION_TTL {
        return Ok(Err(ValidateSessionLocalError::Expired));
    }

    database.update_session_last_used(&hashed_token).await?;

    Ok(Ok(session.user_id))
}

/// Axum extractor that handles auth
pub struct SessionGuard {
    pub user_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthError {
    Unauthorized {
        error: MustBe!("unauthorized"),
        error_description: String,
    },
    InternalServerError {
        error: MustBe!("internal_server_error"),
    },
}

impl AuthError {
    fn unauthorized() -> Self {
        AuthError::Unauthorized {
            error: MustBe!("unauthorized"),
            error_description: "Invalid or expired session token".to_string(),
        }
    }

    fn internal_server_error() -> Self {
        AuthError::InternalServerError {
            error: MustBe!("internal_server_error"),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::Unauthorized { .. } => {
                (StatusCode::UNAUTHORIZED, Json(self)).into_response()
            }

            AuthError::InternalServerError { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
            }
        }
    }
}

impl axum::extract::FromRequestParts<AppState> for SessionGuard {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get(axum::http::header::AUTHORIZATION);
        let Some(auth_header) = auth_header else {
            return Err(AuthError::unauthorized());
        };

        let auth_header = match auth_header.to_str() {
            Ok(s) => s,
            Err(_) => {
                return Err(AuthError::unauthorized());
            }
        };

        let token = match auth_header.strip_prefix("Bearer ") {
            Some(t) => t,
            None => {
                return Err(AuthError::unauthorized());
            }
        };

        let user_id = match validate_session(&state.database, token).await {
            Ok(Ok(user_id)) => user_id,
            Ok(Err(ValidateSessionLocalError::Expired)) => {
                return Err(AuthError::unauthorized());
            }
            Ok(Err(ValidateSessionLocalError::Invalid)) => {
                return Err(AuthError::unauthorized());
            }
            Err(e) => {
                log::error!("Failed to validate session: {:?}", e);
                return Err(AuthError::internal_server_error());
            }
        };

        Ok(SessionGuard { user_id })
    }
}
