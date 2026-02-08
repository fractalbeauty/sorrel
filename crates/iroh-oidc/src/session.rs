use crate::{AppState, database::Database};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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
) -> Result<String, CreateSessionFatalError> {
    let (plain_token, hashed_token) = generate_token();

    database.create_session(&hashed_token, user_id).await?;

    Ok(plain_token)
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

    let session = database.get_session(&hashed_token).await?;
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

impl axum::extract::FromRequestParts<AppState> for SessionGuard {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get(axum::http::header::AUTHORIZATION);
        let Some(auth_header) = auth_header else {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "unauthorized",
                    "error_description": "Missing Authorization header"
                })),
            )
                .into_response());
        };

        let auth_header = match auth_header.to_str() {
            Ok(s) => s,
            Err(_) => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "unauthorized",
                        "error_description": "Invalid or expired access token"
                    })),
                )
                    .into_response());
            }
        };

        let token = match auth_header.strip_prefix("Bearer ") {
            Some(t) => t,
            None => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "unauthorized",
                        "error_description": "Invalid or expired access token"
                    })),
                )
                    .into_response());
            }
        };

        let user_id = match validate_session(&state.database, token).await {
            Ok(Ok(user_id)) => user_id,
            Ok(Err(ValidateSessionLocalError::Expired)) => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "unauthorized",
                        "error_description": "Invalid or expired access token"
                    })),
                )
                    .into_response());
            }
            Ok(Err(ValidateSessionLocalError::Invalid)) => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "unauthorized",
                        "error_description": "Invalid or expired access token"
                    })),
                )
                    .into_response());
            }
            Err(e) => {
                log::error!("Failed to validate session: {:?}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "internal_server_error",
                    })),
                )
                    .into_response());
            }
        };

        Ok(SessionGuard { user_id })
    }
}
