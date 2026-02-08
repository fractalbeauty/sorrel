use crate::auth::AuthError;
use monostate::MustBe;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionInfoResponse {
    Success(SessionInfoSuccess),
    AuthError(AuthError),
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for SessionInfoResponse {
    fn into_response(self) -> axum::response::Response {
        use axum::Json;

        match self {
            SessionInfoResponse::Success(success) => Json(success).into_response(),
            SessionInfoResponse::AuthError(auth_error) => auth_error.into_response(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfoSuccess {
    pub session_id: Uuid,
    pub user_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionListResponse {
    Success(SessionListSuccess),
    InternalServerError {
        error: MustBe!("internal_server_error"),
    },
    AuthError(AuthError),
}

impl SessionListResponse {
    pub fn internal_server_error() -> Self {
        SessionListResponse::InternalServerError {
            error: MustBe!("internal_server_error"),
        }
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for SessionListResponse {
    fn into_response(self) -> axum::response::Response {
        use axum::{Json, http::StatusCode};

        match self {
            SessionListResponse::Success(success) => Json(success).into_response(),
            SessionListResponse::InternalServerError { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
            }
            SessionListResponse::AuthError(auth_error) => auth_error.into_response(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionListSuccess {
    pub sessions: Vec<SessionListSession>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionListSession {
    pub id: Uuid,
    pub last_used_at: u64,
    pub device_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionRevokeRequest {
    pub session_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionRevokeResponse {
    Success {
        success: MustBe!(true),
    },
    NotFound {
        error: MustBe!("not_found"),
    },
    InternalServerError {
        error: MustBe!("internal_server_error"),
    },
    AuthError(AuthError),
    InvalidRequest {
        error: MustBe!("invalid_request"),
        error_description: String,
    },
}

impl SessionRevokeResponse {
    pub fn success() -> Self {
        SessionRevokeResponse::Success {
            success: MustBe!(true),
        }
    }
    pub fn not_found() -> Self {
        SessionRevokeResponse::NotFound {
            error: MustBe!("not_found"),
        }
    }
    pub fn internal_server_error() -> Self {
        SessionRevokeResponse::InternalServerError {
            error: MustBe!("internal_server_error"),
        }
    }
}

#[cfg(feature = "axum")]
impl From<axum::extract::rejection::JsonRejection> for SessionRevokeResponse {
    fn from(rejection: axum::extract::rejection::JsonRejection) -> Self {
        SessionRevokeResponse::InvalidRequest {
            error: MustBe!("invalid_request"),
            error_description: rejection.to_string(),
        }
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for SessionRevokeResponse {
    fn into_response(self) -> axum::response::Response {
        use axum::{Json, http::StatusCode};

        match self {
            SessionRevokeResponse::Success { .. } => Json(self).into_response(),
            SessionRevokeResponse::NotFound { .. } => {
                (StatusCode::NOT_FOUND, Json(self)).into_response()
            }
            SessionRevokeResponse::InternalServerError { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
            }
            SessionRevokeResponse::AuthError(auth_error) => auth_error.into_response(),
            SessionRevokeResponse::InvalidRequest { .. } => {
                (StatusCode::BAD_REQUEST, Json(self)).into_response()
            }
        }
    }
}
