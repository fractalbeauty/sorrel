use crate::auth::AuthError;
use monostate::MustBe;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use uuid::Uuid;

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SetKeyRequest {
    pub app: String,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub public_key: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SetKeyResponse {
    Success {
        success: MustBe!(true),
    },
    AuthError(AuthError),
    InvalidRequest {
        error: MustBe!("invalid_request"),
        error_description: String,
    },
    InternalServerError {
        error: MustBe!("internal_server_error"),
    },
}

impl SetKeyResponse {
    pub fn success() -> Self {
        SetKeyResponse::Success {
            success: MustBe!(true),
        }
    }
}

#[cfg(feature = "axum")]
impl From<axum::extract::rejection::JsonRejection> for SetKeyResponse {
    fn from(rejection: axum::extract::rejection::JsonRejection) -> Self {
        SetKeyResponse::InvalidRequest {
            error: MustBe!("invalid_request"),
            error_description: rejection.to_string(),
        }
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for SetKeyResponse {
    fn into_response(self) -> axum::response::Response {
        use axum::{Json, http::StatusCode};

        match self {
            SetKeyResponse::Success { .. } => Json(self).into_response(),
            SetKeyResponse::AuthError(auth_error) => auth_error.into_response(),
            SetKeyResponse::InvalidRequest { .. } => {
                (StatusCode::BAD_REQUEST, Json(self)).into_response()
            }
            SetKeyResponse::InternalServerError { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ListKeysResponse {
    Success(ListKeysSuccess),
    AuthError(AuthError),
    InternalServerError {
        error: MustBe!("internal_server_error"),
    },
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for ListKeysResponse {
    fn into_response(self) -> axum::response::Response {
        use axum::{Json, http::StatusCode};

        match self {
            ListKeysResponse::Success(success) => Json(success).into_response(),
            ListKeysResponse::AuthError(auth_error) => auth_error.into_response(),
            ListKeysResponse::InternalServerError { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListKeysSuccess {
    pub keys: Vec<ListKeysResponseItem>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ListKeysResponseItem {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub public_key: [u8; 32],
    pub app: String,
    pub session_id: Uuid,
    pub session_last_used_at: u64,
    pub session_device_name: Option<String>,
}
