use monostate::MustBe;
use serde::{Deserialize, Serialize};

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
    pub fn unauthorized() -> Self {
        AuthError::Unauthorized {
            error: MustBe!("unauthorized"),
            error_description: "Invalid or expired session token".to_string(),
        }
    }

    pub fn internal_server_error() -> Self {
        AuthError::InternalServerError {
            error: MustBe!("internal_server_error"),
        }
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        use axum::{Json, http::StatusCode};

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
