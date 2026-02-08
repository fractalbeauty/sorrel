use crate::{
    AppState,
    database::Database,
    session::{AuthError, SessionGuard},
};
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use monostate::MustBe;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionInfoResponse {
    Success(SessionInfoSuccess),
    AuthError(AuthError),
}

impl IntoResponse for SessionInfoResponse {
    fn into_response(self) -> Response {
        match self {
            SessionInfoResponse::Success(success) => Json(success).into_response(),
            SessionInfoResponse::AuthError(auth_error) => auth_error.into_response(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfoSuccess {
    pub user_id: Uuid,
}

pub(crate) async fn api_session_info(
    session: Result<SessionGuard, AuthError>,
) -> SessionInfoResponse {
    let SessionGuard { user_id } = match session {
        Ok(session_guard) => session_guard,
        Err(auth_error) => return SessionInfoResponse::AuthError(auth_error),
    };

    let response = session_info(user_id).await;

    SessionInfoResponse::Success(response)
}

async fn session_info(user_id: Uuid) -> SessionInfoSuccess {
    SessionInfoSuccess { user_id }
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
    fn internal_server_error() -> Self {
        SessionListResponse::InternalServerError {
            error: MustBe!("internal_server_error"),
        }
    }
}

impl IntoResponse for SessionListResponse {
    fn into_response(self) -> Response {
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
    // pub device_name: String,
    pub last_used_at: u64,
}

pub(crate) async fn api_session_list(
    State(state): State<AppState>,
    session: Result<SessionGuard, AuthError>,
) -> SessionListResponse {
    let SessionGuard { user_id } = match session {
        Ok(session_guard) => session_guard,
        Err(auth_error) => return SessionListResponse::AuthError(auth_error),
    };

    match session_list(&state.database, user_id).await {
        Ok(session_list) => SessionListResponse::Success(session_list),

        Err(e) => {
            log::error!("Failed to get session list: {:?}", e);
            SessionListResponse::internal_server_error()
        }
    }
}

#[derive(Debug, Snafu)]
enum SessionListFatalError {
    #[snafu(transparent)]
    Database { source: sqlx::Error },
}

async fn session_list(
    database: &Database,
    user_id: Uuid,
) -> Result<SessionListSuccess, SessionListFatalError> {
    let sessions = database
        .get_sessions_by_user_id(user_id)
        .await?
        .into_iter()
        .map(|session| SessionListSession {
            id: session.id,
            // device_name: session.device_name_hint.unwrap_or_else(|| "Unknown device".to_string()),
            last_used_at: session.last_used_at as u64,
        })
        .collect();

    Ok(SessionListSuccess { sessions })
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
    fn success() -> Self {
        SessionRevokeResponse::Success {
            success: MustBe!(true),
        }
    }
    fn not_found() -> Self {
        SessionRevokeResponse::NotFound {
            error: MustBe!("not_found"),
        }
    }
    fn internal_server_error() -> Self {
        SessionRevokeResponse::InternalServerError {
            error: MustBe!("internal_server_error"),
        }
    }
}

impl From<JsonRejection> for SessionRevokeResponse {
    fn from(rejection: JsonRejection) -> Self {
        SessionRevokeResponse::InvalidRequest {
            error: MustBe!("invalid_request"),
            error_description: rejection.to_string(),
        }
    }
}

impl IntoResponse for SessionRevokeResponse {
    fn into_response(self) -> Response {
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

pub(crate) async fn api_session_revoke(
    State(state): State<AppState>,
    session: Result<SessionGuard, AuthError>,
    request: Result<Json<SessionRevokeRequest>, JsonRejection>,
) -> SessionRevokeResponse {
    let SessionGuard { user_id } = match session {
        Ok(session_guard) => session_guard,
        Err(auth_error) => return SessionRevokeResponse::AuthError(auth_error),
    };

    let request = match request {
        Ok(request) => request,
        Err(json_error) => return SessionRevokeResponse::from(json_error),
    };

    match session_revoke(&state.database, user_id, request.session_id).await {
        Ok(Ok(())) => SessionRevokeResponse::success(),

        Ok(Err(SessionRevokeLocalError::SessionIdNotFound)) => SessionRevokeResponse::not_found(),

        Err(e) => {
            log::error!("Failed to revoke session: {:?}", e);
            SessionRevokeResponse::internal_server_error()
        }
    }
}

#[derive(Debug, Snafu)]
enum SessionRevokeLocalError {
    SessionIdNotFound,
}

#[derive(Debug, Snafu)]
enum SessionRevokeFatalError {
    #[snafu(transparent)]
    Database { source: sqlx::Error },
}

async fn session_revoke(
    database: &Database,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<Result<(), SessionRevokeLocalError>, SessionRevokeFatalError> {
    if !database
        .delete_session_by_session_id_and_user_id(session_id, user_id)
        .await?
    {
        return Ok(Err(SessionRevokeLocalError::SessionIdNotFound));
    }

    Ok(Ok(()))
}
