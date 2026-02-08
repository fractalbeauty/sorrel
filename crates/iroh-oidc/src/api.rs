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
use serde_with::serde_as;
use snafu::Snafu;
use std::convert::Infallible;
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
    pub session_id: Uuid,
    pub user_id: Uuid,
}

pub(crate) async fn api_session_info(
    session: Result<SessionGuard, AuthError>,
) -> SessionInfoResponse {
    let SessionGuard {
        session_id,
        user_id,
    } = match session {
        Ok(session_guard) => session_guard,
        Err(auth_error) => return SessionInfoResponse::AuthError(auth_error),
    };

    let response = session_info(session_id, user_id).await;

    SessionInfoResponse::Success(response)
}

async fn session_info(session_id: Uuid, user_id: Uuid) -> SessionInfoSuccess {
    SessionInfoSuccess {
        session_id,
        user_id,
    }
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
    pub last_used_at: u64,
    pub device_name: Option<String>,
}

pub(crate) async fn api_session_list(
    State(state): State<AppState>,
    session: Result<SessionGuard, AuthError>,
) -> SessionListResponse {
    let SessionGuard { user_id, .. } = match session {
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
            last_used_at: session.last_used_at as u64,
            device_name: session.device_name,
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
    let SessionGuard { user_id, .. } = match session {
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
    fn success() -> Self {
        SetKeyResponse::Success {
            success: MustBe!(true),
        }
    }
}

impl From<JsonRejection> for SetKeyResponse {
    fn from(rejection: JsonRejection) -> Self {
        SetKeyResponse::InvalidRequest {
            error: MustBe!("invalid_request"),
            error_description: rejection.to_string(),
        }
    }
}

impl IntoResponse for SetKeyResponse {
    fn into_response(self) -> Response {
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

pub(crate) async fn api_set_key(
    State(state): State<AppState>,
    session: Result<SessionGuard, AuthError>,
    request: Result<Json<SetKeyRequest>, JsonRejection>,
) -> SetKeyResponse {
    let SessionGuard { session_id, .. } = match session {
        Ok(session_guard) => session_guard,
        Err(auth_error) => return SetKeyResponse::AuthError(auth_error),
    };

    let request = match request {
        Ok(request) => request,
        Err(json_error) => return SetKeyResponse::from(json_error),
    };

    match set_key(
        &state.database,
        session_id,
        &request.app,
        &request.public_key,
    )
    .await
    {
        Ok(Ok(())) => SetKeyResponse::success(),

        Err(e) => {
            log::error!("Failed to set key: {:?}", e);
            SetKeyResponse::InternalServerError {
                error: MustBe!("internal_server_error"),
            }
        }
    }
}

#[derive(Debug, Snafu)]
enum SetKeyFatalError {
    #[snafu(transparent)]
    Database { source: sqlx::Error },
}

async fn set_key(
    database: &Database,
    session_id: Uuid,
    app: &str,
    public_key: &[u8; 32],
) -> Result<Result<(), Infallible>, SetKeyFatalError> {
    database
        .set_key_for_session(session_id, app, public_key)
        .await?;

    Ok(Ok(()))
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

impl IntoResponse for ListKeysResponse {
    fn into_response(self) -> Response {
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

pub(crate) async fn api_list_keys(
    State(state): State<AppState>,
    session: Result<SessionGuard, AuthError>,
) -> ListKeysResponse {
    let SessionGuard { user_id, .. } = match session {
        Ok(session_guard) => session_guard,
        Err(auth_error) => return ListKeysResponse::AuthError(auth_error),
    };

    match list_keys(&state.database, user_id).await {
        Ok(Ok(success)) => ListKeysResponse::Success(success),

        Err(e) => {
            log::error!("Failed to list keys: {:?}", e);
            ListKeysResponse::InternalServerError {
                error: MustBe!("internal_server_error"),
            }
        }
    }
}

#[derive(Debug, Snafu)]
enum ListKeysFatalError {
    #[snafu(transparent)]
    Database { source: sqlx::Error },
    #[snafu(display("Stored public key is invalid"))]
    InvalidPublicKey,
}

async fn list_keys(
    database: &Database,
    user_id: Uuid,
) -> Result<Result<ListKeysSuccess, Infallible>, ListKeysFatalError> {
    let keys = database.get_keys_by_user_id(user_id).await?;

    let keys = keys
        .into_iter()
        .map(|key| {
            let public_key = key
                .public_key
                .try_into()
                .map_err(|_| ListKeysFatalError::InvalidPublicKey)?;

            Ok(ListKeysResponseItem {
                public_key,
                app: key.app,
                session_id: key.session_id,
                session_last_used_at: key.session_last_used_at as u64,
                session_device_name: key.session_device_name,
            })
        })
        .collect::<Result<Vec<ListKeysResponseItem>, ListKeysFatalError>>()?;

    Ok(Ok(ListKeysSuccess { keys }))
}
