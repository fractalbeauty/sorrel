use crate::{AppState, database::Database, session::SessionGuard};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfoResponse {
    pub user_id: Uuid,
}

pub(crate) async fn api_session_info(
    SessionGuard { user_id }: SessionGuard,
) -> Json<SessionInfoResponse> {
    let response = session_info(user_id).await;

    Json(response)
}

async fn session_info(user_id: Uuid) -> SessionInfoResponse {
    SessionInfoResponse { user_id }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionListResponse {
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
    SessionGuard { user_id }: SessionGuard,
) -> Response {
    match session_list(&state.database, user_id).await {
        Ok(session_list) => Json(session_list).into_response(),

        Err(e) => {
            log::error!("Failed to get session list: {:?}", e);

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "internal_server_error",
                })),
            )
                .into_response()
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
) -> Result<SessionListResponse, SessionListFatalError> {
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

    Ok(SessionListResponse { sessions })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionRevokeRequest {
    pub session_id: Uuid,
}

pub(crate) async fn api_session_revoke(
    State(state): State<AppState>,
    SessionGuard { user_id }: SessionGuard,
    Json(request): Json<SessionRevokeRequest>,
) -> Response {
    match session_revoke(&state.database, user_id, request.session_id).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),

        Ok(Err(SessionRevokeLocalError::SessionIdNotFound)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "not_found",
                "error_description": "Session not found"
            })),
        )
            .into_response(),

        Err(e) => {
            log::error!("Failed to revoke session: {:?}", e);

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "internal_server_error",
                })),
            )
                .into_response()
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
