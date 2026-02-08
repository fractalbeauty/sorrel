use snafu::{ResultExt, Snafu};
use sorrel_api::{
    keys::{ListKeysResponse, SetKeyRequest, SetKeyResponse},
    sessions::{
        SessionInfoResponse, SessionListResponse, SessionRevokeRequest, SessionRevokeResponse,
    },
};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

pub mod api {
    pub use sorrel_api::*;
}

#[derive(Debug, Clone)]
pub struct Client {
    base_url: Url,
    client: Arc<reqwest::Client>,
}

#[derive(Debug, Snafu)]
pub enum ClientNewError {
    #[snafu(display("Invalid token header"))]
    TokenHeader,
    #[snafu(transparent)]
    Build { source: reqwest::Error },
}

#[derive(Debug, Snafu)]
pub enum RequestError {
    #[snafu(display("Failed to send request: {}", source))]
    Send { source: reqwest::Error },
    #[snafu(display("Failed to parse response: {}", source))]
    Parse { source: reqwest::Error },
}

impl Client {
    pub fn new(base_url: Url, token: String) -> Result<Self, ClientNewError> {
        let client = reqwest::Client::builder()
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", token)
                        .parse()
                        .map_err(|_| ClientNewError::TokenHeader)?,
                );
                headers
            })
            .build()?;

        Ok(Self {
            base_url,
            client: Arc::new(client),
        })
    }

    pub async fn session_info(&self) -> Result<SessionInfoResponse, RequestError> {
        let url = self.base_url.join("/api/sessions/info").unwrap();

        let response = self.client.get(url).send().await.context(SendSnafu)?;
        response
            .json::<SessionInfoResponse>()
            .await
            .context(ParseSnafu)
    }

    pub async fn list_sessions(&self) -> Result<SessionListResponse, RequestError> {
        let url = self.base_url.join("/api/sessions/list").unwrap();

        let response = self.client.get(url).send().await.context(SendSnafu)?;
        response
            .json::<SessionListResponse>()
            .await
            .context(ParseSnafu)
    }

    pub async fn revoke_session(
        &self,
        session_id: Uuid,
    ) -> Result<SessionRevokeResponse, RequestError> {
        let url = self.base_url.join("/api/sessions/revoke").unwrap();

        let response = self
            .client
            .post(url)
            .json(&SessionRevokeRequest { session_id })
            .send()
            .await
            .context(SendSnafu)?;
        response
            .json::<SessionRevokeResponse>()
            .await
            .context(ParseSnafu)
    }

    pub async fn list_keys(&self) -> Result<ListKeysResponse, RequestError> {
        let url = self.base_url.join("/api/keys").unwrap();

        let response = self.client.get(url).send().await.context(SendSnafu)?;
        response
            .json::<ListKeysResponse>()
            .await
            .context(ParseSnafu)
    }

    pub async fn set_key(&self, request: SetKeyRequest) -> Result<SetKeyResponse, RequestError> {
        let url = self.base_url.join("/api/keys").unwrap();

        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .await
            .context(SendSnafu)?;
        response.json::<SetKeyResponse>().await.context(ParseSnafu)
    }
}
