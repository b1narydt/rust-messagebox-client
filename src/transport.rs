//! The one door every relay HTTP request goes through.
//!
//! Every send, list, ack, permission and quote call reaches the relay through
//! [`RelayHttp`]. It holds the BRC-103 transport behind the [`HttpTransport`]
//! trait, so a response is turned into a client result in exactly one place.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bsv::auth::clients::auth_fetch::AuthFetch;
use bsv::wallet::interfaces::WalletInterface;

use crate::error::MessageBoxError;

/// One relay HTTP response.
#[derive(Debug, Clone)]
pub(crate) struct RelayResponse {
    pub status: u16,
    /// Response headers. Over BRC-104 only the signed `x-bsv-*` headers (and
    /// `content-type`) reach the client.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl RelayResponse {
    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// An authenticated HTTP transport: `AuthFetch` in production, a scripted
/// stand-in in tests.
#[async_trait]
pub(crate) trait HttpTransport: Send + Sync {
    async fn fetch(
        &self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
    ) -> Result<RelayResponse, MessageBoxError>;
}

#[async_trait]
impl<W> HttpTransport for AuthFetch<W>
where
    W: WalletInterface + Clone + Send + Sync + 'static,
{
    async fn fetch(
        &self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
    ) -> Result<RelayResponse, MessageBoxError> {
        let response = AuthFetch::fetch(self, url, method, body, headers)
            .await
            .map_err(|e| MessageBoxError::Auth(e.to_string()))?;
        Ok(RelayResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

/// The client's relay HTTP handle. Cheap to clone; background tasks hold one.
#[derive(Clone)]
pub(crate) struct RelayHttp {
    transport: Arc<dyn HttpTransport>,
}

impl RelayHttp {
    pub(crate) fn new(transport: Arc<dyn HttpTransport>) -> Self {
        Self { transport }
    }

    /// Send one request and return the response whatever its status.
    /// A request with a body is sent as `application/json`.
    pub(crate) async fn fetch_raw(
        &self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
    ) -> Result<RelayResponse, MessageBoxError> {
        let headers = body
            .as_ref()
            .map(|_| HashMap::from([("content-type".to_string(), "application/json".to_string())]));
        self.transport.fetch(url, method, body, headers).await
    }

    /// Send one request; a non-2xx status becomes an error.
    pub(crate) async fn fetch_ok(
        &self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
    ) -> Result<RelayResponse, MessageBoxError> {
        let response = self.fetch_raw(url, method, body).await?;
        if !response.is_success() {
            return Err(MessageBoxError::Http(response.status, url.to_string()));
        }
        Ok(response)
    }
}

/// A scripted transport for unit tests: it answers each request with the next
/// queued response and records what was sent.
#[cfg(test)]
pub(crate) mod scripted {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    pub(crate) struct SentRequest {
        pub url: String,
        pub method: String,
        pub body: Option<serde_json::Value>,
    }

    #[derive(Default)]
    pub(crate) struct ScriptedTransport {
        responses: Mutex<VecDeque<RelayResponse>>,
        sent: Mutex<Vec<SentRequest>>,
    }

    impl ScriptedTransport {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        /// Queue the next response.
        pub(crate) fn push(&self, status: u16, headers: &[(&str, &str)], body: serde_json::Value) {
            self.responses.lock().unwrap().push_back(RelayResponse {
                status,
                headers: headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                body: serde_json::to_vec(&body).unwrap(),
            });
        }

        pub(crate) fn sent(&self) -> Vec<SentRequest> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl HttpTransport for ScriptedTransport {
        async fn fetch(
            &self,
            url: &str,
            method: &str,
            body: Option<Vec<u8>>,
            _headers: Option<HashMap<String, String>>,
        ) -> Result<RelayResponse, MessageBoxError> {
            self.sent.lock().unwrap().push(SentRequest {
                url: url.to_string(),
                method: method.to_string(),
                body: body.and_then(|b| serde_json::from_slice(&b).ok()),
            });
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| MessageBoxError::Auth(format!("no scripted response for {url}")))
        }
    }
}
