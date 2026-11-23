//! The one door every relay HTTP request goes through.
//!
//! Every send, list, ack, permission and quote call reaches the relay through
//! [`RelayHttp`]. It holds the BRC-103 transport behind the [`HttpTransport`]
//! trait, so a response is turned into a client result in exactly one place.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bsv::auth::clients::auth_fetch::AuthFetch;
use bsv::wallet::interfaces::WalletInterface;

use crate::error::MessageBoxError;

/// The longest wait the client takes from a relay's rate-limit answer.
pub(crate) const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
/// The wait when a rate-limit answer names none.
pub(crate) const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(1);

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

    /// The error a non-2xx response stands for.
    ///
    /// - A rate-limit refusal (HTTP 429, or a body with `reason:
    ///   "rate_limited"`) is [`MessageBoxError::RateLimited`]. The relay's body
    ///   has no `code`; the wait comes from the body's `retry_after` (seconds),
    ///   else the `Retry-After` header, else the signed `x-bsv-retry-after`
    ///   header (the only one BRC-104 delivers), capped at [`MAX_RETRY_AFTER`]
    ///   and [`DEFAULT_RETRY_AFTER`] when none is given.
    /// - A JSON body naming a `code` (or, from the identity gate, an `error`)
    ///   is [`MessageBoxError::Relay`].
    /// - Anything else is [`MessageBoxError::Http`].
    pub(crate) fn error(&self, url: &str) -> MessageBoxError {
        let body: Option<serde_json::Map<String, serde_json::Value>> =
            serde_json::from_slice(&self.body).ok();
        let field = |name: &str| {
            body.as_ref()
                .and_then(|b| b.get(name))
                .and_then(|v| v.as_str())
        };

        if self.status == 429 || field("reason") == Some("rate_limited") {
            let seconds = body
                .as_ref()
                .and_then(|b| b.get("retry_after"))
                .and_then(|v| v.as_u64())
                .or_else(|| self.header_seconds("retry-after"))
                .or_else(|| self.header_seconds("x-bsv-retry-after"));
            return MessageBoxError::RateLimited {
                retry_after: seconds
                    .map(Duration::from_secs)
                    .unwrap_or(DEFAULT_RETRY_AFTER)
                    .min(MAX_RETRY_AFTER),
                tier: field("tier").map(str::to_string),
            };
        }

        if let Some(code) = field("code").or_else(|| field("error")) {
            return MessageBoxError::Relay {
                status: self.status,
                code: code.to_string(),
                description: field("description").unwrap_or_default().to_string(),
            };
        }

        MessageBoxError::Http(self.status, url.to_string())
    }

    fn header_seconds(&self, name: &str) -> Option<u64> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.trim().parse().ok())
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

    /// Send one request; a non-2xx status becomes an error
    /// ([`RelayResponse::error`]).
    pub(crate) async fn fetch_ok(
        &self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
    ) -> Result<RelayResponse, MessageBoxError> {
        let response = self.fetch_raw(url, method, body).await?;
        if !response.is_success() {
            return Err(response.error(url));
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> RelayResponse {
        RelayResponse {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_vec(),
        }
    }

    fn rate_limit_body(retry_after: Option<u64>) -> Vec<u8> {
        let mut body = json!({
            "status": "error",
            "reason": "rate_limited",
            "description": "verified identity rate limit exceeded",
            "tier": "uncertified",
        });
        if let Some(seconds) = retry_after {
            body["retry_after"] = json!(seconds);
        }
        serde_json::to_vec(&body).unwrap()
    }

    fn retry_after(response: RelayResponse) -> Duration {
        match response.error("u") {
            MessageBoxError::RateLimited { retry_after, .. } => retry_after,
            other => panic!("not rate limited: {other:?}"),
        }
    }

    /// The relay's 429 has no `code`; it is still a rate limit, and the wait
    /// comes from the body, else the signed header, capped and defaulted.
    #[test]
    fn rate_limit_answers_carry_the_relay_wait() {
        let signed = [("x-bsv-retry-after", "9")];
        assert_eq!(
            retry_after(response(429, &signed, &rate_limit_body(Some(7)))),
            Duration::from_secs(7)
        );
        assert_eq!(
            retry_after(response(429, &signed, &rate_limit_body(None))),
            Duration::from_secs(9)
        );
        assert_eq!(
            retry_after(response(429, &[], &rate_limit_body(Some(3600)))),
            MAX_RETRY_AFTER
        );
        assert_eq!(retry_after(response(429, &[], b"")), DEFAULT_RETRY_AFTER);
        match response(429, &[], &rate_limit_body(Some(7))).error("u") {
            MessageBoxError::RateLimited { tier, .. } => {
                assert_eq!(tier.as_deref(), Some("uncertified"))
            }
            other => panic!("{other:?}"),
        }
    }

    /// A body naming a code (or the identity gate's `error`) keeps it; a body
    /// with neither is a bare HTTP error.
    #[test]
    fn relay_refusals_keep_their_code() {
        let blocked = json!({"status":"error","code":"ERR_DELIVERY_BLOCKED","description":"Blocked recipients: 02ab"});
        match response(403, &[], &serde_json::to_vec(&blocked).unwrap()).error("u") {
            MessageBoxError::Relay {
                status,
                code,
                description,
            } => {
                assert_eq!((status, code.as_str()), (403, "ERR_DELIVERY_BLOCKED"));
                assert_eq!(description, "Blocked recipients: 02ab");
            }
            other => panic!("{other:?}"),
        }
        match response(403, &[], br#"{"error":"not_certified"}"#).error("u") {
            MessageBoxError::Relay { code, .. } => assert_eq!(code, "not_certified"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            response(502, &[], b"<html>bad gateway</html>").error("u"),
            MessageBoxError::Http(502, _)
        ));
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
