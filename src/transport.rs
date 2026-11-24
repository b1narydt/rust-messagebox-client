//! The one door every relay HTTP request goes through.
//!
//! Every send, list, ack, permission and quote call reaches the relay through
//! [`RelayHttp`]. It holds the BRC-103 transport behind the [`HttpTransport`]
//! trait, so a response is turned into a client result in exactly one place,
//! the relay identity pin is checked there before any body is used, and sends
//! and lists wait out the relay's rate limit there ([`RateGate`]).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bsv::auth::clients::auth_fetch::AuthFetch;
use bsv::wallet::interfaces::WalletInterface;

use crate::error::MessageBoxError;

/// The longest wait the client takes from a relay's rate-limit answer.
pub(crate) const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
/// The wait when a rate-limit answer names none, and the shortest one the
/// client takes, so a resend never follows a refusal at once.
pub(crate) const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(1);
/// How long one send or list waits, in all, on the relay's rate limit before
/// it returns [`MessageBoxError::RateLimited`].
pub(crate) const DEFAULT_RATE_LIMIT_WAIT: Duration = MAX_RETRY_AFTER;

/// One relay HTTP response.
#[derive(Debug, Clone)]
pub(crate) struct RelayResponse {
    pub status: u16,
    /// Response headers. Over BRC-104 only the signed `x-bsv-*` headers (and
    /// `content-type`) reach the client.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    /// The identity key the server proved in the BRC-103 handshake. `AuthFetch`
    /// fills it on every authenticated response.
    pub server_identity_key: Option<String>,
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
    ///   header (the only one BRC-104 delivers), kept between
    ///   [`DEFAULT_RETRY_AFTER`] and [`MAX_RETRY_AFTER`], and
    ///   [`DEFAULT_RETRY_AFTER`] when none is given.
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
            let header_seconds = self
                .header_seconds("retry-after")
                .or_else(|| self.header_seconds("x-bsv-retry-after"));
            return rate_limited(body.as_ref(), header_seconds);
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

/// The relay's rate-limit refusal as an error. The wait is the body's
/// `retry_after` (seconds), else `header_seconds`, kept between
/// [`DEFAULT_RETRY_AFTER`] and [`MAX_RETRY_AFTER`]; [`DEFAULT_RETRY_AFTER`]
/// when neither names one. The same body arrives over HTTP (a 429) and over
/// the WebSocket (`messageFailed`).
pub(crate) fn rate_limited(
    body: Option<&serde_json::Map<String, serde_json::Value>>,
    header_seconds: Option<u64>,
) -> MessageBoxError {
    let seconds = body
        .and_then(|b| b.get("retry_after"))
        .and_then(|v| v.as_u64())
        .or(header_seconds);
    MessageBoxError::RateLimited {
        retry_after: seconds
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_RETRY_AFTER)
            .clamp(DEFAULT_RETRY_AFTER, MAX_RETRY_AFTER),
        tier: body
            .and_then(|b| b.get("tier"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
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
            server_identity_key: response.server_identity_key,
        })
    }
}

/// Normalise an identity key for comparison: trimmed, lowercase hex.
pub(crate) fn normalize_identity_key(key: &str) -> String {
    key.trim().to_ascii_lowercase()
}

/// Check a server's proven identity against the pin. With no pin every server
/// passes; with a pin, a different key or no key at all is refused.
pub(crate) fn check_relay_identity(
    expected: Option<&str>,
    observed: Option<&str>,
) -> Result<(), MessageBoxError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    match observed.map(normalize_identity_key) {
        Some(observed) if observed == expected => Ok(()),
        observed => Err(MessageBoxError::RelayIdentityMismatch {
            expected: expected.to_string(),
            observed,
        }),
    }
}

/// The relay's rate-limit holds, one per relay host, shared by every clone of
/// a client's [`RelayHttp`].
///
/// The relay charges HTTP sends, WebSocket sends and lists to one budget per
/// identity, and answers an exhausted budget with `retry_after`. A hold
/// records that answer, so the client's next send or list to that relay
/// waits it out instead of spending a request on a refusal it already knows.
#[derive(Clone, Default)]
pub(crate) struct RateGate {
    holds: Arc<std::sync::Mutex<HashMap<String, Hold>>>,
}

#[derive(Clone)]
struct Hold {
    until: tokio::time::Instant,
    tier: Option<String>,
}

impl RateGate {
    fn holds(&self) -> std::sync::MutexGuard<'_, HashMap<String, Hold>> {
        // A poisoned map still holds valid instants; keep using it.
        self.holds.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn key(host: &str) -> String {
        host.trim().trim_end_matches('/').to_ascii_lowercase()
    }

    /// Hold `host` for `retry_after` from now. A hold that ends later stays.
    pub(crate) fn hold(&self, host: &str, retry_after: Duration, tier: Option<String>) {
        let until = tokio::time::Instant::now() + retry_after;
        let mut holds = self.holds();
        let key = Self::key(host);
        if holds.get(&key).is_none_or(|h| h.until < until) {
            holds.insert(key, Hold { until, tier });
        }
    }

    /// Wait until `host` is not held. When the hold ends after `deadline`,
    /// return [`MessageBoxError::RateLimited`] with the time left, at once.
    pub(crate) async fn wait(
        &self,
        host: &str,
        deadline: tokio::time::Instant,
    ) -> Result<(), MessageBoxError> {
        let key = Self::key(host);
        loop {
            let Some(hold) = self.holds().get(&key).cloned() else {
                return Ok(());
            };
            let now = tokio::time::Instant::now();
            if hold.until <= now {
                return Ok(());
            }
            if hold.until > deadline {
                return Err(MessageBoxError::RateLimited {
                    retry_after: hold.until - now,
                    tier: hold.tier,
                });
            }
            // Look again after the sleep: a later refusal may have extended it.
            tokio::time::sleep_until(hold.until).await;
        }
    }
}

/// The client's relay HTTP handle. Cheap to clone; background tasks hold one.
#[derive(Clone)]
pub(crate) struct RelayHttp {
    transport: Arc<dyn HttpTransport>,
    /// The relay identity pin, normalised. `None` trusts whichever server
    /// answers.
    expected_server_key: Option<String>,
    /// Rate-limit holds, shared by every clone.
    rate_gate: RateGate,
    /// How long one send or list waits, in all, on the rate limit.
    rate_limit_wait: Duration,
}

impl RelayHttp {
    pub(crate) fn new(
        transport: Arc<dyn HttpTransport>,
        expected_server_key: Option<String>,
    ) -> Self {
        Self {
            transport,
            expected_server_key,
            rate_gate: RateGate::default(),
            rate_limit_wait: DEFAULT_RATE_LIMIT_WAIT,
        }
    }

    /// The same transport with a different pin.
    pub(crate) fn with_expected_server_key(self, expected_server_key: Option<String>) -> Self {
        Self {
            expected_server_key,
            ..self
        }
    }

    /// The same handle with a different rate-limit wait.
    pub(crate) fn with_rate_limit_wait(self, rate_limit_wait: Duration) -> Self {
        Self {
            rate_limit_wait,
            ..self
        }
    }

    /// The same handle over a different transport (tests drive a scripted relay).
    #[cfg(test)]
    pub(crate) fn with_transport(self, transport: Arc<dyn HttpTransport>) -> Self {
        Self { transport, ..self }
    }

    /// When a send or list starting now must stop waiting on the rate limit.
    pub(crate) fn rate_limit_deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.rate_limit_wait
    }

    /// Wait out a rate-limit hold on `host` (see [`RateGate::wait`]).
    pub(crate) async fn wait_for_rate_limit(
        &self,
        host: &str,
        deadline: tokio::time::Instant,
    ) -> Result<(), MessageBoxError> {
        self.rate_gate.wait(host, deadline).await
    }

    /// Record a rate-limit refusal from `host`; any other error is ignored.
    pub(crate) fn hold_for_rate_limit(&self, host: &str, error: &MessageBoxError) {
        if let MessageBoxError::RateLimited { retry_after, tier } = error {
            self.rate_gate.hold(host, *retry_after, tier.clone());
        }
    }

    /// POST one send or list to `url` on `host`. These share the relay's
    /// per-identity rate budget (acks do not).
    ///
    /// Waits out any rate-limit hold on `host` first. On a refusal, holds
    /// `host` for the relay's `retry_after`, waits, and sends the same bytes
    /// again, so a resent message keeps its id. When the wait would end past
    /// the rate-limit wait, returns [`MessageBoxError::RateLimited`] instead.
    /// The relay checks the budget before any side effect, so a refused
    /// request changed nothing.
    pub(crate) async fn fetch_budgeted(
        &self,
        host: &str,
        url: &str,
        body: Vec<u8>,
    ) -> Result<RelayResponse, MessageBoxError> {
        let deadline = self.rate_limit_deadline();
        loop {
            self.wait_for_rate_limit(host, deadline).await?;
            match self.fetch_ok(url, "POST", Some(body.clone())).await {
                Err(refused @ MessageBoxError::RateLimited { .. }) => {
                    self.hold_for_rate_limit(host, &refused);
                }
                answer => return answer,
            }
        }
    }

    /// Send one request and return the response whatever its status.
    /// A request with a body is sent as `application/json`.
    ///
    /// With a pin, a response from any other server is an error before its
    /// status or body is looked at. The request itself has already reached
    /// that server.
    pub(crate) async fn fetch_raw(
        &self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
    ) -> Result<RelayResponse, MessageBoxError> {
        let headers = body
            .as_ref()
            .map(|_| HashMap::from([("content-type".to_string(), "application/json".to_string())]));
        let response = self.transport.fetch(url, method, body, headers).await?;
        check_relay_identity(
            self.expected_server_key.as_deref(),
            response.server_identity_key.as_deref(),
        )?;
        Ok(response)
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
            server_identity_key: None,
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
    /// comes from the body, else the signed header, bounded and defaulted.
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
        assert_eq!(
            retry_after(response(429, &[], &rate_limit_body(Some(0)))),
            DEFAULT_RETRY_AFTER,
            "a zero wait would resend at once"
        );
        match response(429, &[], &rate_limit_body(Some(7))).error("u") {
            MessageBoxError::RateLimited { tier, .. } => {
                assert_eq!(tier.as_deref(), Some("uncertified"))
            }
            other => panic!("{other:?}"),
        }
    }

    /// A shorter refusal never cuts a longer hold short.
    #[tokio::test(start_paused = true)]
    async fn a_shorter_refusal_keeps_the_longer_hold() {
        let gate = RateGate::default();
        gate.hold("https://relay.example", Duration::from_secs(30), None);
        gate.hold("https://relay.example", Duration::from_secs(5), None);
        let started = tokio::time::Instant::now();
        gate.wait("https://relay.example", started + MAX_RETRY_AFTER)
            .await
            .expect("within the deadline");
        assert!(started.elapsed() >= Duration::from_secs(30));
    }

    /// A pinned check fails closed when the server proved no key at all.
    #[test]
    fn a_pin_refuses_a_response_with_no_proven_key() {
        assert!(matches!(
            check_relay_identity(Some("03aa"), None),
            Err(MessageBoxError::RelayIdentityMismatch { observed: None, .. })
        ));
        assert!(check_relay_identity(None, None).is_ok());
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

    /// The identity key the scripted relay proves.
    pub(crate) const RELAY_KEY: &str =
        "03aa00000000000000000000000000000000000000000000000000000000000001";

    #[derive(Default)]
    pub(crate) struct ScriptedTransport {
        responses: Mutex<VecDeque<RelayResponse>>,
        sent: Mutex<Vec<SentRequest>>,
    }

    impl ScriptedTransport {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        /// Queue the next response, proven by [`RELAY_KEY`].
        pub(crate) fn push(&self, status: u16, headers: &[(&str, &str)], body: serde_json::Value) {
            self.push_from(RELAY_KEY, status, headers, body);
        }

        /// Queue the next response, proven by `server_key`.
        pub(crate) fn push_from(
            &self,
            server_key: &str,
            status: u16,
            headers: &[(&str, &str)],
            body: serde_json::Value,
        ) {
            self.responses.lock().unwrap().push_back(RelayResponse {
                status,
                headers: headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                body: serde_json::to_vec(&body).unwrap(),
                server_identity_key: Some(server_key.to_string()),
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
