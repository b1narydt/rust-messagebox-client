use std::time::Duration;

use thiserror::Error;

/// Unified error type for all MessageBox client operations.
///
/// Uses String variants for wallet and auth errors to avoid tight coupling
/// to SDK error internals — call sites use `.map_err(|e| MessageBoxError::Wallet(e.to_string()))`.
#[derive(Error, Debug)]
pub enum MessageBoxError {
    #[error("wallet error: {0}")]
    Wallet(String),
    #[error("auth error: {0}")]
    Auth(String),
    /// A non-2xx answer whose body carries no relay error code.
    #[error("HTTP error: status {0} from {1}")]
    Http(u16, String),
    /// The relay refused the request and named why. `code` is the relay's
    /// machine-readable code: the `code` field of its standard error body
    /// (`ERR_INVALID_ACKNOWLEDGMENT`, `ERR_DELIVERY_BLOCKED`, ...) or the
    /// `error` field of the identity gate's body (`not_certified`,
    /// `identity_status_unavailable`).
    #[error("relay refused ({status} {code}): {description}")]
    Relay {
        status: u16,
        code: String,
        description: String,
    },
    /// The relay's rate limit refused the request (an HTTP 429, or
    /// `messageFailed` on the WebSocket), and the wait was longer than the
    /// client's rate-limit wait
    /// ([`MessageBoxClient::with_rate_limit_wait`](crate::MessageBoxClient::with_rate_limit_wait)).
    /// `retry_after` is how long until the relay takes the next send or list;
    /// `tier` is the budget the relay applied (`uncertified` or `certified`),
    /// when it said.
    #[error("rate limited by the relay; retry after {retry_after:?}")]
    RateLimited {
        retry_after: Duration,
        tier: Option<String>,
    },
    /// The client was pinned to one relay identity key
    /// ([`MessageBoxClient::with_expected_relay_key`](crate::MessageBoxClient::with_expected_relay_key))
    /// and a server proved a different key, or none. The answer was not used.
    #[error("relay identity mismatch: expected {expected}, server proved {}", observed.as_deref().unwrap_or("no key"))]
    RelayIdentityMismatch {
        expected: String,
        observed: Option<String>,
    },
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing header: {0}")]
    MissingHeader(String),
    #[error("not initialized")]
    NotInitialized,
    #[error("websocket error: {0}")]
    WebSocket(String),
    #[error("overlay error: {0}")]
    Overlay(String),
    #[error("validation error: {0}")]
    Validation(String),
}
