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
    #[error("HTTP error: status {0} from {1}")]
    Http(u16, String),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing header: {0}")]
    MissingHeader(String),
    #[error("not initialized")]
    NotInitialized,
}
