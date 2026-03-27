use std::collections::HashMap;

use bsv::auth::clients::auth_fetch::{AuthFetch, AuthFetchResponse};
use bsv::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
use tokio::sync::{Mutex, OnceCell};

use crate::error::MessageBoxError;

/// Authenticated HTTP client for the MessageBox protocol.
///
/// `MessageBoxClient<W>` wraps `AuthFetch<W>` behind a `tokio::sync::Mutex`
/// because `AuthFetch::fetch()` takes `&mut self` and must be called from
/// async context.  A `std::sync::Mutex` held across `.await` panics under
/// Tokio — this is load-bearing and must not be changed.
pub struct MessageBoxClient<W: WalletInterface + Clone + 'static> {
    /// Base URL of the MessageBox server (trailing whitespace trimmed on construction).
    host: String,
    /// BRC-31 authenticated HTTP client (needs `&mut self`, hence Mutex).
    auth_fetch: Mutex<AuthFetch<W>>,
    /// Wallet retained for direct encrypt / decrypt calls in `http_ops`.
    wallet: W,
    /// Optional originator string forwarded to wallet operations.
    originator: Option<String>,
    /// Cached identity public key (hex) — populated on first call.
    identity_key: OnceCell<String>,
    /// Ensures assert_initialized runs the full init path at most once.
    /// Phase 5 will populate this — kept now to avoid a breaking struct change later.
    #[allow(dead_code)]
    init_once: OnceCell<()>,
}

impl<W: WalletInterface + Clone + 'static + Send + Sync> MessageBoxClient<W> {
    /// Construct a new `MessageBoxClient`.
    ///
    /// * `host` — Base URL of the MessageBox server.  Trailing whitespace is
    ///   trimmed so callers do not need to sanitize.
    /// * `wallet` — Any `WalletInterface` implementation.
    /// * `originator` — Optional originator string forwarded to wallet ops.
    pub fn new(host: String, wallet: W, originator: Option<String>) -> Self {
        MessageBoxClient {
            host: host.trim().to_string(),
            auth_fetch: Mutex::new(AuthFetch::new(wallet.clone())),
            wallet,
            originator,
            identity_key: OnceCell::new(),
            init_once: OnceCell::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Public getters (needed by http_ops)
    // -----------------------------------------------------------------------

    /// Return the trimmed host URL.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Return a reference to the underlying wallet.
    pub fn wallet(&self) -> &W {
        &self.wallet
    }

    /// Return the originator string, if any.
    pub fn originator(&self) -> Option<&str> {
        self.originator.as_deref()
    }

    // -----------------------------------------------------------------------
    // Identity key
    // -----------------------------------------------------------------------

    /// Return the wallet's identity public key as a DER hex string.
    ///
    /// The result is cached in a `OnceCell` — subsequent calls return the
    /// cached value without calling the wallet again.
    pub async fn get_identity_key(&self) -> Result<String, MessageBoxError> {
        if let Some(k) = self.identity_key.get() {
            return Ok(k.clone());
        }

        let result = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        let key = result.public_key.to_der_hex();
        // Ignore the error — if another caller set the cell first, we just use
        // the stored value.
        let _ = self.identity_key.set(key.clone());
        Ok(key)
    }

    // -----------------------------------------------------------------------
    // Initialization guard
    // -----------------------------------------------------------------------

    /// Ensure the client is initialized before performing any HTTP operation.
    ///
    /// Phase 1 implementation: caches the identity key and returns.
    /// Full overlay init (`anoint_host`, SHIP broadcast) is deferred to Phase 5.
    pub(crate) async fn assert_initialized(&self) -> Result<(), MessageBoxError> {
        self.get_identity_key().await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal HTTP helper
    // -----------------------------------------------------------------------

    /// POST JSON bytes to `url` using BRC-31 authenticated transport.
    ///
    /// The entire `fetch()` call executes while the lock is held.  This is
    /// correct because `fetch()` is the outermost operation; no re-entrant
    /// locking occurs on the Phase 1 code path.
    pub(crate) async fn post_json(
        &self,
        url: &str,
        body_bytes: Vec<u8>,
    ) -> Result<AuthFetchResponse, MessageBoxError> {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let response = self
            .auth_fetch
            .lock()
            .await
            .fetch(url, "POST", Some(body_bytes), Some(headers))
            .await
            .map_err(|e| MessageBoxError::Auth(e.to_string()))?;

        if response.status < 200 || response.status >= 300 {
            return Err(MessageBoxError::Http(
                response.status,
                url.to_string(),
            ));
        }

        Ok(response)
    }

    /// GET `url` using BRC-31 authenticated transport.
    ///
    /// Mirrors `post_json` but sends no body and no content-type header.
    /// The caller is responsible for building the full URL including query string.
    pub(crate) async fn get_json(
        &self,
        url: &str,
    ) -> Result<AuthFetchResponse, MessageBoxError> {
        let response = self
            .auth_fetch
            .lock()
            .await
            .fetch(url, "GET", None, None)
            .await
            .map_err(|e| MessageBoxError::Auth(e.to_string()))?;

        if response.status < 200 || response.status >= 300 {
            return Err(MessageBoxError::Http(
                response.status,
                url.to_string(),
            ));
        }

        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/// Check if a successful (2xx) HTTP response body contains a server-level
/// error indicator (`{"status": "error", "description": "..."}`).
///
/// The MessageBox server can return HTTP 200 with a logical error payload —
/// this helper normalises that into `MessageBoxError::Auth`.
pub(crate) fn check_status_error(body: &[u8]) -> Result<(), MessageBoxError> {
    // Attempt a lightweight parse — ignore failures (malformed JSON is not
    // a server error in this sense).
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
        if v.get("status").and_then(|s| s.as_str()) == Some("error") {
            let description = v
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return Err(MessageBoxError::Auth(description));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::error::WalletError;
    use bsv::wallet::interfaces::*;
    use bsv::wallet::proto_wallet::ProtoWallet;
    use std::sync::Arc;

    /// Thin Arc wrapper that makes ProtoWallet clone-able for test purposes.
    ///
    /// ProtoWallet does not implement Clone because it holds a non-Clone
    /// KeyDeriver.  Wrapping in Arc satisfies the Clone bound while sharing
    /// the same underlying wallet across the clone and the AuthFetch instance.
    #[derive(Clone)]
    struct ArcWallet(Arc<ProtoWallet>);

    impl ArcWallet {
        fn new() -> Self {
            let key = PrivateKey::from_random().expect("random key");
            ArcWallet(Arc::new(ProtoWallet::new(key)))
        }
    }

    // Delegate every WalletInterface method to the inner ProtoWallet.
    #[async_trait::async_trait]
    impl WalletInterface for ArcWallet {
        async fn create_action(&self, args: CreateActionArgs, orig: Option<&str>) -> Result<CreateActionResult, WalletError> { self.0.create_action(args, orig).await }
        async fn sign_action(&self, args: SignActionArgs, orig: Option<&str>) -> Result<SignActionResult, WalletError> { self.0.sign_action(args, orig).await }
        async fn abort_action(&self, args: AbortActionArgs, orig: Option<&str>) -> Result<AbortActionResult, WalletError> { self.0.abort_action(args, orig).await }
        async fn list_actions(&self, args: ListActionsArgs, orig: Option<&str>) -> Result<ListActionsResult, WalletError> { self.0.list_actions(args, orig).await }
        async fn internalize_action(&self, args: InternalizeActionArgs, orig: Option<&str>) -> Result<InternalizeActionResult, WalletError> { self.0.internalize_action(args, orig).await }
        async fn list_outputs(&self, args: ListOutputsArgs, orig: Option<&str>) -> Result<ListOutputsResult, WalletError> { self.0.list_outputs(args, orig).await }
        async fn relinquish_output(&self, args: RelinquishOutputArgs, orig: Option<&str>) -> Result<RelinquishOutputResult, WalletError> { self.0.relinquish_output(args, orig).await }
        async fn get_public_key(&self, args: GetPublicKeyArgs, orig: Option<&str>) -> Result<GetPublicKeyResult, WalletError> { self.0.get_public_key(args, orig).await }
        async fn reveal_counterparty_key_linkage(&self, args: RevealCounterpartyKeyLinkageArgs, orig: Option<&str>) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> { self.0.reveal_counterparty_key_linkage(args, orig).await }
        async fn reveal_specific_key_linkage(&self, args: RevealSpecificKeyLinkageArgs, orig: Option<&str>) -> Result<RevealSpecificKeyLinkageResult, WalletError> { self.0.reveal_specific_key_linkage(args, orig).await }
        async fn encrypt(&self, args: EncryptArgs, orig: Option<&str>) -> Result<EncryptResult, WalletError> { self.0.encrypt(args, orig).await }
        async fn decrypt(&self, args: DecryptArgs, orig: Option<&str>) -> Result<DecryptResult, WalletError> { self.0.decrypt(args, orig).await }
        async fn create_hmac(&self, args: CreateHmacArgs, orig: Option<&str>) -> Result<CreateHmacResult, WalletError> { self.0.create_hmac(args, orig).await }
        async fn verify_hmac(&self, args: VerifyHmacArgs, orig: Option<&str>) -> Result<VerifyHmacResult, WalletError> { self.0.verify_hmac(args, orig).await }
        async fn create_signature(&self, args: CreateSignatureArgs, orig: Option<&str>) -> Result<CreateSignatureResult, WalletError> { self.0.create_signature(args, orig).await }
        async fn verify_signature(&self, args: VerifySignatureArgs, orig: Option<&str>) -> Result<VerifySignatureResult, WalletError> { self.0.verify_signature(args, orig).await }
        async fn acquire_certificate(&self, args: AcquireCertificateArgs, orig: Option<&str>) -> Result<Certificate, WalletError> { self.0.acquire_certificate(args, orig).await }
        async fn list_certificates(&self, args: ListCertificatesArgs, orig: Option<&str>) -> Result<ListCertificatesResult, WalletError> { self.0.list_certificates(args, orig).await }
        async fn prove_certificate(&self, args: ProveCertificateArgs, orig: Option<&str>) -> Result<ProveCertificateResult, WalletError> { self.0.prove_certificate(args, orig).await }
        async fn relinquish_certificate(&self, args: RelinquishCertificateArgs, orig: Option<&str>) -> Result<RelinquishCertificateResult, WalletError> { self.0.relinquish_certificate(args, orig).await }
        async fn discover_by_identity_key(&self, args: DiscoverByIdentityKeyArgs, orig: Option<&str>) -> Result<DiscoverCertificatesResult, WalletError> { self.0.discover_by_identity_key(args, orig).await }
        async fn discover_by_attributes(&self, args: DiscoverByAttributesArgs, orig: Option<&str>) -> Result<DiscoverCertificatesResult, WalletError> { self.0.discover_by_attributes(args, orig).await }
        async fn is_authenticated(&self, orig: Option<&str>) -> Result<AuthenticatedResult, WalletError> { self.0.is_authenticated(orig).await }
        async fn wait_for_authentication(&self, orig: Option<&str>) -> Result<AuthenticatedResult, WalletError> { self.0.wait_for_authentication(orig).await }
        async fn get_height(&self, orig: Option<&str>) -> Result<GetHeightResult, WalletError> { self.0.get_height(orig).await }
        async fn get_header_for_height(&self, args: GetHeaderArgs, orig: Option<&str>) -> Result<GetHeaderResult, WalletError> { self.0.get_header_for_height(args, orig).await }
        async fn get_network(&self, orig: Option<&str>) -> Result<GetNetworkResult, WalletError> { self.0.get_network(orig).await }
        async fn get_version(&self, orig: Option<&str>) -> Result<GetVersionResult, WalletError> { self.0.get_version(orig).await }
    }

    /// `new()` must trim leading/trailing whitespace from the host URL.
    #[tokio::test]
    async fn new_trims_host_url() {
        let wallet = ArcWallet::new();
        let client = MessageBoxClient::new(
            "https://example.com ".to_string(),
            wallet,
            None,
        );
        assert_eq!(client.host(), "https://example.com");
    }

    /// `get_identity_key` returns a non-empty hex string.
    #[tokio::test]
    async fn get_identity_key_returns_non_empty_hex() {
        let wallet = ArcWallet::new();
        let client = MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
        );
        let key = client.get_identity_key().await.expect("get_identity_key");
        assert!(!key.is_empty(), "identity key must be non-empty");
        assert!(
            key.chars().all(|c| c.is_ascii_hexdigit()),
            "identity key must be hex"
        );
    }

    /// `get_json` exists — compile check via type coercion to async fn pointer.
    ///
    /// We verify the method resolves without calling it (no live network needed).
    #[allow(dead_code)]
    fn get_json_compiles(client: &MessageBoxClient<ArcWallet>) {
        // If get_json does not exist or has wrong signature, this fn fails to compile.
        let _fut = client.get_json("https://example.com/test");
    }

    /// `check_status_error` returns Ok for success body.
    #[test]
    fn check_status_error_passes_success_body() {
        use super::check_status_error;
        let body = br#"{"status":"success","data":{}}"#;
        assert!(check_status_error(body).is_ok());
    }

    /// `check_status_error` returns Err for server error body.
    #[test]
    fn check_status_error_returns_err_for_error_body() {
        use super::check_status_error;
        let body = br#"{"status":"error","description":"permission denied"}"#;
        let err = check_status_error(body).unwrap_err();
        assert!(matches!(err, crate::error::MessageBoxError::Auth(_)));
        assert_eq!(err.to_string(), "auth error: permission denied");
    }

    /// `get_identity_key` returns the same value on a second call (OnceCell cache).
    #[tokio::test]
    async fn get_identity_key_caches_result() {
        let wallet = ArcWallet::new();
        let client = MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
        );
        let key1 = client.get_identity_key().await.expect("first call");
        let key2 = client.get_identity_key().await.expect("second call");
        assert_eq!(key1, key2, "OnceCell must return the same value on re-call");
    }
}
