//! The wallet the relay auth channel signs with.
//!
//! `AuthFetch` and the WebSocket client act with the wallet before the client
//! sees an answer: they sign each request for the server that proved its key
//! in the handshake, answer a certificate request by proving certificates to
//! that server, and `AuthFetch` pays a `402` answer by creating a transaction.
//! A relay identity pin checked only on the answer is too late for all three.
//!
//! [`PinnedWallet`] is what those channels get instead of the caller's wallet.
//! With a pin it refuses `create_action`, so the auth channel never pays;
//! refuses `prove_certificate` for any verifier but the pinned relay; refuses
//! `create_signature` for any other counterparty key, so a request is never
//! signed, and so never sent, to a server that proved another key; and
//! refuses both key-linkage reveals, which the auth channel never needs.
//! Every other call goes to the caller's wallet unchanged. Without a pin it
//! changes nothing. [`PinnedWallet::guard_provider`] guards a configured
//! [`CertificateProvider`] the same way.
//!
//! The auth channels report a refusal only as text inside their own error.
//! Each refusal for a server carries [`REFUSED_SERVER`] and that server's key
//! in its text, and [`PinnedWallet::classify`] reads the failure back as the
//! pin mismatch behind it, from that one error alone.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bsv::auth::clients::auth_fetch::AuthFetch;
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::*;
use bsv::wallet::types::CounterpartyType;

use crate::error::MessageBoxError;
use crate::transport::{normalize_identity_key, HttpTransport, RelayResponse};
use crate::websocket::CertificateProvider;

/// What the text of every refusal for a server other than the pin carries,
/// followed by that server's key (hex).
const REFUSED_SERVER: &str = "the relay pin refuses server ";

/// The caller's wallet, as handed to the relay auth channel.
#[derive(Clone)]
pub(crate) struct PinnedWallet<W> {
    inner: W,
    /// The relay identity pin, normalised. `None` delegates every call.
    pin: Option<String>,
}

impl<W> PinnedWallet<W> {
    pub(crate) fn new(inner: W, pin: Option<String>) -> Self {
        Self { inner, pin }
    }

    /// Whether the pin allows proving a certificate to, or signing for, the
    /// server `peer` (hex).
    fn may_answer(&self, peer: &str) -> bool {
        self.pin
            .as_ref()
            .is_none_or(|pin| normalize_identity_key(peer) == *pin)
    }

    /// The text of a refusal of `what` for the server `peer`.
    fn refusal_text(&self, what: &str, peer: &str) -> String {
        format!(
            "{what} refused: {REFUSED_SERVER}{peer}; the client is pinned to relay {}",
            self.pin.as_deref().unwrap_or_default()
        )
    }

    /// The error for a call the pin refuses.
    fn refused_by_pin(&self, what: &str) -> WalletError {
        WalletError::Internal(format!(
            "{what} refused: the client is pinned to relay {}",
            self.pin.as_deref().unwrap_or_default()
        ))
    }

    /// `error` as [`MessageBoxError::RelayIdentityMismatch`] when it is an
    /// auth channel failure whose own text carries this wallet's refusal: the
    /// server it names had proved a key other than the pin. Any other error
    /// unchanged.
    pub(crate) fn classify(&self, error: MessageBoxError) -> MessageBoxError {
        let Some(pin) = &self.pin else {
            return error;
        };
        let (MessageBoxError::Auth(text) | MessageBoxError::WebSocket(text)) = &error else {
            return error;
        };
        let Some((_, rest)) = text.split_once(REFUSED_SERVER) else {
            return error;
        };
        let peer: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
        MessageBoxError::RelayIdentityMismatch {
            expected: pin.clone(),
            observed: Some(normalize_identity_key(&peer)),
        }
    }

    /// `provider`, refusing without calling it any verifier but the pinned
    /// relay. Without a pin, `provider` unchanged.
    pub(crate) fn guard_provider(&self, provider: CertificateProvider) -> CertificateProvider
    where
        W: Clone + Send + Sync + 'static,
    {
        if self.pin.is_none() {
            return provider;
        }
        let guard = self.clone();
        Arc::new(move |verifier, requested| {
            if !guard.may_answer(&verifier) {
                let message = guard.refusal_text("certificate request", &verifier);
                return Box::pin(async move { Err(message) });
            }
            provider(verifier, requested)
        })
    }
}

#[async_trait]
impl<W> WalletInterface for PinnedWallet<W>
where
    W: WalletInterface + Clone + Send + Sync + 'static,
{
    async fn create_action(
        &self,
        args: CreateActionArgs,
        orig: Option<&str>,
    ) -> Result<CreateActionResult, WalletError> {
        if let Some(pin) = &self.pin {
            return Err(WalletError::Internal(format!(
                "the client is pinned to relay {pin}: the relay auth channel never pays"
            )));
        }
        self.inner.create_action(args, orig).await
    }
    async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        orig: Option<&str>,
    ) -> Result<ProveCertificateResult, WalletError> {
        let verifier = args.verifier.to_der_hex();
        if !self.may_answer(&verifier) {
            return Err(WalletError::Internal(
                self.refusal_text("certificate proof", &verifier),
            ));
        }
        self.inner.prove_certificate(args, orig).await
    }
    /// The auth channel signs each message for the server that proved its
    /// key, as `Other(that key)`.
    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        orig: Option<&str>,
    ) -> Result<CreateSignatureResult, WalletError> {
        if let (CounterpartyType::Other, Some(peer)) = (
            &args.counterparty.counterparty_type,
            &args.counterparty.public_key,
        ) {
            let peer = peer.to_der_hex();
            if !self.may_answer(&peer) {
                return Err(WalletError::Internal(self.refusal_text("signature", &peer)));
            }
        }
        self.inner.create_signature(args, orig).await
    }
    async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        orig: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        if self.pin.is_some() {
            return Err(self.refused_by_pin("key linkage"));
        }
        self.inner.reveal_counterparty_key_linkage(args, orig).await
    }
    async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        orig: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        if self.pin.is_some() {
            return Err(self.refused_by_pin("key linkage"));
        }
        self.inner.reveal_specific_key_linkage(args, orig).await
    }

    // Everything below delegates unchanged.

    async fn sign_action(
        &self,
        args: SignActionArgs,
        orig: Option<&str>,
    ) -> Result<SignActionResult, WalletError> {
        self.inner.sign_action(args, orig).await
    }
    async fn abort_action(
        &self,
        args: AbortActionArgs,
        orig: Option<&str>,
    ) -> Result<AbortActionResult, WalletError> {
        self.inner.abort_action(args, orig).await
    }
    async fn list_actions(
        &self,
        args: ListActionsArgs,
        orig: Option<&str>,
    ) -> Result<ListActionsResult, WalletError> {
        self.inner.list_actions(args, orig).await
    }
    async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        orig: Option<&str>,
    ) -> Result<InternalizeActionResult, WalletError> {
        self.inner.internalize_action(args, orig).await
    }
    async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        orig: Option<&str>,
    ) -> Result<ListOutputsResult, WalletError> {
        self.inner.list_outputs(args, orig).await
    }
    async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        orig: Option<&str>,
    ) -> Result<RelinquishOutputResult, WalletError> {
        self.inner.relinquish_output(args, orig).await
    }
    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        orig: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        self.inner.get_public_key(args, orig).await
    }
    async fn encrypt(
        &self,
        args: EncryptArgs,
        orig: Option<&str>,
    ) -> Result<EncryptResult, WalletError> {
        self.inner.encrypt(args, orig).await
    }
    async fn decrypt(
        &self,
        args: DecryptArgs,
        orig: Option<&str>,
    ) -> Result<DecryptResult, WalletError> {
        self.inner.decrypt(args, orig).await
    }
    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        orig: Option<&str>,
    ) -> Result<CreateHmacResult, WalletError> {
        self.inner.create_hmac(args, orig).await
    }
    async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        orig: Option<&str>,
    ) -> Result<VerifyHmacResult, WalletError> {
        self.inner.verify_hmac(args, orig).await
    }
    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        orig: Option<&str>,
    ) -> Result<VerifySignatureResult, WalletError> {
        self.inner.verify_signature(args, orig).await
    }
    async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        orig: Option<&str>,
    ) -> Result<Certificate, WalletError> {
        self.inner.acquire_certificate(args, orig).await
    }
    async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        orig: Option<&str>,
    ) -> Result<ListCertificatesResult, WalletError> {
        self.inner.list_certificates(args, orig).await
    }
    async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        orig: Option<&str>,
    ) -> Result<RelinquishCertificateResult, WalletError> {
        self.inner.relinquish_certificate(args, orig).await
    }
    async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        orig: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        self.inner.discover_by_identity_key(args, orig).await
    }
    async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        orig: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        self.inner.discover_by_attributes(args, orig).await
    }
    async fn is_authenticated(
        &self,
        orig: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        self.inner.is_authenticated(orig).await
    }
    async fn wait_for_authentication(
        &self,
        orig: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        self.inner.wait_for_authentication(orig).await
    }
    async fn get_height(&self, orig: Option<&str>) -> Result<GetHeightResult, WalletError> {
        self.inner.get_height(orig).await
    }
    async fn get_header_for_height(
        &self,
        args: GetHeaderArgs,
        orig: Option<&str>,
    ) -> Result<GetHeaderResult, WalletError> {
        self.inner.get_header_for_height(args, orig).await
    }
    async fn get_network(&self, orig: Option<&str>) -> Result<GetNetworkResult, WalletError> {
        self.inner.get_network(orig).await
    }
    async fn get_version(&self, orig: Option<&str>) -> Result<GetVersionResult, WalletError> {
        self.inner.get_version(orig).await
    }
}

/// `AuthFetch` on a [`PinnedWallet`]. A request that fails because the wallet
/// refused a proof or a signature for a server that proved another key fails
/// with [`MessageBoxError::RelayIdentityMismatch`], and the `AuthFetch` is
/// replaced with a fresh one.
///
/// `AuthFetch` keeps the server it handshook with for each base URL and drops
/// it only on a stale session. Kept, a refused server would be refused on every
/// later request there, even once the pinned relay answers at that URL; the
/// fresh `AuthFetch` handshakes again.
pub(crate) struct PinnedFetch<W>
where
    W: WalletInterface + Clone + Send + Sync + 'static,
{
    fetch: std::sync::RwLock<Arc<AuthFetch<PinnedWallet<W>>>>,
    wallet: PinnedWallet<W>,
}

impl<W> PinnedFetch<W>
where
    W: WalletInterface + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(wallet: PinnedWallet<W>) -> Self {
        Self {
            fetch: std::sync::RwLock::new(Arc::new(AuthFetch::new(wallet.clone()))),
            wallet,
        }
    }
}

#[async_trait]
impl<W> HttpTransport for PinnedFetch<W>
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
        let fetch = self.fetch.read().unwrap_or_else(|p| p.into_inner()).clone();
        let error = match HttpTransport::fetch(fetch.as_ref(), url, method, body, headers).await {
            Ok(answer) => return Ok(answer),
            Err(e) => self.wallet.classify(e),
        };
        if matches!(error, MessageBoxError::RelayIdentityMismatch { .. }) {
            let mut current = self.fetch.write().unwrap_or_else(|p| p.into_inner());
            // Another request may have replaced it already.
            if Arc::ptr_eq(&current, &fetch) {
                *current = Arc::new(AuthFetch::new(self.wallet.clone()));
            }
        }
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::private_key::PrivateKey;
    use bsv::primitives::public_key::PublicKey;
    use bsv::wallet::proto_wallet::ProtoWallet;
    use bsv::wallet::types::{BooleanDefaultFalse, Counterparty, Protocol};

    // `ProtoWallet` answers `create_action` and `prove_certificate` with
    // `NotImplemented`, so that error shows a call reached the inner wallet
    // and `Internal` shows the wrapper refused it.

    fn key(byte: u8) -> PublicKey {
        PrivateKey::from_bytes(&[byte; 32])
            .expect("key")
            .to_public_key()
    }

    fn pinned_to(relay: &PublicKey) -> PinnedWallet<Arc<ProtoWallet>> {
        let inner = Arc::new(ProtoWallet::new(
            PrivateKey::from_bytes(&[1; 32]).expect("key"),
        ));
        PinnedWallet::new(inner, Some(relay.to_der_hex()))
    }

    fn proof_for(verifier: &PublicKey) -> ProveCertificateArgs {
        ProveCertificateArgs {
            certificate: PartialCertificate {
                cert_type: None,
                serial_number: None,
                subject: None,
                certifier: None,
                revocation_outpoint: None,
                fields: None,
                signature: None,
            },
            fields_to_reveal: vec!["membership".to_string()],
            verifier: verifier.clone(),
            privileged: BooleanDefaultFalse(None),
            privileged_reason: None,
        }
    }

    /// What the BRC-103 peer signs a message with: the server's key as
    /// `Other`.
    fn signature_for(server: &PublicKey) -> CreateSignatureArgs {
        CreateSignatureArgs {
            protocol_id: Protocol {
                security_level: 2,
                protocol: "auth message signature".to_string(),
            },
            key_id: "nonce peer-nonce".to_string(),
            counterparty: Counterparty {
                counterparty_type: CounterpartyType::Other,
                public_key: Some(server.clone()),
            },
            data: Some(b"request".to_vec()),
            hash_to_directly_sign: None,
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        }
    }

    /// `refused` is the wallet's refusal, and the auth channel's failure
    /// carrying it reads back as the pin mismatch with `server`'s key.
    fn assert_reads_as_mismatch<T: std::fmt::Debug>(
        wallet: &PinnedWallet<Arc<ProtoWallet>>,
        refused: Result<T, WalletError>,
        server: &PublicKey,
    ) {
        let refused = match refused {
            Err(e @ WalletError::Internal(_)) => e,
            other => panic!("expected the refusal, got {other:?}"),
        };
        match wallet.classify(MessageBoxError::Auth(format!(
            "handshake failed: {refused}"
        ))) {
            MessageBoxError::RelayIdentityMismatch { observed, .. } => {
                assert_eq!(observed, Some(server.to_der_hex()));
            }
            other => panic!("expected the pin mismatch, got {other:?}"),
        }
    }

    /// Each failure is read by itself: another channel's refusal, before or
    /// at the same time, never turns an unrelated failure into a mismatch.
    #[tokio::test]
    async fn only_a_failure_carrying_a_refusal_reads_as_the_pin_mismatch() {
        let wallet = pinned_to(&key(2));
        let refused = wallet.create_signature(signature_for(&key(3)), None).await;
        assert!(refused.is_err(), "{refused:?}");

        let unrelated = wallet.classify(MessageBoxError::Auth("connection reset".to_string()));
        assert!(
            matches!(&unrelated, MessageBoxError::Auth(text) if text == "connection reset"),
            "{unrelated:?}"
        );
    }

    #[tokio::test]
    async fn a_pinned_wallet_signs_only_for_the_pinned_relay() {
        let relay = key(2);
        let other = key(3);
        let wallet = pinned_to(&relay);

        let refused = wallet.create_signature(signature_for(&other), None).await;
        assert_reads_as_mismatch(&wallet, refused, &other);

        let signed = wallet.create_signature(signature_for(&relay), None).await;
        assert!(signed.is_ok(), "{signed:?}");
    }

    #[tokio::test]
    async fn a_pinned_wallet_reveals_no_key_linkage() {
        let relay = key(2);
        let wallet = pinned_to(&relay);
        let counterparty = wallet
            .reveal_counterparty_key_linkage(
                RevealCounterpartyKeyLinkageArgs {
                    counterparty: relay.clone(),
                    verifier: relay.clone(),
                    privileged: None,
                    privileged_reason: None,
                },
                None,
            )
            .await;
        assert!(counterparty.is_err(), "{counterparty:?}");
        let specific = wallet
            .reveal_specific_key_linkage(
                RevealSpecificKeyLinkageArgs {
                    counterparty: signature_for(&relay).counterparty,
                    verifier: relay.clone(),
                    protocol_id: signature_for(&relay).protocol_id,
                    key_id: "1".to_string(),
                    privileged: None,
                    privileged_reason: None,
                },
                None,
            )
            .await;
        assert!(specific.is_err(), "{specific:?}");
    }

    #[tokio::test]
    async fn a_pinned_wallet_never_pays() {
        let wallet = pinned_to(&key(2));
        let args = CreateActionArgs {
            description: "pay the relay".to_string(),
            input_beef: None,
            inputs: None,
            outputs: None,
            lock_time: None,
            version: None,
            labels: None,
            options: None,
            reference: None,
        };
        let refused = wallet.create_action(args, None).await;
        assert!(
            matches!(refused, Err(WalletError::Internal(_))),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn a_pinned_wallet_proves_only_to_the_pinned_relay() {
        let relay = key(2);
        let other = key(3);
        let wallet = pinned_to(&relay);

        let refused = wallet.prove_certificate(proof_for(&other), None).await;
        assert_reads_as_mismatch(&wallet, refused, &other);

        let delegated = wallet.prove_certificate(proof_for(&relay), None).await;
        assert!(
            matches!(delegated, Err(WalletError::NotImplemented(_))),
            "{delegated:?}"
        );
    }
}
