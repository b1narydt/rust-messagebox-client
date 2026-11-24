//! The wallet the relay auth channel signs with.
//!
//! `AuthFetch` and the WebSocket handshake act with the wallet before the
//! client sees the relay's proven identity: they answer a certificate request
//! by proving certificates to whichever server asked, and `AuthFetch` pays a
//! `402` answer by creating a transaction. A relay identity pin is checked only
//! on the answer, which is too late for either.
//!
//! [`PinnedWallet`] is what those channels get instead of the caller's wallet.
//! With a pin it refuses `create_action`, so the auth channel never pays, and
//! refuses `prove_certificate` for any verifier but the pinned relay. Every
//! other call goes to the caller's wallet unchanged. Without a pin it changes
//! nothing. [`PinnedWallet::guard_provider`] does the same for a configured
//! [`CertificateProvider`].

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::*;

use crate::error::MessageBoxError;
use crate::transport::normalize_identity_key;
use crate::websocket::CertificateProvider;

/// The caller's wallet, as handed to the relay auth channel.
#[derive(Clone)]
pub(crate) struct PinnedWallet<W> {
    inner: W,
    /// The relay identity pin, normalised. `None` delegates every call.
    pin: Option<String>,
    /// The last verifier a certificate proof was refused to.
    refused: Arc<Mutex<Option<String>>>,
}

impl<W> PinnedWallet<W> {
    pub(crate) fn new(inner: W, pin: Option<String>) -> Self {
        Self {
            inner,
            pin,
            refused: Arc::default(),
        }
    }

    /// Whether the pin allows proving a certificate to `verifier` (hex). A
    /// refused verifier is recorded for [`refusal`](Self::refusal).
    fn may_prove_to(&self, verifier: &str) -> bool {
        match &self.pin {
            Some(pin) if normalize_identity_key(verifier) != *pin => {
                *self.refused.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some(verifier.to_string());
                false
            }
            _ => true,
        }
    }

    /// The pin mismatch behind a refused certificate proof, if there was one:
    /// the server that asked had proved a key other than the pin.
    pub(crate) fn refusal(&self) -> Option<MessageBoxError> {
        let verifier = self
            .refused
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()?;
        Some(MessageBoxError::RelayIdentityMismatch {
            expected: self.pin.clone().unwrap_or_default(),
            observed: Some(normalize_identity_key(&verifier)),
        })
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
            if !guard.may_prove_to(&verifier) {
                let message = format!(
                    "certificate request from {verifier} refused: the client is pinned to relay {}",
                    guard.pin.as_deref().unwrap_or_default()
                );
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
        if !self.may_prove_to(&verifier) {
            return Err(WalletError::Internal(format!(
                "certificate proof for {verifier} refused: the client is pinned to relay {}",
                self.pin.as_deref().unwrap_or_default()
            )));
        }
        self.inner.prove_certificate(args, orig).await
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
    async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        orig: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        self.inner.reveal_counterparty_key_linkage(args, orig).await
    }
    async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        orig: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        self.inner.reveal_specific_key_linkage(args, orig).await
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
    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        orig: Option<&str>,
    ) -> Result<CreateSignatureResult, WalletError> {
        self.inner.create_signature(args, orig).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::private_key::PrivateKey;
    use bsv::primitives::public_key::PublicKey;
    use bsv::wallet::proto_wallet::ProtoWallet;
    use bsv::wallet::types::BooleanDefaultFalse;

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
        assert!(
            matches!(refused, Err(WalletError::Internal(_))),
            "{refused:?}"
        );
        match wallet.refusal() {
            Some(MessageBoxError::RelayIdentityMismatch { observed, .. }) => {
                assert_eq!(observed, Some(other.to_der_hex()));
            }
            other => panic!("expected the refusal, got {other:?}"),
        }

        let delegated = wallet.prove_certificate(proof_for(&relay), None).await;
        assert!(
            matches!(delegated, Err(WalletError::NotImplemented(_))),
            "{delegated:?}"
        );
    }
}
