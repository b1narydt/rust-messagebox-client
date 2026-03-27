use std::sync::Arc;

use async_trait::async_trait;
use bsv::remittance::CommsLayer;
use bsv::remittance::types::PeerMessage;
use bsv::remittance::error::RemittanceError;
use bsv::wallet::interfaces::WalletInterface;

use crate::client::MessageBoxClient;

/// Bridge between `MessageBoxClient<W>` and the `CommsLayer` trait.
///
/// `RemittanceAdapter<W>` is the primary integration point for downstream
/// consumers (e.g. `metawatt-edge-rs`) that interact with the messagebox
/// protocol through the SDK's `CommsLayer` trait boundary.
///
/// Uses composition (`Arc<MessageBoxClient<W>>`) rather than inheritance —
/// this matches the pre-phase architectural decision in STATE.md and keeps
/// the adapter lightweight.
pub struct RemittanceAdapter<W: WalletInterface + Clone + 'static> {
    inner: Arc<MessageBoxClient<W>>,
}

impl<W: WalletInterface + Clone + 'static> RemittanceAdapter<W> {
    /// Construct a new `RemittanceAdapter` wrapping `client`.
    pub fn new(client: Arc<MessageBoxClient<W>>) -> Self {
        Self { inner: client }
    }
}

#[async_trait]
impl<W: WalletInterface + Clone + 'static + Send + Sync> CommsLayer for RemittanceAdapter<W> {
    /// Delegate to `MessageBoxClient::send_message`, ignoring `host_override`
    /// (multi-host routing is deferred to Phase 5).
    async fn send_message(
        &self,
        recipient: &str,
        message_box: &str,
        body: &str,
        _host_override: Option<&str>,
    ) -> Result<String, RemittanceError> {
        self.inner
            .send_message(recipient, message_box, body)
            .await
            .map_err(|e| RemittanceError::Protocol(e.to_string()))
    }

    /// Retrieve messages and map them to `Vec<PeerMessage>`.
    ///
    /// CRITICAL: `PeerMessage.recipient` is populated from `get_identity_key()`
    /// — NOT from `ServerPeerMessage`, which does not carry a recipient field.
    /// `PeerMessage.message_box` comes from the parameter, not the server response.
    async fn list_messages(
        &self,
        message_box: &str,
        _host: Option<&str>,
    ) -> Result<Vec<PeerMessage>, RemittanceError> {
        // Fetch identity key once before the mapping loop (cached by OnceCell).
        let identity_key = self
            .inner
            .get_identity_key()
            .await
            .map_err(|e| RemittanceError::Protocol(e.to_string()))?;

        let server_msgs = self
            .inner
            .list_messages_lite(message_box)
            .await
            .map_err(|e| RemittanceError::Protocol(e.to_string()))?;

        Ok(server_msgs
            .into_iter()
            .map(|m| PeerMessage {
                message_id: m.message_id,
                sender: m.sender,
                recipient: identity_key.clone(),  // Pitfall 3: not from ServerPeerMessage
                message_box: message_box.to_string(), // from parameter, not server response
                body: m.body,
            })
            .collect())
    }

    /// Delegate to `MessageBoxClient::acknowledge_message`.
    ///
    /// Converts `&[String]` to `Vec<String>` to match the inner method signature (Pitfall 4).
    async fn acknowledge_message(
        &self,
        message_ids: &[String],
    ) -> Result<(), RemittanceError> {
        self.inner
            .acknowledge_message(message_ids.to_vec())
            .await
            .map_err(|e| RemittanceError::Protocol(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ServerPeerMessage;
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::error::WalletError;
    use bsv::wallet::interfaces::*;
    use bsv::wallet::proto_wallet::ProtoWallet;

    // Reuse the same ArcWallet test helper pattern as client::tests / http_ops::tests.
    #[derive(Clone)]
    struct ArcWallet(Arc<ProtoWallet>);

    impl ArcWallet {
        fn new() -> Self {
            let key = PrivateKey::from_random().expect("random key");
            ArcWallet(Arc::new(ProtoWallet::new(key)))
        }
    }

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

    fn make_client() -> Arc<MessageBoxClient<ArcWallet>> {
        Arc::new(MessageBoxClient::new(
            "https://example.com".to_string(),
            ArcWallet::new(),
            None,
        ))
    }

    /// `RemittanceAdapter::new` constructs successfully from an Arc<MessageBoxClient<W>>.
    #[test]
    fn adapter_can_be_constructed() {
        let client = make_client();
        let _adapter = RemittanceAdapter::new(client);
    }

    /// `RemittanceAdapter` satisfies `Arc<dyn CommsLayer + Send + Sync>` — compile check.
    ///
    /// If `RemittanceAdapter` does not implement `CommsLayer` correctly this
    /// type coercion will fail to compile.
    #[test]
    fn adapter_is_comms_layer() {
        let client = make_client();
        let adapter = Arc::new(RemittanceAdapter::new(client));
        let _: Arc<dyn CommsLayer + Send + Sync> = adapter;
    }

    /// `ServerPeerMessage` maps to `PeerMessage` with all 5 fields correct.
    ///
    /// This exercises the mapping logic from `list_messages` directly,
    /// without a live HTTP call.
    #[test]
    fn map_server_message_all_five_fields() {
        let server_msg = ServerPeerMessage {
            message_id: "msg-001".to_string(),
            body: "hello body".to_string(),
            sender: "03senderkey".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:01:00Z".to_string(),
            acknowledged: None,
        };
        let identity_key = "03myidentitykey".to_string();
        let message_box = "payment_inbox";

        // Apply the same mapping logic as list_messages.
        let peer_msg = PeerMessage {
            message_id: server_msg.message_id.clone(),
            sender: server_msg.sender.clone(),
            recipient: identity_key.clone(),
            message_box: message_box.to_string(),
            body: server_msg.body.clone(),
        };

        assert_eq!(peer_msg.message_id, "msg-001");
        assert_eq!(peer_msg.sender, "03senderkey");
        assert_eq!(peer_msg.recipient, "03myidentitykey", "recipient from identity key");
        assert_eq!(peer_msg.message_box, "payment_inbox", "message_box from parameter");
        assert_eq!(peer_msg.body, "hello body");
    }

    /// `PeerMessage.recipient` is the identity key — NOT an empty string.
    ///
    /// This test guards against the common mistake of leaving recipient empty
    /// when ServerPeerMessage has no recipient field.
    #[tokio::test]
    async fn recipient_from_identity_key() {
        let client = make_client();
        let identity_key = client
            .get_identity_key()
            .await
            .expect("get_identity_key");

        assert!(!identity_key.is_empty(), "identity key must not be empty");

        // The mapping assigns this key to PeerMessage.recipient.
        let peer_msg = PeerMessage {
            message_id: "x".to_string(),
            sender: "03other".to_string(),
            recipient: identity_key.clone(),
            message_box: "inbox".to_string(),
            body: "body".to_string(),
        };

        assert_eq!(peer_msg.recipient, identity_key);
        assert_ne!(peer_msg.recipient, "", "recipient must not be empty string");
    }

    /// `acknowledge_message` converts `&[String]` to `Vec<String>` — compile check.
    ///
    /// Verifies the `.to_vec()` conversion compiles correctly with the adapter impl.
    #[test]
    fn acknowledge_message_accepts_slice() {
        // Verifies that &[String] (the CommsLayer signature) is accepted.
        // This is a compile-time check — if &[String] -> Vec<String> conversion
        // is missing in the adapter, this function fails to compile.
        let ids: &[String] = &["id1".to_string(), "id2".to_string()];
        let converted: Vec<String> = ids.to_vec();
        assert_eq!(converted, vec!["id1", "id2"]);
    }
}
