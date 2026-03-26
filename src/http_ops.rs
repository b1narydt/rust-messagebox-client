use bsv::wallet::interfaces::WalletInterface;

use crate::client::MessageBoxClient;
use crate::error::MessageBoxError;
use crate::types::{AcknowledgeMessageParams, ListMessagesParams, ListMessagesResponse, SendMessageParams, SendMessageRequest, ServerPeerMessage};
use crate::encryption;

impl<W: WalletInterface + Clone + 'static + Send + Sync> MessageBoxClient<W> {
    /// Send an encrypted message to a recipient's inbox.
    ///
    /// 1. Asserts the client is initialized (caches identity key).
    /// 2. Encrypts `body` for `recipient` using BRC-78.
    /// 3. Generates a deterministic HMAC message ID.
    /// 4. POSTs `{"message": {recipient, messageBox, body, messageId}}` to `/sendMessage`.
    /// 5. Returns the HMAC-derived message ID.
    pub async fn send_message(
        &self,
        recipient: &str,
        message_box: &str,
        body: &str,
    ) -> Result<String, MessageBoxError> {
        self.assert_initialized().await?;

        // Encrypt the body for the recipient
        let encrypted_body = encryption::encrypt_body(
            self.wallet(),
            body,
            recipient,
            self.originator(),
        )
        .await?;

        // Generate deterministic HMAC message ID
        // NOTE: generate_message_id internally calls serde_json::to_string(body) to replicate
        // TS JSON.stringify(message.body) behavior for exact parity (line 917 in MessageBoxClient.ts)
        let message_id = encryption::generate_message_id(
            self.wallet(),
            body,
            recipient,
            self.originator(),
        )
        .await?;

        // Build request wire format: {"message": {...}}
        let request = SendMessageRequest {
            message: SendMessageParams {
                recipient: recipient.to_string(),
                message_box: message_box.to_string(),
                body: encrypted_body,
                message_id: message_id.clone(),
            },
        };

        let body_bytes = serde_json::to_vec(&request)?;
        let url = format!("{}/sendMessage", self.host());
        self.post_json(&url, body_bytes).await?;

        Ok(message_id)
    }

    /// Retrieve messages from an inbox without payment internalization.
    ///
    /// Calls `/listMessages` and auto-decrypts each message body.
    ///
    /// PARITY: passes `originator: None` to `try_decrypt_message`, matching
    /// the TS `listMessagesLite` which omits originator (Pitfall 4).
    pub async fn list_messages_lite(
        &self,
        message_box: &str,
    ) -> Result<Vec<ServerPeerMessage>, MessageBoxError> {
        self.assert_initialized().await?;

        let params = ListMessagesParams {
            message_box: message_box.to_string(),
        };
        let body_bytes = serde_json::to_vec(&params)?;
        let url = format!("{}/listMessages", self.host());
        let response = self.post_json(&url, body_bytes).await?;

        let mut list_response: ListMessagesResponse =
            serde_json::from_slice(&response.body)?;

        // Decrypt each message body in-place.
        // PARITY: originator is None here — matches TS listMessagesLite which omits originator
        for msg in &mut list_response.messages {
            msg.body = encryption::try_decrypt_message(
                self.wallet(),
                &msg.body,
                &msg.sender,
                None, // PARITY: matches TS listMessagesLite which omits originator
            )
            .await;
        }

        Ok(list_response.messages)
    }

    /// Mark messages as acknowledged (read) by their IDs.
    ///
    /// POSTs `{"messageIds": [...]}` to `/acknowledgeMessage`.
    pub async fn acknowledge_message(
        &self,
        message_ids: Vec<String>,
    ) -> Result<(), MessageBoxError> {
        self.assert_initialized().await?;

        let params = AcknowledgeMessageParams { message_ids };
        let body_bytes = serde_json::to_vec(&params)?;
        let url = format!("{}/acknowledgeMessage", self.host());
        self.post_json(&url, body_bytes).await?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::encryption::generate_message_id;
    use crate::types::{
        AcknowledgeMessageParams, ListMessagesResponse, SendMessageParams, SendMessageRequest,
    };
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::error::WalletError;
    use bsv::wallet::interfaces::*;
    use bsv::wallet::proto_wallet::ProtoWallet;
    use std::sync::Arc;

    // Reuse the same ArcWallet helper as client::tests
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

    // -----------------------------------------------------------------------
    // Wire format tests (no HTTP needed)
    // -----------------------------------------------------------------------

    /// Verify the sendMessage wire format serializes correctly.
    #[test]
    fn test_send_message_request_format() {
        let req = SendMessageRequest {
            message: SendMessageParams {
                recipient: "03abc123".to_string(),
                message_box: "payment_inbox".to_string(),
                body: r#"{"encryptedMessage":"abc=="}"#.to_string(),
                message_id: "deadbeef01234567".to_string(),
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        // Must be wrapped as {"message": {...}}
        assert!(json.starts_with(r#"{"message":"#), "must have message wrapper");
        assert!(json.contains("\"recipient\""), "camelCase recipient");
        assert!(json.contains("\"messageBox\""), "camelCase messageBox");
        assert!(json.contains("\"messageId\""), "camelCase messageId");
        assert!(json.contains("\"payment_inbox\""), "messageBox value preserved");
        assert!(!json.contains("message_box"), "no snake_case leakage");
        assert!(!json.contains("message_id"), "no snake_case leakage");
    }

    /// Verify acknowledge request wire format.
    #[test]
    fn test_acknowledge_request_format() {
        let params = AcknowledgeMessageParams {
            message_ids: vec!["id1".to_string(), "id2".to_string()],
        };
        let json = serde_json::to_string(&params).unwrap();
        assert_eq!(json, r#"{"messageIds":["id1","id2"]}"#);
    }

    /// Verify listMessages response can be parsed from a sample JSON payload.
    #[test]
    fn test_list_messages_response_parsing() {
        let raw = r#"{
            "status": "success",
            "messages": [
                {
                    "messageId": "abc123",
                    "body": "hello world",
                    "sender": "03xyz",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:01:00Z"
                }
            ]
        }"#;
        let resp: ListMessagesResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.status, "success");
        assert_eq!(resp.messages.len(), 1);
        assert_eq!(resp.messages[0].message_id, "abc123");
        assert_eq!(resp.messages[0].body, "hello world");
        assert_eq!(resp.messages[0].sender, "03xyz");
    }

    // -----------------------------------------------------------------------
    // HMAC message ID tests
    // -----------------------------------------------------------------------

    /// HMAC message ID must be exactly 64 lowercase hex characters.
    #[tokio::test]
    async fn test_message_id_is_64_hex_chars() {
        let wallet = ArcWallet::new();
        // Use a placeholder recipient pubkey — need a valid compressed pubkey
        let other = ArcWallet::new();
        let other_pk = other
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
                None,
            )
            .await
            .expect("get_public_key")
            .public_key
            .to_der_hex();

        let id = generate_message_id(&wallet, "test body", &other_pk, None)
            .await
            .expect("generate_message_id");

        assert_eq!(id.len(), 64, "HMAC hex must be 64 chars (32 bytes)");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "all characters must be hex"
        );
        assert!(
            id.chars().all(|c| !c.is_uppercase()),
            "hex must be lowercase"
        );
    }

    /// HMAC message ID must be deterministic — same inputs produce same output.
    #[tokio::test]
    async fn test_message_id_deterministic() {
        let wallet = ArcWallet::new();
        let other = ArcWallet::new();
        let other_pk = other
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
                None,
            )
            .await
            .expect("get_public_key")
            .public_key
            .to_der_hex();

        let id1 = generate_message_id(&wallet, "same body", &other_pk, None)
            .await
            .expect("first call");
        let id2 = generate_message_id(&wallet, "same body", &other_pk, None)
            .await
            .expect("second call");

        assert_eq!(id1, id2, "same inputs must produce the same HMAC");
    }
}
