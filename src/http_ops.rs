use std::collections::{HashMap, HashSet};

use bsv::remittance::types::PeerMessage;
use bsv::wallet::interfaces::{InternalizeActionArgs, InternalizeOutput, Payment, WalletInterface};
use bsv::wallet::types::BooleanDefaultTrue;
use bsv::primitives::public_key::PublicKey;
use futures_util::future::join_all;

use crate::client::MessageBoxClient;
use crate::error::MessageBoxError;
use crate::client::check_status_error;
use crate::types::{AcknowledgeMessageParams, ListMessagesParams, ListMessagesResponse, SendMessageParams, SendMessageRequest, SendMessageResponse, ServerPeerMessage};
use crate::encryption;

/// Deduplicate messages from multiple hosts by `message_id`.
///
/// First occurrence wins — matches TS `Promise.allSettled` + Map-based dedup semantics.
/// All results from all hosts are flattened and deduplicated into a single Vec.
pub(crate) fn dedup_messages(results: Vec<Vec<PeerMessage>>) -> Vec<PeerMessage> {
    let mut seen: HashMap<String, PeerMessage> = HashMap::new();
    // Process in order so first-seen always wins
    for host_messages in results {
        for msg in host_messages {
            seen.entry(msg.message_id.clone()).or_insert(msg);
        }
    }
    seen.into_values().collect()
}

/// Intermediate type for server's wrapped message body format.
/// The server MAY wrap message body as { "message": ..., "payment": ... }
/// where payment contains delivery fee data for internalization.
#[derive(serde::Deserialize)]
pub(crate) struct WrappedMessageBody {
    pub message: Option<serde_json::Value>,
    pub payment: Option<ServerPayment>,
}

#[derive(serde::Deserialize)]
pub(crate) struct ServerPayment {
    pub tx: Option<Vec<u8>>,
    pub outputs: Option<Vec<ServerPaymentOutput>>,
    pub description: Option<String>,
}

/// One output entry from the server's delivery-fee payment.
/// All fields are optional — internalization is best-effort and errors are ignored.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerPaymentOutput {
    pub output_index: Option<u32>,
    /// Derivation prefix as byte array.
    pub derivation_prefix: Option<Vec<u8>>,
    /// Derivation suffix as byte array.
    pub derivation_suffix: Option<Vec<u8>>,
    /// Sender identity key as DER hex.
    pub sender_identity_key: Option<String>,
}

impl<W: WalletInterface + Clone + 'static + Send + Sync> MessageBoxClient<W> {
    /// Send an encrypted message to a recipient's inbox.
    ///
    /// CRITICAL TS PARITY: resolves the recipient's MessageBox host via overlay
    /// (`resolveHostForRecipient`) before sending — matching TS line 952:
    /// `const finalHost = overrideHost ?? await this.resolveHostForRecipient(message.recipient)`
    ///
    /// 1. Asserts the client is initialized.
    /// 2. Resolves recipient's host via overlay (falls back to self.host if unreachable).
    /// 3. Delegates to `send_message_to_host` with the resolved host.
    pub async fn send_message(
        &self,
        recipient: &str,
        message_box: &str,
        body: &str,
    ) -> Result<String, MessageBoxError> {
        self.assert_initialized().await?;
        let host = self.resolve_host_for_recipient(recipient).await?;
        self.send_message_to_host(&host, recipient, message_box, body).await
    }

    /// Send an encrypted message to a recipient's inbox at an explicit host.
    ///
    /// Lower-level helper used by `send_message` (after host resolution) and by
    /// `RemittanceAdapter` when `host_override` is provided.
    ///
    /// 1. Encrypts `body` for `recipient` using BRC-78.
    /// 2. Generates a deterministic HMAC message ID.
    /// 3. POSTs `{"message": {recipient, messageBox, body, messageId}}` to `{host}/sendMessage`.
    /// 4. Returns the HMAC-derived message ID (or server ID if present).
    pub(crate) async fn send_message_to_host(
        &self,
        host: &str,
        recipient: &str,
        message_box: &str,
        body: &str,
    ) -> Result<String, MessageBoxError> {
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
        let url = format!("{host}/sendMessage");
        let response = self.post_json(&url, body_bytes).await?;
        check_status_error(&response.body)?;

        // PARITY: TS returns server messageId when present, falls back to HMAC ID
        if let Ok(resp) = serde_json::from_slice::<SendMessageResponse>(&response.body) {
            if let Some(server_id) = resp.message_id {
                return Ok(server_id);
            }
        }
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
        check_status_error(&response.body)?;

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

    /// Retrieve messages from an inbox with optional server payment internalization.
    ///
    /// Unlike `list_messages_lite`, this method:
    /// - Returns `Vec<PeerMessage>` (not `Vec<ServerPeerMessage>`) with `recipient`
    ///   populated from `get_identity_key()` and `message_box` from the parameter.
    /// - Parses the server's `{ message, payment }` wrapper body format.
    /// - When `accept_payments` is true, internalizes the server delivery-fee payment
    ///   via `wallet.internalize_action`. Errors are logged/ignored (TS parity).
    ///
    /// Multi-host: queries all hosts advertised by this identity concurrently and
    /// deduplicates results by `message_id`. Matches TS `Promise.allSettled` semantics:
    /// if at least one host succeeds, partial results are returned.
    ///
    /// NOTE: This handles the server delivery-fee payment wrapper, NOT PeerPay
    /// PaymentTokens (peer-to-peer). PeerPay tokens are handled by `list_incoming_payments`.
    pub async fn list_messages(
        &self,
        message_box: &str,
        accept_payments: bool,
    ) -> Result<Vec<PeerMessage>, MessageBoxError> {
        self.assert_initialized().await?;

        // Discover all known hosts for this identity.
        let identity_key = self.get_identity_key().await?;
        let ads = self.query_advertisements(Some(&identity_key), None).await.unwrap_or_default();

        // Build the set of unique host URLs: ads + self.host (always included).
        let mut host_set: HashSet<String> = ads.into_iter().map(|ad| ad.host).collect();
        host_set.insert(self.host().to_string());

        if host_set.len() == 1 {
            // Single-host path — no need for dedup.
            return self.list_messages_from_host(self.host(), message_box, accept_payments).await;
        }

        // Multi-host path: query all concurrently (TS Promise.allSettled semantics).
        let futures: Vec<_> = host_set
            .iter()
            .map(|h| self.list_messages_from_host(h, message_box, accept_payments))
            .collect();

        let outcomes = join_all(futures).await;
        let successful: Vec<Vec<PeerMessage>> = outcomes
            .into_iter()
            .filter_map(|r| r.ok())
            .collect();

        if successful.is_empty() {
            return Err(MessageBoxError::Http(0, format!("list_messages: all {} hosts failed", host_set.len())));
        }

        Ok(dedup_messages(successful))
    }

    /// Retrieve messages from a single explicit host.
    ///
    /// Core implementation extracted so `list_messages` can call it per-host
    /// for multi-host deduplication without repeating internalization logic.
    async fn list_messages_from_host(
        &self,
        host: &str,
        message_box: &str,
        accept_payments: bool,
    ) -> Result<Vec<PeerMessage>, MessageBoxError> {
        // Cache identity key once — used as recipient in every PeerMessage.
        let identity_key = self.get_identity_key().await?;

        let params = ListMessagesParams {
            message_box: message_box.to_string(),
        };
        let body_bytes = serde_json::to_vec(&params)?;
        let url = format!("{host}/listMessages");
        let response = self.post_json(&url, body_bytes).await?;
        check_status_error(&response.body)?;

        let list_response: ListMessagesResponse = serde_json::from_slice(&response.body)?;

        let mut result = Vec::with_capacity(list_response.messages.len());
        for msg in list_response.messages {
            // Try to parse the body as a server-wrapped { message, payment } envelope.
            let plain_body: String = if let Ok(wrapped) = serde_json::from_str::<WrappedMessageBody>(&msg.body) {
                // Attempt to internalize the server delivery-fee payment when accept_payments=true.
                if accept_payments {
                    if let Some(payment) = &wrapped.payment {
                        if let Some(tx_bytes) = &payment.tx {
                            let description = payment
                                .description
                                .clone()
                                .unwrap_or_else(|| "Server delivery fee".to_string());

                            // Build output list from server payment data.
                            // Errors are intentionally ignored — matches TS try/catch behavior.
                            let outputs: Vec<InternalizeOutput> = payment
                                .outputs
                                .as_deref()
                                .unwrap_or(&[])
                                .iter()
                                .filter_map(|o| {
                                    // Try to parse sender key — skip output if invalid.
                                    let sender_pk = o.sender_identity_key
                                        .as_deref()
                                        .and_then(|k| PublicKey::from_string(k).ok())?;
                                    Some(InternalizeOutput::WalletPayment {
                                        output_index: o.output_index.unwrap_or(0),
                                        payment: Payment {
                                            derivation_prefix: o.derivation_prefix.clone().unwrap_or_default(),
                                            derivation_suffix: o.derivation_suffix.clone().unwrap_or_default(),
                                            sender_identity_key: sender_pk,
                                        },
                                    })
                                })
                                .collect();

                            let args = InternalizeActionArgs {
                                tx: tx_bytes.clone(),
                                description,
                                labels: vec!["server-delivery-fee".to_string()],
                                seek_permission: BooleanDefaultTrue(Some(false)),
                                outputs,
                            };
                            // Defensive: ignore internalization errors, continue processing.
                            let _ = self.wallet().internalize_action(args, self.originator()).await;
                        }
                    }
                }

                // Extract the message sub-field from the wrapper regardless of accept_payments.
                match wrapped.message {
                    Some(serde_json::Value::String(s)) => s,
                    Some(v) => v.to_string(),
                    None => msg.body.clone(),
                }
            } else {
                // Not a wrapped body — pass through as plain text.
                msg.body.clone()
            };

            // Decrypt the extracted body.
            let decrypted = encryption::try_decrypt_message(
                self.wallet(),
                &plain_body,
                &msg.sender,
                self.originator(),
            )
            .await;

            result.push(PeerMessage {
                message_id: msg.message_id,
                sender: msg.sender,
                recipient: identity_key.clone(),
                message_box: message_box.to_string(),
                body: decrypted,
            });
        }

        Ok(result)
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
        let response = self.post_json(&url, body_bytes).await?;
        check_status_error(&response.body)?;

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

    // -----------------------------------------------------------------------
    // list_messages body parsing tests (no HTTP needed)
    // -----------------------------------------------------------------------

    /// Verify wrapped {message, payment} body is unwrapped to the message sub-field.
    #[test]
    fn list_messages_parses_wrapped_body() {
        use super::WrappedMessageBody;
        let raw = r#"{"message": "hello world", "payment": {"tx": [1,2,3]}}"#;
        let wrapped: WrappedMessageBody = serde_json::from_str(raw).unwrap();
        assert!(wrapped.message.is_some(), "message sub-field must be present");
        assert!(wrapped.payment.is_some(), "payment sub-field must be present");
        // The message value is a JSON string
        let msg_val = wrapped.message.unwrap();
        assert_eq!(msg_val.as_str().unwrap(), "hello world");
    }

    /// Non-wrapped body must fail to parse as WrappedMessageBody gracefully.
    #[test]
    fn list_messages_plain_body_passthrough() {
        use super::WrappedMessageBody;
        // A plain string "hello" is NOT valid JSON for WrappedMessageBody
        let plain = "plain body text";
        let result = serde_json::from_str::<WrappedMessageBody>(plain);
        assert!(result.is_err(), "plain text must not parse as wrapped body");
    }

    /// Wrapped body with payment: null must not crash.
    #[test]
    fn list_messages_missing_payment_no_crash() {
        use super::WrappedMessageBody;
        let raw = r#"{"message": "the content", "payment": null}"#;
        let wrapped: WrappedMessageBody = serde_json::from_str(raw).unwrap();
        assert!(wrapped.message.is_some(), "message present");
        assert!(wrapped.payment.is_none(), "payment is none when null");
    }

    /// `dedup_messages` deduplicates by message_id — first occurrence wins.
    #[test]
    fn test_list_messages_dedup_by_id() {
        use super::dedup_messages;
        use bsv::remittance::types::PeerMessage;

        let msg_a = PeerMessage {
            message_id: "id-1".to_string(),
            sender: "03sender".to_string(),
            recipient: "03me".to_string(),
            message_box: "inbox".to_string(),
            body: "first".to_string(),
        };
        let msg_a_dup = PeerMessage {
            message_id: "id-1".to_string(), // same id — should be deduplicated
            sender: "03sender".to_string(),
            recipient: "03me".to_string(),
            message_box: "inbox".to_string(),
            body: "duplicate".to_string(), // different body — first-seen wins
        };
        let msg_b = PeerMessage {
            message_id: "id-2".to_string(),
            sender: "03sender".to_string(),
            recipient: "03me".to_string(),
            message_box: "inbox".to_string(),
            body: "second".to_string(),
        };

        // Two hosts: host1 has [msg_a, msg_b], host2 has [msg_a_dup]
        let results = vec![vec![msg_a.clone(), msg_b.clone()], vec![msg_a_dup]];
        let deduped = dedup_messages(results);

        assert_eq!(deduped.len(), 2, "must deduplicate to 2 unique messages");
        // First-seen wins: id-1 body must be "first", not "duplicate"
        let first = deduped.iter().find(|m| m.message_id == "id-1").unwrap();
        assert_eq!(first.body, "first", "first-seen must win on deduplication");
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
