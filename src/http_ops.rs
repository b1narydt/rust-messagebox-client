use std::collections::{HashMap, HashSet};

use bsv::remittance::types::PeerMessage;
use bsv::wallet::interfaces::{InternalizeActionArgs, InternalizeOutput, Payment, WalletInterface};
use bsv::wallet::types::BooleanDefaultTrue;
use bsv::primitives::public_key::PublicKey;
use futures_util::future::join_all;

use crate::client::MessageBoxClient;
use crate::error::MessageBoxError;
use crate::client::check_status_error;
use crate::types::{AcknowledgeMessageParams, FailedRecipient, ListMessagesParams, ListMessagesResponse, MessagePayment, MessagePaymentOutput, SendListParams, SendListResult, SentRecipient, SendMessageParams, SendMessageRequest, SendMessageResponse, ServerPeerMessage};
use crate::encryption;

/// Deduplicate messages from multiple hosts by `message_id`, preserving order.
///
/// First occurrence wins — matches TS `Promise.allSettled` + Map-based dedup semantics.
/// Server returns messages newest-first; this preserves that ordering by using a
/// HashSet for seen-tracking and a Vec for ordered output (TS parity: sorted newest-first).
pub(crate) fn dedup_messages(results: Vec<Vec<PeerMessage>>) -> Vec<PeerMessage> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for host_messages in results {
        for msg in host_messages {
            if seen.insert(msg.message_id.clone()) {
                out.push(msg);
            }
        }
    }
    out
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
    /// Protocol type — TS filters to `"wallet payment"` only.
    pub protocol: Option<String>,
    /// Derivation prefix as byte array.
    pub derivation_prefix: Option<Vec<u8>>,
    /// Derivation suffix as byte array.
    pub derivation_suffix: Option<Vec<u8>>,
    /// Sender identity key as DER hex.
    pub sender_identity_key: Option<String>,
}

impl<W: WalletInterface + Clone + 'static + Send + Sync> MessageBoxClient<W> {
    /// Send a message to a recipient's inbox.
    ///
    /// CRITICAL TS PARITY: resolves the recipient's MessageBox host via overlay
    /// (`resolveHostForRecipient`) before sending — matching TS line 952:
    /// `const finalHost = overrideHost ?? await this.resolveHostForRecipient(message.recipient)`
    ///
    /// When `override_host` is Some, it is used directly without overlay resolution.
    ///
    /// 1. Asserts the client is initialized.
    /// 2. Resolves recipient's host via overlay (falls back to self.host if unreachable).
    /// 3. Delegates to `send_message_to_host` with the resolved host.
    pub async fn send_message(
        &self,
        recipient: &str,
        message_box: &str,
        body: &str,
        skip_encryption: bool,
        check_permissions: bool,
        message_id: Option<&str>,
        override_host: Option<&str>,
    ) -> Result<String, MessageBoxError> {
        self.assert_initialized().await?;
        let host = match override_host {
            Some(h) => h.to_string(),
            None => self.resolve_host_for_recipient(recipient).await?,
        };
        self.send_message_to_host(
            &host,
            recipient,
            message_box,
            body,
            skip_encryption,
            check_permissions,
            message_id,
            None,
        )
        .await
    }

    /// Send a message to a recipient's inbox at an explicit host.
    ///
    /// Lower-level helper used by `send_message` (after host resolution) and by
    /// `RemittanceAdapter` when `host_override` is provided.
    ///
    /// Parameters:
    /// - `skip_encryption`: when true, sends body as-is without BRC-78 encryption.
    /// - `check_permissions`: when true, fetches a fee quote and creates a payment if needed.
    /// - `message_id`: when Some, uses caller-supplied ID instead of HMAC-derived ID.
    /// - `payment`: pre-created payment (used by batch sends to avoid re-creating the tx).
    ///
    /// Returns the HMAC-derived message ID (or server ID if present).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_message_to_host(
        &self,
        host: &str,
        recipient: &str,
        message_box: &str,
        body: &str,
        skip_encryption: bool,
        check_permissions: bool,
        message_id: Option<&str>,
        payment: Option<MessagePayment>,
    ) -> Result<String, MessageBoxError> {
        // Encrypt body (or use as-is when skipEncryption is true).
        let wire_body = if skip_encryption {
            body.to_string()
        } else {
            encryption::encrypt_body(
                self.wallet(),
                body,
                recipient,
                self.originator(),
            )
            .await?
        };

        // Resolve or generate message ID.
        // NOTE: generate_message_id internally calls serde_json::to_string(body) to replicate
        // TS JSON.stringify(message.body) behavior for exact parity (line 917 in MessageBoxClient.ts)
        let resolved_message_id = if let Some(id) = message_id {
            id.to_string()
        } else {
            encryption::generate_message_id(
                self.wallet(),
                body,
                recipient,
                self.originator(),
            )
            .await?
        };

        // When check_permissions is true and no payment was supplied, obtain a fee quote
        // and create a message payment if any fees are required.
        let payment = if check_permissions && payment.is_none() {
            let quote = self.get_message_box_quote(recipient, message_box, None).await?;
            if quote.delivery_fee > 0 || quote.recipient_fee > 0 {
                let p = self.create_message_payment(recipient, &quote, None).await?;
                Some(p)
            } else {
                None
            }
        } else {
            payment
        };

        // Build request wire format: {"message": {...}, "payment": ...}
        let request = SendMessageRequest {
            message: SendMessageParams {
                recipient: recipient.to_string(),
                message_box: message_box.to_string(),
                body: wire_body,
                message_id: resolved_message_id.clone(),
            },
            payment,
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
        Ok(resolved_message_id)
    }

    /// Create a message delivery payment for a single recipient.
    ///
    /// Called by `send_message_to_host` when `check_permissions` is true and fees are required.
    ///
    /// TS PARITY (critical — must match exactly for cross-client interop):
    /// - Protocol: `[2, "3241645161d8"]` (same as PeerPay, NOT `[1, "messagebox"]`)
    /// - Nonces: `Random(32)` + base64 encode (NOT wallet create_nonce)
    /// - Delivery fee senderIdentityKey: current user's identity key (NOT the agent's key)
    /// - Recipient fee: derived via `ProtoWallet('anyone')`, senderIdentityKey = anyone wallet's key
    async fn create_message_payment(
        &self,
        recipient: &str,
        quote: &crate::types::MessageBoxQuote,
        description: Option<&str>,
    ) -> Result<MessagePayment, MessageBoxError> {
        use bsv::wallet::interfaces::{
            CreateActionArgs, CreateActionOptions, CreateActionOutput, GetPublicKeyArgs,
        };
        use bsv::wallet::types::{BooleanDefaultTrue, Counterparty, CounterpartyType, Protocol};
        use bsv::primitives::public_key::PublicKey;
        use bsv::primitives::utils::from_hex;
        use bsv::script::templates::{P2PKH, ScriptTemplateLock};
        use bsv::wallet::proto_wallet::ProtoWallet;
        use base64::Engine;

        let desc = description.unwrap_or("MessageBox delivery fee");
        let sender_identity_key = self.get_identity_key().await?;

        let mut output_index: u32 = 0;
        let mut outputs = Vec::new();
        let mut payment_outputs = Vec::new();

        // --- Delivery fee output (if > 0) ---
        if quote.delivery_fee > 0 {
            // TS: Random(32) + Utils.toBase64() for nonces
            let prefix_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let suffix_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let prefix = base64::engine::general_purpose::STANDARD.encode(&prefix_bytes);
            let suffix = base64::engine::general_purpose::STANDARD.encode(&suffix_bytes);

            let agent_pk = PublicKey::from_string(&quote.delivery_agent_identity_key)
                .map_err(|e| MessageBoxError::Wallet(format!("agent key: {e}")))?;

            // TS: protocolID [2, '3241645161d8'], counterparty = deliveryAgentIdentityKey
            let delivery_key = self
                .wallet()
                .get_public_key(
                    GetPublicKeyArgs {
                        identity_key: false,
                        protocol_id: Some(Protocol {
                            security_level: 2,
                            protocol: "3241645161d8".to_string(),
                        }),
                        key_id: Some(format!("{prefix} {suffix}")),
                        counterparty: Some(Counterparty {
                            counterparty_type: CounterpartyType::Other,
                            public_key: Some(agent_pk),
                        }),
                        privileged: false,
                        privileged_reason: None,
                        for_self: None,
                        seek_permission: None,
                    },
                    self.originator(),
                )
                .await
                .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

            let hash_vec = delivery_key.public_key.to_hash();
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&hash_vec);
            let lock = P2PKH::from_public_key_hash(hash)
                .lock()
                .map_err(|e| MessageBoxError::Wallet(format!("P2PKH lock: {e}")))?;
            let lock_bytes = from_hex(&lock.to_hex())
                .map_err(|e| MessageBoxError::Wallet(format!("hex decode: {e}")))?;

            outputs.push(CreateActionOutput {
                locking_script: Some(lock_bytes),
                satoshis: quote.delivery_fee as u64,
                output_description: "MessageBox server delivery fee".to_string(),
                basket: None,
                custom_instructions: None,
                tags: vec![],
            });

            // TS: senderIdentityKey = current user's identity key (NOT agent key)
            payment_outputs.push(MessagePaymentOutput {
                output_index,
                derivation_prefix: prefix.as_bytes().to_vec(),
                derivation_suffix: suffix.as_bytes().to_vec(),
                sender_identity_key: sender_identity_key.clone(),
            });
            output_index += 1;
        }

        // --- Recipient fee output (if > 0) ---
        if quote.recipient_fee > 0 {
            let prefix_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let suffix_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let prefix = base64::engine::general_purpose::STANDARD.encode(&prefix_bytes);
            let suffix = base64::engine::general_purpose::STANDARD.encode(&suffix_bytes);

            // TS: uses ProtoWallet('anyone') for the recipient fee key derivation.
            // In Rust SDK, CounterpartyType::Anyone is the equivalent — it uses PrivateKey(1)
            // as the "anyone" wallet's root key, matching the TS SDK's CachedKeyDeriver('anyone').
            let anyone_wallet = ProtoWallet::anyone();

            let recipient_pk = PublicKey::from_string(recipient)
                .map_err(|e| MessageBoxError::Wallet(format!("recipient key: {e}")))?;

            // TS: protocolID [2, '3241645161d8'], counterparty = recipient, via anyoneWallet
            let recv_key = anyone_wallet
                .get_public_key(
                    GetPublicKeyArgs {
                        identity_key: false,
                        protocol_id: Some(Protocol {
                            security_level: 2,
                            protocol: "3241645161d8".to_string(),
                        }),
                        key_id: Some(format!("{prefix} {suffix}")),
                        counterparty: Some(Counterparty {
                            counterparty_type: CounterpartyType::Other,
                            public_key: Some(recipient_pk),
                        }),
                        privileged: false,
                        privileged_reason: None,
                        for_self: None,
                        seek_permission: None,
                    },
                    None,
                )
                .await
                .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

            let hash_vec2 = recv_key.public_key.to_hash();
            let mut hash2 = [0u8; 20];
            hash2.copy_from_slice(&hash_vec2);
            let lock_recv = P2PKH::from_public_key_hash(hash2)
                .lock()
                .map_err(|e| MessageBoxError::Wallet(format!("P2PKH lock: {e}")))?;
            let lock_recv_bytes = from_hex(&lock_recv.to_hex())
                .map_err(|e| MessageBoxError::Wallet(format!("hex decode: {e}")))?;

            outputs.push(CreateActionOutput {
                locking_script: Some(lock_recv_bytes),
                satoshis: quote.recipient_fee as u64,
                output_description: "Recipient message fee".to_string(),
                basket: None,
                custom_instructions: None,
                tags: vec![],
            });

            // TS: senderIdentityKey = anyoneWallet's identity key (PrivateKey(1).toPublicKey())
            let anyone_id = anyone_wallet
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
                .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

            payment_outputs.push(MessagePaymentOutput {
                output_index,
                derivation_prefix: prefix.as_bytes().to_vec(),
                derivation_suffix: suffix.as_bytes().to_vec(),
                sender_identity_key: anyone_id.public_key.to_der_hex(),
            });
        }

        let create_result = self
            .wallet()
            .create_action(
                CreateActionArgs {
                    description: desc.to_string(),
                    input_beef: None,
                    inputs: vec![],
                    outputs,
                    lock_time: None,
                    version: None,
                    labels: vec!["messagebox".to_string()],
                    options: Some(CreateActionOptions {
                        randomize_outputs: BooleanDefaultTrue(Some(false)),
                        ..Default::default()
                    }),
                    reference: None,
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        let tx = create_result
            .tx
            .ok_or_else(|| MessageBoxError::Wallet("create_action returned no tx".to_string()))?;

        Ok(MessagePayment {
            tx,
            outputs: payment_outputs,
        })
    }


    /// Send a message to a list of recipients in a single batch operation.
    ///
    /// Matches the TS `sendMesagetoRecepients` behavior (note the TS typo — Rust uses corrected name):
    /// 1. Gets multi-recipient quote; blocked recipients are separated out.
    /// 2. Creates a single batch payment transaction covering all payable recipients.
    /// 3. Loops individual `send_message_to_host` calls sharing the batch payment.
    pub async fn send_message_to_recipients(
        &self,
        params: &SendListParams,
        override_host: Option<&str>,
    ) -> Result<SendListResult, MessageBoxError> {
        self.assert_initialized().await?;

        let skip_enc = params.skip_encryption.unwrap_or(false);

        let recipient_refs: Vec<&str> = params.recipients.iter().map(|s| s.as_str()).collect();
        let multi_quote = self
            .get_message_box_quote_multi(&recipient_refs, &params.message_box, override_host)
            .await?;

        // Separate blocked from sendable based on recipient_fee == -1 (blocked status).
        let blocked: Vec<String> = multi_quote.blocked_recipients.clone();
        let sendable: Vec<&crate::types::RecipientQuote> = multi_quote
            .quotes_by_recipient
            .iter()
            .filter(|rq| rq.status != "blocked")
            .collect();

        // Resolve host per-recipient (or use override).
        let mut recipient_hosts: HashMap<String, String> = HashMap::new();
        for rq in &sendable {
            let host = if let Some(h) = override_host {
                h.to_string()
            } else {
                self.resolve_host_for_recipient(&rq.recipient).await.unwrap_or_else(|_| self.host().to_string())
            };
            recipient_hosts.insert(rq.recipient.clone(), host);
        }

        // Create a single batch payment if any fees exist.
        let needs_payment = sendable
            .iter()
            .any(|rq| rq.delivery_fee > 0 || rq.recipient_fee > 0);

        let batch_payment = if needs_payment {
            // Build the (recipient, host) tuples for batch payment creation.
            let pairs_for_payment: Vec<(String, i64, i64, String)> = sendable
                .iter()
                .map(|rq| {
                    let host = recipient_hosts.get(&rq.recipient).cloned().unwrap_or_else(|| self.host().to_string());
                    let agent_key = multi_quote.delivery_agent_identity_key_by_host.get(&host).cloned().unwrap_or_default();
                    (rq.recipient.clone(), rq.delivery_fee, rq.recipient_fee, agent_key)
                })
                .collect();

            match self.create_message_payment_batch_from_tuples(&pairs_for_payment, None).await {
                Ok(p) => Some(p),
                Err(e) => {
                    // If batch payment creation fails, all sendable recipients fail.
                    let failed_entries: Vec<FailedRecipient> = sendable
                        .iter()
                        .map(|rq| FailedRecipient {
                            recipient: rq.recipient.clone(),
                            error: e.to_string(),
                        })
                        .collect();
                    return Ok(SendListResult {
                        status: "error".to_string(),
                        description: "Batch payment creation failed".to_string(),
                        sent: vec![],
                        blocked,
                        failed: failed_entries,
                        totals: None,
                    });
                }
            }
        } else {
            None
        };

        // Send to each recipient individually.
        let mut sent: Vec<SentRecipient> = Vec::new();
        let mut failed: Vec<FailedRecipient> = Vec::new();

        for rq in &sendable {
            let host = recipient_hosts
                .get(&rq.recipient)
                .cloned()
                .unwrap_or_else(|| self.host().to_string());

            match self
                .send_message_to_host(
                    &host,
                    &rq.recipient,
                    &params.message_box,
                    &params.body,
                    skip_enc,
                    false, // payment already prepared
                    None,
                    batch_payment.clone(),
                )
                .await
            {
                Ok(msg_id) => sent.push(SentRecipient {
                    recipient: rq.recipient.clone(),
                    message_id: msg_id,
                }),
                Err(e) => failed.push(FailedRecipient {
                    recipient: rq.recipient.clone(),
                    error: e.to_string(),
                }),
            }
        }

        Ok(SendListResult {
            status: "success".to_string(),
            description: format!("Sent to {} recipients", sent.len()),
            sent,
            blocked,
            failed,
            totals: multi_quote.totals,
        })
    }

    /// Internal helper: create a batch payment from pre-resolved (recipient, delivery_fee, recipient_fee, agent_key) tuples.
    async fn create_message_payment_batch_from_tuples(
        &self,
        tuples: &[(String, i64, i64, String)],
        description: Option<&str>,
    ) -> Result<MessagePayment, MessageBoxError> {
        use bsv::auth::utils::create_nonce;
        use bsv::wallet::interfaces::{
            CreateActionArgs, CreateActionOptions, CreateActionOutput, GetPublicKeyArgs,
        };
        use bsv::wallet::types::{BooleanDefaultTrue, Counterparty, CounterpartyType, Protocol};
        use bsv::primitives::public_key::PublicKey;
        use bsv::primitives::utils::from_hex;
        use bsv::script::templates::{P2PKH, ScriptTemplateLock};

        let desc = description.unwrap_or("MessageBox batch delivery fee");
        let mut outputs: Vec<CreateActionOutput> = Vec::new();
        let mut payment_outputs: Vec<MessagePaymentOutput> = Vec::new();

        for (recipient, delivery_fee, recipient_fee, agent_key) in tuples {
            if *delivery_fee > 0 && !agent_key.is_empty() {
                let prefix = create_nonce(self.wallet())
                    .await
                    .map_err(|e| MessageBoxError::Auth(format!("create_nonce: {e}")))?;
                let suffix = create_nonce(self.wallet())
                    .await
                    .map_err(|e| MessageBoxError::Auth(format!("create_nonce: {e}")))?;

                let agent_pk = PublicKey::from_string(agent_key)
                    .map_err(|e| MessageBoxError::Wallet(format!("agent key: {e}")))?;

                let key = self
                    .wallet()
                    .get_public_key(
                        GetPublicKeyArgs {
                            identity_key: false,
                            protocol_id: Some(Protocol {
                                security_level: 1,
                                protocol: "messagebox".to_string(),
                            }),
                            key_id: Some(format!("{prefix} {suffix}")),
                            counterparty: Some(Counterparty {
                                counterparty_type: CounterpartyType::Other,
                                public_key: Some(agent_pk),
                            }),
                            privileged: false,
                            privileged_reason: None,
                            for_self: None,
                            seek_permission: None,
                        },
                        self.originator(),
                    )
                    .await
                    .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

                let hash_vec = key.public_key.to_hash();
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&hash_vec);
                let lock = P2PKH::from_public_key_hash(hash)
                    .lock()
                    .map_err(|e| MessageBoxError::Wallet(format!("P2PKH lock: {e}")))?;
                let lock_bytes = from_hex(&lock.to_hex())
                    .map_err(|e| MessageBoxError::Wallet(format!("hex decode: {e}")))?;

                let output_index = outputs.len() as u32;
                outputs.push(CreateActionOutput {
                    locking_script: Some(lock_bytes),
                    satoshis: *delivery_fee as u64,
                    output_description: format!("Delivery fee for {}", recipient),
                    basket: None,
                    custom_instructions: None,
                    tags: vec![],
                });
                payment_outputs.push(MessagePaymentOutput {
                    output_index,
                    derivation_prefix: prefix.as_bytes().to_vec(),
                    derivation_suffix: suffix.as_bytes().to_vec(),
                    sender_identity_key: agent_key.clone(),
                });
            }

            if *recipient_fee > 0 {
                let prefix = create_nonce(self.wallet())
                    .await
                    .map_err(|e| MessageBoxError::Auth(format!("create_nonce: {e}")))?;
                let suffix = create_nonce(self.wallet())
                    .await
                    .map_err(|e| MessageBoxError::Auth(format!("create_nonce: {e}")))?;

                let recipient_pk = PublicKey::from_string(recipient)
                    .map_err(|e| MessageBoxError::Wallet(format!("recipient key: {e}")))?;

                let key = self
                    .wallet()
                    .get_public_key(
                        GetPublicKeyArgs {
                            identity_key: false,
                            protocol_id: Some(Protocol {
                                security_level: 1,
                                protocol: "messagebox".to_string(),
                            }),
                            key_id: Some(format!("{prefix} {suffix}")),
                            counterparty: Some(Counterparty {
                                counterparty_type: CounterpartyType::Other,
                                public_key: Some(recipient_pk),
                            }),
                            privileged: false,
                            privileged_reason: None,
                            for_self: None,
                            seek_permission: None,
                        },
                        self.originator(),
                    )
                    .await
                    .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

                let hash_vec = key.public_key.to_hash();
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&hash_vec);
                let lock = P2PKH::from_public_key_hash(hash)
                    .lock()
                    .map_err(|e| MessageBoxError::Wallet(format!("P2PKH lock: {e}")))?;
                let lock_bytes = from_hex(&lock.to_hex())
                    .map_err(|e| MessageBoxError::Wallet(format!("hex decode: {e}")))?;

                let output_index = outputs.len() as u32;
                outputs.push(CreateActionOutput {
                    locking_script: Some(lock_bytes),
                    satoshis: *recipient_fee as u64,
                    output_description: format!("Recipient fee for {}", recipient),
                    basket: None,
                    custom_instructions: None,
                    tags: vec![],
                });
                payment_outputs.push(MessagePaymentOutput {
                    output_index,
                    derivation_prefix: prefix.as_bytes().to_vec(),
                    derivation_suffix: suffix.as_bytes().to_vec(),
                    sender_identity_key: recipient.clone(),
                });
            }
        }

        if outputs.is_empty() {
            return Ok(MessagePayment { tx: vec![], outputs: vec![] });
        }

        let create_result = self
            .wallet()
            .create_action(
                CreateActionArgs {
                    description: desc.to_string(),
                    input_beef: None,
                    inputs: vec![],
                    outputs,
                    lock_time: None,
                    version: None,
                    labels: vec!["messagebox".to_string()],
                    options: Some(CreateActionOptions {
                        randomize_outputs: BooleanDefaultTrue(Some(false)),
                        ..Default::default()
                    }),
                    reference: None,
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        let tx = create_result
            .tx
            .ok_or_else(|| MessageBoxError::Wallet("create_action returned no tx".to_string()))?;

        Ok(MessagePayment {
            tx,
            outputs: payment_outputs,
        })
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
        override_host: Option<&str>,
    ) -> Result<Vec<ServerPeerMessage>, MessageBoxError> {
        self.assert_initialized().await?;

        let host = override_host.unwrap_or_else(|| self.host());
        let params = ListMessagesParams {
            message_box: message_box.to_string(),
        };
        let body_bytes = serde_json::to_vec(&params)?;
        let url = format!("{host}/listMessages");
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
        override_host: Option<&str>,
    ) -> Result<Vec<PeerMessage>, MessageBoxError> {
        self.assert_initialized().await?;

        // When override_host is provided, skip multi-host overlay and use that single host.
        if let Some(host) = override_host {
            return self.list_messages_from_host(host, message_box, accept_payments).await;
        }

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
                                    // TS: only internalizes outputs where protocol === 'wallet payment'
                                    if o.protocol.as_deref() != Some("wallet payment") && o.protocol.is_some() {
                                        return None;
                                    }
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
    /// TS PARITY: When `override_host` is None, fans out to ALL advertised hosts in parallel
    /// (same `join_all` pattern as `list_messages`). Returns Ok if ANY host succeeds.
    /// When `override_host` is Some, acks on that single host only.
    pub async fn acknowledge_message(
        &self,
        message_ids: Vec<String>,
        override_host: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        self.assert_initialized().await?;

        if let Some(host) = override_host {
            return self.acknowledge_message_on_host(host, &message_ids).await;
        }

        // Multi-host fan-out: ack on all known hosts concurrently.
        let identity_key = self.get_identity_key().await?;
        let ads = self.query_advertisements(Some(&identity_key), None).await.unwrap_or_default();

        let mut host_set: HashSet<String> = ads.into_iter().map(|ad| ad.host).collect();
        host_set.insert(self.host().to_string());

        if host_set.len() == 1 {
            return self.acknowledge_message_on_host(self.host(), &message_ids).await;
        }

        // Fan out in parallel — return Ok if at least one succeeds.
        let futures: Vec<_> = host_set
            .iter()
            .map(|h| self.acknowledge_message_on_host(h, &message_ids))
            .collect();

        let outcomes = join_all(futures).await;
        let any_ok = outcomes.iter().any(|r| r.is_ok());

        if any_ok {
            Ok(())
        } else {
            Err(MessageBoxError::Http(0, format!("acknowledge_message: all {} hosts failed", host_set.len())))
        }
    }

    /// Acknowledge messages on a single explicit host.
    async fn acknowledge_message_on_host(
        &self,
        host: &str,
        message_ids: &[String],
    ) -> Result<(), MessageBoxError> {
        let params = AcknowledgeMessageParams {
            message_ids: message_ids.to_vec(),
        };
        let body_bytes = serde_json::to_vec(&params)?;
        let url = format!("{host}/acknowledgeMessage");
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
            payment: None,
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
