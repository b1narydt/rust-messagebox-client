use std::collections::{HashMap, HashSet};

use bsv::primitives::public_key::PublicKey;
use bsv::remittance::types::PeerMessage;
use bsv::wallet::interfaces::{
    BasketInsertion, InternalizeActionArgs, InternalizeOutput, Payment, WalletInterface,
};
use bsv::wallet::types::BooleanDefaultTrue;
use futures_util::future::join_all;

use crate::client::MessageBoxClient;
use crate::client::{check_status_error, is_duplicate_message_rejection};
use crate::encryption;
use crate::error::MessageBoxError;
use crate::types::{
    AcknowledgeMessageParams, FailedRecipient, ListMessagePaymentOutcome, ListMessagesParams,
    ListMessagesResponse, MessagePayment, MessagePaymentOutput, PaymentAwarePeerMessage,
    PaymentAwareServerPeerMessage, SendListParams, SendListResult, SendMessageParams,
    SendMessageRequest, SendMessageResponse, SentRecipient, ServerPeerMessage,
};

/// Deduplicate messages from multiple hosts by `message_id`, preserving order.
///
/// First occurrence wins — matches TS `Promise.allSettled` + Map-based dedup semantics.
/// Server returns messages newest-first; this preserves that ordering by using a
/// HashSet for seen-tracking and a Vec for ordered output (TS parity: sorted newest-first).
#[cfg(test)]
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

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerPayment {
    pub tx: Option<Vec<u8>>,
    pub outputs: Option<Vec<ServerPaymentOutput>>,
    pub description: Option<String>,
}

/// One output entry from the server's recipient-fee payment.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerPaymentOutput {
    pub output_index: Option<u32>,
    pub protocol: Option<String>,
    pub payment_remittance: Option<ServerPaymentRemittance>,
    pub insertion_remittance: Option<ServerInsertionRemittance>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerPaymentRemittance {
    pub derivation_prefix: Option<String>,
    pub derivation_suffix: Option<String>,
    pub sender_identity_key: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerInsertionRemittance {
    pub basket: Option<String>,
    pub custom_instructions: Option<String>,
    pub tags: Option<Vec<String>>,
}

struct SplitMessageBody {
    inner_body: String,
    payment: Option<Result<ServerPayment, ()>>,
    raw_payment_envelope: Option<String>,
    oversized: bool,
}

struct ProcessedMessageBody {
    inner_body: String,
    authenticated_decrypt: bool,
    payment_outcome: ListMessagePaymentOutcome,
    raw_payment_envelope: Option<String>,
}

const MAX_PAYMENT_TX_BYTES: usize = 32 * 1024 * 1024;
const MAX_PAYMENT_OUTPUTS: usize = 101;
const MAX_PAYMENT_DESCRIPTION_BYTES: usize = 50;
/// Matches the MessageBox protocol's 4 MiB body limit. Apply it before JSON
/// parsing so a hostile stored body cannot trigger an unbounded parse tree or a
/// second retained copy. Oversized bodies are represented by a bounded marker.
const MAX_LIST_MESSAGE_BODY_BYTES: usize = 4 * 1024 * 1024;
const OVERSIZED_MESSAGE_BODY: &str = "[Message body exceeds the 4 MiB processing limit]";
/// Send-side derivation nonces are 32 bytes, whose padded base64 form is 44 bytes.
const MAX_DERIVATION_BYTES: usize = 32;
const MAX_DERIVATION_BASE64_BYTES: usize = 44;
const MAX_BASKET_FIELD_BYTES: usize = 300;
const MAX_CUSTOM_INSTRUCTIONS_BYTES: usize = 1000;
const MAX_BASKET_TAGS: usize = 10_000;

fn into_legacy_peer_message(receipt: PaymentAwarePeerMessage) -> PeerMessage {
    let mut message = receipt.message;
    if !receipt.payment_outcome.payment_is_safe() {
        if let Some(raw_envelope) = receipt.raw_payment_envelope {
            message.body = raw_envelope;
        }
    }
    message
}

fn into_legacy_server_message(receipt: PaymentAwareServerPeerMessage) -> ServerPeerMessage {
    let mut message = receipt.message;
    if !receipt.payment_outcome.payment_is_safe() {
        if let Some(raw_envelope) = receipt.raw_payment_envelope {
            message.body = raw_envelope;
            message.authenticated_decrypt = false;
        }
    }
    message
}

fn split_message_body(raw_body: &str) -> SplitMessageBody {
    if raw_body.len() > MAX_LIST_MESSAGE_BODY_BYTES {
        return SplitMessageBody {
            inner_body: OVERSIZED_MESSAGE_BODY.to_string(),
            payment: None,
            raw_payment_envelope: None,
            oversized: true,
        };
    }

    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(raw_body) else {
        return SplitMessageBody {
            inner_body: raw_body.to_string(),
            payment: None,
            raw_payment_envelope: None,
            oversized: false,
        };
    };
    let Some(object) = value.as_object_mut() else {
        return SplitMessageBody {
            inner_body: raw_body.to_string(),
            payment: None,
            raw_payment_envelope: None,
            oversized: false,
        };
    };

    let inner_body = match object.get("message") {
        Some(serde_json::Value::String(message)) => message.clone(),
        Some(message) => message.to_string(),
        None => raw_body.to_string(),
    };
    let Some(payment_value) = object.remove("payment").filter(|value| !value.is_null()) else {
        return SplitMessageBody {
            inner_body,
            payment: None,
            raw_payment_envelope: None,
            oversized: false,
        };
    };

    SplitMessageBody {
        inner_body,
        payment: Some(serde_json::from_value(payment_value).map_err(|_| ())),
        raw_payment_envelope: Some(raw_body.to_string()),
        oversized: false,
    }
}

fn valid_payment_description(description: Option<String>) -> Result<String, ()> {
    let description = description.unwrap_or_else(|| "MessageBox recipient payment".to_string());
    let has_control = description
        .chars()
        .any(|character| matches!(character, '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}'));
    if description.is_empty()
        || description.trim() != description
        || description.len() > MAX_PAYMENT_DESCRIPTION_BYTES
        || has_control
    {
        return Err(());
    }
    Ok(description)
}

fn normalized_basket_field(value: String) -> Result<String, ()> {
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty() || normalized.len() > MAX_BASKET_FIELD_BYTES {
        return Err(());
    }
    Ok(normalized)
}

fn build_internalize_args(payment: ServerPayment) -> Result<InternalizeActionArgs, ()> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let tx = payment.tx.ok_or(())?;
    if tx.is_empty() || tx.len() > MAX_PAYMENT_TX_BYTES {
        return Err(());
    }
    let outputs = payment.outputs.ok_or(())?;
    if outputs.is_empty() || outputs.len() > MAX_PAYMENT_OUTPUTS {
        return Err(());
    }
    let description = valid_payment_description(payment.description)?;

    // Validate and construct the complete set first. No wallet call is made if
    // any member of a mixed set is malformed or uses an unknown protocol.
    let mut internalize_outputs = Vec::with_capacity(outputs.len());
    for output in outputs {
        let output_index = output.output_index.ok_or(())?;
        match output.protocol.as_deref() {
            Some("wallet payment") => {
                if output.insertion_remittance.is_some() {
                    return Err(());
                }
                let remittance = output.payment_remittance.ok_or(())?;
                let prefix = remittance.derivation_prefix.ok_or(())?;
                let suffix = remittance.derivation_suffix.ok_or(())?;
                let prefix = prefix.trim();
                let suffix = suffix.trim();
                if prefix.is_empty()
                    || suffix.is_empty()
                    || prefix.len() > MAX_DERIVATION_BASE64_BYTES
                    || suffix.len() > MAX_DERIVATION_BASE64_BYTES
                {
                    return Err(());
                }
                let derivation_prefix = STANDARD.decode(prefix).map_err(|_| ())?;
                let derivation_suffix = STANDARD.decode(suffix).map_err(|_| ())?;
                if derivation_prefix.is_empty()
                    || derivation_suffix.is_empty()
                    || derivation_prefix.len() > MAX_DERIVATION_BYTES
                    || derivation_suffix.len() > MAX_DERIVATION_BYTES
                {
                    return Err(());
                }
                let sender_identity_key = remittance.sender_identity_key.ok_or(())?;
                if sender_identity_key.len() != 66
                    || (!sender_identity_key.starts_with("02")
                        && !sender_identity_key.starts_with("03"))
                    || !sender_identity_key
                        .as_bytes()
                        .iter()
                        .all(u8::is_ascii_hexdigit)
                {
                    return Err(());
                }
                let sender_identity_key =
                    PublicKey::from_string(&sender_identity_key).map_err(|_| ())?;
                internalize_outputs.push(InternalizeOutput::WalletPayment {
                    output_index,
                    payment: Payment {
                        derivation_prefix,
                        derivation_suffix,
                        sender_identity_key,
                    },
                });
            }
            Some("basket insertion") => {
                if output.payment_remittance.is_some() {
                    return Err(());
                }
                let insertion = output.insertion_remittance.ok_or(())?;
                let basket = normalized_basket_field(insertion.basket.ok_or(())?)?;
                if insertion
                    .custom_instructions
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_CUSTOM_INSTRUCTIONS_BYTES)
                {
                    return Err(());
                }
                let tags = insertion.tags.unwrap_or_default();
                if tags.len() > MAX_BASKET_TAGS {
                    return Err(());
                }
                let tags = tags
                    .into_iter()
                    .map(normalized_basket_field)
                    .collect::<Result<Vec<_>, _>>()?;
                internalize_outputs.push(InternalizeOutput::BasketInsertion {
                    output_index,
                    insertion: BasketInsertion {
                        basket,
                        custom_instructions: insertion.custom_instructions,
                        tags,
                    },
                });
            }
            Some(_) | None => return Err(()),
        }
    }

    Ok(InternalizeActionArgs {
        tx,
        description,
        labels: Some(vec!["server-delivery-fee".to_string()]),
        seek_permission: BooleanDefaultTrue(Some(false)),
        outputs: internalize_outputs,
    })
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
    #[allow(clippy::too_many_arguments)]
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
            encryption::encrypt_body(self.wallet(), body, recipient, self.originator()).await?
        };

        // Resolve or generate message ID.
        // NOTE: generate_message_id internally calls serde_json::to_string(body) to replicate
        // TS JSON.stringify(message.body) behavior for exact parity (line 917 in MessageBoxClient.ts)
        let resolved_message_id = if let Some(id) = message_id {
            id.to_string()
        } else {
            encryption::generate_message_id(self.wallet(), body, recipient, self.originator())
                .await?
        };

        // When check_permissions is true and no payment was supplied, obtain a fee quote
        // and create a message payment if any fees are required.
        let payment = if check_permissions && payment.is_none() {
            let quote = self
                .get_message_box_quote(recipient, message_box, None)
                .await?;
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
        // Use the raw POST so we can inspect the body even on a non-2xx status.
        // The relay rejects a duplicate `messageId` with HTTP 400 + a structured
        // body; `post_json` would early-return `Err(Http(400))` and discard that
        // body, hiding the duplicate signal from us.
        let response = self.post_json_raw(&url, body_bytes).await?;

        // IDEMPOTENT-DELIVERY SEMANTICS: a duplicate-message rejection means the
        // relay ALREADY has this exact `messageId` stored — i.e. the message was
        // already delivered. Because `generate_message_id` is a deterministic
        // HMAC over (body, recipient, originator), two concurrent sends of the
        // same logical message collide on the same id: one insert wins, the
        // other gets `ERR_DUPLICATE_MESSAGE`. The logical send DID succeed, so we
        // return Ok with the (already-known) message id instead of an error. This
        // prevents spurious failures + retries under concurrent presign sends.
        //
        // We match the relay's PRECISE duplicate signal (`code ==
        // "ERR_DUPLICATE_MESSAGE"`), never a blanket "swallow all 400s" — genuine
        // auth / validation rejections continue to surface as errors below.
        if is_duplicate_message_rejection(&response.body) {
            return Ok(resolved_message_id);
        }

        // Non-2xx that ISN'T a duplicate → genuine HTTP failure. Preserve the
        // status-code error `post_json` would have produced.
        if response.status < 200 || response.status >= 300 {
            return Err(MessageBoxError::Http(response.status, url));
        }

        // 2xx but possibly a logical `{"status":"error",...}` payload.
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
        use base64::Engine;
        use bsv::primitives::public_key::PublicKey;
        use bsv::primitives::utils::from_hex;
        use bsv::script::templates::{ScriptTemplateLock, P2PKH};
        use bsv::wallet::interfaces::{
            CreateActionArgs, CreateActionOptions, CreateActionOutput, GetPublicKeyArgs,
        };
        use bsv::wallet::proto_wallet::ProtoWallet;
        use bsv::wallet::types::{BooleanDefaultTrue, Counterparty, CounterpartyType, Protocol};

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
                tags: None,
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
                tags: None,
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
                    inputs: None,
                    outputs: Some(outputs),
                    lock_time: None,
                    version: None,
                    labels: Some(vec!["messagebox".to_string()]),
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
                self.resolve_host_for_recipient(&rq.recipient)
                    .await
                    .unwrap_or_else(|_| self.host().to_string())
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
                    let host = recipient_hosts
                        .get(&rq.recipient)
                        .cloned()
                        .unwrap_or_else(|| self.host().to_string());
                    let agent_key = multi_quote
                        .delivery_agent_identity_key_by_host
                        .get(&host)
                        .cloned()
                        .unwrap_or_default();
                    (
                        rq.recipient.clone(),
                        rq.delivery_fee,
                        rq.recipient_fee,
                        agent_key,
                    )
                })
                .collect();

            match self
                .create_message_payment_batch_from_tuples(&pairs_for_payment, None)
                .await
            {
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
    ///
    /// TS PARITY (must match `createMessagePaymentBatch` exactly):
    /// - Protocol: `[2, "3241645161d8"]` for ALL key derivations
    /// - Nonces: `Random(32)` + base64 encode
    /// - Delivery fee senderIdentityKey: current user's identity key
    /// - Recipient fee: derived via `ProtoWallet::anyone()`, senderIdentityKey = anyone wallet's key
    async fn create_message_payment_batch_from_tuples(
        &self,
        tuples: &[(String, i64, i64, String)],
        description: Option<&str>,
    ) -> Result<MessagePayment, MessageBoxError> {
        use base64::Engine;
        use bsv::primitives::public_key::PublicKey;
        use bsv::primitives::utils::from_hex;
        use bsv::script::templates::{ScriptTemplateLock, P2PKH};
        use bsv::wallet::interfaces::{
            CreateActionArgs, CreateActionOptions, CreateActionOutput, GetPublicKeyArgs,
        };
        use bsv::wallet::proto_wallet::ProtoWallet;
        use bsv::wallet::types::{BooleanDefaultTrue, Counterparty, CounterpartyType, Protocol};

        let desc = description.unwrap_or("MessageBox batch delivery fee");
        let sender_identity_key = self.get_identity_key().await?;
        let anyone_wallet = ProtoWallet::anyone();
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
        let anyone_id_hex = anyone_id.public_key.to_der_hex();

        let mut outputs: Vec<CreateActionOutput> = Vec::new();
        let mut payment_outputs: Vec<MessagePaymentOutput> = Vec::new();

        for (recipient, delivery_fee, recipient_fee, agent_key) in tuples {
            // --- Delivery fee output ---
            if *delivery_fee > 0 && !agent_key.is_empty() {
                let prefix_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
                let suffix_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
                let prefix = base64::engine::general_purpose::STANDARD.encode(&prefix_bytes);
                let suffix = base64::engine::general_purpose::STANDARD.encode(&suffix_bytes);

                let agent_pk = PublicKey::from_string(agent_key)
                    .map_err(|e| MessageBoxError::Wallet(format!("agent key: {e}")))?;

                let key = self
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
                    tags: None,
                });
                payment_outputs.push(MessagePaymentOutput {
                    output_index,
                    derivation_prefix: prefix.as_bytes().to_vec(),
                    derivation_suffix: suffix.as_bytes().to_vec(),
                    sender_identity_key: sender_identity_key.clone(),
                });
            }

            // --- Recipient fee output ---
            if *recipient_fee > 0 {
                let prefix_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
                let suffix_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
                let prefix = base64::engine::general_purpose::STANDARD.encode(&prefix_bytes);
                let suffix = base64::engine::general_purpose::STANDARD.encode(&suffix_bytes);

                let recipient_pk = PublicKey::from_string(recipient)
                    .map_err(|e| MessageBoxError::Wallet(format!("recipient key: {e}")))?;

                // TS: uses anyoneWallet for recipient fee key derivation
                let key = anyone_wallet
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
                    tags: None,
                });
                payment_outputs.push(MessagePaymentOutput {
                    output_index,
                    derivation_prefix: prefix.as_bytes().to_vec(),
                    derivation_suffix: suffix.as_bytes().to_vec(),
                    sender_identity_key: anyone_id_hex.clone(),
                });
            }
        }

        if outputs.is_empty() {
            return Ok(MessagePayment {
                tx: vec![],
                outputs: vec![],
            });
        }

        let create_result = self
            .wallet()
            .create_action(
                CreateActionArgs {
                    description: desc.to_string(),
                    input_beef: None,
                    inputs: None,
                    outputs: Some(outputs),
                    lock_time: None,
                    version: None,
                    labels: Some(vec!["messagebox".to_string()]),
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
        let detailed = self
            .list_messages_lite_detailed(message_box, override_host)
            .await?;
        Ok(detailed
            .into_iter()
            .map(into_legacy_server_message)
            .collect())
    }

    /// Retrieve messages from one host with explicit payment outcomes.
    ///
    /// The inner message is decrypted exactly as in `list_messages_lite`, while
    /// every payment is reported as `Skipped` and its byte-exact outer envelope
    /// is retained for a later accepting list or application-managed retry.
    pub async fn list_messages_lite_detailed(
        &self,
        message_box: &str,
        override_host: Option<&str>,
    ) -> Result<Vec<PaymentAwareServerPeerMessage>, MessageBoxError> {
        self.assert_initialized().await?;

        let host = override_host.unwrap_or_else(|| self.host());
        let params = ListMessagesParams {
            message_box: message_box.to_string(),
        };
        let body_bytes = serde_json::to_vec(&params)?;
        let url = format!("{host}/listMessages");
        let response = self.post_json(&url, body_bytes).await?;
        check_status_error(&response.body)?;

        let list_response: ListMessagesResponse = serde_json::from_slice(&response.body)?;
        let mut result = Vec::with_capacity(list_response.messages.len());
        for mut message in list_response.messages {
            let processed = self
                .process_listed_body(&message.body, &message.sender, false, None)
                .await;
            message.body = processed.inner_body;
            message.authenticated_decrypt = processed.authenticated_decrypt;
            result.push(PaymentAwareServerPeerMessage {
                message,
                payment_outcome: processed.payment_outcome,
                raw_payment_envelope: processed.raw_payment_envelope,
            });
        }
        Ok(result)
    }

    /// Retrieve messages from an inbox with optional server payment internalization.
    ///
    /// Unlike `list_messages_lite`, this method:
    /// - Returns `Vec<PeerMessage>` (not `Vec<ServerPeerMessage>`) with `recipient`
    ///   populated from `get_identity_key()` and `message_box` from the parameter.
    /// - Parses the server's `{ message, payment }` wrapper body format.
    /// - When `accept_payments` is true, internalizes the server recipient-fee payment.
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
        let detailed = self
            .list_messages_detailed(message_box, accept_payments, override_host)
            .await?;
        Ok(detailed.into_iter().map(into_legacy_peer_message).collect())
    }

    /// Retrieve messages with explicit payment outcomes and retry envelopes.
    ///
    /// Multi-host fetching and first-seen deduplication are identical to
    /// `list_messages`. `message.body` contains the decrypted inner message even
    /// when payment handling fails; inspect `payment_outcome` before acknowledging.
    pub async fn list_messages_detailed(
        &self,
        message_box: &str,
        accept_payments: bool,
        override_host: Option<&str>,
    ) -> Result<Vec<PaymentAwarePeerMessage>, MessageBoxError> {
        self.assert_initialized().await?;

        if let Some(host) = override_host {
            return self
                .list_messages_detailed_from_host(host, message_box, accept_payments)
                .await;
        }

        let identity_key = self.get_identity_key().await?;
        let ads = self
            .query_advertisements(Some(&identity_key), None)
            .await
            .unwrap_or_default();
        let mut host_set: HashSet<String> = ads.into_iter().map(|ad| ad.host).collect();
        host_set.insert(self.host().to_string());

        if host_set.len() == 1 {
            return self
                .list_messages_detailed_from_host(self.host(), message_box, accept_payments)
                .await;
        }

        let futures: Vec<_> = host_set
            .iter()
            .map(|host| self.list_messages_detailed_from_host(host, message_box, accept_payments))
            .collect();
        let successful: Vec<Vec<PaymentAwarePeerMessage>> = join_all(futures)
            .await
            .into_iter()
            .filter_map(Result::ok)
            .collect();
        if successful.is_empty() {
            return Err(MessageBoxError::Http(
                0,
                format!("list_messages: all {} hosts failed", host_set.len()),
            ));
        }

        let mut seen = HashSet::new();
        Ok(successful
            .into_iter()
            .flatten()
            .filter(|receipt| seen.insert(receipt.message.message_id.clone()))
            .collect())
    }

    /// Retrieve detailed messages from a single explicit host.
    ///
    /// Core implementation extracted so `list_messages_detailed` can call it per-host
    /// for multi-host deduplication without repeating internalization logic.
    async fn list_messages_detailed_from_host(
        &self,
        host: &str,
        message_box: &str,
        accept_payments: bool,
    ) -> Result<Vec<PaymentAwarePeerMessage>, MessageBoxError> {
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
            let processed = self
                .process_listed_body(&msg.body, &msg.sender, accept_payments, self.originator())
                .await;
            result.push(PaymentAwarePeerMessage {
                message: PeerMessage {
                    message_id: msg.message_id,
                    sender: msg.sender,
                    recipient: identity_key.clone(),
                    message_box: message_box.to_string(),
                    body: processed.inner_body,
                },
                payment_outcome: processed.payment_outcome,
                raw_payment_envelope: processed.raw_payment_envelope,
            });
        }

        Ok(result)
    }

    async fn process_listed_body(
        &self,
        raw_body: &str,
        sender: &str,
        accept_payments: bool,
        originator: Option<&str>,
    ) -> ProcessedMessageBody {
        let split = split_message_body(raw_body);
        let payment_outcome = if split.oversized {
            ListMessagePaymentOutcome::Unprocessable
        } else {
            match split.payment {
                None => ListMessagePaymentOutcome::NoPayment,
                Some(_) if !accept_payments => ListMessagePaymentOutcome::Skipped,
                Some(Err(())) => ListMessagePaymentOutcome::Unprocessable,
                Some(Ok(payment)) => match build_internalize_args(payment) {
                    Err(()) => ListMessagePaymentOutcome::Unprocessable,
                    Ok(args) => match self.wallet().internalize_action(args, originator).await {
                        Ok(result) if result.accepted => ListMessagePaymentOutcome::Internalized,
                        Ok(_) => ListMessagePaymentOutcome::Declined,
                        Err(_) => ListMessagePaymentOutcome::Failed,
                    },
                },
            }
        };
        let decrypt_outcome = encryption::try_decrypt_message_typed(
            self.wallet(),
            &split.inner_body,
            sender,
            originator,
        )
        .await;
        let authenticated_decrypt = decrypt_outcome.is_authenticated();
        ProcessedMessageBody {
            inner_body: decrypt_outcome.into_body(),
            authenticated_decrypt,
            payment_outcome,
            raw_payment_envelope: if payment_outcome.payment_is_safe() {
                None
            } else {
                split.raw_payment_envelope
            },
        }
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
        let ads = self
            .query_advertisements(Some(&identity_key), None)
            .await
            .unwrap_or_default();

        let mut host_set: HashSet<String> = ads.into_iter().map(|ad| ad.host).collect();
        host_set.insert(self.host().to_string());

        if host_set.len() == 1 {
            return self
                .acknowledge_message_on_host(self.host(), &message_ids)
                .await;
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
            Err(MessageBoxError::Http(
                0,
                format!("acknowledge_message: all {} hosts failed", host_set.len()),
            ))
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
    use bsv::remittance::types::PeerMessage;
    use bsv::wallet::error::WalletError;
    use bsv::wallet::interfaces::*;
    use bsv::wallet::proto_wallet::ProtoWallet;
    use std::sync::Arc;

    // Reuse the same ArcWallet helper as client::tests
    #[derive(Clone, Copy)]
    enum InternalizeMode {
        Passthrough,
        Fail,
        Answer(bool),
    }

    type InternalizeObservations =
        Arc<std::sync::Mutex<Vec<(InternalizeActionArgs, Option<String>)>>>;

    #[derive(Clone)]
    struct ArcWallet(Arc<ProtoWallet>, InternalizeMode, InternalizeObservations);

    impl ArcWallet {
        fn new() -> Self {
            let key = PrivateKey::from_random().expect("random key");
            ArcWallet(
                Arc::new(ProtoWallet::new(key)),
                InternalizeMode::Passthrough,
                Arc::new(std::sync::Mutex::new(Vec::new())),
            )
        }

        fn internalize_answering(accepted: bool) -> Self {
            let mut wallet = Self::new();
            wallet.1 = InternalizeMode::Answer(accepted);
            wallet
        }

        fn failing_internalize() -> Self {
            let mut wallet = Self::new();
            wallet.1 = InternalizeMode::Fail;
            wallet
        }

        fn internalize_observations(&self) -> Vec<(InternalizeActionArgs, Option<String>)> {
            self.2.lock().expect("internalize observations").clone()
        }

        async fn identity_hex(&self) -> String {
            self.get_public_key(
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
            .expect("identity key")
            .public_key
            .to_der_hex()
        }
    }

    #[async_trait::async_trait]
    impl WalletInterface for ArcWallet {
        async fn create_action(
            &self,
            args: CreateActionArgs,
            orig: Option<&str>,
        ) -> Result<CreateActionResult, WalletError> {
            self.0.create_action(args, orig).await
        }
        async fn sign_action(
            &self,
            args: SignActionArgs,
            orig: Option<&str>,
        ) -> Result<SignActionResult, WalletError> {
            self.0.sign_action(args, orig).await
        }
        async fn abort_action(
            &self,
            args: AbortActionArgs,
            orig: Option<&str>,
        ) -> Result<AbortActionResult, WalletError> {
            self.0.abort_action(args, orig).await
        }
        async fn list_actions(
            &self,
            args: ListActionsArgs,
            orig: Option<&str>,
        ) -> Result<ListActionsResult, WalletError> {
            self.0.list_actions(args, orig).await
        }
        async fn internalize_action(
            &self,
            args: InternalizeActionArgs,
            orig: Option<&str>,
        ) -> Result<InternalizeActionResult, WalletError> {
            self.2
                .lock()
                .expect("internalize observations")
                .push((args.clone(), orig.map(str::to_owned)));
            match self.1 {
                InternalizeMode::Passthrough => self.0.internalize_action(args, orig).await,
                InternalizeMode::Fail => Err(WalletError::Internal("injected failure".into())),
                InternalizeMode::Answer(accepted) => Ok(InternalizeActionResult { accepted }),
            }
        }
        async fn list_outputs(
            &self,
            args: ListOutputsArgs,
            orig: Option<&str>,
        ) -> Result<ListOutputsResult, WalletError> {
            self.0.list_outputs(args, orig).await
        }
        async fn relinquish_output(
            &self,
            args: RelinquishOutputArgs,
            orig: Option<&str>,
        ) -> Result<RelinquishOutputResult, WalletError> {
            self.0.relinquish_output(args, orig).await
        }
        async fn get_public_key(
            &self,
            args: GetPublicKeyArgs,
            orig: Option<&str>,
        ) -> Result<GetPublicKeyResult, WalletError> {
            self.0.get_public_key(args, orig).await
        }
        async fn reveal_counterparty_key_linkage(
            &self,
            args: RevealCounterpartyKeyLinkageArgs,
            orig: Option<&str>,
        ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
            self.0.reveal_counterparty_key_linkage(args, orig).await
        }
        async fn reveal_specific_key_linkage(
            &self,
            args: RevealSpecificKeyLinkageArgs,
            orig: Option<&str>,
        ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
            self.0.reveal_specific_key_linkage(args, orig).await
        }
        async fn encrypt(
            &self,
            args: EncryptArgs,
            orig: Option<&str>,
        ) -> Result<EncryptResult, WalletError> {
            self.0.encrypt(args, orig).await
        }
        async fn decrypt(
            &self,
            args: DecryptArgs,
            orig: Option<&str>,
        ) -> Result<DecryptResult, WalletError> {
            self.0.decrypt(args, orig).await
        }
        async fn create_hmac(
            &self,
            args: CreateHmacArgs,
            orig: Option<&str>,
        ) -> Result<CreateHmacResult, WalletError> {
            self.0.create_hmac(args, orig).await
        }
        async fn verify_hmac(
            &self,
            args: VerifyHmacArgs,
            orig: Option<&str>,
        ) -> Result<VerifyHmacResult, WalletError> {
            self.0.verify_hmac(args, orig).await
        }
        async fn create_signature(
            &self,
            args: CreateSignatureArgs,
            orig: Option<&str>,
        ) -> Result<CreateSignatureResult, WalletError> {
            self.0.create_signature(args, orig).await
        }
        async fn verify_signature(
            &self,
            args: VerifySignatureArgs,
            orig: Option<&str>,
        ) -> Result<VerifySignatureResult, WalletError> {
            self.0.verify_signature(args, orig).await
        }
        async fn acquire_certificate(
            &self,
            args: AcquireCertificateArgs,
            orig: Option<&str>,
        ) -> Result<Certificate, WalletError> {
            self.0.acquire_certificate(args, orig).await
        }
        async fn list_certificates(
            &self,
            args: ListCertificatesArgs,
            orig: Option<&str>,
        ) -> Result<ListCertificatesResult, WalletError> {
            self.0.list_certificates(args, orig).await
        }
        async fn prove_certificate(
            &self,
            args: ProveCertificateArgs,
            orig: Option<&str>,
        ) -> Result<ProveCertificateResult, WalletError> {
            self.0.prove_certificate(args, orig).await
        }
        async fn relinquish_certificate(
            &self,
            args: RelinquishCertificateArgs,
            orig: Option<&str>,
        ) -> Result<RelinquishCertificateResult, WalletError> {
            self.0.relinquish_certificate(args, orig).await
        }
        async fn discover_by_identity_key(
            &self,
            args: DiscoverByIdentityKeyArgs,
            orig: Option<&str>,
        ) -> Result<DiscoverCertificatesResult, WalletError> {
            self.0.discover_by_identity_key(args, orig).await
        }
        async fn discover_by_attributes(
            &self,
            args: DiscoverByAttributesArgs,
            orig: Option<&str>,
        ) -> Result<DiscoverCertificatesResult, WalletError> {
            self.0.discover_by_attributes(args, orig).await
        }
        async fn is_authenticated(
            &self,
            orig: Option<&str>,
        ) -> Result<AuthenticatedResult, WalletError> {
            self.0.is_authenticated(orig).await
        }
        async fn wait_for_authentication(
            &self,
            orig: Option<&str>,
        ) -> Result<AuthenticatedResult, WalletError> {
            self.0.wait_for_authentication(orig).await
        }
        async fn get_height(&self, orig: Option<&str>) -> Result<GetHeightResult, WalletError> {
            self.0.get_height(orig).await
        }
        async fn get_header_for_height(
            &self,
            args: GetHeaderArgs,
            orig: Option<&str>,
        ) -> Result<GetHeaderResult, WalletError> {
            self.0.get_header_for_height(args, orig).await
        }
        async fn get_network(&self, orig: Option<&str>) -> Result<GetNetworkResult, WalletError> {
            self.0.get_network(orig).await
        }
        async fn get_version(&self, orig: Option<&str>) -> Result<GetVersionResult, WalletError> {
            self.0.get_version(orig).await
        }
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
        assert!(
            json.starts_with(r#"{"message":"#),
            "must have message wrapper"
        );
        assert!(json.contains("\"recipient\""), "camelCase recipient");
        assert!(json.contains("\"messageBox\""), "camelCase messageBox");
        assert!(json.contains("\"messageId\""), "camelCase messageId");
        assert!(
            json.contains("\"payment_inbox\""),
            "messageBox value preserved"
        );
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
        let raw = r#"{"message": "hello world", "payment": {"tx": [1,2,3]}}"#;
        let split = super::split_message_body(raw);
        assert_eq!(split.inner_body, "hello world");
        assert!(split.payment.is_some(), "payment sub-field must be present");
        assert_eq!(split.raw_payment_envelope.as_deref(), Some(raw));
    }

    /// Non-wrapped bodies pass through and have no payment state.
    #[test]
    fn list_messages_plain_body_passthrough() {
        let plain = "plain body text";
        let split = super::split_message_body(plain);
        assert_eq!(split.inner_body, plain);
        assert!(split.payment.is_none());
        assert!(split.raw_payment_envelope.is_none());
    }

    /// Wrapped body with payment: null must not crash.
    #[test]
    fn list_messages_missing_payment_no_crash() {
        let raw = r#"{"message": "the content", "payment": null}"#;
        let split = super::split_message_body(raw);
        assert_eq!(split.inner_body, "the content");
        assert!(split.payment.is_none(), "payment is none when null");
        assert!(split.raw_payment_envelope.is_none());
    }

    fn payment_client(
        wallet: ArcWallet,
        originator: Option<&str>,
    ) -> crate::MessageBoxClient<ArcWallet> {
        crate::MessageBoxClient::new(
            "https://unused.example".to_string(),
            wallet,
            originator.map(str::to_owned),
            bsv::services::overlay_tools::Network::Mainnet,
        )
    }

    fn wallet_output(sender_identity_key: &str, output_index: u32) -> serde_json::Value {
        serde_json::json!({
            "outputIndex": output_index,
            "protocol": "wallet payment",
            "paymentRemittance": {
                "derivationPrefix": "BAU=",
                "derivationSuffix": "Bgc=",
                "senderIdentityKey": sender_identity_key,
            },
        })
    }

    fn basket_output(output_index: u32) -> serde_json::Value {
        serde_json::json!({
            "outputIndex": output_index,
            "protocol": "basket insertion",
            "insertionRemittance": {
                "basket": "  Received Tokens  ",
                "customInstructions": "keep metadata",
                "tags": ["  Paid ", "Invoice-42"],
            },
        })
    }

    fn payment_value(outputs: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({
            "tx": [1, 2, 3, 4],
            "description": "Recipient payment",
            "outputs": outputs,
        })
    }

    fn payment_envelope(message: serde_json::Value, payment: serde_json::Value) -> String {
        serde_json::json!({
            "futureOuterField": {"must": "survive"},
            "message": message,
            "payment": payment,
        })
        .to_string()
    }

    #[tokio::test]
    async fn detailed_list_skip_retains_exact_envelope_and_legacy_restores_it() {
        let wallet = ArcWallet::internalize_answering(true);
        let sender = wallet.identity_hex().await;
        let client = payment_client(wallet.clone(), None);
        let raw = payment_envelope(
            serde_json::json!("inner message"),
            payment_value(vec![wallet_output(&sender, 0)]),
        );

        let processed = client.process_listed_body(&raw, &sender, false, None).await;
        assert_eq!(processed.inner_body, "inner message");
        assert_eq!(
            processed.payment_outcome,
            crate::ListMessagePaymentOutcome::Skipped
        );
        assert_eq!(
            processed.raw_payment_envelope.as_deref(),
            Some(raw.as_str())
        );
        assert!(wallet.internalize_observations().is_empty());

        let legacy = super::into_legacy_peer_message(crate::PaymentAwarePeerMessage {
            message: PeerMessage {
                message_id: "m1".into(),
                sender,
                recipient: "recipient".into(),
                message_box: "inbox".into(),
                body: processed.inner_body,
            },
            payment_outcome: processed.payment_outcome,
            raw_payment_envelope: processed.raw_payment_envelope,
        });
        assert_eq!(legacy.body, raw, "legacy callers must keep retry data");
    }

    #[tokio::test]
    async fn detailed_list_distinguishes_wallet_failure_and_decline() {
        for (wallet, expected) in [
            (
                ArcWallet::failing_internalize(),
                crate::ListMessagePaymentOutcome::Failed,
            ),
            (
                ArcWallet::internalize_answering(false),
                crate::ListMessagePaymentOutcome::Declined,
            ),
        ] {
            let sender = wallet.identity_hex().await;
            let raw = payment_envelope(
                serde_json::json!("inner"),
                payment_value(vec![wallet_output(&sender, 0)]),
            );
            let client = payment_client(wallet.clone(), None);
            let processed = client.process_listed_body(&raw, &sender, true, None).await;
            assert_eq!(processed.payment_outcome, expected);
            assert_eq!(processed.inner_body, "inner");
            assert_eq!(
                processed.raw_payment_envelope.as_deref(),
                Some(raw.as_str())
            );
            assert_eq!(wallet.internalize_observations().len(), 1);
        }
    }

    #[tokio::test]
    async fn malformed_unknown_and_mixed_payments_are_atomic_and_unprocessable() {
        let wallet = ArcWallet::internalize_answering(true);
        let sender = wallet.identity_hex().await;
        let malformed_payment = serde_json::json!("not an object");
        let missing_remittance = payment_value(vec![serde_json::json!({
            "outputIndex": 0,
            "protocol": "wallet payment"
        })]);
        let missing_protocol = payment_value(vec![serde_json::json!({
            "outputIndex": 0,
            "paymentRemittance": {
                "derivationPrefix": "BAU=",
                "derivationSuffix": "Bgc=",
                "senderIdentityKey": sender,
            }
        })]);
        let missing_output_index = payment_value(vec![serde_json::json!({
            "protocol": "wallet payment",
            "paymentRemittance": {
                "derivationPrefix": "BAU=",
                "derivationSuffix": "Bgc=",
                "senderIdentityKey": sender,
            }
        })]);
        let bad_base64 = payment_value(vec![serde_json::json!({
            "outputIndex": 0,
            "protocol": "wallet payment",
            "paymentRemittance": {
                "derivationPrefix": "not base64!",
                "derivationSuffix": "Bgc=",
                "senderIdentityKey": sender,
            }
        })]);
        let bad_key = payment_value(vec![serde_json::json!({
            "outputIndex": 0,
            "protocol": "wallet payment",
            "paymentRemittance": {
                "derivationPrefix": "BAU=",
                "derivationSuffix": "Bgc=",
                "senderIdentityKey": "04deadbeef",
            }
        })]);
        let bad_basket = payment_value(vec![serde_json::json!({
            "outputIndex": 0,
            "protocol": "basket insertion",
            "insertionRemittance": {"basket": "   "}
        })]);
        let conflicting_remittances = payment_value(vec![serde_json::json!({
            "outputIndex": 0,
            "protocol": "basket insertion",
            "paymentRemittance": {
                "derivationPrefix": "BAU=",
                "derivationSuffix": "Bgc=",
                "senderIdentityKey": sender,
            },
            "insertionRemittance": {"basket": "tokens"}
        })]);
        let unknown = payment_value(vec![serde_json::json!({
            "outputIndex": 0,
            "protocol": "future payment"
        })]);
        let mixed_invalid = payment_value(vec![
            wallet_output(&sender, 0),
            serde_json::json!({"outputIndex": 1, "protocol": "future payment"}),
        ]);
        let client = payment_client(wallet.clone(), None);

        for payment in [
            malformed_payment,
            missing_remittance,
            missing_protocol,
            missing_output_index,
            bad_base64,
            bad_key,
            bad_basket,
            conflicting_remittances,
            unknown,
            mixed_invalid,
        ] {
            let raw = payment_envelope(serde_json::json!("inner"), payment);
            let processed = client.process_listed_body(&raw, &sender, true, None).await;
            assert_eq!(
                processed.payment_outcome,
                crate::ListMessagePaymentOutcome::Unprocessable
            );
            assert_eq!(
                processed.raw_payment_envelope.as_deref(),
                Some(raw.as_str())
            );
        }
        assert!(
            wallet.internalize_observations().is_empty(),
            "no supported subset may be partially internalized"
        );
    }

    #[tokio::test]
    async fn wallet_basket_and_mixed_outputs_use_one_atomic_call() {
        for outputs in [
            vec![wallet_output("KEY", 0)],
            vec![basket_output(0)],
            vec![wallet_output("KEY", 0), basket_output(1)],
        ] {
            let wallet = ArcWallet::internalize_answering(true);
            let sender = wallet.identity_hex().await;
            let expected_output_count = outputs.len();
            let outputs = outputs
                .into_iter()
                .map(|mut output| {
                    if output["protocol"] == "wallet payment" {
                        output["paymentRemittance"]["senderIdentityKey"] =
                            serde_json::json!(sender.clone());
                    }
                    output
                })
                .collect();
            let raw = payment_envelope(serde_json::json!("inner"), payment_value(outputs));
            let client = payment_client(wallet.clone(), Some("app.example"));
            let processed = client
                .process_listed_body(&raw, &sender, true, client.originator())
                .await;
            assert_eq!(
                processed.payment_outcome,
                crate::ListMessagePaymentOutcome::Internalized
            );
            assert!(processed.raw_payment_envelope.is_none());

            let observations = wallet.internalize_observations();
            assert_eq!(observations.len(), 1, "exactly one wallet call per payment");
            assert_eq!(observations[0].1.as_deref(), Some("app.example"));
            assert_eq!(observations[0].0.outputs.len(), expected_output_count);
            for output in &observations[0].0.outputs {
                if let InternalizeOutput::BasketInsertion { insertion, .. } = output {
                    assert_eq!(insertion.basket, "received tokens");
                    assert_eq!(insertion.tags, vec!["paid", "invoice-42"]);
                    assert_eq!(
                        insertion.custom_instructions.as_deref(),
                        Some("keep metadata")
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn mixed_output_call_contains_both_protocols() {
        let wallet = ArcWallet::internalize_answering(true);
        let sender = wallet.identity_hex().await;
        let raw = payment_envelope(
            serde_json::json!("inner"),
            payment_value(vec![wallet_output(&sender, 4), basket_output(9)]),
        );
        let client = payment_client(wallet.clone(), None);
        let processed = client.process_listed_body(&raw, &sender, true, None).await;
        assert_eq!(
            processed.payment_outcome,
            crate::ListMessagePaymentOutcome::Internalized
        );
        let observations = wallet.internalize_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].0.outputs.len(), 2);
        assert!(matches!(
            observations[0].0.outputs[0],
            InternalizeOutput::WalletPayment {
                output_index: 4,
                ..
            }
        ));
        assert!(matches!(
            observations[0].0.outputs[1],
            InternalizeOutput::BasketInsertion {
                output_index: 9,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn encrypted_inner_decrypts_while_skipped_raw_envelope_survives() {
        let sender_wallet = ArcWallet::new();
        let receiver_wallet = ArcWallet::internalize_answering(true);
        let sender = sender_wallet.identity_hex().await;
        let receiver = receiver_wallet.identity_hex().await;
        let encrypted =
            crate::encryption::encrypt_body(&sender_wallet, "authenticated inner", &receiver, None)
                .await
                .expect("encrypt inner");
        let raw = payment_envelope(
            serde_json::json!(encrypted),
            payment_value(vec![wallet_output(&sender, 0)]),
        );
        let client = payment_client(receiver_wallet.clone(), None);

        let processed = client.process_listed_body(&raw, &sender, false, None).await;
        assert_eq!(processed.inner_body, "authenticated inner");
        assert!(processed.authenticated_decrypt);
        assert_eq!(
            processed.payment_outcome,
            crate::ListMessagePaymentOutcome::Skipped
        );
        assert_eq!(
            processed.raw_payment_envelope.as_deref(),
            Some(raw.as_str())
        );
        assert!(receiver_wallet.internalize_observations().is_empty());
    }

    #[tokio::test]
    async fn legacy_body_stays_inner_for_no_payment_and_success() {
        let wallet = ArcWallet::internalize_answering(true);
        let sender = wallet.identity_hex().await;
        let client = payment_client(wallet, None);

        let no_payment = client
            .process_listed_body("plain inner", &sender, true, None)
            .await;
        assert_eq!(
            no_payment.payment_outcome,
            crate::ListMessagePaymentOutcome::NoPayment
        );
        assert_eq!(no_payment.inner_body, "plain inner");
        assert!(no_payment.raw_payment_envelope.is_none());

        let raw = payment_envelope(
            serde_json::json!("paid inner"),
            payment_value(vec![wallet_output(&sender, 0)]),
        );
        let paid = client.process_listed_body(&raw, &sender, true, None).await;
        assert_eq!(
            paid.payment_outcome,
            crate::ListMessagePaymentOutcome::Internalized
        );
        assert_eq!(paid.inner_body, "paid inner");
        assert!(paid.raw_payment_envelope.is_none());
    }

    #[tokio::test]
    async fn oversized_outer_body_is_bounded_unprocessable_for_detailed_and_legacy() {
        let wallet = ArcWallet::internalize_answering(true);
        let client = payment_client(wallet.clone(), None);
        let raw = "x".repeat(super::MAX_LIST_MESSAGE_BODY_BYTES + 1);

        for accept_payments in [false, true] {
            let processed = client
                .process_listed_body(&raw, "not-used-for-bounded-marker", accept_payments, None)
                .await;
            assert_eq!(
                processed.payment_outcome,
                crate::ListMessagePaymentOutcome::Unprocessable
            );
            assert_eq!(processed.inner_body, super::OVERSIZED_MESSAGE_BODY);
            assert!(processed.raw_payment_envelope.is_none());
            assert!(processed.inner_body.len() < 100);
        }
        assert!(wallet.internalize_observations().is_empty());

        let legacy = super::into_legacy_peer_message(crate::PaymentAwarePeerMessage {
            message: PeerMessage {
                message_id: "oversized".into(),
                sender: "sender".into(),
                recipient: "recipient".into(),
                message_box: "inbox".into(),
                body: super::OVERSIZED_MESSAGE_BODY.into(),
            },
            payment_outcome: crate::ListMessagePaymentOutcome::Unprocessable,
            raw_payment_envelope: None,
        });
        assert_eq!(legacy.body, super::OVERSIZED_MESSAGE_BODY);

        let legacy_lite = super::into_legacy_server_message(crate::PaymentAwareServerPeerMessage {
            message: crate::ServerPeerMessage {
                message_id: "oversized".into(),
                body: super::OVERSIZED_MESSAGE_BODY.into(),
                sender: "sender".into(),
                created_at: String::new(),
                updated_at: String::new(),
                acknowledged: None,
                authenticated_decrypt: false,
            },
            payment_outcome: crate::ListMessagePaymentOutcome::Unprocessable,
            raw_payment_envelope: None,
        });
        assert_eq!(legacy_lite.body, super::OVERSIZED_MESSAGE_BODY);
        assert!(!legacy_lite.authenticated_decrypt);
    }

    #[tokio::test]
    async fn oversized_derivation_fields_fail_before_wallet_internalization() {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let wallet = ArcWallet::internalize_answering(true);
        let sender = wallet.identity_hex().await;
        let client = payment_client(wallet.clone(), None);
        let too_many_decoded_bytes = STANDARD.encode(vec![7_u8; super::MAX_DERIVATION_BYTES + 1]);
        assert!(too_many_decoded_bytes.len() <= super::MAX_DERIVATION_BASE64_BYTES);

        for (prefix, suffix) in [
            (
                "A".repeat(super::MAX_DERIVATION_BASE64_BYTES + 1),
                "Bgc=".to_string(),
            ),
            ("BAU=".to_string(), too_many_decoded_bytes.clone()),
            (too_many_decoded_bytes, "Bgc=".to_string()),
        ] {
            let payment = payment_value(vec![serde_json::json!({
                "outputIndex": 0,
                "protocol": "wallet payment",
                "paymentRemittance": {
                    "derivationPrefix": prefix,
                    "derivationSuffix": suffix,
                    "senderIdentityKey": sender,
                }
            })]);
            let raw = payment_envelope(serde_json::json!("inner"), payment);
            let processed = client.process_listed_body(&raw, &sender, true, None).await;
            assert_eq!(
                processed.payment_outcome,
                crate::ListMessagePaymentOutcome::Unprocessable
            );
            assert_eq!(processed.inner_body, "inner");
            assert_eq!(
                processed.raw_payment_envelope.as_deref(),
                Some(raw.as_str())
            );
        }
        assert!(wallet.internalize_observations().is_empty());
    }

    #[test]
    fn payment_limits_reject_before_wallet_call() {
        let key = PrivateKey::from_random()
            .expect("key")
            .to_public_key()
            .to_der_hex();
        let base = wallet_output(&key, 0);
        for payment in [
            serde_json::json!({"tx": [], "outputs": [base.clone()]}),
            serde_json::json!({
                "tx": vec![0_u8; super::MAX_PAYMENT_TX_BYTES + 1],
                "outputs": [base.clone()]
            }),
            serde_json::json!({
                "tx": [1],
                "description": " padded ",
                "outputs": [base.clone()]
            }),
            serde_json::json!({
                "tx": [1],
                "description": "x".repeat(super::MAX_PAYMENT_DESCRIPTION_BYTES + 1),
                "outputs": [base.clone()]
            }),
            serde_json::json!({
                "tx": [1],
                "description": "é".repeat(26),
                "outputs": [base.clone()]
            }),
            serde_json::json!({
                "tx": [1],
                "description": "control\u{0007}",
                "outputs": [base.clone()]
            }),
            serde_json::json!({
                "tx": [1],
                "outputs": [{
                    "outputIndex": 0,
                    "protocol": "basket insertion",
                    "insertionRemittance": {
                        "basket": "tokens",
                        "customInstructions": "x".repeat(super::MAX_CUSTOM_INSTRUCTIONS_BYTES + 1)
                    }
                }]
            }),
            serde_json::json!({
                "tx": [1],
                "outputs": [{
                    "outputIndex": 0,
                    "protocol": "basket insertion",
                    "insertionRemittance": {
                        "basket": "tokens",
                        "tags": ["x".repeat(super::MAX_BASKET_FIELD_BYTES + 1)]
                    }
                }]
            }),
            serde_json::json!({
                "tx": [1],
                "outputs": vec![base.clone(); super::MAX_PAYMENT_OUTPUTS + 1]
            }),
        ] {
            let parsed: super::ServerPayment = serde_json::from_value(payment).unwrap();
            assert!(super::build_internalize_args(parsed).is_err());
        }
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
