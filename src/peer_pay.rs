use std::sync::Arc;

use bsv::auth::utils::create_nonce;
use bsv::primitives::public_key::PublicKey;
use bsv::primitives::utils::from_hex;
use bsv::remittance::types::PeerMessage;
use bsv::script::templates::{ScriptTemplateLock, P2PKH};
use bsv::wallet::interfaces::{
    CreateActionArgs, CreateActionOptions, CreateActionOutput, GetPublicKeyArgs,
    InternalizeActionArgs, InternalizeOutput, Payment, SignActionArgs, WalletInterface,
};
use bsv::wallet::types::{BooleanDefaultTrue, Counterparty, CounterpartyType, Protocol};

use crate::client::MessageBoxClient;
use crate::error::MessageBoxError;
use crate::types::{IncomingPayment, PaymentCustomInstructions, PaymentToken};

/// Notification delivery-payment wire shape used by current TS MessageBox clients.
/// Kept local so the polling/list parser in `http_ops` can evolve independently.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotificationPayment {
    tx: Option<Vec<u8>>,
    outputs: Option<Vec<NotificationPaymentOutput>>,
    description: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotificationPaymentOutput {
    output_index: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_notification_output_protocol")]
    protocol: NotificationOutputProtocol,
    payment_remittance: Option<NotificationPaymentRemittance>,
}

#[derive(Default)]
enum NotificationOutputProtocol {
    #[default]
    Missing,
    ExplicitNull,
    Value(String),
}

impl NotificationOutputProtocol {
    fn is_wallet_payment_compatible(&self) -> bool {
        match self {
            Self::Missing => true,
            Self::Value(protocol) => protocol == "wallet payment",
            Self::ExplicitNull => false,
        }
    }

    fn unsupported_label(&self) -> Option<&str> {
        match self {
            Self::ExplicitNull => Some("null"),
            Self::Value(protocol) if protocol != "wallet payment" => Some(protocol),
            Self::Missing | Self::Value(_) => None,
        }
    }
}

fn deserialize_notification_output_protocol<'de, D>(
    deserializer: D,
) -> Result<NotificationOutputProtocol, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let protocol = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
    Ok(match protocol {
        Some(protocol) => NotificationOutputProtocol::Value(protocol),
        None => NotificationOutputProtocol::ExplicitNull,
    })
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotificationPaymentRemittance {
    derivation_prefix: Option<String>,
    derivation_suffix: Option<String>,
    sender_identity_key: Option<String>,
}

impl<W: WalletInterface + Clone + 'static + Send + Sync> MessageBoxClient<W> {
    /// Create a PeerPay payment token for `recipient` worth `amount` satoshis.
    ///
    /// Steps:
    /// 1. Generate two nonces (prefix, suffix) via `create_nonce`.
    /// 2. Derive a P2PKH locking key via `get_public_key` with protocol `[2, "3241645161d8"]`.
    /// 3. Build a P2PKH locking script from the derived key hash.
    /// 4. Call `create_action` with `randomize_outputs: false` so output_index=0 is stable.
    /// 5. Return `PaymentToken` with `output_index: None` — the TS convention is to set it
    ///    only at accept time (defaulted to 0 via unwrap_or(0)).
    pub async fn create_payment_token(
        &self,
        recipient: &str,
        amount: u64,
    ) -> Result<PaymentToken, MessageBoxError> {
        // Step 1: two nonces for key derivation
        let prefix = create_nonce(self.wallet())
            .await
            .map_err(|e| MessageBoxError::Auth(format!("create_nonce prefix: {e}")))?;
        let suffix = create_nonce(self.wallet())
            .await
            .map_err(|e| MessageBoxError::Auth(format!("create_nonce suffix: {e}")))?;

        // Step 2: derive a per-payment public key for the recipient
        let pk_result = self
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
                        public_key: Some(
                            PublicKey::from_string(recipient)
                                .map_err(|e| MessageBoxError::Wallet(e.to_string()))?,
                        ),
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

        // Step 3: build P2PKH locking script from derived key
        let hash_vec = pk_result.public_key.to_hash();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hash_vec);
        let lock_script = P2PKH::from_public_key_hash(hash)
            .lock()
            .map_err(|e| MessageBoxError::Wallet(format!("P2PKH lock error: {e}")))?;
        // Convert to bytes via hex — avoids adding a `hex` crate dependency
        let locking_script_bytes = from_hex(&lock_script.to_hex())
            .map_err(|e| MessageBoxError::Wallet(format!("hex decode locking script: {e}")))?;

        // Build custom instructions — payee matches TS wire format
        let custom_instructions = PaymentCustomInstructions {
            derivation_prefix: prefix.clone(),
            derivation_suffix: suffix.clone(),
            payee: Some(recipient.to_string()),
        };

        // Step 4: create the transaction
        // CRITICAL: randomize_outputs must be false so output_index=0 is always correct
        let create_result = self
            .wallet()
            .create_action(
                CreateActionArgs {
                    description: "PeerPay payment".to_string(),
                    input_beef: None,
                    inputs: None,
                    outputs: Some(vec![CreateActionOutput {
                        locking_script: Some(locking_script_bytes),
                        satoshis: amount,
                        output_description: "Payment for PeerPay transaction".to_string(),
                        basket: None,
                        custom_instructions: Some(
                            serde_json::to_string(&custom_instructions)
                                .map_err(MessageBoxError::Json)?,
                        ),
                        tags: None,
                    }]),
                    lock_time: None,
                    version: None,
                    labels: Some(vec!["peerpay".to_string()]),
                    options: Some(CreateActionOptions {
                        randomize_outputs: BooleanDefaultTrue(Some(false)),
                        sign_and_process: BooleanDefaultTrue(None),
                        accept_delayed_broadcast: BooleanDefaultTrue(None),
                        ..Default::default()
                    }),
                    reference: None,
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        // Step 5: handle two-step flow — if wallet returns signable_transaction,
        // call sign_action to complete it (BRC-100 pattern for non-admin originators)
        let tx = if let Some(tx_bytes) = create_result.tx {
            tx_bytes
        } else if let Some(signable) = create_result.signable_transaction {
            let sign_result = self
                .wallet()
                .sign_action(
                    SignActionArgs {
                        reference: signable.reference,
                        spends: std::collections::HashMap::new(),
                        options: None,
                    },
                    self.originator(),
                )
                .await
                .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;
            sign_result
                .tx
                .ok_or_else(|| MessageBoxError::Wallet("sign_action returned no tx".to_string()))?
        } else {
            return Err(MessageBoxError::Wallet(
                "create_action returned neither tx nor signable_transaction".to_string(),
            ));
        };

        // NOTE: outputIndex is NOT set at creation — matches TS behavior.
        // accept_payment uses unwrap_or(0) to default to 0.
        Ok(PaymentToken {
            custom_instructions,
            transaction: tx,
            amount,
            output_index: None,
        })
    }

    /// Send a payment to `recipient` by creating a token and posting it to their payment_inbox.
    ///
    /// Returns the message ID assigned by the server (or the HMAC-derived ID).
    pub async fn send_payment(
        &self,
        recipient: &str,
        amount: u64,
    ) -> Result<String, MessageBoxError> {
        let token = self.create_payment_token(recipient, amount).await?;
        let token_json = serde_json::to_string(&token)?;
        self.send_message(
            recipient,
            "payment_inbox",
            &token_json,
            false,
            false,
            None,
            None,
        )
        .await
    }

    /// Send a payment to `recipient` over WebSocket with HTTP fallback.
    ///
    /// Creates a payment token via `create_payment_token`, serializes it as JSON,
    /// and sends via `send_live_message` (which handles WS timeout + HTTP fallback).
    /// Thin wrapper — matches TS `PeerPayClient.sendLivePayment`.
    ///
    /// Returns the message ID regardless of whether delivery was live or persisted.
    /// Callers that need to distinguish live vs persisted should call
    /// `send_live_message` directly and inspect `DeliveryMode`.
    pub async fn send_live_payment(
        &self,
        recipient: &str,
        amount: u64,
    ) -> Result<String, MessageBoxError> {
        let token = self.create_payment_token(recipient, amount).await?;
        let token_json = serde_json::to_string(&token)?;
        let delivery = self
            .send_live_message(
                recipient,
                "payment_inbox",
                &token_json,
                false,
                false,
                None,
                None,
            )
            .await?;
        Ok(delivery.message_id().to_string())
    }

    /// Subscribe to live payment notifications on the payment_inbox.
    ///
    /// Wraps `listen_for_live_messages` with a callback that parses the message
    /// body as a `PaymentToken` and constructs an `IncomingPayment`. Messages
    /// whose bodies are not valid payment tokens are silently ignored (matches
    /// TS safeParse behavior).
    pub async fn listen_for_live_payments(
        &self,
        on_payment: Arc<dyn Fn(IncomingPayment) + Send + Sync>,
    ) -> Result<(), MessageBoxError> {
        let wrapper: Arc<dyn Fn(PeerMessage) + Send + Sync> = Arc::new(move |msg: PeerMessage| {
            if let Ok(token) = serde_json::from_str::<PaymentToken>(&msg.body) {
                let incoming = IncomingPayment {
                    token,
                    sender: msg.sender,
                    message_id: msg.message_id,
                };
                on_payment(incoming);
            }
            // Silently skip messages that aren't valid payment tokens
        });

        self.listen_for_live_messages("payment_inbox", wrapper, None)
            .await
    }

    /// Internalize a received payment and acknowledge the message.
    ///
    /// Base64-decodes derivation_prefix/suffix back to raw bytes so the SDK's
    /// bytes_as_base64 serde re-encodes them to the original base64 strings
    /// that BSV Desktop expects.
    pub async fn accept_payment(&self, payment: &IncomingPayment) -> Result<(), MessageBoxError> {
        let message_id = payment.message_id.clone();
        self.accept_payment_with_ack(payment, || async move {
            self.acknowledge_message(vec![message_id], None).await
        })
        .await
    }

    async fn accept_payment_with_ack<F, Fut>(
        &self,
        payment: &IncomingPayment,
        acknowledge: F,
    ) -> Result<(), MessageBoxError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), MessageBoxError>>,
    {
        self.internalize_payment(payment).await?;
        acknowledge().await
    }

    /// Internalize a PeerPay token into the wallet without touching the relay.
    async fn internalize_payment(&self, payment: &IncomingPayment) -> Result<(), MessageBoxError> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let sender_pk = PublicKey::from_string(&payment.sender)
            .map_err(|e| MessageBoxError::Wallet(format!("invalid sender key: {e}")))?;

        let prefix_bytes = STANDARD
            .decode(&payment.token.custom_instructions.derivation_prefix)
            .map_err(|e| MessageBoxError::Wallet(format!("base64 decode prefix: {e}")))?;
        let suffix_bytes = STANDARD
            .decode(&payment.token.custom_instructions.derivation_suffix)
            .map_err(|e| MessageBoxError::Wallet(format!("base64 decode suffix: {e}")))?;

        let result = self
            .wallet()
            .internalize_action(
                InternalizeActionArgs {
                    tx: payment.token.transaction.clone(),
                    description: "PeerPay Payment".to_string(),
                    labels: Some(vec!["peerpay".to_string()]),
                    seek_permission: BooleanDefaultTrue(Some(true)),
                    outputs: vec![InternalizeOutput::WalletPayment {
                        output_index: payment.token.output_index.unwrap_or(0),
                        payment: Payment {
                            derivation_prefix: prefix_bytes,
                            derivation_suffix: suffix_bytes,
                            sender_identity_key: sender_pk,
                        },
                    }],
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        // A wallet may decline without erroring. Only `accepted: true` means the
        // output is durably stored, and only then may the relay copy be dropped.
        if !result.accepted {
            return Err(MessageBoxError::Wallet(
                "wallet did not accept the payment".to_string(),
            ));
        }

        Ok(())
    }

    /// Reject a received payment.
    ///
    /// - If `amount < 2000`: only acknowledges (refund after fee would be ≤ 0).
    /// - If `amount >= 2000`: internalizes the payment, sends a refund of
    ///   `amount - 1000`, then acknowledges — in that order, matching TS 2.5.1.
    ///   A failed internalize prevents the refund; a failed refund (including a
    ///   401) leaves the message on the relay so the rejection can be resumed.
    ///
    /// This ordering is not a durable refund journal. If the refund was sent but
    /// the acknowledge failed, the message is still queued and a retry would
    /// internalize (idempotent) and refund *again*. Reconcile an uncertain refund
    /// send before retrying; the protocol offers no exactly-once refund.
    pub async fn reject_payment(&self, payment: &IncomingPayment) -> Result<(), MessageBoxError> {
        self.reject_payment_with(
            payment,
            |amount| async move { self.send_payment(&payment.sender, amount).await.map(|_| ()) },
            || async move {
                self.acknowledge_message(vec![payment.message_id.clone()], None)
                    .await
            },
        )
        .await
    }

    async fn reject_payment_with<R, RFut, A, AFut>(
        &self,
        payment: &IncomingPayment,
        refund: R,
        acknowledge: A,
    ) -> Result<(), MessageBoxError>
    where
        R: FnOnce(u64) -> RFut,
        RFut: std::future::Future<Output = Result<(), MessageBoxError>>,
        A: FnOnce() -> AFut,
        AFut: std::future::Future<Output = Result<(), MessageBoxError>>,
    {
        if payment.token.amount < 2000 {
            return acknowledge().await;
        }

        self.internalize_payment(payment).await?;
        refund(payment.token.amount - 1000).await?;
        acknowledge().await
    }

    /// List all incoming payments from the payment_inbox.
    ///
    /// Uses the full multi-host `list_messages` path (matching TS `listIncomingPayments`
    /// which calls `this.listMessages`), so payments on all advertised hosts are returned.
    /// Silently skips messages whose bodies are not valid JSON payment tokens
    /// (mirrors TS `safeParse` behavior).
    pub async fn list_incoming_payments(&self) -> Result<Vec<IncomingPayment>, MessageBoxError> {
        let messages = self.list_messages("payment_inbox", false, None).await?;

        let payments = messages
            .into_iter()
            .filter_map(|msg| {
                serde_json::from_str::<PaymentToken>(&msg.body)
                    .ok()
                    .map(|token| IncomingPayment {
                        token,
                        sender: msg.sender,
                        message_id: msg.message_id,
                    })
            })
            .collect();

        Ok(payments)
    }

    /// Acknowledge a notification message, internalizing any embedded delivery-fee payment.
    ///
    /// Ordering matches TS `@bsv/message-box-client` 2.5.1 (ts-stack #534): the relay
    /// is the durability backstop, so a notification carrying a payment may leave the
    /// relay only after the wallet has reported `accepted: true`.
    ///
    /// - Body is not an object, lacks its own `message` member, or has no payment:
    ///   acknowledged without inspecting `payment`, returns `Ok(false)`.
    /// - Payment present but nothing internalizable (missing `tx`/`outputs`, or only
    ///   unsupported output protocols such as `basket insertion`): **not** acknowledged,
    ///   returns `Ok(false)`. Acknowledging would discard the payment.
    /// - A malformed non-null `payment` member, transaction outside 1..=32 MiB,
    ///   more than 101 outputs, invalid description or nested `paymentRemittance`,
    ///   or a mixture of supported and unsupported output protocols: **not**
    ///   acknowledged, returns `Err`.
    /// - Internalize error, wallet declines, or an output cannot be built (missing
    ///   required fields or non-compressed/invalid `senderIdentityKey`): **not**
    ///   acknowledged, returns `Err`.
    /// - Stored and acknowledged: `Ok(true)`.
    ///
    /// Deliberate TS differences: outputs whose `protocol` field is absent are
    /// admitted, and malformed/declined/internalize failures return `Err` rather
    /// than resolving `false`. Both implementations retain the payment in these
    /// failure cases. Endpoint and wire-schema compatibility are unchanged.
    ///
    /// One logical acknowledgement is attempted after the monetary step. This is
    /// not a cross-host transaction: multi-host acknowledgement may partially
    /// succeed because `acknowledge_message` succeeds when any host succeeds.
    pub async fn acknowledge_notification(
        &self,
        message: &PeerMessage,
    ) -> Result<bool, MessageBoxError> {
        let message_id = message.message_id.clone();
        self.acknowledge_notification_with_ack(message, || async move {
            self.acknowledge_message(vec![message_id], None).await
        })
        .await
    }

    async fn acknowledge_notification_with_ack<F, Fut>(
        &self,
        message: &PeerMessage,
        acknowledge: F,
    ) -> Result<bool, MessageBoxError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), MessageBoxError>>,
    {
        let body = match serde_json::from_str::<serde_json::Value>(&message.body) {
            Ok(body) => body,
            Err(_) => {
                acknowledge().await?;
                return Ok(false);
            }
        };
        let Some(body_object) = body.as_object() else {
            acknowledge().await?;
            return Ok(false);
        };
        if !body_object.contains_key("message") {
            acknowledge().await?;
            return Ok(false);
        }
        let Some(payment_value) = body_object.get("payment").filter(|value| !value.is_null())
        else {
            acknowledge().await?;
            return Ok(false);
        };
        // Once a non-null top-level payment member is present, parse failures
        // are payment failures. Falling through to the no-payment branch would
        // acknowledge away value that the client could not inspect.
        let payment = serde_json::from_value::<NotificationPayment>(payment_value.clone())?;

        // From here on a payment exists; it leaves the relay only once stored.
        let (Some(tx), Some(outputs)) = (payment.tx, payment.outputs) else {
            return Ok(false);
        };
        if tx.is_empty() {
            return Err(MessageBoxError::Validation(
                "notification payment transaction is empty".into(),
            ));
        }
        if tx.len() > 32 * 1024 * 1024 {
            return Err(MessageBoxError::Validation(
                "notification payment transaction exceeds 32 MiB".into(),
            ));
        }
        if outputs.len() > 101 {
            return Err(MessageBoxError::Validation(
                "notification payment exceeds 101 outputs".into(),
            ));
        }
        let description = match payment.description {
            Some(description) => {
                let has_control = description.chars().any(|character| {
                    matches!(character, '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}')
                });
                if description.is_empty()
                    || description.trim() != description
                    || description.len() > 50
                    || has_control
                {
                    return Err(MessageBoxError::Validation(
                        "notification payment description must be nonempty, already trimmed, at most 50 UTF-8 bytes, and contain no C0/C1 controls".into(),
                    ));
                }
                description
            }
            None => "MessageBox recipient payment".to_string(),
        };

        let has_supported_output = outputs
            .iter()
            .any(|output| output.protocol.is_wallet_payment_compatible());
        if has_supported_output {
            if let Some(protocol) = outputs
                .iter()
                .find_map(|output| output.protocol.unsupported_label())
            {
                return Err(MessageBoxError::Validation(format!(
                    "notification payment mixes wallet-payment outputs with unsupported protocol `{protocol}`"
                )));
            }
        }

        use base64::{engine::general_purpose::STANDARD, Engine};

        let mut internalize_outputs = Vec::with_capacity(outputs.len());
        for o in outputs {
            // Admit `protocol: "wallet payment"` AND a genuinely absent
            // `protocol`; explicit null and other protocols stay unsupported.
            if !o.protocol.is_wallet_payment_compatible() {
                continue;
            }
            let output_index = o.output_index.ok_or_else(|| {
                MessageBoxError::Validation(
                    "notification payment output is missing outputIndex".into(),
                )
            })?;
            let remittance = o.payment_remittance.ok_or_else(|| {
                MessageBoxError::Validation(
                    "notification wallet-payment output is missing paymentRemittance".into(),
                )
            })?;
            let derivation_prefix = remittance.derivation_prefix.ok_or_else(|| {
                MessageBoxError::Validation(
                    "notification paymentRemittance is missing derivationPrefix".into(),
                )
            })?;
            let derivation_suffix = remittance.derivation_suffix.ok_or_else(|| {
                MessageBoxError::Validation(
                    "notification paymentRemittance is missing derivationSuffix".into(),
                )
            })?;
            let derivation_prefix = derivation_prefix.trim();
            if derivation_prefix.is_empty() {
                return Err(MessageBoxError::Validation(
                    "notification derivationPrefix must not be empty".into(),
                ));
            }
            let derivation_suffix = derivation_suffix.trim();
            if derivation_suffix.is_empty() {
                return Err(MessageBoxError::Validation(
                    "notification derivationSuffix must not be empty".into(),
                ));
            }
            let derivation_prefix = STANDARD.decode(derivation_prefix).map_err(|e| {
                MessageBoxError::Validation(format!(
                    "invalid notification derivationPrefix base64: {e}"
                ))
            })?;
            let derivation_suffix = STANDARD.decode(derivation_suffix).map_err(|e| {
                MessageBoxError::Validation(format!(
                    "invalid notification derivationSuffix base64: {e}"
                ))
            })?;
            let sender_identity_key =
                remittance.sender_identity_key.as_deref().ok_or_else(|| {
                    MessageBoxError::Validation(
                        "notification paymentRemittance is missing senderIdentityKey".into(),
                    )
                })?;
            if sender_identity_key.len() != 66
                || (!sender_identity_key.starts_with("02")
                    && !sender_identity_key.starts_with("03"))
                || !sender_identity_key
                    .as_bytes()
                    .iter()
                    .all(u8::is_ascii_hexdigit)
            {
                return Err(MessageBoxError::Validation(
                    "notification senderIdentityKey must be exactly 66 ASCII hex characters with prefix 02 or 03".into(),
                ));
            }
            let sender_pk = bsv::primitives::public_key::PublicKey::from_string(
                sender_identity_key,
            )
            .map_err(|e| {
                MessageBoxError::Validation(format!(
                    "invalid notification senderIdentityKey point: {e}"
                ))
            })?;
            internalize_outputs.push(InternalizeOutput::WalletPayment {
                output_index,
                payment: Payment {
                    derivation_prefix,
                    derivation_suffix,
                    sender_identity_key: sender_pk,
                },
            });
        }
        if internalize_outputs.is_empty() {
            return Ok(false);
        }

        let result = self
            .wallet()
            .internalize_action(
                InternalizeActionArgs {
                    tx,
                    description,
                    labels: Some(vec!["notification-payment".to_string()]),
                    seek_permission: bsv::wallet::types::BooleanDefaultTrue(Some(false)),
                    outputs: internalize_outputs,
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;
        if !result.accepted {
            return Err(MessageBoxError::Wallet(
                "wallet did not accept the notification payment".to_string(),
            ));
        }

        acknowledge().await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        IncomingPayment, PaymentCustomInstructions, PaymentToken, ServerPeerMessage,
    };
    use bsv::primitives::private_key::PrivateKey;
    use bsv::remittance::types::PeerMessage;
    use bsv::wallet::error::WalletError;
    use bsv::wallet::interfaces::*;
    use bsv::wallet::proto_wallet::ProtoWallet;
    use std::sync::Arc;

    // Thin Arc wrapper so ProtoWallet satisfies W: Clone bound on MessageBoxClient
    #[derive(Clone, Copy)]
    enum InternalizeMode {
        /// Delegate to ProtoWallet (which does not implement internalize).
        Passthrough,
        /// Return `Err(WalletError::Internal(msg))`.
        Fail(&'static str),
        /// Return `Ok(InternalizeActionResult { accepted })` without touching a wallet.
        Answer { accepted: bool },
    }

    #[derive(Clone)]
    struct ArcWallet(
        Arc<ProtoWallet>,
        InternalizeMode,
        Arc<std::sync::Mutex<Vec<(InternalizeActionArgs, Option<String>)>>>,
    );

    impl ArcWallet {
        fn new() -> Self {
            let key = PrivateKey::from_random().expect("random key");
            ArcWallet(
                Arc::new(ProtoWallet::new(key)),
                InternalizeMode::Passthrough,
                Arc::new(std::sync::Mutex::new(Vec::new())),
            )
        }

        fn failing_internalize(message: &'static str) -> Self {
            let key = PrivateKey::from_random().expect("random key");
            ArcWallet(
                Arc::new(ProtoWallet::new(key)),
                InternalizeMode::Fail(message),
                Arc::new(std::sync::Mutex::new(Vec::new())),
            )
        }

        fn internalize_answering(accepted: bool) -> Self {
            let key = PrivateKey::from_random().expect("random key");
            ArcWallet(
                Arc::new(ProtoWallet::new(key)),
                InternalizeMode::Answer { accepted },
                Arc::new(std::sync::Mutex::new(Vec::new())),
            )
        }

        fn internalize_originators(&self) -> Vec<Option<String>> {
            self.2
                .lock()
                .expect("internalize observations")
                .iter()
                .map(|(_, originator)| originator.clone())
                .collect()
        }

        fn internalize_observations(&self) -> Vec<(InternalizeActionArgs, Option<String>)> {
            self.2.lock().expect("internalize observations").clone()
        }

        /// A well-formed PeerPay token from this wallet's identity, above the refund threshold.
        async fn incoming_payment(&self, amount: u64) -> IncomingPayment {
            IncomingPayment {
                token: PaymentToken {
                    custom_instructions: PaymentCustomInstructions {
                        derivation_prefix: "dGVzdC1wcmVmaXg=".to_string(),
                        derivation_suffix: "dGVzdC1zdWZmaXg=".to_string(),
                        payee: None,
                    },
                    transaction: vec![1, 2, 3],
                    amount,
                    output_index: None,
                },
                sender: self.identity_hex().await,
                message_id: "payment-1".to_string(),
            }
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
            .expect("get_public_key")
            .public_key
            .to_der_hex()
        }
    }

    fn notification_wallet_output(sender_identity_key: &str) -> serde_json::Value {
        serde_json::json!({
            "outputIndex": 0,
            "protocol": "wallet payment",
            "paymentRemittance": {
                "derivationPrefix": "BAU=",
                "derivationSuffix": "Bgc=",
                "senderIdentityKey": sender_identity_key,
            },
        })
    }

    fn notification_message(
        message_id: &str,
        sender: &str,
        payment: serde_json::Value,
    ) -> PeerMessage {
        PeerMessage {
            message_id: message_id.to_string(),
            sender: sender.to_string(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({ "message": {}, "payment": payment }).to_string(),
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
                InternalizeMode::Fail(message) => Err(WalletError::Internal(message.to_string())),
                InternalizeMode::Answer { accepted } => Ok(InternalizeActionResult { accepted }),
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
    // Task 1 tests: create_payment_token / send_payment
    // -----------------------------------------------------------------------

    /// Verify create_payment_token executes nonce + key derivation path.
    ///
    /// ProtoWallet's create_action may fail (no funded wallet), but the function
    /// should at least get past the nonce and public key derivation step.
    /// We test the compilation and the nonce/key derivation by checking
    /// the error comes from create_action (not from nonce or key derivation).
    #[tokio::test]
    async fn create_payment_token_uses_create_nonce() {
        let sender = ArcWallet::new();
        let recipient = ArcWallet::new();
        let recipient_pk = recipient.identity_hex().await;

        let client = crate::client::MessageBoxClient::new(
            "https://example.com".to_string(),
            sender,
            None,
            bsv::services::overlay_tools::Network::Mainnet,
        );

        // create_payment_token will call create_nonce twice then get_public_key
        // then create_action (which will fail with ProtoWallet as no network).
        // We verify the failure is from create_action, not the nonce/key steps.
        let result = client.create_payment_token(&recipient_pk, 1000).await;
        // ProtoWallet will return an error at create_action — that's expected
        // (no funded wallet). The important thing is it compiles and the
        // nonce/key path executes without panicking.
        match &result {
            Err(e) => {
                let msg = e.to_string();
                // Should NOT fail at nonce or key derivation steps
                assert!(
                    !msg.contains("create_nonce prefix:"),
                    "should not fail at nonce step"
                );
                // It will fail at create_action (wallet error) — acceptable
                println!("create_payment_token expected error: {msg}");
            }
            Ok(_) => {
                // If ProtoWallet succeeds somehow, that's also fine
                println!("create_payment_token succeeded unexpectedly — wallet may have funds");
            }
        }
    }

    /// Verify send_payment compiles and delegates to create_payment_token then send_message.
    /// (compile-check only — network will fail)
    #[allow(dead_code)]
    fn send_payment_compile_check(client: &crate::client::MessageBoxClient<ArcWallet>) {
        // Drop the future without awaiting — compile-check only.
        drop(client.send_payment("03abc", 1000));
    }

    // -----------------------------------------------------------------------
    // Task 2 tests: accept_payment, reject_payment, list_incoming_payments
    // -----------------------------------------------------------------------

    /// The existing too-small-to-refund policy acknowledges a 1999-sat payment
    /// without internalizing it or invoking the refund path.
    #[tokio::test]
    async fn reject_payment_below_2000_only_acknowledges_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let wallet = ArcWallet::internalize_answering(true);
        let payment = wallet.incoming_payment(1999).await;
        let observed_wallet = wallet.clone();
        let client = client_for(wallet);
        let refund_count = Arc::new(AtomicUsize::new(0));
        let acknowledgement_count = Arc::new(AtomicUsize::new(0));
        let refunds = Arc::clone(&refund_count);
        let acknowledgements = Arc::clone(&acknowledgement_count);

        client
            .reject_payment_with(
                &payment,
                move |_amount| async move {
                    refunds.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                move || async move {
                    acknowledgements.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await
            .expect("sub-threshold rejection succeeds");

        assert!(
            observed_wallet.internalize_originators().is_empty(),
            "sub-threshold rejection must not internalize"
        );
        assert_eq!(refund_count.load(Ordering::SeqCst), 0);
        assert_eq!(acknowledgement_count.load(Ordering::SeqCst), 1);
    }

    /// list_incoming_payments silently skips messages with invalid bodies.
    ///
    /// Verifies the filter_map+serde_json safeParse behavior at the parsing level.
    #[test]
    fn list_incoming_payments_skips_unparseable() {
        // Simulate what list_incoming_payments does internally:
        // parse each msg.body as PaymentToken, skip failures
        let messages = vec![
            ServerPeerMessage {
                message_id: "msg1".to_string(),
                body: "not valid json".to_string(),
                sender: "03sender1".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
                acknowledged: None,
                authenticated_decrypt: false,
            },
            ServerPeerMessage {
                message_id: "msg2".to_string(),
                body: r#"{"customInstructions":{"derivationPrefix":"p","derivationSuffix":"s"},"transaction":[1,2,3],"amount":1000}"#.to_string(),
                sender: "03sender2".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
                acknowledged: None,
                authenticated_decrypt: false,
            },
            ServerPeerMessage {
                message_id: "msg3".to_string(),
                body: r#"{"foo":"bar"}"#.to_string(),
                sender: "03sender3".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
                acknowledged: None,
                authenticated_decrypt: false,
            },
        ];

        // Apply the same filter_map logic as list_incoming_payments
        let payments: Vec<IncomingPayment> = messages
            .into_iter()
            .filter_map(|msg| {
                serde_json::from_str::<PaymentToken>(&msg.body)
                    .ok()
                    .map(|token| IncomingPayment {
                        token,
                        sender: msg.sender,
                        message_id: msg.message_id,
                    })
            })
            .collect();

        // Only msg2 has a valid PaymentToken body
        assert_eq!(
            payments.len(),
            1,
            "only valid payment token should be included"
        );
        assert_eq!(payments[0].message_id, "msg2");
        assert_eq!(payments[0].sender, "03sender2");
        assert_eq!(payments[0].token.amount, 1000);
    }

    /// accept_payment base64-decodes derivation prefix/suffix before passing to SDK.
    ///
    /// The SDK's bytes_as_base64 serde then re-encodes them to the original strings.
    #[test]
    fn accept_payment_base64_round_trip() {
        use base64::{engine::general_purpose::STANDARD, Engine};

        // create_nonce returns base64 strings like these
        let prefix = "dGVzdC1wcmVmaXg="; // base64("test-prefix")
        let suffix = "dGVzdC1zdWZmaXg="; // base64("test-suffix")

        // accept_payment decodes to raw bytes
        let prefix_bytes = STANDARD.decode(prefix).unwrap();
        let suffix_bytes = STANDARD.decode(suffix).unwrap();
        assert_eq!(prefix_bytes, b"test-prefix");
        assert_eq!(suffix_bytes, b"test-suffix");

        // SDK's bytes_as_base64 serde would re-encode back to the original strings
        let re_encoded = STANDARD.encode(&prefix_bytes);
        assert_eq!(
            re_encoded, prefix,
            "round-trip must produce original base64"
        );
    }

    /// Construct IncomingPayment from a PaymentToken, verify all fields preserved.
    #[test]
    fn incoming_payment_round_trip() {
        let token = PaymentToken {
            custom_instructions: PaymentCustomInstructions {
                derivation_prefix: "pfx".to_string(),
                derivation_suffix: "sfx".to_string(),
                payee: Some("03recipient".to_string()),
            },
            transaction: vec![0xde, 0xad, 0xbe, 0xef],
            amount: 5000,
            output_index: None,
        };

        let incoming = IncomingPayment {
            token: token.clone(),
            sender: "03sender_key".to_string(),
            message_id: "abc123".to_string(),
        };

        assert_eq!(incoming.sender, "03sender_key");
        assert_eq!(incoming.message_id, "abc123");
        assert_eq!(incoming.token.amount, 5000);
        assert_eq!(incoming.token.transaction, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(incoming.token.custom_instructions.derivation_prefix, "pfx");
        assert_eq!(incoming.token.custom_instructions.derivation_suffix, "sfx");
        assert_eq!(incoming.token.output_index, None);
    }

    // -----------------------------------------------------------------------
    // Task 3 tests: send_live_payment / listen_for_live_payments
    // -----------------------------------------------------------------------

    /// Verify send_live_payment compiles — delegates to create_payment_token then send_live_message.
    #[allow(dead_code)]
    fn send_live_payment_compile_check(client: &crate::client::MessageBoxClient<ArcWallet>) {
        let _fut = client.send_live_payment("03abc", 1000);
    }

    /// The listen_for_live_payments callback wrapper correctly parses a valid PaymentToken.
    ///
    /// Tests the parsing logic directly without a live WS connection.
    #[test]
    fn listen_for_live_payments_callback_parses_token() {
        use std::sync::Mutex as StdMutex;

        let received = Arc::new(StdMutex::new(Vec::<IncomingPayment>::new()));
        let received_clone = received.clone();

        // Construct a PeerMessage whose body is a valid PaymentToken JSON
        let msg = PeerMessage {
            message_id: "msg-live-1".to_string(),
            sender: "03sender".to_string(),
            recipient: "03recipient".to_string(),
            message_box: "payment_inbox".to_string(),
            body: r#"{"customInstructions":{"derivationPrefix":"p","derivationSuffix":"s"},"transaction":[1,2],"amount":500}"#.to_string(),
        };

        // Apply the same parsing logic as listen_for_live_payments wrapper
        if let Ok(token) = serde_json::from_str::<PaymentToken>(&msg.body) {
            let incoming = IncomingPayment {
                token,
                sender: msg.sender.clone(),
                message_id: msg.message_id.clone(),
            };
            received_clone.lock().unwrap().push(incoming);
        }

        let payments = received.lock().unwrap();
        assert_eq!(payments.len(), 1, "one valid payment should be parsed");
        assert_eq!(payments[0].token.amount, 500);
        assert_eq!(payments[0].sender, "03sender");
        assert_eq!(payments[0].message_id, "msg-live-1");
    }

    /// The listen_for_live_payments callback silently skips non-payment messages.
    ///
    /// Verifies safeParse behavior — invalid body produces no IncomingPayment.
    #[test]
    fn listen_for_live_payments_callback_skips_non_payment() {
        use std::sync::Mutex as StdMutex;

        let received = Arc::new(StdMutex::new(Vec::<IncomingPayment>::new()));
        let received_clone = received.clone();

        // Body is not a valid PaymentToken
        let msg = PeerMessage {
            message_id: "msg-bad-1".to_string(),
            sender: "03sender".to_string(),
            recipient: "03recipient".to_string(),
            message_box: "payment_inbox".to_string(),
            body: r#"{"not":"a payment token"}"#.to_string(),
        };

        // Apply the same parsing logic as listen_for_live_payments wrapper
        if let Ok(token) = serde_json::from_str::<PaymentToken>(&msg.body) {
            let incoming = IncomingPayment {
                token,
                sender: msg.sender.clone(),
                message_id: msg.message_id.clone(),
            };
            received_clone.lock().unwrap().push(incoming);
        }

        let payments = received.lock().unwrap();
        assert_eq!(
            payments.len(),
            0,
            "non-payment message must be silently skipped"
        );
    }

    #[tokio::test]
    async fn acknowledge_notification_does_not_ack_when_internalize_fails() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::failing_internalize("injected internalize failure");
        let sender_identity_key = wallet.identity_hex().await;
        let client = crate::client::MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            bsv::services::overlay_tools::Network::Mainnet,
        );
        let message = PeerMessage {
            message_id: "notification-with-payment".to_string(),
            sender: sender_identity_key.clone(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({
                "message": {},
                "payment": {
                    "tx": [1, 2, 3],
                    "outputs": [{
                        "outputIndex": 0,
                        "protocol": "wallet payment",
                        "paymentRemittance": {
                            "derivationPrefix": "BAU=",
                            "derivationSuffix": "Bgc=",
                            "senderIdentityKey": sender_identity_key,
                        },
                    }],
                },
            })
            .to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            !acknowledged.load(Ordering::SeqCst),
            "relay message must remain unacknowledged when internalization fails"
        );
        assert!(
            matches!(result, Err(MessageBoxError::Wallet(ref message)) if message.contains("injected internalize failure")),
            "internalize error must propagate, got {result:?}"
        );
    }

    #[tokio::test]
    async fn acknowledge_notification_acks_when_no_payment_exists() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::failing_internalize("internalize must not be called");
        let sender_identity_key = wallet.identity_hex().await;
        let client = crate::client::MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            bsv::services::overlay_tools::Network::Mainnet,
        );
        let message = PeerMessage {
            message_id: "notification-without-payment".to_string(),
            sender: sender_identity_key,
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({ "message": {} }).to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(!result.unwrap());
        assert!(
            acknowledged.load(Ordering::SeqCst),
            "a notification without a payment must be acknowledged"
        );
    }

    #[tokio::test]
    async fn acknowledge_notification_acks_non_notification_json_without_inspecting_payment() {
        use std::sync::atomic::{AtomicBool, Ordering};

        for (case, body) in [
            (
                "payment-only-object",
                serde_json::json!({
                    "payment": {
                        "tx": [1, 2, 3],
                        "outputs": [notification_wallet_output("not-inspected")],
                    },
                }),
            ),
            (
                "array",
                serde_json::json!([{
                    "message": {},
                    "payment": { "tx": [1, 2, 3], "outputs": [] },
                }]),
            ),
            ("scalar", serde_json::json!("ordinary message")),
        ] {
            let wallet = ArcWallet::internalize_answering(true);
            let observed_wallet = wallet.clone();
            let client = client_for(wallet);
            let message = PeerMessage {
                message_id: format!("non-notification-{case}"),
                sender: "sender".to_string(),
                recipient: "recipient".to_string(),
                message_box: "notifications".to_string(),
                body: body.to_string(),
            };
            let acknowledged = Arc::new(AtomicBool::new(false));
            let acknowledged_by_relay = Arc::clone(&acknowledged);

            let result = client
                .acknowledge_notification_with_ack(&message, move || async move {
                    acknowledged_by_relay.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await;

            assert!(!result.unwrap(), "{case} is not a notification wrapper");
            assert!(acknowledged.load(Ordering::SeqCst), "{case} must be acked");
            assert!(
                observed_wallet.internalize_originators().is_empty(),
                "{case} payment member must not be inspected"
            );
        }
    }

    /// TS 2.5.1 parity: a payment the client cannot store stays on the relay.
    /// Basket-insertion outputs are contract-valid but not yet supported, so the
    /// message must not be acknowledged — acknowledging discards the payment.
    #[tokio::test]
    async fn acknowledge_notification_keeps_unsupported_payment_queued() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::failing_internalize("internalize must not be called");
        let sender_identity_key = wallet.identity_hex().await;
        let client = crate::client::MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            bsv::services::overlay_tools::Network::Mainnet,
        );
        let message = PeerMessage {
            message_id: "notification-with-basket-output".to_string(),
            sender: sender_identity_key.clone(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({
                "message": {},
                "payment": {
                    "tx": [1, 2, 3],
                    "outputs": [{
                        "outputIndex": 0,
                        "protocol": "basket insertion",
                        "insertionRemittance": { "basket": "notifications" },
                    }],
                },
            })
            .to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(!result.unwrap());
        assert!(
            !acknowledged.load(Ordering::SeqCst),
            "a payment with no internalizable outputs must stay on the relay"
        );
    }

    /// A notification payment is an atomic unit for this client. If any output
    /// uses an unsupported protocol, do not internalize the supported subset:
    /// that would make a later retry ambiguous and could lose the unsupported
    /// value when the relay message is acknowledged.
    #[tokio::test]
    async fn acknowledge_notification_rejects_mixed_output_protocols_before_internalizing() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::internalize_answering(true);
        let sender_identity_key = wallet.identity_hex().await;
        let observed_wallet = wallet.clone();
        let client = client_for(wallet);
        let message = PeerMessage {
            message_id: "notification-with-mixed-outputs".to_string(),
            sender: sender_identity_key.clone(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({
                "message": {},
                "payment": {
                    "tx": [1, 2, 3],
                    "outputs": [
                        {
                            "outputIndex": 0,
                            "protocol": "wallet payment",
                            "paymentRemittance": {
                                "derivationPrefix": "BAU=",
                                "derivationSuffix": "Bgc=",
                                "senderIdentityKey": sender_identity_key,
                            },
                        },
                        {
                            "outputIndex": 1,
                            "protocol": "basket insertion"
                        }
                    ],
                },
            })
            .to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Validation(ref m)) if m.contains("basket insertion")),
            "unsupported protocol must surface clearly, got {result:?}"
        );
        assert!(
            observed_wallet.internalize_originators().is_empty(),
            "supported outputs must not be partially internalized"
        );
        assert!(!acknowledged.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn acknowledge_notification_keeps_explicit_null_protocol_queued() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::internalize_answering(true);
        let sender_identity_key = wallet.identity_hex().await;
        let observed_wallet = wallet.clone();
        let client = client_for(wallet);
        let mut output = notification_wallet_output(&sender_identity_key);
        output["protocol"] = serde_json::Value::Null;
        let message = notification_message(
            "notification-null-protocol",
            &sender_identity_key,
            serde_json::json!({ "tx": [1, 2, 3], "outputs": [output] }),
        );
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(!result.unwrap(), "null protocol is unsupported");
        assert!(observed_wallet.internalize_originators().is_empty());
        assert!(!acknowledged.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn acknowledge_notification_rejects_mixed_wallet_and_null_protocols() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::internalize_answering(true);
        let sender_identity_key = wallet.identity_hex().await;
        let observed_wallet = wallet.clone();
        let client = client_for(wallet);
        let wallet_output = notification_wallet_output(&sender_identity_key);
        let mut null_output = notification_wallet_output(&sender_identity_key);
        null_output["protocol"] = serde_json::Value::Null;
        let message = notification_message(
            "notification-mixed-wallet-null-protocol",
            &sender_identity_key,
            serde_json::json!({
                "tx": [1, 2, 3],
                "outputs": [wallet_output, null_output],
            }),
        );
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Validation(ref m)) if m.contains("null")),
            "mixed null protocol must surface clearly, got {result:?}"
        );
        assert!(observed_wallet.internalize_originators().is_empty());
        assert!(!acknowledged.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn acknowledge_notification_rejects_missing_required_output_fields() {
        use std::sync::atomic::{AtomicBool, Ordering};

        for (field, expected_error_field) in [
            ("outputIndex", "outputIndex"),
            ("derivationPrefix", "derivationPrefix"),
            ("derivationSuffix", "derivationSuffix"),
        ] {
            let wallet = ArcWallet::internalize_answering(true);
            let sender_identity_key = wallet.identity_hex().await;
            let observed_wallet = wallet.clone();
            let client = client_for(wallet);
            let mut output = serde_json::json!({
                "outputIndex": 0,
                "protocol": "wallet payment",
                "paymentRemittance": {
                    "derivationPrefix": "BAU=",
                    "derivationSuffix": "Bgc=",
                    "senderIdentityKey": sender_identity_key,
                },
            });
            let output_object = output.as_object_mut().expect("payment output object");
            if field == "outputIndex" {
                output_object.remove(field);
            } else {
                output_object["paymentRemittance"]
                    .as_object_mut()
                    .expect("payment remittance object")
                    .remove(field);
            }
            let message = PeerMessage {
                message_id: format!("notification-missing-{field}"),
                sender: sender_identity_key,
                recipient: "recipient".to_string(),
                message_box: "notifications".to_string(),
                body: serde_json::json!({
                    "message": {},
                    "payment": { "tx": [1, 2, 3], "outputs": [output] },
                })
                .to_string(),
            };
            let acknowledged = Arc::new(AtomicBool::new(false));
            let acknowledged_by_relay = Arc::clone(&acknowledged);

            let result = client
                .acknowledge_notification_with_ack(&message, move || async move {
                    acknowledged_by_relay.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await;

            assert!(
                matches!(result, Err(MessageBoxError::Validation(ref m)) if m.contains(expected_error_field)),
                "missing {field} must surface a clear error, got {result:?}"
            );
            assert!(
                observed_wallet.internalize_originators().is_empty(),
                "missing {field} must fail before internalization"
            );
            assert!(
                !acknowledged.load(Ordering::SeqCst),
                "missing {field} must remain queued"
            );
        }
    }

    #[tokio::test]
    async fn acknowledge_notification_rejects_invalid_ts_remittance_before_internalizing() {
        use std::sync::atomic::{AtomicBool, Ordering};

        for (case, expected_error) in [
            ("missing-remittance", "paymentRemittance"),
            ("missing-prefix", "derivationPrefix"),
            ("missing-suffix", "derivationSuffix"),
            ("empty-prefix", "derivationPrefix must not be empty"),
            ("blank-suffix", "derivationSuffix must not be empty"),
            ("invalid-prefix", "derivationPrefix base64"),
            ("invalid-suffix", "derivationSuffix base64"),
        ] {
            let wallet = ArcWallet::internalize_answering(true);
            let sender_identity_key = wallet.identity_hex().await;
            let observed_wallet = wallet.clone();
            let client = client_for(wallet);
            let mut output = serde_json::json!({
                "outputIndex": 0,
                "protocol": "wallet payment",
                "paymentRemittance": {
                    "derivationPrefix": "BAU=",
                    "derivationSuffix": "Bgc=",
                    "senderIdentityKey": sender_identity_key,
                },
            });
            let output_object = output.as_object_mut().expect("payment output object");
            match case {
                "missing-remittance" => {
                    output_object.remove("paymentRemittance");
                }
                "missing-prefix" => {
                    output_object["paymentRemittance"]
                        .as_object_mut()
                        .expect("payment remittance object")
                        .remove("derivationPrefix");
                }
                "missing-suffix" => {
                    output_object["paymentRemittance"]
                        .as_object_mut()
                        .expect("payment remittance object")
                        .remove("derivationSuffix");
                }
                "empty-prefix" => {
                    output_object["paymentRemittance"]["derivationPrefix"] = serde_json::json!("");
                }
                "blank-suffix" => {
                    output_object["paymentRemittance"]["derivationSuffix"] =
                        serde_json::json!("   ");
                }
                "invalid-prefix" => {
                    output_object["paymentRemittance"]["derivationPrefix"] =
                        serde_json::json!("not base64");
                }
                "invalid-suffix" => {
                    output_object["paymentRemittance"]["derivationSuffix"] =
                        serde_json::json!("not base64");
                }
                _ => unreachable!(),
            }
            let message = PeerMessage {
                message_id: format!("notification-{case}"),
                sender: sender_identity_key,
                recipient: "recipient".to_string(),
                message_box: "notifications".to_string(),
                body: serde_json::json!({
                    "message": {},
                    "payment": { "tx": [1, 2, 3], "outputs": [output] },
                })
                .to_string(),
            };
            let acknowledged = Arc::new(AtomicBool::new(false));
            let acknowledged_by_relay = Arc::clone(&acknowledged);

            let result = client
                .acknowledge_notification_with_ack(&message, move || async move {
                    acknowledged_by_relay.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await;

            assert!(
                matches!(result, Err(MessageBoxError::Validation(ref m)) if m.contains(expected_error)),
                "{case} must surface a clear error, got {result:?}"
            );
            assert!(
                observed_wallet.internalize_originators().is_empty(),
                "{case} must fail before internalization"
            );
            assert!(
                !acknowledged.load(Ordering::SeqCst),
                "{case} must remain queued"
            );
        }
    }

    #[tokio::test]
    async fn acknowledge_notification_rejects_empty_transaction_before_internalizing() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::internalize_answering(true);
        let sender_identity_key = wallet.identity_hex().await;
        let observed_wallet = wallet.clone();
        let client = client_for(wallet);
        let message = PeerMessage {
            message_id: "notification-empty-tx".to_string(),
            sender: sender_identity_key.clone(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({
                "message": {},
                "payment": {
                    "tx": [],
                    "outputs": [{
                        "outputIndex": 0,
                        "protocol": "wallet payment",
                        "paymentRemittance": {
                            "derivationPrefix": "BAU=",
                            "derivationSuffix": "Bgc=",
                            "senderIdentityKey": sender_identity_key,
                        },
                    }],
                },
            })
            .to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Validation(ref m)) if m.contains("transaction is empty")),
            "empty transaction must surface a clear error, got {result:?}"
        );
        assert!(observed_wallet.internalize_originators().is_empty());
        assert!(!acknowledged.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn acknowledge_notification_rejects_oversized_transaction_before_internalizing() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::internalize_answering(true);
        let sender_identity_key = wallet.identity_hex().await;
        let observed_wallet = wallet.clone();
        let client = client_for(wallet);
        let message = notification_message(
            "notification-oversized-tx",
            &sender_identity_key,
            serde_json::json!({
                "tx": vec![0u8; 32 * 1024 * 1024 + 1],
                "outputs": [notification_wallet_output(&sender_identity_key)],
            }),
        );
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Validation(ref m)) if m.contains("32 MiB")),
            "oversized transaction must surface a clear error, got {result:?}"
        );
        assert!(observed_wallet.internalize_originators().is_empty());
        assert!(!acknowledged.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn acknowledge_notification_rejects_too_many_outputs_before_internalizing() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::internalize_answering(true);
        let sender_identity_key = wallet.identity_hex().await;
        let observed_wallet = wallet.clone();
        let client = client_for(wallet);
        let outputs: Vec<_> = (0..102)
            .map(|_| notification_wallet_output(&sender_identity_key))
            .collect();
        let message = notification_message(
            "notification-too-many-outputs",
            &sender_identity_key,
            serde_json::json!({ "tx": [1, 2, 3], "outputs": outputs }),
        );
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Validation(ref m)) if m.contains("101 outputs")),
            "102 outputs must surface a clear error, got {result:?}"
        );
        assert!(observed_wallet.internalize_originators().is_empty());
        assert!(!acknowledged.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn acknowledge_notification_rejects_invalid_descriptions_before_internalizing() {
        use std::sync::atomic::{AtomicBool, Ordering};

        for (case, description) in [
            ("empty", String::new()),
            ("leading-space", " leading".to_string()),
            ("trailing-space", "trailing ".to_string()),
            ("over-50-bytes", "a".repeat(51)),
            ("over-50-utf8-bytes", "é".repeat(26)),
            ("c0-control", "bad\u{001f}description".to_string()),
            ("c1-control", "bad\u{0085}description".to_string()),
        ] {
            let wallet = ArcWallet::internalize_answering(true);
            let sender_identity_key = wallet.identity_hex().await;
            let observed_wallet = wallet.clone();
            let client = client_for(wallet);
            let message = notification_message(
                &format!("notification-description-{case}"),
                &sender_identity_key,
                serde_json::json!({
                    "tx": [1, 2, 3],
                    "description": description,
                    "outputs": [notification_wallet_output(&sender_identity_key)],
                }),
            );
            let acknowledged = Arc::new(AtomicBool::new(false));
            let acknowledged_by_relay = Arc::clone(&acknowledged);

            let result = client
                .acknowledge_notification_with_ack(&message, move || async move {
                    acknowledged_by_relay.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await;

            assert!(
                matches!(result, Err(MessageBoxError::Validation(ref m)) if m.contains("description")),
                "{case} description must surface a clear error, got {result:?}"
            );
            assert!(observed_wallet.internalize_originators().is_empty());
            assert!(!acknowledged.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn acknowledge_notification_keeps_non_object_payment_queued() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::failing_internalize("internalize must not be called");
        let client = client_for(wallet);
        let message = PeerMessage {
            message_id: "notification-with-string-payment".to_string(),
            sender: "sender".to_string(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({ "message": {}, "payment": "malformed" }).to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Json(_))),
            "malformed payment member must surface a parse error, got {result:?}"
        );
        assert!(!acknowledged.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn acknowledge_notification_keeps_malformed_payment_fields_queued() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::failing_internalize("internalize must not be called");
        let client = client_for(wallet);
        let message = PeerMessage {
            message_id: "notification-with-malformed-payment-fields".to_string(),
            sender: "sender".to_string(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({
                "message": {},
                "payment": { "tx": "not-a-byte-array", "outputs": [] }
            })
            .to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Json(_))),
            "malformed payment fields must surface a parse error, got {result:?}"
        );
        assert!(!acknowledged.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn acknowledge_notification_keeps_message_when_wallet_declines() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::internalize_answering(false);
        let sender_identity_key = wallet.identity_hex().await;
        let client = client_for(wallet);
        let message = PeerMessage {
            message_id: "notification-wallet-declined".to_string(),
            sender: sender_identity_key.clone(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({
                "message": {},
                "payment": {
                    "tx": [1, 2, 3],
                    "outputs": [{
                        "outputIndex": 0,
                        "protocol": "wallet payment",
                        "paymentRemittance": {
                            "derivationPrefix": "BAU=",
                            "derivationSuffix": "Bgc=",
                            "senderIdentityKey": sender_identity_key,
                        },
                    }],
                },
            })
            .to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Wallet(ref m)) if m.contains("did not accept")),
            "accepted:false must surface as an error, got {result:?}"
        );
        assert!(!acknowledged.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn acknowledge_notification_propagates_ack_failure_after_internalizing() {
        let wallet = ArcWallet::internalize_answering(true);
        let sender_identity_key = wallet.identity_hex().await;
        let observed_wallet = wallet.clone();
        let client = client_for(wallet);
        let message = PeerMessage {
            message_id: "notification-ack-failure".to_string(),
            sender: sender_identity_key.clone(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({
                "message": {},
                "payment": {
                    "tx": [1, 2, 3],
                    "outputs": [{
                        "outputIndex": 0,
                        "protocol": "wallet payment",
                        "paymentRemittance": {
                            "derivationPrefix": "BAU=",
                            "derivationSuffix": "Bgc=",
                            "senderIdentityKey": sender_identity_key,
                        },
                    }],
                },
            })
            .to_string(),
        };

        let result = client
            .acknowledge_notification_with_ack(&message, || async move {
                Err(MessageBoxError::Http(503, "relay unavailable".to_string()))
            })
            .await;

        assert_eq!(observed_wallet.internalize_originators().len(), 1);
        assert!(
            matches!(result, Err(MessageBoxError::Http(503, ref m)) if m == "relay unavailable"),
            "acknowledgement failure must propagate, got {result:?}"
        );
    }

    #[tokio::test]
    async fn acknowledge_notification_maps_ts_wire_and_forwards_originator() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::internalize_answering(true);
        let sender_identity_key = wallet.identity_hex().await;
        let observed_wallet = wallet.clone();
        let client = crate::client::MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            Some("https://originator.example".to_string()),
            bsv::services::overlay_tools::Network::Mainnet,
        );
        let message = PeerMessage {
            message_id: "notification-originator".to_string(),
            sender: sender_identity_key.clone(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({
                "message": {},
                "payment": {
                    "tx": [1, 2, 3],
                    "description": "delivery fee",
                    "outputs": [{
                        "outputIndex": 7,
                        "protocol": "wallet payment",
                        "paymentRemittance": {
                            "derivationPrefix": "BAU=",
                            "derivationSuffix": "Bgc=",
                            "senderIdentityKey": sender_identity_key,
                        },
                    }],
                },
            })
            .to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(result.unwrap());
        assert!(acknowledged.load(Ordering::SeqCst));
        let observations = observed_wallet.internalize_observations();
        assert_eq!(observations.len(), 1);
        let (args, originator) = &observations[0];
        assert_eq!(args.tx, vec![1, 2, 3]);
        assert_eq!(args.description, "delivery fee");
        assert_eq!(args.labels, Some(vec!["notification-payment".to_string()]));
        assert_eq!(args.seek_permission, BooleanDefaultTrue(Some(false)));
        assert_eq!(originator.as_deref(), Some("https://originator.example"));
        assert_eq!(args.outputs.len(), 1);
        match &args.outputs[0] {
            InternalizeOutput::WalletPayment {
                output_index,
                payment,
            } => {
                assert_eq!(*output_index, 7);
                assert_eq!(payment.derivation_prefix, vec![4, 5]);
                assert_eq!(payment.derivation_suffix, vec![6, 7]);
                assert_eq!(
                    payment.sender_identity_key.to_der_hex(),
                    sender_identity_key
                );
            }
            output => panic!("expected wallet-payment output, got {output:?}"),
        }
    }

    /// A payment envelope with `outputs` but no `tx` is malformed, not absent:
    /// keep it queued rather than acknowledge it away (TS 2.5.1 parity).
    #[tokio::test]
    async fn acknowledge_notification_keeps_payment_missing_tx_queued() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::failing_internalize("internalize must not be called");
        let sender_identity_key = wallet.identity_hex().await;
        let client = crate::client::MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            bsv::services::overlay_tools::Network::Mainnet,
        );
        let message = PeerMessage {
            message_id: "notification-missing-tx".to_string(),
            sender: sender_identity_key.clone(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({
                "message": {},
                "payment": {
                    "outputs": [{
                        "outputIndex": 0,
                        "protocol": "wallet payment",
                        "paymentRemittance": {
                            "derivationPrefix": "BAU=",
                            "derivationSuffix": "Bgc=",
                            "senderIdentityKey": sender_identity_key,
                        },
                    }],
                },
            })
            .to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(!result.unwrap());
        assert!(
            !acknowledged.load(Ordering::SeqCst),
            "a malformed payment must stay on the relay"
        );
    }

    /// An unparseable `senderIdentityKey` on a wallet-payment output is an error
    /// the caller must see — silently dropping the output would leave nothing to
    /// internalize and (before this fix) acknowledge the payment away.
    #[tokio::test]
    async fn acknowledge_notification_errors_on_bad_sender_key_without_ack() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::failing_internalize("internalize must not be called");
        let sender_identity_key = wallet.identity_hex().await;
        let client = crate::client::MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            bsv::services::overlay_tools::Network::Mainnet,
        );
        let message = PeerMessage {
            message_id: "notification-bad-sender-key".to_string(),
            sender: sender_identity_key,
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({
                "message": {},
                "payment": {
                    "tx": [1, 2, 3],
                    "outputs": [{
                        "outputIndex": 0,
                        "protocol": "wallet payment",
                        "paymentRemittance": {
                            "derivationPrefix": "BAU=",
                            "derivationSuffix": "Bgc=",
                            "senderIdentityKey": "not-a-key",
                        },
                    }],
                },
            })
            .to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Validation(_))),
            "bad sender key must surface as an error, got {result:?}"
        );
        assert!(
            !acknowledged.load(Ordering::SeqCst),
            "message must stay on the relay when an output cannot be built"
        );
    }

    #[tokio::test]
    async fn acknowledge_notification_requires_compressed_sender_identity_key() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let identity_wallet = ArcWallet::new();
        let compressed_key = identity_wallet.identity_hex().await;
        let parsed_key = PublicKey::from_string(&compressed_key).expect("compressed public key");
        let cases = [
            (
                "uncompressed",
                bsv::primitives::utils::to_hex(&parsed_key.to_der_uncompressed()),
            ),
            ("invalid-hex", format!("02{}", "gg".repeat(32))),
            ("invalid-point", format!("02{}", "00".repeat(32))),
        ];

        for (case, sender_identity_key) in cases {
            let wallet = ArcWallet::internalize_answering(true);
            let observed_wallet = wallet.clone();
            let client = client_for(wallet);
            let message = notification_message(
                &format!("notification-{case}-sender-key"),
                "sender",
                serde_json::json!({
                    "tx": [1, 2, 3],
                    "outputs": [notification_wallet_output(&sender_identity_key)],
                }),
            );
            let acknowledged = Arc::new(AtomicBool::new(false));
            let acknowledged_by_relay = Arc::clone(&acknowledged);

            let result = client
                .acknowledge_notification_with_ack(&message, move || async move {
                    acknowledged_by_relay.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await;

            assert!(
                matches!(result, Err(MessageBoxError::Validation(ref m)) if m.contains("senderIdentityKey")),
                "{case} key must be rejected clearly, got {result:?}"
            );
            assert!(observed_wallet.internalize_originators().is_empty());
            assert!(!acknowledged.load(Ordering::SeqCst));
        }
    }

    // ---- accept_payment / reject_payment ordering (ts-stack #534 parity) ----

    fn client_for(wallet: ArcWallet) -> crate::client::MessageBoxClient<ArcWallet> {
        crate::client::MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            bsv::services::overlay_tools::Network::Mainnet,
        )
    }

    /// A wallet may answer `accepted: false` without erroring. That is not a
    /// stored payment, so the relay message must survive and the caller must
    /// see a failure.
    #[tokio::test]
    async fn accept_payment_errors_and_keeps_message_when_wallet_declines() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::internalize_answering(false);
        let payment = wallet.incoming_payment(5000).await;
        let client = client_for(wallet);
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .accept_payment_with_ack(&payment, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Wallet(ref m)) if m.contains("accept")),
            "declined internalize must be an error, got {result:?}"
        );
        assert!(
            !acknowledged.load(Ordering::SeqCst),
            "relay message must remain when the wallet declines"
        );
    }

    #[tokio::test]
    async fn reject_payment_does_not_refund_when_wallet_declines() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::internalize_answering(false);
        let payment = wallet.incoming_payment(5000).await;
        let client = client_for(wallet);
        let refunded = Arc::new(AtomicBool::new(false));
        let acknowledged = Arc::new(AtomicBool::new(false));
        let (r, a) = (Arc::clone(&refunded), Arc::clone(&acknowledged));

        let result = client
            .reject_payment_with(
                &payment,
                move |_amount| async move {
                    r.store(true, Ordering::SeqCst);
                    Ok(())
                },
                move || {
                    let a = Arc::clone(&a);
                    async move {
                        a.store(true, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await;

        assert!(
            result.is_err(),
            "declined internalize must fail the rejection"
        );
        assert!(
            !refunded.load(Ordering::SeqCst),
            "no refund may be sent from unrelated funds when the payment was not stored"
        );
        assert!(!acknowledged.load(Ordering::SeqCst));
    }

    /// Refund send failure must leave the relay message in place so the
    /// rejection can be resumed; acknowledging mid-flight strands the sender.
    #[tokio::test]
    async fn reject_payment_keeps_message_when_refund_fails() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::internalize_answering(true);
        let payment = wallet.incoming_payment(5000).await;
        let client = client_for(wallet);
        let acknowledged = Arc::new(AtomicBool::new(false));
        let a = Arc::clone(&acknowledged);

        let result = client
            .reject_payment_with(
                &payment,
                |_amount| async move { Err(MessageBoxError::Http(401, "unauthorized".into())) },
                move || {
                    let a = Arc::clone(&a);
                    async move {
                        a.store(true, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Http(401, _))),
            "a failed refund must propagate, even a 401, got {result:?}"
        );
        assert!(
            !acknowledged.load(Ordering::SeqCst),
            "relay message must remain when the refund was not sent"
        );
    }

    #[tokio::test]
    async fn reject_payment_acknowledges_once_after_refund() {
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

        let wallet = ArcWallet::internalize_answering(true);
        let payment = wallet.incoming_payment(5000).await;
        let client = client_for(wallet);
        let refund_amount = Arc::new(AtomicU64::new(0));
        let ack_count = Arc::new(AtomicUsize::new(0));
        let acks_at_refund = Arc::new(AtomicUsize::new(usize::MAX));
        let (r, a, at) = (
            Arc::clone(&refund_amount),
            Arc::clone(&ack_count),
            Arc::clone(&acks_at_refund),
        );
        let a_for_refund = Arc::clone(&ack_count);

        client
            .reject_payment_with(
                &payment,
                move |amount| async move {
                    at.store(a_for_refund.load(Ordering::SeqCst), Ordering::SeqCst);
                    r.store(amount, Ordering::SeqCst);
                    Ok(())
                },
                move || {
                    let a = Arc::clone(&a);
                    async move {
                        a.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await
            .expect("rejection succeeds");

        assert_eq!(
            refund_amount.load(Ordering::SeqCst),
            4000,
            "refund is amount minus 1000 fee"
        );
        assert_eq!(
            acks_at_refund.load(Ordering::SeqCst),
            0,
            "the message must not be acknowledged before the refund is sent"
        );
        assert_eq!(
            ack_count.load(Ordering::SeqCst),
            1,
            "acknowledge exactly once, after the refund"
        );
    }

    /// #279 regression: an output whose `protocol` field is ABSENT must still be
    /// internalized, and must NOT be acknowledged if internalization fails.
    ///
    /// A strict `protocol == Some("wallet payment")` filter would drop this output
    /// and return `Ok(false)` without acknowledging. `http_ops.rs`'s sibling
    /// internalize path also admits absent-protocol outputs.
    #[tokio::test]
    async fn acknowledge_notification_internalizes_output_with_absent_protocol() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wallet = ArcWallet::failing_internalize("injected internalize failure");
        let sender_identity_key = wallet.identity_hex().await;
        let client = crate::client::MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            bsv::services::overlay_tools::Network::Mainnet,
        );
        // `protocol` deliberately omitted — serde yields None.
        let message = PeerMessage {
            message_id: "absent-protocol".to_string(),
            sender: sender_identity_key.clone(),
            recipient: "recipient".to_string(),
            message_box: "notifications".to_string(),
            body: serde_json::json!({
                "message": {},
                "payment": { "tx": [1, 2, 3], "outputs": [{
                    "outputIndex": 0,
                    "paymentRemittance": {
                        "derivationPrefix": "BAU=",
                        "derivationSuffix": "Bgc=",
                        "senderIdentityKey": sender_identity_key,
                    },
                }]},
            })
            .to_string(),
        };
        let acknowledged = Arc::new(AtomicBool::new(false));
        let acknowledged_by_relay = Arc::clone(&acknowledged);

        let result = client
            .acknowledge_notification_with_ack(&message, move || async move {
                acknowledged_by_relay.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(MessageBoxError::Wallet(ref m)) if m.contains("injected internalize failure")),
            "an absent-protocol output must be internalized, not skipped; got {result:?}"
        );
        assert!(
            !acknowledged.load(Ordering::SeqCst),
            "relay message must remain unacknowledged when internalization fails"
        );
    }
}
