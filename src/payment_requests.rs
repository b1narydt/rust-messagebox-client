//! Payment Request System — Rust parity with TypeScript PeerPayClient.
//!
//! Implements the three-mailbox payment request flow:
//! - `payment_requests` — incoming payment requests
//! - `payment_request_responses` — responses to sent requests
//! - `payment_inbox` — actual payments (existing PeerPay)
//!
//! HMAC-based request proofs tie each request to the sender's identity,
//! preventing replay and ensuring directionality.

use std::sync::Arc;

use bsv::auth::utils::create_nonce;
use bsv::wallet::interfaces::{
    CreateHmacArgs, VerifyHmacArgs, WalletInterface,
};
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};
use bsv::primitives::public_key::PublicKey;
use bsv::remittance::types::PeerMessage;

use crate::client::MessageBoxClient;
use crate::error::MessageBoxError;
use crate::types::{
    IncomingPaymentRequest, PaymentRequestLimits, PaymentRequestMessage,
    PaymentRequestResponse, PaymentRequestResult, PAYMENT_REQUESTS_MESSAGEBOX,
    PAYMENT_REQUEST_RESPONSES_MESSAGEBOX,
};

/// Build the protocol for payment request auth HMACs.
fn payment_request_auth_protocol() -> Protocol {
    Protocol {
        security_level: 2,
        protocol: "payment request auth".to_string(),
    }
}

/// Convert a hex string to raw bytes.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, MessageBoxError> {
    hex::decode(hex).map_err(|e| MessageBoxError::Auth(format!("hex decode: {e}")))
}

/// Convert raw bytes to lowercase hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

impl<W: WalletInterface + Clone + 'static + Send + Sync> MessageBoxClient<W> {
    // -----------------------------------------------------------------------
    // Sending payment requests
    // -----------------------------------------------------------------------

    /// Send a payment request to `recipient` for `amount` satoshis.
    ///
    /// Generates a unique request ID and HMAC proof tying the request to the
    /// sender's identity. Returns the request ID and proof (needed for
    /// cancellation).
    ///
    /// Matches TS `PeerPayClient.requestPayment()`.
    pub async fn request_payment(
        &self,
        recipient: &str,
        amount: u64,
        description: &str,
        expires_at: u64,
    ) -> Result<PaymentRequestResult, MessageBoxError> {
        if amount == 0 {
            return Err(MessageBoxError::Validation(
                "Payment request amount must be greater than 0".to_string(),
            ));
        }

        // Generate unique request ID
        let request_id = create_nonce(self.wallet())
            .await
            .map_err(|e| MessageBoxError::Auth(format!("create_nonce request_id: {e}")))?;

        let sender_identity_key = self.get_identity_key().await?;

        // Create HMAC proof: data = requestId + recipient (as UTF-8 bytes)
        let proof_data = format!("{}{}", request_id, recipient);
        let hmac_result = self
            .wallet()
            .create_hmac(
                CreateHmacArgs {
                    data: proof_data.as_bytes().to_vec(),
                    protocol_id: payment_request_auth_protocol(),
                    key_id: request_id.clone(),
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(
                            PublicKey::from_string(recipient)
                                .map_err(|e| MessageBoxError::Auth(format!("invalid recipient key: {e}")))?,
                        ),
                    },
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        let request_proof = bytes_to_hex(&hmac_result.hmac);

        let message = PaymentRequestMessage {
            request_id: request_id.clone(),
            sender_identity_key,
            request_proof: request_proof.clone(),
            amount: Some(amount),
            description: Some(description.to_string()),
            expires_at: Some(expires_at),
            cancelled: None,
        };

        let body = serde_json::to_string(&message)?;

        match self
            .send_message(recipient, PAYMENT_REQUESTS_MESSAGEBOX, &body, false, false, None, None)
            .await
        {
            Ok(_) => {}
            Err(MessageBoxError::Http(403, _)) => {
                return Err(MessageBoxError::Validation(
                    "Payment request blocked — you are not on the recipient's whitelist.".to_string(),
                ));
            }
            Err(e) => return Err(e),
        }

        Ok(PaymentRequestResult {
            request_id,
            request_proof,
        })
    }

    /// Cancel a previously sent payment request.
    ///
    /// Requires the original `request_id` and `request_proof` returned from
    /// `request_payment()`. Sends a cancellation message to the recipient's
    /// `payment_requests` inbox.
    ///
    /// Matches TS `PeerPayClient.cancelPaymentRequest()`.
    pub async fn cancel_payment_request(
        &self,
        recipient: &str,
        request_id: &str,
        request_proof: &str,
        host_override: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        let sender_identity_key = self.get_identity_key().await?;

        let message = PaymentRequestMessage {
            request_id: request_id.to_string(),
            sender_identity_key,
            request_proof: request_proof.to_string(),
            amount: None,
            description: None,
            expires_at: None,
            cancelled: Some(true),
        };

        let body = serde_json::to_string(&message)?;
        self.send_message(
            recipient,
            PAYMENT_REQUESTS_MESSAGEBOX,
            &body,
            false,
            false,
            None,
            host_override,
        )
        .await?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Receiving and processing payment requests
    // -----------------------------------------------------------------------

    /// List active incoming payment requests with automatic filtering.
    ///
    /// Performs multi-stage filtering matching TS `listIncomingPaymentRequests`:
    /// 1. Parse and validate all messages
    /// 2. Collect and verify cancellations (HMAC proof check)
    /// 3. Filter: expired, cancelled, out-of-range, invalid proof
    /// 4. Auto-acknowledge filtered messages
    ///
    /// Returns only valid, active, in-range requests.
    pub async fn list_incoming_payment_requests(
        &self,
        host_override: Option<&str>,
        limits: Option<PaymentRequestLimits>,
    ) -> Result<Vec<IncomingPaymentRequest>, MessageBoxError> {
        let limits = limits.unwrap_or_default();
        let my_identity_key = self.get_identity_key().await?;

        let messages = self
            .list_messages(PAYMENT_REQUESTS_MESSAGEBOX, false, host_override)
            .await?;

        // Stage 1: Parse all messages
        let mut parsed: Vec<(PeerMessage, PaymentRequestMessage)> = Vec::new();
        let mut malformed_ids: Vec<String> = Vec::new();

        for msg in &messages {
            match serde_json::from_str::<PaymentRequestMessage>(&msg.body) {
                Ok(body) if is_valid_payment_request(&body) => {
                    parsed.push((msg.clone(), body));
                }
                _ => {
                    malformed_ids.push(msg.message_id.clone());
                }
            }
        }

        // Stage 2: Collect verified cancellations
        let mut cancelled_requests: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut cancellation_ids: Vec<String> = Vec::new();

        for (msg, body) in &parsed {
            if body.cancelled == Some(true) {
                // Verify cancellation HMAC proof
                let proof_data = format!("{}{}", body.request_id, my_identity_key);
                let proof_bytes = match hex_to_bytes(&body.request_proof) {
                    Ok(b) => b,
                    Err(_) => {
                        malformed_ids.push(msg.message_id.clone());
                        continue;
                    }
                };

                let verify_result = self
                    .wallet()
                    .verify_hmac(
                        VerifyHmacArgs {
                            data: proof_data.as_bytes().to_vec(),
                            hmac: proof_bytes,
                            protocol_id: payment_request_auth_protocol(),
                            key_id: body.request_id.clone(),
                            counterparty: Counterparty {
                                counterparty_type: CounterpartyType::Other,
                                public_key: PublicKey::from_string(&msg.sender).ok(),
                            },
                            privileged: false,
                            privileged_reason: None,
                            seek_permission: None,
                        },
                        self.originator(),
                    )
                    .await;

                match verify_result {
                    Ok(r) if r.valid => {
                        cancelled_requests
                            .insert(body.request_id.clone(), msg.sender.clone());
                        cancellation_ids.push(msg.message_id.clone());
                    }
                    _ => {
                        malformed_ids.push(msg.message_id.clone());
                    }
                }
            }
        }

        // Stage 3: Filter active requests
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut result: Vec<IncomingPaymentRequest> = Vec::new();
        let mut expired_ids: Vec<String> = Vec::new();
        let mut cancelled_original_ids: Vec<String> = Vec::new();
        let mut out_of_range_ids: Vec<String> = Vec::new();

        for (msg, body) in &parsed {
            // Skip cancellation messages themselves
            if body.cancelled == Some(true) {
                continue;
            }

            let amount = match body.amount {
                Some(a) => a,
                None => {
                    malformed_ids.push(msg.message_id.clone());
                    continue;
                }
            };
            let description = match &body.description {
                Some(d) => d.clone(),
                None => {
                    malformed_ids.push(msg.message_id.clone());
                    continue;
                }
            };
            let expires_at = match body.expires_at {
                Some(e) => e,
                None => {
                    malformed_ids.push(msg.message_id.clone());
                    continue;
                }
            };

            // Check expiry
            if expires_at < now_ms {
                expired_ids.push(msg.message_id.clone());
                continue;
            }

            // Check cancellation
            if let Some(cancel_sender) = cancelled_requests.get(&body.request_id) {
                if cancel_sender == &msg.sender {
                    cancelled_original_ids.push(msg.message_id.clone());
                    continue;
                }
            }

            // Check range
            if amount < limits.min_amount || amount > limits.max_amount {
                out_of_range_ids.push(msg.message_id.clone());
                continue;
            }

            // Verify HMAC proof
            let proof_data = format!("{}{}", body.request_id, my_identity_key);
            let proof_bytes = match hex_to_bytes(&body.request_proof) {
                Ok(b) => b,
                Err(_) => {
                    malformed_ids.push(msg.message_id.clone());
                    continue;
                }
            };

            let verify_result = self
                .wallet()
                .verify_hmac(
                    VerifyHmacArgs {
                        data: proof_data.as_bytes().to_vec(),
                        hmac: proof_bytes,
                        protocol_id: payment_request_auth_protocol(),
                        key_id: body.request_id.clone(),
                        counterparty: Counterparty {
                            counterparty_type: CounterpartyType::Other,
                            public_key: PublicKey::from_string(&msg.sender).ok(),
                        },
                        privileged: false,
                        privileged_reason: None,
                        seek_permission: None,
                    },
                    self.originator(),
                )
                .await;

            match verify_result {
                Ok(r) if r.valid => {
                    result.push(IncomingPaymentRequest {
                        message_id: msg.message_id.clone(),
                        sender: msg.sender.clone(),
                        request_id: body.request_id.clone(),
                        amount,
                        description,
                        expires_at,
                    });
                }
                _ => {
                    malformed_ids.push(msg.message_id.clone());
                }
            }
        }

        // Stage 4: Acknowledge filtered messages
        let mut ack_ids: Vec<String> = Vec::new();
        ack_ids.extend(expired_ids);
        ack_ids.extend(cancelled_original_ids);
        ack_ids.extend(cancellation_ids);
        ack_ids.extend(out_of_range_ids);
        ack_ids.extend(malformed_ids);

        if !ack_ids.is_empty() {
            // Best-effort acknowledge — don't fail the listing
            let _ = self.acknowledge_message(ack_ids, host_override).await;
        }

        Ok(result)
    }

    /// Fulfill a payment request — send payment and notify the requester.
    ///
    /// 1. Sends the requested amount via PeerPay
    /// 2. Sends a "paid" response to the requester's response inbox
    /// 3. Acknowledges the original request
    ///
    /// Matches TS `PeerPayClient.fulfillPaymentRequest()`.
    pub async fn fulfill_payment_request(
        &self,
        request: &IncomingPaymentRequest,
        note: Option<&str>,
        host_override: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        // Step 1: Send payment
        self.send_payment(&request.sender, request.amount).await?;

        // Step 2: Send "paid" response
        let mut response = PaymentRequestResponse {
            request_id: request.request_id.clone(),
            status: "paid".to_string(),
            amount_paid: Some(request.amount),
            note: None,
        };
        if let Some(n) = note {
            response.note = Some(n.to_string());
        }

        let body = serde_json::to_string(&response)?;
        self.send_message(
            &request.sender,
            PAYMENT_REQUEST_RESPONSES_MESSAGEBOX,
            &body,
            false,
            false,
            None,
            host_override,
        )
        .await?;

        // Step 3: Acknowledge original request
        self.acknowledge_message(vec![request.message_id.clone()], host_override)
            .await?;

        Ok(())
    }

    /// Decline a payment request — notify the requester without sending payment.
    ///
    /// Matches TS `PeerPayClient.declinePaymentRequest()`.
    pub async fn decline_payment_request(
        &self,
        request: &IncomingPaymentRequest,
        note: Option<&str>,
        host_override: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        let mut response = PaymentRequestResponse {
            request_id: request.request_id.clone(),
            status: "declined".to_string(),
            amount_paid: None,
            note: None,
        };
        if let Some(n) = note {
            response.note = Some(n.to_string());
        }

        let body = serde_json::to_string(&response)?;
        self.send_message(
            &request.sender,
            PAYMENT_REQUEST_RESPONSES_MESSAGEBOX,
            &body,
            false,
            false,
            None,
            host_override,
        )
        .await?;

        // Acknowledge original request
        self.acknowledge_message(vec![request.message_id.clone()], host_override)
            .await?;

        Ok(())
    }

    /// Listen for live payment requests via WebSocket.
    ///
    /// Wraps `listen_for_live_messages` on the `payment_requests` inbox.
    /// Cancellation messages are silently skipped.
    ///
    /// Matches TS `PeerPayClient.listenForLivePaymentRequests()`.
    pub async fn listen_for_live_payment_requests(
        &self,
        on_request: Arc<dyn Fn(IncomingPaymentRequest) + Send + Sync>,
        override_host: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        let wrapper: Arc<dyn Fn(PeerMessage) + Send + Sync> = Arc::new(move |msg: PeerMessage| {
            if let Ok(body) = serde_json::from_str::<PaymentRequestMessage>(&msg.body) {
                // Skip cancellations
                if body.cancelled == Some(true) {
                    return;
                }
                // Skip malformed (missing required fields)
                if let (Some(amount), Some(description), Some(expires_at)) =
                    (body.amount, body.description.clone(), body.expires_at)
                {
                    on_request(IncomingPaymentRequest {
                        message_id: msg.message_id,
                        sender: msg.sender,
                        request_id: body.request_id,
                        amount,
                        description,
                        expires_at,
                    });
                }
            }
        });

        self.listen_for_live_messages(PAYMENT_REQUESTS_MESSAGEBOX, wrapper, override_host)
            .await
    }

    /// List responses to payment requests we've sent.
    ///
    /// Returns all parsed responses from the `payment_request_responses` inbox.
    /// Unparseable messages are silently skipped (safeParse behavior).
    ///
    /// Matches TS `PeerPayClient.listPaymentRequestResponses()`.
    pub async fn list_payment_request_responses(
        &self,
        host_override: Option<&str>,
    ) -> Result<Vec<PaymentRequestResponse>, MessageBoxError> {
        let messages = self
            .list_messages(PAYMENT_REQUEST_RESPONSES_MESSAGEBOX, false, host_override)
            .await?;

        let responses = messages
            .into_iter()
            .filter_map(|msg| serde_json::from_str::<PaymentRequestResponse>(&msg.body).ok())
            .collect();

        Ok(responses)
    }

    // -----------------------------------------------------------------------
    // Permission helpers
    // -----------------------------------------------------------------------

    /// Allow payment requests from a specific identity key.
    ///
    /// Sets recipient_fee to 0 (always allow) for the `payment_requests` inbox.
    ///
    /// Matches TS `PeerPayClient.allowPaymentRequestsFrom()`.
    pub async fn allow_payment_requests_from(
        &self,
        identity_key: &str,
        host_override: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        self.set_message_box_permission(
            crate::types::SetPermissionParams {
                message_box: PAYMENT_REQUESTS_MESSAGEBOX.to_string(),
                sender: Some(identity_key.to_string()),
                recipient_fee: 0,
            },
            host_override,
        )
        .await
    }

    /// Block payment requests from a specific identity key.
    ///
    /// Sets recipient_fee to -1 (blocked) for the `payment_requests` inbox.
    ///
    /// Matches TS `PeerPayClient.blockPaymentRequestsFrom()`.
    pub async fn block_payment_requests_from(
        &self,
        identity_key: &str,
        host_override: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        self.set_message_box_permission(
            crate::types::SetPermissionParams {
                message_box: PAYMENT_REQUESTS_MESSAGEBOX.to_string(),
                sender: Some(identity_key.to_string()),
                recipient_fee: -1,
            },
            host_override,
        )
        .await
    }

    /// List payment request permissions.
    ///
    /// Returns a list of `(identity_key, allowed)` pairs for the
    /// `payment_requests` inbox.
    ///
    /// Matches TS `PeerPayClient.listPaymentRequestPermissions()`.
    pub async fn list_payment_request_permissions(
        &self,
        host_override: Option<&str>,
    ) -> Result<Vec<(String, bool)>, MessageBoxError> {
        let permissions = self
            .list_message_box_permissions(Some(PAYMENT_REQUESTS_MESSAGEBOX), None, None, host_override)
            .await?;

        let result = permissions
            .into_iter()
            .filter(|p| p.sender.is_some() && !p.sender.as_ref().unwrap().is_empty())
            .map(|p| {
                let allowed = p.status() != "blocked";
                (p.sender.unwrap_or_default(), allowed)
            })
            .collect();

        Ok(result)
    }
}

/// Validate that a PaymentRequestMessage has the required fields.
///
/// Matches TS `isValidPaymentRequestMessage()`:
/// - Must have `requestId`, `senderIdentityKey`, `requestProof` (non-empty strings)
/// - Must be either a cancellation (`cancelled: true`) or have `amount`, `description`, `expiresAt`
fn is_valid_payment_request(msg: &PaymentRequestMessage) -> bool {
    if msg.request_id.is_empty()
        || msg.sender_identity_key.is_empty()
        || msg.request_proof.is_empty()
    {
        return false;
    }

    if msg.cancelled == Some(true) {
        return true;
    }

    msg.amount.is_some() && msg.description.is_some() && msg.expires_at.is_some()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_request_message_serializes_camel_case() {
        let msg = PaymentRequestMessage {
            request_id: "req-123".to_string(),
            sender_identity_key: "03abc".to_string(),
            request_proof: "deadbeef".to_string(),
            amount: Some(5000),
            description: Some("test payment".to_string()),
            expires_at: Some(1700000000000),
            cancelled: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"requestId\""));
        assert!(json.contains("\"senderIdentityKey\""));
        assert!(json.contains("\"requestProof\""));
        assert!(json.contains("\"expiresAt\""));
        assert!(!json.contains("request_id"));
        assert!(!json.contains("sender_identity_key"));
        assert!(!json.contains("cancelled"));
    }

    #[test]
    fn cancellation_message_serializes_correctly() {
        let msg = PaymentRequestMessage {
            request_id: "req-456".to_string(),
            sender_identity_key: "03def".to_string(),
            request_proof: "cafebabe".to_string(),
            amount: None,
            description: None,
            expires_at: None,
            cancelled: Some(true),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"cancelled\":true"));
        assert!(!json.contains("amount"));
        assert!(!json.contains("description"));
        assert!(!json.contains("expiresAt"));
    }

    #[test]
    fn payment_request_response_round_trip() {
        let resp = PaymentRequestResponse {
            request_id: "req-789".to_string(),
            status: "paid".to_string(),
            note: Some("done".to_string()),
            amount_paid: Some(5000),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: PaymentRequestResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.request_id, "req-789");
        assert_eq!(back.status, "paid");
        assert_eq!(back.amount_paid, Some(5000));
        assert_eq!(back.note, Some("done".to_string()));
    }

    #[test]
    fn declined_response_omits_amount_paid() {
        let resp = PaymentRequestResponse {
            request_id: "req-abc".to_string(),
            status: "declined".to_string(),
            note: None,
            amount_paid: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("amountPaid"));
        assert!(!json.contains("note"));
    }

    #[test]
    fn is_valid_payment_request_validates_correctly() {
        // Valid new request
        let valid = PaymentRequestMessage {
            request_id: "r1".to_string(),
            sender_identity_key: "03abc".to_string(),
            request_proof: "proof".to_string(),
            amount: Some(1000),
            description: Some("test".to_string()),
            expires_at: Some(999999),
            cancelled: None,
        };
        assert!(is_valid_payment_request(&valid));

        // Valid cancellation
        let cancel = PaymentRequestMessage {
            request_id: "r2".to_string(),
            sender_identity_key: "03def".to_string(),
            request_proof: "proof".to_string(),
            amount: None,
            description: None,
            expires_at: None,
            cancelled: Some(true),
        };
        assert!(is_valid_payment_request(&cancel));

        // Invalid: missing request_id
        let bad = PaymentRequestMessage {
            request_id: "".to_string(),
            sender_identity_key: "03abc".to_string(),
            request_proof: "proof".to_string(),
            amount: Some(1000),
            description: Some("test".to_string()),
            expires_at: Some(999999),
            cancelled: None,
        };
        assert!(!is_valid_payment_request(&bad));

        // Invalid: not cancelled but missing amount
        let bad2 = PaymentRequestMessage {
            request_id: "r3".to_string(),
            sender_identity_key: "03abc".to_string(),
            request_proof: "proof".to_string(),
            amount: None,
            description: Some("test".to_string()),
            expires_at: Some(999999),
            cancelled: None,
        };
        assert!(!is_valid_payment_request(&bad2));
    }

    #[test]
    fn payment_request_limits_default() {
        let limits = PaymentRequestLimits::default();
        assert_eq!(limits.min_amount, 1000);
        assert_eq!(limits.max_amount, 10_000_000);
    }
}
