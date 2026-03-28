use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Phase 6 — parity types: sendList, multi-quote, payment metadata
// ---------------------------------------------------------------------------

/// Parameters for sending a message to multiple recipients in one call.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SendListParams {
    pub recipients: Vec<String>,
    pub message_box: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_encryption: Option<bool>,
}

/// A single successfully-delivered recipient entry in a sendList result.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SentRecipient {
    pub recipient: String,
    pub message_id: String,
}

/// A failed recipient entry in a sendList result.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FailedRecipient {
    pub recipient: String,
    pub error: String,
}

/// Aggregate fee totals returned in a sendList or multi-quote response.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SendListTotals {
    pub delivery_fees: i64,
    pub recipient_fees: i64,
    pub total_for_payable_recipients: i64,
}

/// Result of a sendList operation.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SendListResult {
    pub status: String,
    pub description: String,
    pub sent: Vec<SentRecipient>,
    pub blocked: Vec<String>,
    pub failed: Vec<FailedRecipient>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totals: Option<SendListTotals>,
}

/// Quote for a single recipient in a multi-recipient quote request.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RecipientQuote {
    pub recipient: String,
    pub message_box: String,
    pub delivery_fee: i64,
    pub recipient_fee: i64,
    pub status: String,
}

/// Aggregated delivery quotes for multiple recipients.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MessageBoxMultiQuote {
    pub quotes_by_recipient: Vec<RecipientQuote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totals: Option<SendListTotals>,
    pub blocked_recipients: Vec<String>,
    pub delivery_agent_identity_key_by_host: HashMap<String, String>,
}

/// Remittance output describing how a payment was routed to a recipient.
///
/// Carries the derivation keys needed to prove the counterparty can redeem.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRemittanceInfo {
    pub derivation_prefix: String,
    pub derivation_suffix: String,
    pub sender_identity_key: String,
}

/// Basket insertion remittance — used when the output targets a basket.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InsertionRemittanceInfo {
    pub basket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_instructions: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// A single output within a Payment struct.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PaymentOutput {
    pub output_index: u32,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_remittance: Option<PaymentRemittanceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insertion_remittance: Option<InsertionRemittanceInfo>,
}

/// A payment token for attaching BSV remittance to a sendList call.
///
/// Distinct from `PaymentToken` (PeerPay p2p) — this type represents an
/// on-chain payment submitted alongside a multi-recipient send.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Payment {
    pub tx: Vec<u8>,
    pub outputs: Vec<PaymentOutput>,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seek_permission: Option<bool>,
}

// ---------------------------------------------------------------------------
// Phase 5 — overlay advertisement and device registration types
// ---------------------------------------------------------------------------

/// An advertisement token recovered from an overlay lookup.
///
/// Represents a single UTXO that encodes a MessageBox host advertisement via
/// PushDrop: fields[0] = identity key bytes, fields[1] = host URL bytes.
#[derive(Clone, Debug)]
pub struct AdvertisementToken {
    /// The host URL encoded in the advertisement.
    pub host: String,
    /// Transaction ID of the advertising UTXO.
    pub txid: String,
    /// Output index within the advertising transaction.
    pub output_index: u32,
    /// Hex-encoded locking script of the advertising output.
    pub locking_script: String,
    /// Raw BEEF bytes for the advertising transaction (needed for revocation).
    pub beef: Vec<u8>,
}

/// Request body for registering an FCM device token.
///
/// Serializes to camelCase JSON for POST to `{host}/registerDevice`.
/// Optional fields are omitted when None per TS wire format.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    pub fcm_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

/// A registered device record as returned by the server's `/devices` endpoint.
///
/// All fields are `Option` because the server may omit any of them.
/// Includes ALL known server fields to prevent deserialization failures
/// against go-messagebox-server.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredDevice {
    pub id: Option<i64>,
    pub device_id: Option<String>,
    pub platform: Option<String>,
    pub fcm_token: String,
    pub active: Option<bool>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub last_used: Option<String>,
}

/// Response from the `/registerDevice` endpoint.
///
/// TS returns `{ status, message, deviceId }`.
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceResponse {
    pub status: String,
    pub message: Option<String>,
    pub device_id: Option<i64>,
}

/// Response from the `/devices` (list registered devices) endpoint.
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListDevicesResponse {
    pub status: String,
    pub devices: Vec<RegisteredDevice>,
}

// ---------------------------------------------------------------------------
// Phase 2 — permission / quote types
// ---------------------------------------------------------------------------

/// Parameters for setting a permission rule on a message box.
///
/// Serializes to camelCase for POST body to `/permissions/set`.
/// `sender` is omitted when `None` — the server treats absence as "any sender".
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SetPermissionParams {
    pub message_box: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// -1 = block, 0 = always allow, >0 = satoshi fee required
    pub recipient_fee: i64,
}

/// A permission record as returned by `/permissions/get` (camelCase) or
/// `/permissions/list` (snake_case).
///
/// Uses per-field `#[serde(alias)]` instead of `rename_all` so the same
/// struct deserializes from BOTH server endpoint formats.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MessageBoxPermission {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(alias = "messageBox")]
    pub message_box: String,
    #[serde(alias = "recipientFee")]
    pub recipient_fee: i64,
    #[serde(alias = "createdAt")]
    pub created_at: String,
    #[serde(alias = "updatedAt")]
    pub updated_at: String,
}

impl MessageBoxPermission {
    /// Compute the permission status from the `recipient_fee` value.
    ///
    /// Mirrors the TypeScript SDK's `getStatusFromFee()`:
    /// -1 → "blocked", 0 → "always_allow", >0 → "payment_required"
    pub fn status(&self) -> &str {
        match self.recipient_fee {
            f if f < 0 => "blocked",
            0 => "always_allow",
            _ => "payment_required",
        }
    }
}

/// Quote for delivering a message to a recipient.
///
/// NOT deserialized directly from JSON — constructed manually after parsing
/// the wrapped `{"quote": {"recipientFee": N, "deliveryFee": N}}` response
/// body and extracting the `x-bsv-auth-identity-key` response header.
#[derive(Clone, Debug)]
pub struct MessageBoxQuote {
    pub delivery_fee: i64,
    pub recipient_fee: i64,
    /// Populated from the `x-bsv-auth-identity-key` response header, not the body.
    pub delivery_agent_identity_key: String,
}

/// Parameters for sending a message to a recipient's inbox.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageParams {
    pub recipient: String,
    pub message_box: String,
    pub body: String,
    pub message_id: String,
}

/// Payment structure included in a sendMessage request when check_permissions requires a fee.
///
/// Serializes the transaction bytes and outputs to wire format matching TS Payment type.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MessagePayment {
    /// Raw transaction bytes.
    pub tx: Vec<u8>,
    /// Outputs from the payment transaction.
    pub outputs: Vec<MessagePaymentOutput>,
}

/// One output entry in a MessagePayment.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MessagePaymentOutput {
    pub output_index: u32,
    pub derivation_prefix: Vec<u8>,
    pub derivation_suffix: Vec<u8>,
    pub sender_identity_key: String,
}

/// Wire format wrapper — serializes as `{"message": <params>}` for the `/sendMessage` endpoint.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SendMessageRequest {
    pub message: SendMessageParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<MessagePayment>,
}


/// Parameters for listing messages from a specific inbox.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListMessagesParams {
    pub message_box: String,
}

/// Parameters for acknowledging (marking as read) a set of messages.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AcknowledgeMessageParams {
    pub message_ids: Vec<String>,
}

/// A message as returned by the server's list endpoint.
///
/// Uses explicit `serde(rename)` on camelCase fields because the server mixes
/// naming conventions: `messageId`, `sender` are camelCase but `created_at` /
/// `updated_at` are snake_case. Do NOT use `deny_unknown_fields` — the server
/// may add new fields at any time.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerPeerMessage {
    #[serde(rename = "messageId")]
    pub message_id: String,
    pub body: String,
    pub sender: String,
    #[serde(alias = "createdAt")]
    pub created_at: String,
    #[serde(alias = "updatedAt")]
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<bool>,
}

/// Response from the `/listMessages` endpoint.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListMessagesResponse {
    pub status: String,
    pub messages: Vec<ServerPeerMessage>,
}

/// Response from the `/sendMessage` endpoint.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageResponse {
    pub status: String,
    /// The server-assigned message ID (may be absent on some server versions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Phase 4 — WebSocket live messaging wire types
// ---------------------------------------------------------------------------

/// Payload for the sendMessage WebSocket event.
///
/// Serialized as JSON and passed to socket.emit("sendMessage", ...).
/// Wire format: {"roomId": "recipient-inbox", "message": {"messageId": "...", ...}}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WsSendMessageData {
    pub room_id: String,
    pub message: WsSendMessagePayload,
}

/// The message object inside a sendMessage event.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WsSendMessagePayload {
    pub message_id: String,
    pub recipient: String,
    pub body: String,
}

// ---------------------------------------------------------------------------
// Phase 3 — PeerPay payment types
// ---------------------------------------------------------------------------

/// Custom instructions embedded in a PeerPay transaction output.
///
/// Serializes to camelCase JSON for the TS wire format.
/// `payee` is omitted when None (TS omits it when there's no explicit payee override).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PaymentCustomInstructions {
    pub derivation_prefix: String,
    pub derivation_suffix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payee: Option<String>,
}

/// A PeerPay payment token sent to a recipient's payment_inbox.
///
/// Serializes to camelCase JSON matching the TS PaymentToken wire format:
/// - `transaction` is a number array (Vec<u8>) on the wire
/// - `outputIndex` is omitted at creation time (None); defaulted to 0 at accept time
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PaymentToken {
    pub custom_instructions: PaymentCustomInstructions,
    /// Raw transaction bytes.
    pub transaction: Vec<u8>,
    pub amount: u64,
    /// Only present after being set by the sender; defaults to 0 at accept time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_index: Option<u32>,
}

/// A parsed incoming payment from the payment_inbox.
///
/// Holds the decoded token plus routing metadata needed for accept/reject.
/// NOT serialized — constructed internally from a ServerPeerMessage.
#[derive(Clone, Debug)]
pub struct IncomingPayment {
    pub token: PaymentToken,
    pub sender: String,
    pub message_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Phase 2 — permission type tests
    // -----------------------------------------------------------------------

    #[test]
    fn set_permission_params_serializes_camel_case() {
        let p = SetPermissionParams {
            message_box: "payment_inbox".to_string(),
            sender: None,
            recipient_fee: 100,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"messageBox\""), "messageBox field name");
        assert!(json.contains("\"recipientFee\""), "recipientFee field name");
        assert!(!json.contains("message_box"), "no snake_case leakage");
        assert!(!json.contains("recipient_fee"), "no snake_case leakage");
        assert!(!json.contains("sender"), "sender absent when None");
    }

    #[test]
    fn set_permission_params_includes_sender_when_some() {
        let p = SetPermissionParams {
            message_box: "inbox".to_string(),
            sender: Some("03abc".to_string()),
            recipient_fee: 0,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"sender\""), "sender present when Some");
        assert!(json.contains("\"03abc\""), "sender value correct");
    }

    #[test]
    fn message_box_permission_deserializes_camel_case() {
        let raw = r#"{
            "messageBox": "payment_inbox",
            "recipientFee": 50,
            "createdAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-02T00:00:00Z"
        }"#;
        let perm: MessageBoxPermission = serde_json::from_str(raw).unwrap();
        assert_eq!(perm.message_box, "payment_inbox");
        assert_eq!(perm.recipient_fee, 50);
        assert_eq!(perm.created_at, "2024-01-01T00:00:00Z");
        assert_eq!(perm.updated_at, "2024-01-02T00:00:00Z");
    }

    #[test]
    fn message_box_permission_deserializes_snake_case() {
        // The /permissions/list endpoint returns snake_case field names.
        let raw = r#"{
            "message_box": "payment_inbox",
            "recipient_fee": 75,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-02T00:00:00Z"
        }"#;
        let perm: MessageBoxPermission = serde_json::from_str(raw).unwrap();
        assert_eq!(perm.message_box, "payment_inbox");
        assert_eq!(perm.recipient_fee, 75);
        assert_eq!(perm.created_at, "2024-01-01T00:00:00Z");
        assert_eq!(perm.updated_at, "2024-01-02T00:00:00Z");
    }

    #[test]
    fn message_box_permission_status_computes_correctly() {
        let make = |fee: i64| MessageBoxPermission {
            sender: None,
            message_box: "inbox".to_string(),
            recipient_fee: fee,
            created_at: "2024-01-01".to_string(),
            updated_at: "2024-01-01".to_string(),
        };
        assert_eq!(make(-1).status(), "blocked");
        assert_eq!(make(0).status(), "always_allow");
        assert_eq!(make(100).status(), "payment_required");
        assert_eq!(make(1).status(), "payment_required");
    }

    #[test]
    fn message_box_quote_can_be_constructed() {
        // MessageBoxQuote is manually constructed — not deserialized from JSON.
        let quote = MessageBoxQuote {
            delivery_fee: 10,
            recipient_fee: 50,
            delivery_agent_identity_key: "03deadbeef".to_string(),
        };
        assert_eq!(quote.delivery_fee, 10);
        assert_eq!(quote.recipient_fee, 50);
        assert_eq!(quote.delivery_agent_identity_key, "03deadbeef");
    }

    // -----------------------------------------------------------------------
    // Phase 3 — payment type tests
    // -----------------------------------------------------------------------

    #[test]
    fn payment_custom_instructions_round_trip() {
        let ci = PaymentCustomInstructions {
            derivation_prefix: "pfx123".to_string(),
            derivation_suffix: "sfx456".to_string(),
            payee: Some("03abc".to_string()),
        };
        let json = serde_json::to_string(&ci).unwrap();
        let back: PaymentCustomInstructions = serde_json::from_str(&json).unwrap();
        assert_eq!(back.derivation_prefix, "pfx123");
        assert_eq!(back.derivation_suffix, "sfx456");
        assert_eq!(back.payee, Some("03abc".to_string()));
    }

    #[test]
    fn payment_token_serializes_camel_case() {
        let token = PaymentToken {
            custom_instructions: PaymentCustomInstructions {
                derivation_prefix: "pfx".to_string(),
                derivation_suffix: "sfx".to_string(),
                payee: Some("03recipient".to_string()),
            },
            transaction: vec![1, 2, 3],
            amount: 1000,
            output_index: Some(0),
        };
        let json = serde_json::to_string(&token).unwrap();
        // Verify camelCase field names
        assert!(json.contains("\"customInstructions\""), "customInstructions field name");
        assert!(json.contains("\"derivationPrefix\""), "derivationPrefix field name");
        assert!(json.contains("\"derivationSuffix\""), "derivationSuffix field name");
        assert!(json.contains("\"payee\""), "payee present when Some");
        assert!(json.contains("\"outputIndex\""), "outputIndex present when Some");
        // No snake_case leakage
        assert!(!json.contains("custom_instructions"), "no snake_case leakage");
        assert!(!json.contains("derivation_prefix"), "no snake_case leakage");
        assert!(!json.contains("output_index"), "no snake_case leakage");
    }

    #[test]
    fn payment_token_no_output_index_by_default() {
        let token = PaymentToken {
            custom_instructions: PaymentCustomInstructions {
                derivation_prefix: "pfx".to_string(),
                derivation_suffix: "sfx".to_string(),
                payee: None,
            },
            transaction: vec![0xab, 0xcd],
            amount: 500,
            output_index: None,
        };
        let json = serde_json::to_string(&token).unwrap();
        // outputIndex must be absent when None
        assert!(!json.contains("outputIndex"), "outputIndex absent when None");
        // payee must be absent when None
        assert!(!json.contains("payee"), "payee absent when None");
    }

    #[test]
    fn incoming_payment_can_be_constructed() {
        let token = PaymentToken {
            custom_instructions: PaymentCustomInstructions {
                derivation_prefix: "p".to_string(),
                derivation_suffix: "s".to_string(),
                payee: None,
            },
            transaction: vec![0x01],
            amount: 2000,
            output_index: None,
        };
        let incoming = IncomingPayment {
            token: token.clone(),
            sender: "03sender".to_string(),
            message_id: "msg001".to_string(),
        };
        assert_eq!(incoming.sender, "03sender");
        assert_eq!(incoming.message_id, "msg001");
        assert_eq!(incoming.token.amount, 2000);
    }

    // -----------------------------------------------------------------------
    // Phase 5 — overlay/device registration type tests
    // -----------------------------------------------------------------------

    #[test]
    fn register_device_request_camel_case() {
        let req = RegisterDeviceRequest {
            fcm_token: "tok123".to_string(),
            device_id: Some("dev-abc".to_string()),
            platform: Some("android".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"fcmToken\""), "fcmToken field name");
        assert!(json.contains("\"deviceId\""), "deviceId field name");
        assert!(json.contains("\"platform\""), "platform field name");
        assert!(!json.contains("fcm_token"), "no snake_case leakage");
        assert!(!json.contains("device_id"), "no snake_case leakage");
    }

    #[test]
    fn register_device_request_omits_optional_fields_when_none() {
        let req = RegisterDeviceRequest {
            fcm_token: "tok456".to_string(),
            device_id: None,
            platform: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"fcmToken\""), "fcmToken present");
        assert!(!json.contains("deviceId"), "deviceId absent when None");
        assert!(!json.contains("platform"), "platform absent when None");
    }

    #[test]
    fn registered_device_deserializes_camel_case() {
        let raw = r#"{
            "id": 42,
            "deviceId": "dev-123",
            "platform": "ios",
            "fcmToken": "fcm-abc",
            "active": true,
            "createdAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-02T00:00:00Z",
            "lastUsed": "2024-01-03T00:00:00Z"
        }"#;
        let dev: RegisteredDevice = serde_json::from_str(raw).unwrap();
        assert_eq!(dev.id, Some(42));
        assert_eq!(dev.device_id.as_deref(), Some("dev-123"));
        assert_eq!(dev.platform.as_deref(), Some("ios"));
        assert_eq!(dev.fcm_token, "fcm-abc");
        assert_eq!(dev.active, Some(true));
        assert_eq!(dev.created_at.as_deref(), Some("2024-01-01T00:00:00Z"));
        assert_eq!(dev.last_used.as_deref(), Some("2024-01-03T00:00:00Z"));
    }

    // -----------------------------------------------------------------------
    // Phase 1 — existing tests
    // -----------------------------------------------------------------------

    #[test]
    fn send_message_params_serializes_camel_case() {
        let p = SendMessageParams {
            recipient: "03abc".to_string(),
            message_box: "inbox".to_string(),
            body: "hello".to_string(),
            message_id: "deadbeef".to_string(),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"messageBox\""), "messageBox field name");
        assert!(json.contains("\"messageId\""), "messageId field name");
        assert!(!json.contains("message_box"), "no snake_case leakage");
        assert!(!json.contains("message_id"), "no snake_case leakage");
    }

    #[test]
    fn acknowledge_params_serializes_camel_case() {
        let p = AcknowledgeMessageParams {
            message_ids: vec!["id1".to_string(), "id2".to_string()],
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"messageIds\""), "messageIds field name");
        assert!(!json.contains("message_ids"), "no snake_case leakage");
    }

    #[test]
    fn server_peer_message_tolerates_unknown_fields() {
        // The server may add fields not in our struct — must NOT reject them.
        let raw = r#"{
            "messageId": "abc123",
            "body": "hello",
            "sender": "03xyz",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "acknowledged": false,
            "unknownField": "should be ignored",
            "anotherExtra": 42
        }"#;
        let msg: ServerPeerMessage = serde_json::from_str(raw).unwrap();
        assert_eq!(msg.message_id, "abc123");
        assert_eq!(msg.body, "hello");
        assert_eq!(msg.acknowledged, Some(false));
    }
}
