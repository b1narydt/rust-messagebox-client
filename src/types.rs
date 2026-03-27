use serde::{Deserialize, Serialize};

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

/// Wire format wrapper — serializes as `{"message": <params>}` for the `/sendMessage` endpoint.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SendMessageRequest {
    pub message: SendMessageParams,
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
    pub created_at: String,
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
