use serde::{Deserialize, Serialize};

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
