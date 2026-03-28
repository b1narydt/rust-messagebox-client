use std::sync::Arc;

use async_trait::async_trait;
use rust_socketio::asynchronous::Client;
use rust_socketio::Payload;
use tokio::sync::{mpsc, Mutex};

use bsv::auth::error::AuthError;
use bsv::auth::transports::Transport;
use bsv::auth::types::AuthMessage;

// ---------------------------------------------------------------------------
// Event encode/decode helpers (TS parity: AuthSocketClient.encodeEventPayload)
// ---------------------------------------------------------------------------

/// Encode an application event as a JSON bytes payload for BRC-103 general messages.
///
/// Produces `{"eventName": event_name, "data": data}` serialized to UTF-8 bytes.
/// Matches TS `AuthSocketClient.encodeEventPayload`.
// Used in Plan 02 (websocket.rs Peer integration)
#[allow(dead_code)]
pub(crate) fn encode_ws_event(event_name: &str, data: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "eventName": event_name,
        "data": data
    }))
    .unwrap_or_default()
}

/// Decode an application event from a JSON bytes payload.
///
/// Returns `Some((event_name, data))` on success.
/// Returns `None` on invalid UTF-8, invalid JSON, or missing `eventName` field.
/// Matches TS `AuthSocketClient.decodeEventPayload`.
// Used in Plan 02 (websocket.rs Peer integration)
#[allow(dead_code)]
pub(crate) fn decode_ws_event(payload: &[u8]) -> Option<(String, serde_json::Value)> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let event_name = v.get("eventName")?.as_str()?.to_string();
    let data = v.get("data").cloned().unwrap_or(serde_json::Value::Null);
    Some((event_name, data))
}

// ---------------------------------------------------------------------------
// Parse helper
// ---------------------------------------------------------------------------

/// Extract an `AuthMessage` from a rust_socketio `Payload`.
///
/// Only handles `Payload::Text` with a valid `AuthMessage` JSON as the first element.
/// Returns `None` for `Payload::Binary` or if JSON parsing fails.
// Used in Plan 02 (on("authMessage") callback in websocket.rs)
#[allow(dead_code)]
pub(crate) fn parse_auth_message_from_payload(payload: &Payload) -> Option<AuthMessage> {
    match payload {
        Payload::Text(values) => {
            let first = values.first()?;
            serde_json::from_value::<AuthMessage>(first.clone()).ok()
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// SocketIOTransport
// ---------------------------------------------------------------------------

/// Socket.IO transport adapter implementing the SDK's `Transport` trait.
///
/// Bridges `authMessage` Socket.IO events to/from `mpsc` channels so the SDK's
/// `Peer` can use a Socket.IO connection for BRC-103 mutual authentication.
///
/// **Construction pattern:** `SocketIOTransport` receives an already-built
/// `Client` (from `ClientBuilder::connect().await`) and the rx end of a channel
/// whose tx was captured inside the `on("authMessage", ...)` callback during
/// `ClientBuilder` setup (in `websocket.rs`). This avoids `SocketIOTransport`
/// needing to own the `ClientBuilder` or duplicate the `on_any` application
/// event handler.
///
/// **Client sharing:** `rust_socketio::Client` is `Clone` — clones share the
/// same underlying connection. `MessageBoxWebSocket` owns the primary `Client`;
/// `SocketIOTransport` holds a clone so both can emit on the same socket.
///
/// **subscribe() is take-once:** The `incoming_rx` is wrapped in
/// `Arc<Mutex<Option>>`. `subscribe()` calls `blocking_lock().take()` — it
/// panics on second call, matching the SDK contract.
pub struct SocketIOTransport {
    client: Client,
    incoming_rx: Arc<Mutex<Option<mpsc::Receiver<AuthMessage>>>>,
}

impl SocketIOTransport {
    /// Create a new `SocketIOTransport` from an already-connected client.
    ///
    /// `incoming_rx` is the receive end of the channel that the `on("authMessage", ...)`
    /// closure pushes messages to. The caller must set up the corresponding
    /// `mpsc::Sender` in the `ClientBuilder` before calling this.
    pub fn new(client: Client, incoming_rx: mpsc::Receiver<AuthMessage>) -> Self {
        Self {
            client,
            incoming_rx: Arc::new(Mutex::new(Some(incoming_rx))),
        }
    }
}

#[async_trait]
impl Transport for SocketIOTransport {
    /// Serialize `message` as JSON and emit it on the `authMessage` Socket.IO event.
    async fn send(&self, message: AuthMessage) -> Result<(), AuthError> {
        let json = serde_json::to_value(&message)
            .map_err(|e| AuthError::SerializationError(e.to_string()))?;
        self.client
            .emit("authMessage", json)
            .await
            .map_err(|e| AuthError::TransportError(e.to_string()))
    }

    /// Return the `mpsc::Receiver` for incoming `AuthMessage` events.
    ///
    /// Uses `try_lock` because the SDK trait method is `fn subscribe(&self)`
    /// (non-async) and `blocking_lock` panics inside a tokio runtime.
    /// Panics on second call — create a fresh `SocketIOTransport` on reconnect.
    fn subscribe(&self) -> mpsc::Receiver<AuthMessage> {
        self.incoming_rx
            .try_lock()
            .expect("subscribe() mutex should not be contended")
            .take()
            .expect("subscribe() can only be called once per SocketIOTransport")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::auth::types::MessageType;

    // ------------------------------------------------------------------
    // encode_ws_event / decode_ws_event round-trip
    // ------------------------------------------------------------------

    #[test]
    fn encode_decode_round_trip() {
        let data = serde_json::json!({"identityKey": "03abc"});
        let encoded = encode_ws_event("authenticated", data.clone());
        let (name, decoded_data) = decode_ws_event(&encoded).expect("round-trip should succeed");
        assert_eq!(name, "authenticated");
        assert_eq!(decoded_data, data);
    }

    #[test]
    fn encode_produces_correct_json_structure() {
        let encoded = encode_ws_event("myEvent", serde_json::json!(42));
        let v: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(v["eventName"], "myEvent");
        assert_eq!(v["data"], 42);
    }

    #[test]
    fn decode_invalid_utf8_returns_none() {
        // Bytes that are not valid UTF-8
        let bad = vec![0xFF, 0xFE, 0x00];
        assert!(decode_ws_event(&bad).is_none());
    }

    #[test]
    fn decode_valid_json_missing_event_name_returns_none() {
        let json = br#"{"data": {"foo": "bar"}}"#;
        assert!(decode_ws_event(json).is_none());
    }

    #[test]
    fn decode_empty_bytes_returns_none() {
        assert!(decode_ws_event(&[]).is_none());
    }

    #[test]
    fn encode_decode_preserves_nested_data() {
        let data = serde_json::json!({"nested": {"a": 1, "b": [1, 2, 3]}});
        let encoded = encode_ws_event("complexEvent", data.clone());
        let (name, decoded) = decode_ws_event(&encoded).unwrap();
        assert_eq!(name, "complexEvent");
        assert_eq!(decoded, data);
    }

    // ------------------------------------------------------------------
    // parse_auth_message_from_payload
    // ------------------------------------------------------------------

    fn make_valid_auth_message_value() -> serde_json::Value {
        serde_json::json!({
            "version": "0.1",
            "messageType": "initialRequest",
            "identityKey": "03abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
        })
    }

    #[test]
    fn parse_auth_message_from_text_payload_valid() {
        let payload = Payload::Text(vec![make_valid_auth_message_value()]);
        let result = parse_auth_message_from_payload(&payload);
        assert!(result.is_some(), "should parse valid AuthMessage from Text payload");
        let msg = result.unwrap();
        assert_eq!(msg.message_type, MessageType::InitialRequest);
        assert_eq!(
            msg.identity_key,
            "03abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
        );
    }

    #[test]
    fn parse_auth_message_from_text_payload_non_auth_json_returns_none() {
        // JSON object that doesn't match AuthMessage schema
        let payload = Payload::Text(vec![serde_json::json!({"foo": "bar"})]);
        let result = parse_auth_message_from_payload(&payload);
        assert!(result.is_none(), "non-auth JSON should return None");
    }

    #[test]
    fn parse_auth_message_from_empty_text_returns_none() {
        let payload = Payload::Text(vec![]);
        let result = parse_auth_message_from_payload(&payload);
        assert!(result.is_none(), "empty Text payload should return None");
    }

    #[test]
    fn parse_auth_message_from_binary_returns_none() {
        // Payload::from(Vec<u8>) produces Payload::Binary
        let payload = Payload::from(b"some bytes".to_vec());
        let result = parse_auth_message_from_payload(&payload);
        assert!(result.is_none(), "Binary payload should return None");
    }

    // ------------------------------------------------------------------
    // SocketIOTransport::subscribe — take-once behaviour
    // ------------------------------------------------------------------

    /// Verify that subscribe() returns a receiver and a second call panics.
    ///
    /// We can't easily build a real Client without a live server, so we test
    /// the subscribe/panic behaviour by inspecting the Arc<Mutex<Option>> directly.
    /// The Transport send path requires a live socket; that is verified via
    /// compile + type checks only.
    #[test]
    #[should_panic(expected = "subscribe() can only be called once per SocketIOTransport")]
    fn subscribe_panics_on_second_call() {
        // Construct only the `incoming_rx` side of the transport for isolation.
        let (_tx, rx) = mpsc::channel::<AuthMessage>(1);
        let incoming_rx = Arc::new(Mutex::new(Some(rx)));

        // First take — succeeds
        {
            let _receiver = incoming_rx.blocking_lock().take().expect("subscribe() can only be called once per SocketIOTransport");
        }
        // Second take — panics
        let _receiver = incoming_rx.blocking_lock().take().expect("subscribe() can only be called once per SocketIOTransport");
    }

    #[test]
    fn subscribe_first_call_returns_receiver() {
        let (_tx, rx) = mpsc::channel::<AuthMessage>(1);
        let incoming_rx = Arc::new(Mutex::new(Some(rx)));

        // First take returns Some
        let result = incoming_rx.blocking_lock().take();
        assert!(result.is_some(), "first subscribe should return a receiver");

        // Second take returns None (not panic — manual take test, not via struct method)
        let result2 = incoming_rx.blocking_lock().take();
        assert!(result2.is_none(), "second take should return None");
    }
}
