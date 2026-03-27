use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use rust_socketio::asynchronous::{Client as SocketClient, ClientBuilder};
use rust_socketio::{Event, Payload};
use serde_json::json;
use tokio::sync::{oneshot, Mutex};

use bsv::remittance::types::PeerMessage;
use bsv::wallet::interfaces::WalletInterface;

use crate::encryption;
use crate::error::MessageBoxError;
use crate::types::ServerPeerMessage;

/// WebSocket connection to the MessageBox server using Socket.IO v4 protocol.
///
/// Manages authentication handshake, room-based pub/sub, and event dispatch.
/// The wallet and originator are captured at connect time — decryption of
/// incoming messages happens inside the `on_any` callback to preserve ordering.
pub struct MessageBoxWebSocket {
    client: SocketClient,
    /// Map of event key (e.g. "sendMessage-{roomId}") to subscriber callback.
    subscriptions: Arc<Mutex<HashMap<String, Arc<dyn Fn(PeerMessage) + Send + Sync>>>>,
    /// Pending ack channels keyed by "sendMessageAck-{roomId}".
    pending_acks: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
    /// Rooms currently joined (for idempotency on join_room).
    joined_rooms: Arc<Mutex<HashSet<String>>>,
    /// True once the server sends authenticationSuccess.
    connected: Arc<AtomicBool>,
}

impl MessageBoxWebSocket {
    /// Connect to the MessageBox Socket.IO server and authenticate.
    ///
    /// The `on_any` callback is set up at build time and captures the wallet
    /// and originator for inline decryption of incoming messages.
    ///
    /// Returns an error if authentication does not succeed within 5 seconds.
    pub async fn connect<W>(
        url: &str,
        identity_key: &str,
        wallet: W,
        originator: Option<String>,
    ) -> Result<Self, MessageBoxError>
    where
        W: WalletInterface + Clone + Send + Sync + 'static,
    {
        let subscriptions: Arc<Mutex<HashMap<String, Arc<dyn Fn(PeerMessage) + Send + Sync>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_acks: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let joined_rooms: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let connected = Arc::new(AtomicBool::new(false));

        let (auth_tx, auth_rx) = oneshot::channel::<bool>();
        // Wrap in Mutex so we can send exactly once from the closure
        let auth_tx = Arc::new(Mutex::new(Some(auth_tx)));

        // Clone shared state for the closure
        let subs_clone = subscriptions.clone();
        let acks_clone = pending_acks.clone();
        let conn_clone = connected.clone();
        let auth_tx_clone = auth_tx.clone();

        // Wallet and originator captured by value for decryption inside on_any
        let wallet_clone = wallet.clone();
        let originator_clone = originator.clone();

        let client = ClientBuilder::new(url)
            .on_any(move |event, payload, _socket| {
                let subs = subs_clone.clone();
                let acks = acks_clone.clone();
                let conn = conn_clone.clone();
                let auth_tx = auth_tx_clone.clone();
                let wallet = wallet_clone.clone();
                let originator = originator_clone.clone();

                async move {
                    match &event {
                        Event::Custom(name) => {
                            if name == "authenticationSuccess" {
                                conn.store(true, Ordering::SeqCst);
                                let mut guard = auth_tx.lock().await;
                                if let Some(tx) = guard.take() {
                                    let _ = tx.send(true);
                                }
                            } else if name == "authenticationFailed" {
                                let mut guard = auth_tx.lock().await;
                                if let Some(tx) = guard.take() {
                                    let _ = tx.send(false);
                                }
                            } else if name.starts_with("sendMessage-") {
                                // Event key matches subscription map key
                                let event_key = name.clone();

                                // Parse the incoming message from the payload
                                if let Some(server_msg) = extract_server_peer_message(&payload) {
                                    let callback = {
                                        let guard = subs.lock().await;
                                        guard.get(&event_key).cloned()
                                    };

                                    if let Some(cb) = callback {
                                        // room_id is the part after "sendMessage-"
                                        let room_id = name.strip_prefix("sendMessage-")
                                            .unwrap_or("")
                                            .to_string();

                                        // Decrypt inline — preserves message ordering since
                                        // rust_socketio serializes on_any calls
                                        let decrypted_body = encryption::try_decrypt_message(
                                            &wallet,
                                            &server_msg.body,
                                            &server_msg.sender,
                                            originator.as_deref(),
                                        )
                                        .await;

                                        // Extract recipient and message_box from room_id.
                                        // room_id format: "{identityKey}-{messageBox}"
                                        // Identity keys are hex-only (no hyphens), so split at
                                        // last hyphen to separate key from message box name.
                                        // HOWEVER: we can't reliably split at last hyphen since
                                        // identity keys are 66 hex chars (no hyphens).
                                        // Split at first hyphen after the hex prefix instead.
                                        // The room_id when listening is set as "{myKey}-{mb}".
                                        // We parse from room_id since we don't have identity_key in scope here.
                                        let (recipient, message_box) = split_room_id(&room_id);

                                        cb(PeerMessage {
                                            message_id: server_msg.message_id,
                                            sender: server_msg.sender,
                                            recipient,
                                            message_box,
                                            body: decrypted_body,
                                        });
                                    }
                                }
                            } else if name.starts_with("sendMessageAck-") {
                                // Look up and remove the oneshot sender
                                let mut guard = acks.lock().await;
                                if let Some(tx) = guard.remove(name.as_str()) {
                                    // Parse status from payload — "success" = true
                                    let success = parse_ack_status(&payload);
                                    let _ = tx.send(success);
                                }
                            }
                        }
                        Event::Close => {
                            conn.store(false, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                }
                .boxed()
            })
            .reconnect(true)
            .reconnect_on_disconnect(true)
            .connect()
            .await
            .map_err(|e| MessageBoxError::WebSocket(e.to_string()))?;

        // Emit the authentication event
        client
            .emit("authenticated", json!({"identityKey": identity_key}))
            .await
            .map_err(|e| MessageBoxError::WebSocket(e.to_string()))?;

        // Wait up to 5 seconds for authenticationSuccess
        match tokio::time::timeout(Duration::from_secs(5), auth_rx).await {
            Ok(Ok(true)) => {}
            _ => {
                let _ = client.disconnect().await;
                return Err(MessageBoxError::WebSocket(
                    "authentication failed or timed out".to_string(),
                ));
            }
        }

        Ok(Self {
            client,
            subscriptions,
            pending_acks,
            joined_rooms,
            connected,
        })
    }

    /// Return true if the connection is currently authenticated.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Join a Socket.IO room (idempotent — no-op if already joined).
    pub async fn join_room(&self, room_id: &str) -> Result<(), MessageBoxError> {
        {
            let guard = self.joined_rooms.lock().await;
            if guard.contains(room_id) {
                return Ok(());
            }
        }
        self.client
            .emit("joinRoom", json!(room_id))
            .await
            .map_err(|e| MessageBoxError::WebSocket(e.to_string()))?;
        self.joined_rooms.lock().await.insert(room_id.to_string());
        Ok(())
    }

    /// Leave a Socket.IO room and remove its subscription.
    pub async fn leave_room(&self, room_id: &str) -> Result<(), MessageBoxError> {
        self.joined_rooms.lock().await.remove(room_id);
        let event_key = format!("sendMessage-{room_id}");
        self.subscriptions.lock().await.remove(&event_key);
        self.client
            .emit("leaveRoom", json!(room_id))
            .await
            .map_err(|e| MessageBoxError::WebSocket(e.to_string()))?;
        Ok(())
    }

    /// Register a callback for incoming messages on a given event key.
    ///
    /// `event_key` is typically `"sendMessage-{room_id}"`.
    pub async fn subscribe(
        &self,
        event_key: String,
        callback: Arc<dyn Fn(PeerMessage) + Send + Sync>,
    ) {
        self.subscriptions.lock().await.insert(event_key, callback);
    }

    /// Emit a sendMessage event and register an ack channel.
    ///
    /// The ack channel will be triggered when the server emits
    /// `sendMessageAck-{ack_key}` with status "success" or an error.
    pub async fn emit_send_message(
        &self,
        payload: serde_json::Value,
        ack_key: String,
        ack_tx: oneshot::Sender<bool>,
    ) -> Result<(), MessageBoxError> {
        self.pending_acks.lock().await.insert(ack_key, ack_tx);
        self.client
            .emit("sendMessage", payload)
            .await
            .map_err(|e| {
                // NOTE: we don't remove ack_tx on emit error — caller handles cleanup
                MessageBoxError::WebSocket(e.to_string())
            })?;
        Ok(())
    }

    /// Remove a pending ack entry (called on timeout to prevent leaking channels).
    pub async fn remove_pending_ack(&self, key: &str) {
        self.pending_acks.lock().await.remove(key);
    }

    /// Disconnect from the server and clear all state.
    ///
    /// Sends false to all remaining pending ack channels before dropping them.
    pub async fn disconnect(&self) -> Result<(), MessageBoxError> {
        self.connected.store(false, Ordering::SeqCst);
        // Drain pending acks — send false to signal failure
        {
            let mut guard = self.pending_acks.lock().await;
            for (_, tx) in guard.drain() {
                let _ = tx.send(false);
            }
        }
        self.subscriptions.lock().await.clear();
        self.joined_rooms.lock().await.clear();
        self.client
            .disconnect()
            .await
            .map_err(|e| MessageBoxError::WebSocket(e.to_string()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Parse a `ServerPeerMessage` from the first element of a Payload::Text.
fn extract_server_peer_message(payload: &Payload) -> Option<ServerPeerMessage> {
    match payload {
        Payload::Text(values) => {
            let first = values.first()?;
            serde_json::from_value(first.clone()).ok()
        }
        _ => None,
    }
}

/// Parse the ack status from a Socket.IO payload.
///
/// Returns true if the status is "success", false otherwise.
fn parse_ack_status(payload: &Payload) -> bool {
    match payload {
        Payload::Text(values) => {
            if let Some(v) = values.first() {
                return v.get("status").and_then(|s| s.as_str()) == Some("success");
            }
            false
        }
        #[allow(deprecated)]
        Payload::String(s) => s.contains("success"),
        _ => false,
    }
}

/// Split a room ID into (recipient/owner_identity_key, message_box_name).
///
/// Room ID format when listening: `"{identityKey}-{messageBox}"`
/// Identity keys are 66-char hex strings (compressed public key, no hyphens).
/// So we split at the 67th character (index 66) which must be `-`.
///
/// If the format doesn't match (e.g., the room ID is shorter), falls back to
/// splitting at the first `-`.
fn split_room_id(room_id: &str) -> (String, String) {
    // Compressed public key hex is always exactly 66 characters (33 bytes × 2)
    const HEX_KEY_LEN: usize = 66;
    if room_id.len() > HEX_KEY_LEN && room_id.as_bytes()[HEX_KEY_LEN] == b'-' {
        let key = room_id[..HEX_KEY_LEN].to_string();
        let mb = room_id[HEX_KEY_LEN + 1..].to_string();
        return (key, mb);
    }
    // Fallback: split at first hyphen
    if let Some(pos) = room_id.find('-') {
        (room_id[..pos].to_string(), room_id[pos + 1..].to_string())
    } else {
        (room_id.to_string(), String::new())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{WsSendMessageData, WsSendMessagePayload};
    use std::collections::HashSet;

    /// Room ID format: listen room is `{identity_key}-{message_box}`, send room is `{recipient}-{message_box}`.
    ///
    /// These are asymmetric by design: you listen on YOUR identity key's room,
    /// but send to the RECIPIENT'S room.
    #[test]
    fn room_id_format() {
        let my_key = "03abc";
        let recipient = "03def";
        let message_box = "payment_inbox";

        let listen_room = format!("{my_key}-{message_box}");
        let send_room = format!("{recipient}-{message_box}");

        assert_eq!(listen_room, "03abc-payment_inbox");
        assert_eq!(send_room, "03def-payment_inbox");
        // They must be different for different parties
        assert_ne!(listen_room, send_room);
    }

    /// WsSendMessageData must serialize with camelCase field names.
    #[test]
    fn send_message_data_serializes_camel_case() {
        let data = WsSendMessageData {
            room_id: "03abc-payment_inbox".to_string(),
            message: WsSendMessagePayload {
                message_id: "deadbeef".to_string(),
                recipient: "03abc".to_string(),
                body: "encrypted".to_string(),
            },
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"roomId\""), "roomId field name");
        assert!(json.contains("\"messageId\""), "messageId field name");
        assert!(!json.contains("room_id"), "no snake_case leakage");
        assert!(!json.contains("message_id"), "no snake_case leakage");
    }

    /// WsSendMessagePayload must round-trip through JSON.
    #[test]
    fn send_message_payload_round_trip() {
        let payload = WsSendMessagePayload {
            message_id: "abc123".to_string(),
            recipient: "03def456".to_string(),
            body: r#"{"encryptedMessage":"abc=="}"#.to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: WsSendMessagePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.message_id, "abc123");
        assert_eq!(back.recipient, "03def456");
        assert_eq!(back.body, r#"{"encryptedMessage":"abc=="}"#);
    }

    /// The authenticated event must serialize to `{"identityKey": "03abc"}`.
    #[test]
    fn authenticated_event_format() {
        let identity_key = "03abcdef1234567890";
        let v = json!({"identityKey": identity_key});
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, r#"{"identityKey":"03abcdef1234567890"}"#);
    }

    /// HashSet insert returns false on second insert — confirms idempotency logic.
    #[test]
    fn join_room_idempotency_uses_hashset() {
        let mut rooms: HashSet<String> = HashSet::new();
        let room_id = "03abc-payment_inbox";
        let first = rooms.insert(room_id.to_string());
        let second = rooms.insert(room_id.to_string());
        assert!(first, "first insert returns true");
        assert!(!second, "second insert returns false (already present)");
        assert_eq!(rooms.len(), 1, "only one entry in set");
    }

    /// split_room_id correctly extracts key and message box for standard 66-char keys.
    #[test]
    fn split_room_id_hex_key() {
        // 66 hex chars = 33 bytes compressed pubkey
        let key = "a".repeat(66);
        let mb = "my_inbox";
        let room_id = format!("{key}-{mb}");
        let (got_key, got_mb) = split_room_id(&room_id);
        assert_eq!(got_key, key);
        assert_eq!(got_mb, mb);
    }

    /// split_room_id handles message box names with hyphens.
    #[test]
    fn split_room_id_mb_with_hyphen() {
        let key = "b".repeat(66);
        let mb = "payment-inbox-v2";
        let room_id = format!("{key}-{mb}");
        let (got_key, got_mb) = split_room_id(&room_id);
        assert_eq!(got_key, key);
        assert_eq!(got_mb, mb);
    }
}
