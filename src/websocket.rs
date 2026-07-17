//! MessageBox WebSocket layer over the shared [`authsocket`] client.
//!
//! The generic BRC-103/Socket.IO transport (connect + namespace-ack gate,
//! client-initiated handshake, `authenticationSuccess` oneshot, receive loop,
//! keepalive + read-deadline watchdog, signed emit/join_room/leave_room) lives
//! in the `authsocket` crate's `client` feature — it was extracted from this
//! file. What remains here is the MessageBox **application** protocol:
//!
//! - `sendMessage-{roomId}` room deliveries: decode [`ServerPeerMessage`],
//!   decrypt (BRC-78) with authenticated-decrypt provenance, and dispatch to
//!   the room subscription callback.
//! - `sendMessageAck-{roomId}` FIFO ack correlation: the server's ack is
//!   *room*-scoped (no messageId), so N concurrent sends to one room resolve
//!   oldest-first against a per-key `VecDeque` of waiters.
//! - the public [`MessageBoxWebSocket`] API surface, unchanged for `client.rs`
//!   and `delivery.rs`.
//!
//! Inbound routing preserves the old dispatcher's strict FIFO semantics: the
//! authsocket fallback handler forwards `(event_name, data)` onto an internal
//! channel consumed by one dispatcher task, so per-room message/ack ordering
//! is exactly as the server emitted it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, Mutex};

use authsocket::client::AuthSocketClient;
use bsv::wallet::interfaces::WalletInterface;

use crate::encryption;
use crate::error::MessageBoxError;
use crate::types::{AuthenticatedPeerMessage, ServerPeerMessage};

/// Subscriber callback: event key → message handler.
type SubscriptionMap =
    Arc<Mutex<HashMap<String, Arc<dyn Fn(AuthenticatedPeerMessage) + Send + Sync>>>>;

/// Pending ack queue keyed by `sendMessageAck-{roomId}`.
///
/// The server's `sendMessageAck-{roomId}` carries only a `status` — it is
/// *room*-scoped, not *message*-scoped (no `messageId` to correlate on). So when
/// N concurrent sends target the same room, they must be matched to acks in FIFO
/// order: the server processes a room's sends serially and acks each in turn, so
/// the i-th ack belongs to the i-th still-pending send. A `VecDeque` per key
/// preserves that ordering.
type PendingAcks = Arc<Mutex<HashMap<String, VecDeque<oneshot::Sender<bool>>>>>;

/// WebSocket connection to the MessageBox server: the shared authsocket
/// BRC-103 client plus the MessageBox application routing.
pub struct MessageBoxWebSocket {
    /// The shared authenticated Socket.IO client (authsocket crate).
    ws: AuthSocketClient,
    /// Map of event key (e.g. "sendMessage-{roomId}") to subscriber callback.
    subscriptions: SubscriptionMap,
    /// Pending ack waiters keyed by "sendMessageAck-{roomId}", FIFO per key.
    pending_acks: PendingAcks,
    /// Rooms tracked locally so `leave_room` can clear subscriptions.
    joined_rooms: Arc<Mutex<HashSet<String>>>,
}

impl MessageBoxWebSocket {
    /// Connect to the MessageBox Socket.IO server and authenticate via BRC-103.
    ///
    /// Performs the full BRC-103 mutual authentication handshake before
    /// returning (the authsocket client blocks until the server's signed
    /// `authenticationSuccess`).
    pub async fn connect<W>(
        url: &str,
        identity_key: &str,
        wallet: W,
        originator: Option<String>,
    ) -> Result<Self, MessageBoxError>
    where
        W: WalletInterface + Clone + Send + Sync + 'static,
    {
        let ws = AuthSocketClient::connect(url, identity_key, wallet.clone())
            .await
            .map_err(|e| MessageBoxError::WebSocket(e.to_string()))?;

        let subscriptions: SubscriptionMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_acks: PendingAcks = Arc::new(Mutex::new(HashMap::new()));
        let joined_rooms: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

        // Internal FIFO: the authsocket fallback (sync) forwards every verified
        // event here; ONE dispatcher task consumes it so per-room ordering of
        // deliveries and acks matches the server's emit order exactly.
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<(String, serde_json::Value)>();
        ws.set_fallback(Arc::new(move |event_name, data| {
            let _ = event_tx.send((event_name, data));
        }))
        .await;

        // Dispatcher task: MessageBox application routing (extracted verbatim
        // from the old general_msg_dispatcher, minus the transport concerns
        // that moved into the authsocket crate).
        {
            let subscriptions = subscriptions.clone();
            let pending_acks = pending_acks.clone();
            let wallet = wallet.clone();
            let originator = originator.clone();
            tokio::spawn(async move {
                while let Some((event_name, data)) = event_rx.recv().await {
                    if let Some(room_id) = event_name.strip_prefix("sendMessage-") {
                        let room_id = room_id.to_string();
                        let Ok(server_msg) =
                            serde_json::from_value::<ServerPeerMessage>(data.clone())
                        else {
                            continue;
                        };
                        let callback = {
                            let guard = subscriptions.lock().await;
                            guard.get(&event_name).cloned()
                        };
                        if let Some(cb) = callback {
                            // Typed decrypt: carry authenticated-decrypt
                            // provenance to the subscriber so the MPC transport
                            // can fail closed.
                            let outcome = encryption::try_decrypt_message_typed(
                                &wallet,
                                &server_msg.body,
                                &server_msg.sender,
                                originator.as_deref(),
                            )
                            .await;
                            let authenticated_decrypt = outcome.is_authenticated();
                            let (recipient, message_box) = split_room_id(&room_id);
                            cb(AuthenticatedPeerMessage {
                                message_id: server_msg.message_id,
                                sender: server_msg.sender,
                                recipient,
                                message_box,
                                body: outcome.into_body(),
                                authenticated_decrypt,
                            });
                        }
                    } else if event_name.starts_with("sendMessageAck-") {
                        // Room-scoped ack: resolve the OLDEST still-pending
                        // send for this room (FIFO).
                        let success =
                            data.get("status").and_then(|s| s.as_str()) == Some("success");
                        let mut guard = pending_acks.lock().await;
                        if let Some(queue) = guard.get_mut(&event_name) {
                            if let Some(tx) = queue.pop_front() {
                                let _ = tx.send(success);
                            }
                            if queue.is_empty() {
                                guard.remove(&event_name);
                            }
                        }
                    }
                    // authenticationSuccess and other transport-level events are
                    // handled inside the authsocket client.
                }
            });
        }

        Ok(Self {
            ws,
            subscriptions,
            pending_acks,
            joined_rooms,
        })
    }

    /// Return true if the connection is currently authenticated.
    pub fn is_connected(&self) -> bool {
        self.ws.is_connected()
    }

    /// Milliseconds since the last inbound frame of any kind (the read-deadline
    /// tracker used for half-open detection).
    pub fn ms_since_last_inbound(&self) -> u64 {
        self.ws.ms_since_last_inbound()
    }

    /// Return the server's BRC-103 identity key captured during the handshake.
    pub fn server_identity_key(&self) -> &str {
        self.ws.server_identity_key()
    }

    /// Join a Socket.IO room (idempotent — no-op if already joined).
    ///
    /// The joinRoom event is sent as a signed BRC-103 authMessage envelope.
    pub async fn join_room(&self, room_id: &str) -> Result<(), MessageBoxError> {
        {
            let guard = self.joined_rooms.lock().await;
            if guard.contains(room_id) {
                return Ok(());
            }
        }
        self.ws
            .join_room(room_id)
            .await
            .map_err(|e| MessageBoxError::WebSocket(e.to_string()))?;
        self.joined_rooms.lock().await.insert(room_id.to_string());
        Ok(())
    }

    /// Leave a Socket.IO room and remove its subscription.
    ///
    /// Local subscription state is torn down unconditionally before the wire
    /// emit, so a dead socket cannot leave a stale subscription behind.
    pub async fn leave_room(&self, room_id: &str) -> Result<(), MessageBoxError> {
        self.joined_rooms.lock().await.remove(room_id);
        let event_key = format!("sendMessage-{room_id}");
        self.subscriptions.lock().await.remove(&event_key);
        self.ws
            .leave_room(room_id)
            .await
            .map_err(|e| MessageBoxError::WebSocket(e.to_string()))
    }

    /// Register a callback for incoming messages on a given event key.
    ///
    /// `event_key` is typically `"sendMessage-{room_id}"`.
    pub async fn subscribe(
        &self,
        event_key: String,
        callback: Arc<dyn Fn(AuthenticatedPeerMessage) + Send + Sync>,
    ) {
        self.subscriptions.lock().await.insert(event_key, callback);
    }

    /// Emit a sendMessage event and register an ack waiter.
    ///
    /// The sendMessage event is signed as a BRC-103 general message and emitted
    /// directly on the socket — concurrent calls sign + emit + await their acks
    /// in parallel. The ack waiter is enqueued under `sendMessageAck-{ack_key}`
    /// and resolved FIFO when the server emits that room-scoped ack.
    pub async fn emit_send_message(
        &self,
        payload: serde_json::Value,
        ack_key: String,
        ack_tx: oneshot::Sender<bool>,
    ) -> Result<(), MessageBoxError> {
        // Register the ack waiter BEFORE sending — avoids the race where the
        // server acks before we enqueue.
        self.pending_acks
            .lock()
            .await
            .entry(ack_key.clone())
            .or_default()
            .push_back(ack_tx);

        if let Err(e) = self.ws.emit("sendMessage", &payload).await {
            // Send failed — pull our just-enqueued waiter back off the tail so
            // it doesn't leak (and isn't mismatched to a later ack).
            let mut guard = self.pending_acks.lock().await;
            if let Some(queue) = guard.get_mut(&ack_key) {
                queue.pop_back();
                if queue.is_empty() {
                    guard.remove(&ack_key);
                }
            }
            return Err(MessageBoxError::WebSocket(e.to_string()));
        }
        Ok(())
    }

    /// Remove a pending ack entry (called on timeout to prevent leaking channels).
    ///
    /// Pops the OLDEST waiter for the key — under FIFO ack matching, a timeout
    /// on the oldest in-flight send is the one most likely to have been abandoned.
    pub async fn remove_pending_ack(&self, key: &str) {
        let mut guard = self.pending_acks.lock().await;
        if let Some(queue) = guard.get_mut(key) {
            queue.pop_front();
            if queue.is_empty() {
                guard.remove(key);
            }
        }
    }

    /// Disconnect from the server and clear all state.
    ///
    /// Sends `false` to all remaining pending ack waiters before dropping them.
    pub async fn disconnect(&self) -> Result<(), MessageBoxError> {
        {
            let mut guard = self.pending_acks.lock().await;
            for (_, queue) in guard.drain() {
                for tx in queue {
                    let _ = tx.send(false);
                }
            }
        }
        self.subscriptions.lock().await.clear();
        self.joined_rooms.lock().await.clear();
        self.ws
            .disconnect()
            .await
            .map_err(|e| MessageBoxError::WebSocket(e.to_string()))
    }
}

/// Split a room ID into (recipient/owner_identity_key, message_box_name).
///
/// Room ID format when listening: `"{identityKey}-{messageBox}"`. Identity
/// keys are 66-char hex strings, so split after index 66; falls back to the
/// first `-` for non-standard ids.
fn split_room_id(room_id: &str) -> (String, String) {
    const HEX_KEY_LEN: usize = 66;
    if room_id.len() > HEX_KEY_LEN && room_id.as_bytes()[HEX_KEY_LEN] == b'-' {
        let key = room_id[..HEX_KEY_LEN].to_string();
        let mb = room_id[HEX_KEY_LEN + 1..].to_string();
        return (key, mb);
    }
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
    use serde_json::json;
    use std::collections::HashSet;

    /// Room ID format: listen room is `{identity_key}-{message_box}`, send room
    /// is `{recipient}-{message_box}` — asymmetric by design.
    #[test]
    fn room_id_format() {
        let my_key = "03abc";
        let recipient = "03def";
        let message_box = "payment_inbox";

        let listen_room = format!("{my_key}-{message_box}");
        let send_room = format!("{recipient}-{message_box}");

        assert_eq!(listen_room, "03abc-payment_inbox");
        assert_eq!(send_room, "03def-payment_inbox");
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

    /// split_room_id correctly extracts key and message box for 66-char keys.
    #[test]
    fn split_room_id_hex_key() {
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

    // -----------------------------------------------------------------------
    // FIFO ack router — concurrent same-room send correlation
    // -----------------------------------------------------------------------

    /// Two concurrent sends to the SAME room each enqueue a waiter; two acks
    /// resolve them oldest-first.
    #[tokio::test]
    async fn fifo_acks_resolve_concurrent_same_room_sends_in_order() {
        let acks: PendingAcks = Arc::new(Mutex::new(HashMap::new()));
        let key = "sendMessageAck-03abc-inbox".to_string();

        let (tx1, rx1) = oneshot::channel::<bool>();
        let (tx2, rx2) = oneshot::channel::<bool>();
        {
            let mut g = acks.lock().await;
            g.entry(key.clone()).or_default().push_back(tx1);
            g.entry(key.clone()).or_default().push_back(tx2);
            assert_eq!(g.get(&key).unwrap().len(), 2, "both waiters queued");
        }

        {
            let mut g = acks.lock().await;
            let q = g.get_mut(&key).unwrap();
            let _ = q.pop_front().unwrap().send(true);
            assert!(!q.is_empty(), "second waiter still queued");
        }
        assert!(rx1.await.unwrap(), "first send resolved by first ack");

        {
            let mut g = acks.lock().await;
            let q = g.get_mut(&key).unwrap();
            let _ = q.pop_front().unwrap().send(false);
            if q.is_empty() {
                g.remove(&key);
            }
            assert!(!g.contains_key(&key), "key removed once queue drains");
        }
        assert!(!rx2.await.unwrap(), "second send resolved by second ack");
    }

    /// `remove_pending_ack` semantics: popping the oldest waiter on timeout and
    /// removing the key once the queue drains — no leaked entries.
    #[tokio::test]
    async fn remove_pending_ack_pops_oldest_and_clears_empty_key() {
        let acks: PendingAcks = Arc::new(Mutex::new(HashMap::new()));
        let key = "sendMessageAck-03abc-inbox".to_string();
        let (tx, _rx) = oneshot::channel::<bool>();
        acks.lock().await.entry(key.clone()).or_default().push_back(tx);

        {
            let mut g = acks.lock().await;
            if let Some(q) = g.get_mut(&key) {
                q.pop_front();
                if q.is_empty() {
                    g.remove(&key);
                }
            }
        }
        assert!(acks.lock().await.is_empty(), "no leaked ack entries");
    }

    /// Acks for DIFFERENT rooms are independent.
    #[tokio::test]
    async fn acks_are_per_room_independent() {
        let acks: PendingAcks = Arc::new(Mutex::new(HashMap::new()));
        let key_a = "sendMessageAck-03aaa-inbox".to_string();
        let key_b = "sendMessageAck-03bbb-inbox".to_string();
        let (tx_a, rx_a) = oneshot::channel::<bool>();
        let (tx_b, rx_b) = oneshot::channel::<bool>();
        {
            let mut g = acks.lock().await;
            g.entry(key_a.clone()).or_default().push_back(tx_a);
            g.entry(key_b.clone()).or_default().push_back(tx_b);
        }
        {
            let mut g = acks.lock().await;
            let q = g.get_mut(&key_a).unwrap();
            let _ = q.pop_front().unwrap().send(true);
            if q.is_empty() {
                g.remove(&key_a);
            }
        }
        assert!(rx_a.await.unwrap(), "room A resolved");
        assert!(acks.lock().await.contains_key(&key_b), "room B still pending");
        drop(rx_b);
    }
}
