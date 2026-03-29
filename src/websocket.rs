use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use rust_socketio::asynchronous::{Client as SocketClient, ClientBuilder};
use rust_socketio::{Event, Payload};
use serde_json::json;
use tokio::sync::{oneshot, Mutex};
use tokio::sync::mpsc;

use bsv::auth::peer::Peer;
use bsv::auth::types::MessageType;
use bsv::remittance::types::PeerMessage;
use bsv::wallet::interfaces::WalletInterface;

use crate::encryption;
use crate::error::MessageBoxError;
use crate::socket_transport::{
    decode_ws_event, encode_ws_event, parse_auth_message_from_payload, SocketIOTransport,
};
use crate::types::ServerPeerMessage;

/// Subscriber callback: event key → message handler.
type SubscriptionMap = Arc<Mutex<HashMap<String, Arc<dyn Fn(PeerMessage) + Send + Sync>>>>;

/// Commands sent from public methods to the background peer task.
enum PeerCommand {
    SendMessage {
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Shutdown,
}

/// WebSocket connection to the MessageBox server using Socket.IO v4 protocol
/// with BRC-103 mutual authentication via `Peer<W>`.
///
/// All application-level Socket.IO events (sendMessage, joinRoom, leaveRoom, etc.)
/// are sent through cryptographically signed `authMessage` envelopes. The public API
/// surface is unchanged from the pre-BRC-103 version.
///
/// The wallet type is erased at connection time: `Peer<W>` lives in a background
/// Tokio task and is accessed exclusively via the `peer_tx` command channel.
pub struct MessageBoxWebSocket {
    client: SocketClient,
    /// Map of event key (e.g. "sendMessage-{roomId}") to subscriber callback.
    subscriptions: SubscriptionMap,
    /// Pending ack channels keyed by "sendMessageAck-{roomId}".
    pending_acks: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
    /// Rooms currently joined (for idempotency on join_room).
    joined_rooms: Arc<Mutex<HashSet<String>>>,
    /// True once the server sends authenticationSuccess.
    connected: Arc<AtomicBool>,
    /// Channel to the background peer task that owns the BRC-103 Peer.
    peer_tx: mpsc::Sender<PeerCommand>,
    /// The server's identity key captured during the BRC-103 handshake.
    server_identity_key: String,
}

impl MessageBoxWebSocket {
    /// Connect to the MessageBox Socket.IO server and authenticate via BRC-103.
    ///
    /// Performs the full BRC-103 mutual authentication handshake before returning.
    /// The `Peer<W>` is type-erased into a background task — callers see only the
    /// unchanged public API surface.
    ///
    /// Returns an error if the handshake does not complete within 10 seconds, or
    /// if `authenticationSuccess` is not received within 5 additional seconds.
    pub async fn connect<W>(
        url: &str,
        identity_key: &str,
        wallet: W,
        originator: Option<String>,
    ) -> Result<Self, MessageBoxError>
    where
        W: WalletInterface + Clone + Send + Sync + 'static,
    {
        let subscriptions: SubscriptionMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_acks: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let joined_rooms: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let connected = Arc::new(AtomicBool::new(false));

        // Channel for incoming BRC-103 authMessage Socket.IO events → SocketIOTransport → Peer
        let (auth_msg_tx, auth_msg_rx) = mpsc::channel(64);

        // Channel to capture the server's identity key from the InitialRequest message
        let (server_key_tx, mut server_key_rx) = mpsc::channel::<String>(1);

        // Shared oneshot for authenticationSuccess — fired by whichever path delivers it first
        // (on_any fallback OR general_msg_dispatcher primary path)
        let (auth_success_tx, auth_success_rx) = oneshot::channel::<()>();
        let auth_success_shared: Arc<Mutex<Option<oneshot::Sender<()>>>> =
            Arc::new(Mutex::new(Some(auth_success_tx)));

        // Clone shared state for the on_any callback closure
        let subs_clone = subscriptions.clone();
        let acks_clone = pending_acks.clone();
        let conn_clone = connected.clone();
        let auth_success_on_any = auth_success_shared.clone();

        // Wallet and originator captured by value — needed in defensive on_any fallback paths
        let wallet_clone = wallet.clone();
        let originator_clone = originator.clone();

        // Move owned copies into the on("authMessage") callback
        let auth_msg_tx_clone = auth_msg_tx.clone();
        let server_key_tx_clone = server_key_tx.clone();

        let client = ClientBuilder::new(url)
            // BRC-103 transport layer: all authMessage events feed into the Peer channel
            .on("authMessage", move |payload, _socket| {
                let tx = auth_msg_tx_clone.clone();
                let key_tx = server_key_tx_clone.clone();
                async move {
                    if let Some(msg) = parse_auth_message_from_payload(&payload) {
                        // Capture the server identity key from InitialRequest or InitialResponse
                        // so we can retrieve it after handshake completes.
                        if msg.message_type == MessageType::InitialRequest
                            || msg.message_type == MessageType::InitialResponse
                        {
                            let _ = key_tx.send(msg.identity_key.clone()).await;
                        }
                        let _ = tx.send(msg).await;
                    }
                }
                .boxed()
            })
            // Application event layer: defensive fallback for non-BRC-103 paths.
            //
            // NOTE (confirmed 2026-03-29): The live Babbage server sends ALL handshake and
            // room events as BRC-103 authMessage envelopes. For room message broadcasts,
            // the server does NOT push to other clients via Socket.IO — messages are
            // delivered via the HTTP polling fallback in listen_for_live_messages instead.
            // These on_any handlers are retained as a defensive fallback for servers that
            // DO broadcast raw Socket.IO events.
            .on_any(move |event, payload, _socket| {
                let subs = subs_clone.clone();
                let acks = acks_clone.clone();
                let conn = conn_clone.clone();
                let auth_success = auth_success_on_any.clone();
                let wallet = wallet_clone.clone();
                let originator = originator_clone.clone();

                async move {
                    match &event {
                        // BRC-103 replaces the bare `authenticated` emit on connect.
                        // Do NOT re-emit here — the Peer handles authentication.
                        Event::Connect => {}
                        Event::Custom(name) => {
                            if name == "authenticationSuccess" {
                                conn.store(true, Ordering::SeqCst);
                                // Race with general_msg_dispatcher — first one wins
                                let mut guard = auth_success.lock().await;
                                if let Some(tx) = guard.take() {
                                    let _ = tx.send(());
                                }
                            } else if name.starts_with("sendMessage-") {
                                // Defensive fallback — primary path is general_msg_dispatcher
                                let event_key = name.clone();
                                if let Some(server_msg) = extract_server_peer_message(&payload) {
                                    let callback = {
                                        let guard = subs.lock().await;
                                        guard.get(&event_key).cloned()
                                    };
                                    if let Some(cb) = callback {
                                        let room_id = name.strip_prefix("sendMessage-")
                                            .unwrap_or("")
                                            .to_string();
                                        let decrypted_body = encryption::try_decrypt_message(
                                            &wallet,
                                            &server_msg.body,
                                            &server_msg.sender,
                                            originator.as_deref(),
                                        )
                                        .await;
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
                                // Defensive fallback — primary path is general_msg_dispatcher
                                let mut guard = acks.lock().await;
                                if let Some(tx) = guard.remove(name.as_str()) {
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
            // Disable auto-reconnect for v1 — reconnect requires fresh Peer + Transport.
            // TODO: Phase 8 — implement transparent BRC-103 reconnect
            .reconnect(false)
            .connect()
            .await
            .map_err(|e| MessageBoxError::WebSocket(e.to_string()))?;

        // Build SocketIOTransport from the connected client + incoming channel receiver.
        // The Sender lives in the on("authMessage") callback above.
        let transport_client = client.clone();
        let transport = SocketIOTransport::new(transport_client, auth_msg_rx);

        // Create the Peer — calls transport.subscribe() to get transport_rx, stores it.
        // Does NOT spawn any background task; we must drive it via process_next().
        let mut peer = Peer::new(wallet.clone(), Arc::new(transport));

        // Take the general message receiver BEFORE moving peer into the background task.
        // on_general_message() is take-once — panics on second call.
        let general_msg_rx = peer
            .on_general_message()
            .expect("on_general_message take-once: must be called before peer_task spawn");

        // -----------------------------------------------------------------------
        // Handshake: client-initiated BRC-103
        //
        // The client initiates the BRC-103 mutual auth handshake by calling
        // peer.send_message("", payload). When no session exists for the given
        // identity key, the Peer calls initiate_handshake() which:
        //   1. Sends InitialRequest as an authMessage Socket.IO event
        //   2. Polls the transport for InitialResponse from the server
        //   3. Verifies the server's signature and completes mutual auth
        //   4. Updates the session with the real server identity key
        //   5. Sends the authenticated General message through the session
        //
        // We pass "" as the server identity key since we don't know it yet.
        // The Peer discovers it from the server's InitialResponse and updates
        // the session accordingly.
        // -----------------------------------------------------------------------
        let auth_payload = encode_ws_event("authenticated", json!({"identityKey": identity_key}));
        peer.send_message("", auth_payload)
            .await
            .map_err(|e| MessageBoxError::WebSocket(format!("BRC-103 handshake: {e}")))?;

        // Extract the server identity key captured by the on("authMessage") callback
        // from the server's InitialResponse during the handshake.
        let server_identity_key = server_key_rx
            .try_recv()
            .map_err(|_| {
                MessageBoxError::WebSocket(
                    "BRC-103 handshake completed but server identity key not captured".into(),
                )
            })?;

        // -----------------------------------------------------------------------
        // Spawn peer_task: owns the Peer, runs process_next() continuously + handles commands.
        //
        // The tokio::select! loop drains both:
        //   (a) PeerCommand channel — for send_message calls from public API methods
        //   (b) process_next() polling — drives incoming message dispatch from transport_rx
        //
        // Note: initiate_handshake() (triggered by send_message if no session) blocks on
        // transport_rx.recv().await — safe here because the Peer is single-owned, and
        // initiate_handshake re-dispatches non-InitialResponse messages so nothing is lost.
        // -----------------------------------------------------------------------
        let (peer_cmd_tx, mut peer_cmd_rx) = mpsc::channel::<PeerCommand>(32);
        let server_identity_key_for_task = server_identity_key.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    cmd = peer_cmd_rx.recv() => {
                        match cmd {
                            Some(PeerCommand::SendMessage { payload, reply }) => {
                                let result = peer
                                    .send_message(&server_identity_key_for_task, payload)
                                    .await
                                    .map_err(|e| e.to_string());
                                let _ = reply.send(result);
                            }
                            Some(PeerCommand::Shutdown) | None => break,
                        }
                    }
                    _ = async {
                        // Continuously drain the transport channel and dispatch messages
                        match peer.process_next().await {
                            Ok(_dispatched) => {
                                if !_dispatched {
                                    tokio::time::sleep(Duration::from_millis(20)).await;
                                }
                            }
                            Err(_) => {
                                // BRC-103 verification errors (e.g. stale session, replayed nonce)
                                // are non-fatal — the connection remains open; sleep briefly.
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    } => {}
                }
            }
        });

        // -----------------------------------------------------------------------
        // Spawn general_msg_dispatcher: reads decoded general messages from the Peer
        // and routes them to subscriptions / acks / auth-success oneshot.
        //
        // This is the PRIMARY path for ALL application events (confirmed via TS source).
        // The on_any handlers are defensive fallbacks only.
        // -----------------------------------------------------------------------
        let auth_success_shared2 = auth_success_shared.clone();
        let subs_clone2 = subscriptions.clone();
        let acks_clone2 = pending_acks.clone();
        let conn_clone2 = connected.clone();
        let wallet_clone2 = wallet.clone();
        let originator_clone2 = originator.clone();
        let mut general_msg_rx = general_msg_rx;

        tokio::spawn(async move {
            while let Some((_sender_key, payload_bytes)) = general_msg_rx.recv().await {
                if let Some((event_name, data)) = decode_ws_event(&payload_bytes) {
                    if event_name == "authenticationSuccess" {
                        conn_clone2.store(true, Ordering::SeqCst);
                        // Race to fire the shared oneshot — on_any may also attempt this
                        let mut guard = auth_success_shared2.lock().await;
                        if let Some(tx) = guard.take() {
                            let _ = tx.send(());
                        }
                    } else if event_name.starts_with("sendMessage-") {
                        let event_key = event_name.clone();
                        if let Ok(server_msg) =
                            serde_json::from_value::<ServerPeerMessage>(data.clone())
                        {
                            let callback = {
                                let guard = subs_clone2.lock().await;
                                guard.get(&event_key).cloned()
                            };
                            if let Some(cb) = callback {
                                let room_id = event_name
                                    .strip_prefix("sendMessage-")
                                    .unwrap_or("")
                                    .to_string();
                                let decrypted_body = encryption::try_decrypt_message(
                                    &wallet_clone2,
                                    &server_msg.body,
                                    &server_msg.sender,
                                    originator_clone2.as_deref(),
                                )
                                .await;
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
                    } else if event_name.starts_with("sendMessageAck-") {
                        let mut guard = acks_clone2.lock().await;
                        if let Some(tx) = guard.remove(&event_name) {
                            let success = data.get("status").and_then(|s| s.as_str())
                                == Some("success");
                            let _ = tx.send(success);
                        }
                    }
                }
            }
        });

        // -----------------------------------------------------------------------
        // Wait for authenticationSuccess from whichever path fires first.
        //
        // Both on_any (fallback) and general_msg_dispatcher (primary) race to send
        // on the shared oneshot. The peer_task must be running by now so that
        // process_next() drains BRC-103 general messages containing authenticationSuccess.
        // -----------------------------------------------------------------------
        tokio::time::timeout(Duration::from_secs(5), auth_success_rx)
            .await
            .map_err(|_| {
                MessageBoxError::WebSocket("authenticationSuccess not received within 5s".into())
            })?
            .map_err(|_| {
                MessageBoxError::WebSocket("auth success channel dropped".into())
            })?;

        Ok(Self {
            client,
            subscriptions,
            pending_acks,
            joined_rooms,
            connected,
            peer_tx: peer_cmd_tx,
            server_identity_key,
        })
    }

    /// Return true if the connection is currently authenticated.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Return the server's BRC-103 identity key captured during the handshake.
    ///
    /// This is a 66-character compressed public key hex string. Useful for
    /// diagnostics and integration tests to verify the handshake completed
    /// successfully and the correct server identity was established.
    pub fn server_identity_key(&self) -> &str {
        &self.server_identity_key
    }

    /// Join a Socket.IO room (idempotent — no-op if already joined).
    ///
    /// The joinRoom event is sent through the BRC-103 Peer channel as a signed
    /// authMessage envelope.
    pub async fn join_room(&self, room_id: &str) -> Result<(), MessageBoxError> {
        {
            let guard = self.joined_rooms.lock().await;
            if guard.contains(room_id) {
                return Ok(());
            }
        }
        let payload = encode_ws_event("joinRoom", json!(room_id));
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_tx
            .send(PeerCommand::SendMessage {
                payload,
                reply: reply_tx,
            })
            .await
            .map_err(|_| MessageBoxError::WebSocket("peer task closed".into()))?;
        reply_rx
            .await
            .map_err(|_| MessageBoxError::WebSocket("peer reply dropped".into()))?
            .map_err(|e| MessageBoxError::WebSocket(e))?;
        self.joined_rooms.lock().await.insert(room_id.to_string());
        Ok(())
    }

    /// Leave a Socket.IO room and remove its subscription.
    ///
    /// The leaveRoom event is sent through the BRC-103 Peer channel.
    pub async fn leave_room(&self, room_id: &str) -> Result<(), MessageBoxError> {
        self.joined_rooms.lock().await.remove(room_id);
        let event_key = format!("sendMessage-{room_id}");
        self.subscriptions.lock().await.remove(&event_key);
        let payload = encode_ws_event("leaveRoom", json!(room_id));
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_tx
            .send(PeerCommand::SendMessage {
                payload,
                reply: reply_tx,
            })
            .await
            .map_err(|_| MessageBoxError::WebSocket("peer task closed".into()))?;
        reply_rx
            .await
            .map_err(|_| MessageBoxError::WebSocket("peer reply dropped".into()))?
            .map_err(|e| MessageBoxError::WebSocket(e))?;
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
    /// The sendMessage event is encoded as a BRC-103 payload and sent through
    /// the Peer command channel. The ack channel is triggered when the server
    /// emits `sendMessageAck-{ack_key}` (primary: via BRC-103 general message,
    /// fallback: via raw Socket.IO event).
    pub async fn emit_send_message(
        &self,
        payload: serde_json::Value,
        ack_key: String,
        ack_tx: oneshot::Sender<bool>,
    ) -> Result<(), MessageBoxError> {
        // Register ack BEFORE sending — avoids race where server acks before we register
        self.pending_acks
            .lock()
            .await
            .insert(ack_key.clone(), ack_tx);

        let event_payload = encode_ws_event("sendMessage", payload);
        let (reply_tx, reply_rx) = oneshot::channel();
        if let Err(_) = self
            .peer_tx
            .send(PeerCommand::SendMessage {
                payload: event_payload,
                reply: reply_tx,
            })
            .await
        {
            // Clean up the pending ack so it doesn't leak until timeout
            self.pending_acks.lock().await.remove(&ack_key);
            return Err(MessageBoxError::WebSocket("peer task closed".into()));
        }
        if let Err(e) = reply_rx
            .await
            .map_err(|_| MessageBoxError::WebSocket("peer reply dropped".into()))?
        {
            self.pending_acks.lock().await.remove(&ack_key);
            return Err(MessageBoxError::WebSocket(e));
        }
        Ok(())
    }

    /// Remove a pending ack entry (called on timeout to prevent leaking channels).
    pub async fn remove_pending_ack(&self, key: &str) {
        self.pending_acks.lock().await.remove(key);
    }

    /// Disconnect from the server and clear all state.
    ///
    /// Signals the peer_task to shut down, then disconnects the Socket.IO client.
    /// Sends false to all remaining pending ack channels before dropping them.
    pub async fn disconnect(&self) -> Result<(), MessageBoxError> {
        self.connected.store(false, Ordering::SeqCst);
        // Signal the peer_task to terminate (best-effort — channel may already be closed)
        let _ = self.peer_tx.send(PeerCommand::Shutdown).await;
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
