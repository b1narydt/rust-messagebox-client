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
//! - live-send answers: the relay acks an accepted send with
//!   `sendMessageAck-{roomId}` `{status, messageId}` and refuses one with
//!   `messageFailed {reason}`, which names no message. Waiters are keyed by
//!   message id; a refusal fails every waiter on the socket (see
//!   `AckWaiters`).
//! - the public [`MessageBoxWebSocket`] API surface.
//!
//! Inbound routing preserves the old dispatcher's strict FIFO semantics: the
//! authsocket fallback handler forwards `(event_name, data)` onto an internal
//! channel consumed by one dispatcher task, so per-room message/ack ordering
//! is exactly as the server emitted it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, Mutex};

use authsocket::client::AuthSocketClient;
/// Answers a relay's certificate request during the WebSocket handshake:
/// given the relay's identity key and the requested set, return the
/// certificates to show. An error or an empty batch fails the connection
/// (authsocket refuses both).
pub use authsocket::client::CertificateProvider;
use bsv::wallet::interfaces::WalletInterface;

use crate::encryption;
use crate::error::MessageBoxError;
use crate::types::{AuthenticatedPeerMessage, ServerPeerMessage, WsSendMessageData};

/// Subscriber callback: event key → message handler.
type SubscriptionMap =
    Arc<Mutex<HashMap<String, Arc<dyn Fn(AuthenticatedPeerMessage) + Send + Sync>>>>;

/// The relay's answer to one live send: accepted, or refused and why.
type AckOutcome = Result<(), MessageBoxError>;

/// Live sends on one socket that the relay has not answered yet, oldest first.
///
/// - `sendMessageAck-{roomId}` `{status: "success", messageId}` resolves the
///   waiter for that message id only. An ack naming no waiting id is logged
///   and ignored.
/// - `messageFailed {reason}` carries no message id and no room, so the
///   refusal cannot be pinned on one send: it fails every waiter. A
///   `reason: "rate_limited"` refusal becomes [`MessageBoxError::RateLimited`].
///   Each failed send then takes the HTTP fallback with its own id, which
///   gets a per-request answer.
/// - A waiter leaves only by its own token (answered, or its
///   [`LiveSendAck`] dropped), so a send that gives up never removes another.
#[derive(Default)]
pub(crate) struct AckWaiters {
    next_token: u64,
    waiting: BTreeMap<u64, (String, oneshot::Sender<AckOutcome>)>,
}

pub(crate) type PendingAcks = Arc<std::sync::Mutex<AckWaiters>>;

impl AckWaiters {
    fn register(&mut self, message_id: &str) -> (u64, oneshot::Receiver<AckOutcome>) {
        let token = self.next_token;
        self.next_token += 1;
        let (tx, rx) = oneshot::channel();
        // The relay trims the id before it acks.
        self.waiting
            .insert(token, (message_id.trim().to_string(), tx));
        (token, rx)
    }

    fn remove(&mut self, token: u64) {
        self.waiting.remove(&token);
    }

    fn fail_all(&mut self, error: impl Fn() -> MessageBoxError) {
        for (_, (_, tx)) in std::mem::take(&mut self.waiting) {
            let _ = tx.send(Err(error()));
        }
    }

    /// Apply one verified relay event. Events other than acks and refusals
    /// are left alone.
    pub(crate) fn route(&mut self, event_name: &str, data: &serde_json::Value) {
        if event_name == "messageFailed" {
            let body = data.as_object();
            let reason = body
                .and_then(|b| b.get("reason"))
                .and_then(|v| v.as_str())
                .unwrap_or("unspecified")
                .to_string();
            tracing::warn!(
                %reason,
                pending = self.waiting.len(),
                "relay refused a live send; failing every pending send on this socket"
            );
            if reason == "rate_limited" {
                self.fail_all(|| crate::transport::rate_limited(body, None));
            } else {
                self.fail_all(|| {
                    MessageBoxError::WebSocket(format!("relay refused the live send: {reason}"))
                });
            }
        } else if event_name.starts_with("sendMessageAck-") {
            let Some(message_id) = data.get("messageId").and_then(|v| v.as_str()) else {
                tracing::warn!(event = %event_name, "relay ack names no message id; ignored");
                return;
            };
            let message_id = message_id.trim();
            let Some(token) = self
                .waiting
                .iter()
                .find(|(_, (id, _))| id == message_id)
                .map(|(token, _)| *token)
            else {
                tracing::warn!(%message_id, "relay ack for no pending send; ignored");
                return;
            };
            let (_, tx) = self.waiting.remove(&token).expect("token was just found");
            let status = data.get("status").and_then(|v| v.as_str()).unwrap_or("");
            let _ = tx.send(if status == "success" {
                Ok(())
            } else {
                Err(MessageBoxError::WebSocket(format!(
                    "relay acked {message_id} with status {status:?}"
                )))
            });
        }
    }
}

pub(crate) fn lock_waiters(waiters: &PendingAcks) -> std::sync::MutexGuard<'_, AckWaiters> {
    waiters
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The relay's answer to one live send, still to come.
///
/// Dropping it withdraws this send's waiter and no other, so a send that
/// times out or is cancelled never leaves an entry behind and never takes
/// another send's answer.
pub struct LiveSendAck {
    token: u64,
    rx: oneshot::Receiver<AckOutcome>,
    waiters: PendingAcks,
}

impl LiveSendAck {
    pub(crate) fn register(waiters: &PendingAcks, message_id: &str) -> Self {
        let (token, rx) = lock_waiters(waiters).register(message_id);
        Self {
            token,
            rx,
            waiters: waiters.clone(),
        }
    }

    /// Wait up to `timeout` for the relay to accept (`Ok`) or refuse (`Err`)
    /// this send. No answer in time is an error too.
    pub async fn wait(mut self, timeout: Duration) -> Result<(), MessageBoxError> {
        match tokio::time::timeout(timeout, &mut self.rx).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => Err(MessageBoxError::WebSocket(
                "the socket closed before the relay answered".to_string(),
            )),
            Err(_) => Err(MessageBoxError::WebSocket(format!(
                "no answer from the relay within {timeout:?}"
            ))),
        }
    }
}

impl Drop for LiveSendAck {
    fn drop(&mut self) {
        lock_waiters(&self.waiters).remove(self.token);
    }
}

/// WebSocket connection to the MessageBox server: the shared authsocket
/// BRC-103 client plus the MessageBox application routing.
pub struct MessageBoxWebSocket {
    /// The shared authenticated Socket.IO client (authsocket crate).
    ws: AuthSocketClient,
    /// Map of event key (e.g. "sendMessage-{roomId}") to subscriber callback.
    subscriptions: SubscriptionMap,
    /// Live sends waiting for the relay's answer.
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
        Self::open(url, identity_key, wallet, originator, None).await
    }

    /// [`connect`](Self::connect), answering the relay's certificate request
    /// with `provider`. A relay whose identity gate is armed asks for a
    /// certificate during the handshake; the provider's batch is sent before
    /// the client's first signed `authenticated` event.
    pub async fn connect_with_certificate_provider<W>(
        url: &str,
        identity_key: &str,
        wallet: W,
        originator: Option<String>,
        provider: CertificateProvider,
    ) -> Result<Self, MessageBoxError>
    where
        W: WalletInterface + Clone + Send + Sync + 'static,
    {
        Self::open(url, identity_key, wallet, originator, Some(provider)).await
    }

    async fn open<W>(
        url: &str,
        identity_key: &str,
        wallet: W,
        originator: Option<String>,
        provider: Option<CertificateProvider>,
    ) -> Result<Self, MessageBoxError>
    where
        W: WalletInterface + Clone + Send + Sync + 'static,
    {
        let ws = match provider {
            Some(provider) => {
                AuthSocketClient::connect_with_certificate_provider(
                    url,
                    identity_key,
                    wallet.clone(),
                    provider,
                )
                .await
            }
            None => AuthSocketClient::connect(url, identity_key, wallet.clone()).await,
        }
        .map_err(|e| MessageBoxError::WebSocket(e.to_string()))?;

        let subscriptions: SubscriptionMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_acks: PendingAcks = Arc::default();
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
                    } else {
                        lock_waiters(&pending_acks).route(&event_name, &data);
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

    /// Emit a sendMessage event and return the waiter for the relay's answer.
    ///
    /// The event is signed as a BRC-103 general message and emitted directly
    /// on the socket, so concurrent sends emit and wait in parallel. The
    /// waiter is registered under `data.message.message_id` before the emit,
    /// so an ack that beats the return is not lost.
    pub async fn emit_send_message(
        &self,
        data: &WsSendMessageData,
    ) -> Result<LiveSendAck, MessageBoxError> {
        let payload = serde_json::to_value(data)?;
        let ack = LiveSendAck::register(&self.pending_acks, &data.message.message_id);
        // On error `ack` drops here and withdraws its own waiter.
        self.ws
            .emit("sendMessage", &payload)
            .await
            .map_err(|e| MessageBoxError::WebSocket(e.to_string()))?;
        Ok(ack)
    }

    /// Disconnect from the server and clear all state. Every send still
    /// waiting for the relay's answer fails.
    pub async fn disconnect(&self) -> Result<(), MessageBoxError> {
        lock_waiters(&self.pending_acks)
            .fail_all(|| MessageBoxError::WebSocket("disconnected".to_string()));
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
    // Live-send answers
    // -----------------------------------------------------------------------

    fn waiters() -> PendingAcks {
        Arc::default()
    }

    fn ack(message_id: &str) -> serde_json::Value {
        json!({"status": "success", "messageId": message_id})
    }

    /// An ack resolves the send it names and no other, whatever the order.
    #[tokio::test]
    async fn an_ack_resolves_only_the_send_it_names() {
        let waiters = waiters();
        let a = LiveSendAck::register(&waiters, "id-a");
        let b = LiveSendAck::register(&waiters, "id-b");

        lock_waiters(&waiters).route("sendMessageAck-03abc-inbox", &ack("id-c"));
        lock_waiters(&waiters).route("sendMessageAck-03abc-inbox", &ack("id-b"));
        b.wait(Duration::from_secs(1)).await.expect("b accepted");

        assert_eq!(lock_waiters(&waiters).waiting.len(), 1, "a still waits");
        lock_waiters(&waiters).route("sendMessageAck-03abc-inbox", &ack(" id-a "));
        a.wait(Duration::from_secs(1)).await.expect("a accepted");
    }

    /// A refusal names no send, so every pending send on the socket fails;
    /// a rate-limit refusal carries the relay's wait.
    #[tokio::test]
    async fn a_refusal_fails_every_pending_send() {
        let waiters = waiters();
        let a = LiveSendAck::register(&waiters, "id-a");
        let b = LiveSendAck::register(&waiters, "id-b");

        lock_waiters(&waiters).route(
            "messageFailed",
            &json!({"status":"error","reason":"rate_limited","tier":"uncertified","retry_after":4}),
        );
        for pending in [a, b] {
            match pending.wait(Duration::from_secs(1)).await {
                Err(MessageBoxError::RateLimited { retry_after, .. }) => {
                    assert_eq!(retry_after, Duration::from_secs(4))
                }
                other => panic!("{other:?}"),
            }
        }

        let c = LiveSendAck::register(&waiters, "id-c");
        lock_waiters(&waiters).route(
            "messageFailed",
            &json!({"reason": "Delivery blocked by recipient"}),
        );
        assert!(matches!(
            c.wait(Duration::from_secs(1)).await,
            Err(MessageBoxError::WebSocket(reason)) if reason.contains("Delivery blocked")
        ));
    }

    /// A send that times out withdraws its own waiter, not an older one.
    #[tokio::test(start_paused = true)]
    async fn a_timeout_withdraws_only_its_own_waiter() {
        let waiters = waiters();
        let older = LiveSendAck::register(&waiters, "id-old");
        let newer = LiveSendAck::register(&waiters, "id-new");

        assert!(newer.wait(Duration::from_secs(10)).await.is_err());
        lock_waiters(&waiters).route("sendMessageAck-03abc-inbox", &ack("id-old"));
        older
            .wait(Duration::from_secs(10))
            .await
            .expect("the older send keeps its answer");
        assert!(lock_waiters(&waiters).waiting.is_empty(), "nothing leaks");
    }
}
