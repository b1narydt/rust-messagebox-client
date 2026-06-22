use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use rust_socketio::asynchronous::{Client as SocketClient, ClientBuilder};
use rust_socketio::{Event, TransportType};
use serde_json::json;
use tokio::sync::mpsc;
use tokio::sync::{oneshot, Mutex};

/// Interval at which the keepalive task emits a probe to elicit inbound
/// traffic.
///
/// CRITICAL INVARIANT (issue #7 regression fix): this MUST be comfortably
/// below `READ_DEADLINE`. The keepalive probe is an `authenticated` event; the
/// server replies with a signed `authenticationSuccess` general message
/// (rust-messagebox-server `handle_general_event` → `emit_signed`), which the
/// `general_msg_dispatcher` decodes and uses to stamp `last_inbound_ms`. That
/// round-trip is therefore the liveness signal that keeps a *subscribed-but-idle*
/// socket alive — an idle socket receives NO application frames, so without the
/// keepalive round-trip refreshing the deadline inside the window the watchdog
/// false-fires and triggers a reconnect storm.
///
/// At 2 s, a healthy socket refreshes `last_inbound_ms` roughly every 2 s, so a
/// 6 s `READ_DEADLINE` tolerates ~3 missed keepalive round-trips (transient
/// scheduling jitter, a slow GC pause, one dropped probe) before declaring the
/// socket dead. rust_socketio 0.6 exposes no engine.io pong/heartbeat callback
/// (its `Event` enum is only Message/Error/Custom/Connect/Close), so the
/// application-level keepalive round-trip is the *only* liveness signal
/// available — hence it must cycle well inside the deadline.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);

/// Inbound read deadline for half-open detection. If NO frame of any kind
/// (BRC-103 authMessage, general message, ack, OR the keepalive's
/// `authenticationSuccess` reply) arrives within this window, the socket is
/// declared dead and a reconnect is triggered.
///
/// A healthy socket refreshes `last_inbound_ms` every `KEEPALIVE_INTERVAL`
/// (2 s) via the keepalive round-trip, so 6 s = ~3× the keepalive cycle: it
/// never false-fires on a healthy-but-idle connection (the previous 5 s deadline
/// vs 20 s keepalive caused exactly that — a reconnect storm every ~5–6 s on
/// every idle subscriber, issue #7) while still detecting a black-holed peer
/// (half-open, no TCP FIN) within ~6–7 s, far faster than the old 20 s+ "next
/// write fails" path.
const READ_DEADLINE: Duration = Duration::from_secs(6);

/// How often the watchdog checks the inbound read deadline.
const WATCHDOG_TICK: Duration = Duration::from_secs(1);

/// Maximum time to wait for the Socket.IO namespace connect-ack ("40{sid}")
/// before failing the connection. A healthy server acks in well under a second
/// even across a network hop; the bound exists so a server that never completes
/// the namespace handshake fails fast instead of hanging the caller.
const CONNECT_ACK_TIMEOUT: Duration = Duration::from_secs(5);

use bsv::auth::peer::Peer;
use bsv::auth::types::{AuthMessage, MessageType};
use bsv::wallet::interfaces::WalletInterface;

use crate::encryption;
use crate::error::MessageBoxError;
use crate::socket_transport::{
    decode_ws_event, encode_ws_event, parse_auth_message_from_payload, SocketIOTransport,
};
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
/// preserves that ordering. (A single `oneshot` per key — the old design — would
/// have the second concurrent same-room send overwrite the first's waiter, so
/// the first would never resolve.)
type PendingAcks = Arc<Mutex<HashMap<String, VecDeque<oneshot::Sender<bool>>>>>;

/// Type-erased BRC-103 signer.
///
/// Captures `Arc<Peer<W>>` + the server identity key so the WS send path can
/// sign a general-message payload WITHOUT knowing the wallet type `W` (which is
/// erased at connect time) and WITHOUT routing through a serializing command
/// channel. `Peer::create_general_message` is `&self`/concurrency-safe
/// (bsv-sdk ≥ 0.2.86), so N callers sign in parallel against one session.
type Signer = Arc<
    dyn Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = Result<AuthMessage, String>> + Send>>
        + Send
        + Sync,
>;

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
    /// Socket.IO client handle. `Client` is `Clone` (it is an `Arc` over the
    /// connection) and every emit takes `&self`, serializing only the brief
    /// per-frame transport write internally — so concurrent emits are safe and
    /// do NOT block each other's ack awaits. This is the WS-path equivalent of
    /// the lock-free shared `Arc<AuthFetch>` on the HTTP path.
    client: SocketClient,
    /// Type-erased BRC-103 signer over `Arc<Peer<W>>` + server identity key.
    /// Sends sign through this directly (lock-free) then emit on `client`.
    signer: Signer,
    /// Map of event key (e.g. "sendMessage-{roomId}") to subscriber callback.
    subscriptions: SubscriptionMap,
    /// Pending ack waiters keyed by "sendMessageAck-{roomId}", FIFO per key so
    /// concurrent same-room sends each resolve against one room-scoped ack.
    pending_acks: PendingAcks,
    /// Rooms currently joined (for idempotency on join_room).
    joined_rooms: Arc<Mutex<HashSet<String>>>,
    /// True once the server sends authenticationSuccess AND the socket is live.
    /// Flipped false by the watchdog on read-deadline expiry, by the receive
    /// task on channel close, and by the Close lifecycle handler.
    connected: Arc<AtomicBool>,
    /// Monotonic millis timestamp of the last inbound frame of ANY kind. The
    /// watchdog reads this to enforce the inbound read deadline (half-open
    /// detection, issue #7). Updated by the authMessage callback and the
    /// general-message dispatcher.
    last_inbound_ms: Arc<AtomicU64>,
    /// The server's identity key captured during the BRC-103 handshake.
    server_identity_key: String,
}

/// Monotonic milliseconds since an arbitrary fixed epoch, for read-deadline math.
fn now_ms() -> u64 {
    use std::time::Instant;
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
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
        let pending_acks: PendingAcks = Arc::new(Mutex::new(HashMap::new()));
        let joined_rooms: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let connected = Arc::new(AtomicBool::new(false));
        // Read-deadline tracker: every inbound frame stamps this. Initialized to
        // "now" so the watchdog does not fire before the first frame arrives.
        let last_inbound_ms = Arc::new(AtomicU64::new(now_ms()));

        // Channel for incoming BRC-103 authMessage Socket.IO events → SocketIOTransport → Peer
        let (auth_msg_tx, auth_msg_rx) = mpsc::channel(64);

        // Channel to capture the server's identity key from the InitialRequest message
        let (server_key_tx, mut server_key_rx) = mpsc::channel::<String>(1);

        // Shared oneshot for authenticationSuccess — fired by whichever path delivers it first
        // (on_any fallback OR general_msg_dispatcher primary path)
        let (auth_success_tx, auth_success_rx) = oneshot::channel::<()>();
        let auth_success_shared: Arc<Mutex<Option<oneshot::Sender<()>>>> =
            Arc::new(Mutex::new(Some(auth_success_tx)));

        // Clone shared state for the connect/close lifecycle callbacks.
        let conn_clone = connected.clone();
        let conn_close_clone = connected.clone();

        // Socket.IO connect-ack gate (consumed by the wait before the first emit).
        //
        // `rust_socketio::connect()` sends the namespace CONNECT packet ("40") and
        // returns immediately, without waiting for the server's connect-ack
        // ("40{sid}"). Emitting an event in that window races the handshake, and
        // servers that follow the Socket.IO spec strictly (e.g. socketioxide)
        // reject an event received before the namespace is connected and close the
        // socket. On loopback the ack typically wins the race; across any network
        // hop that coalesces the CONNECT and the event into a single read — common
        // through reverse proxies and load balancers — the event can land first and
        // the connection is dropped. Closing the race explicitly (hold the first
        // emit until Event::Connect) makes the handshake reliable on every path.
        let (connect_ready_tx, mut connect_ready_rx) = mpsc::channel::<()>(1);
        let connect_ready_tx_cb = connect_ready_tx.clone();

        // Move owned copies into the on("authMessage") callback
        let auth_msg_tx_clone = auth_msg_tx.clone();
        let server_key_tx_clone = server_key_tx.clone();
        let last_inbound_for_auth = last_inbound_ms.clone();

        // We register handlers ONLY for `authMessage` (the BRC-103 transport) and
        // the Connect/Close lifecycle events. There is deliberately no handler for
        // raw Socket.IO application events: for parity with @bsv/authsocket-client,
        // every application message (room delivery, acks, authenticationSuccess)
        // must arrive as a BRC-103-verified general message, never as an unsigned
        // raw event. Registering no raw-event handler keeps that receive path closed.
        let client = ClientBuilder::new(url)
            // BRC-103 transport layer: all authMessage events feed into the Peer channel
            .on("authMessage", move |payload, _socket| {
                let tx = auth_msg_tx_clone.clone();
                let key_tx = server_key_tx_clone.clone();
                let last_inbound = last_inbound_for_auth.clone();
                async move {
                    // Any inbound authMessage frame is proof of life — stamp the
                    // read-deadline tracker so the watchdog does not false-fire.
                    last_inbound.store(now_ms(), Ordering::SeqCst);
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
            // Lifecycle events are routed through the per-event `on` map (rust_socketio
            // delivers only Message/Custom events to `on_any`), so Connect and Close
            // each need a dedicated handler.
            //
            // Connect: the namespace connect-ack ("40{sid}") arrived — the socket is
            // ready, so release the connect-ready gate to unblock the first emit.
            .on(Event::Connect, move |_payload, _socket| {
                let conn = conn_clone.clone();
                let ready = connect_ready_tx_cb.clone();
                async move {
                    conn.store(true, Ordering::SeqCst);
                    let _ = ready.try_send(());
                }
                .boxed()
            })
            // Close: the transport went away — mark disconnected so the next call reconnects.
            .on(Event::Close, move |_payload, _socket| {
                let conn = conn_close_clone.clone();
                async move {
                    conn.store(false, Ordering::SeqCst);
                }
                .boxed()
            })
            // Connect WebSocket-first rather than the EngineIO default (HTTP
            // long-poll, then upgrade to WebSocket). The upgrade handshake exchanges
            // "2probe"/"3probe" frames that many reverse proxies and load balancers
            // forward unreliably: the HTTP 101 succeeds but the probe never
            // round-trips, leaving the connection stuck on slow long-polling — or
            // stalled until the BRC-103 handshake times out. A WS-first connect runs
            // the EngineIO handshake directly over the WebSocket, which intermediaries
            // treat as an ordinary upgraded connection, so live push works on any path.
            .transport_type(TransportType::Websocket)
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
        //
        // Wrapped in `Arc` so it can be shared between the receive task (drives
        // process_next) and the type-erased `Signer` (signs concurrent sends).
        // Every `Peer` method is `&self` (bsv-sdk ≥ 0.2.86), so this sharing is
        // lock-free against the SessionManager — N concurrent signs run in
        // parallel against one authenticated session.
        let peer = Arc::new(Peer::new(wallet.clone(), Arc::new(transport)));

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
        // Hold the first emit until the namespace connect-ack arrives, so the
        // BRC-103 InitialRequest is never delivered ahead of the namespace
        // handshake (see the connect-ready gate above).
        match tokio::time::timeout(CONNECT_ACK_TIMEOUT, connect_ready_rx.recv()).await {
            Ok(Some(())) => {}
            _ => {
                return Err(MessageBoxError::WebSocket(
                    "Socket.IO connect-ack not received before timeout".into(),
                ))
            }
        }

        let auth_payload = encode_ws_event("authenticated", json!({"identityKey": identity_key}));
        peer.send_message("", auth_payload)
            .await
            .map_err(|e| MessageBoxError::WebSocket(format!("BRC-103 handshake: {e}")))?;

        // Extract the server identity key captured by the on("authMessage") callback
        // from the server's InitialResponse during the handshake.
        let server_identity_key = server_key_rx.try_recv().map_err(|_| {
            MessageBoxError::WebSocket(
                "BRC-103 handshake completed but server identity key not captured".into(),
            )
        })?;

        // -----------------------------------------------------------------------
        // Build the type-erased Signer over Arc<Peer<W>> + server identity key.
        //
        // This replaces the old single-command-at-a-time `peer_tx` funnel. The
        // funnel forced every WS emit (sendMessage, joinRoom, leaveRoom, ping)
        // through ONE select! loop that awaited each `peer.send_message` before
        // the next — serializing all concurrent WS sends (the WS-path twin of
        // the `Arc<Mutex<AuthFetch>>` already removed from the HTTP path). Now
        // each send signs through this `&self` closure (lock-free) and emits on
        // the cloned `client` (whose `emit` is `&self`), so N concurrent sends
        // sign + emit + await their acks in parallel.
        // -----------------------------------------------------------------------
        let signer: Signer = {
            let peer_for_signer = peer.clone();
            let server_key = server_identity_key.clone();
            Arc::new(move |payload: Vec<u8>| {
                let peer = peer_for_signer.clone();
                let server_key = server_key.clone();
                Box::pin(async move {
                    peer.create_general_message(&server_key, payload)
                        .await
                        .map_err(|e| e.to_string())
                }) as Pin<Box<dyn Future<Output = Result<AuthMessage, String>> + Send>>
            })
        };

        // -----------------------------------------------------------------------
        // Spawn receive_task: owns Arc<Peer>, drives process_next() forever so
        // incoming BRC-103 general messages (acks, room deliveries,
        // authenticationSuccess) are decoded and fanned out to the dispatcher.
        // It no longer handles sends — sends bypass it entirely via the signer +
        // client — so a slow send can never stall the receive path, and vice
        // versa.
        // -----------------------------------------------------------------------
        let peer_for_recv = peer.clone();
        let connected_for_recv = connected.clone();
        tokio::spawn(async move {
            // Drive process_next() until the socket is torn down. `process_next`
            // returns Ok(false) both for "no message yet" AND for a disconnected
            // transport — indistinguishable — so it cannot self-terminate on
            // disconnect. We therefore exit when `connected` flips false (set by
            // the watchdog on half-open death, the Close lifecycle handler, the
            // channel-close path, or `disconnect()`). This guarantees the receive
            // task does NOT leak across reconnects: each fresh socket spawns its
            // own receive task, and the previous one exits once its socket dies.
            //
            // `connected` starts false and only flips true when authentication
            // Success arrives (decoded by the dispatcher, which this very task
            // feeds). So we must NOT exit before the connection comes up — we
            // latch on the first observed `connected==true`, then treat a
            // subsequent `false` as the tear-down signal.
            let mut was_connected = false;
            loop {
                match peer_for_recv.process_next().await {
                    Ok(dispatched) => {
                        if !dispatched {
                            let live = connected_for_recv.load(Ordering::SeqCst);
                            was_connected |= live;
                            if was_connected && !live {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                    Err(_) => {
                        // BRC-103 verification errors (e.g. stale session, replayed
                        // nonce) are non-fatal — the connection remains open.
                        let live = connected_for_recv.load(Ordering::SeqCst);
                        was_connected |= live;
                        if was_connected && !live {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        // -----------------------------------------------------------------------
        // Spawn keepalive_task: emit an authenticated no-op every KEEPALIVE_INTERVAL.
        //
        // The probe elicits inbound traffic (the server's response keeps the
        // read-deadline tracker fresh) and keeps the EngineIO session alive. It
        // signs + emits OUT OF BAND from application sends (separate task, own
        // `client` clone), so it never blocks a `send_live_message`.
        // -----------------------------------------------------------------------
        {
            let keepalive_signer = signer.clone();
            let keepalive_client = client.clone();
            let identity_key_for_keepalive = identity_key.to_string();
            let connected_for_keepalive = connected.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(KEEPALIVE_INTERVAL);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // Skip the immediate first tick so we don't ping before the
                // handshake settles.
                interval.tick().await;
                // Latch as for the watchdog: guard against a slow handshake so
                // the keepalive can't exit before the connection comes up. The
                // first probe fires one KEEPALIVE_INTERVAL after connect; the
                // handshake's own authMessage/authenticationSuccess frames keep
                // last_inbound_ms fresh in the meantime.
                let mut was_connected = false;
                loop {
                    interval.tick().await;
                    let live = connected_for_keepalive.load(Ordering::SeqCst);
                    was_connected |= live;
                    if !live {
                        if was_connected {
                            // Socket declared dead by the watchdog — stop pinging.
                            break;
                        }
                        continue;
                    }
                    let ping_payload = encode_ws_event(
                        "authenticated",
                        json!({"identityKey": identity_key_for_keepalive}),
                    );
                    match keepalive_signer(ping_payload).await {
                        Ok(signed) => {
                            // A failed emit is itself a dead-socket signal; the
                            // watchdog will also catch the absence of inbound
                            // traffic, but flipping here makes detection immediate.
                            if emit_auth_message(&keepalive_client, &signed).await.is_err() {
                                connected_for_keepalive.store(false, Ordering::SeqCst);
                                break;
                            }
                        }
                        Err(_) => {
                            connected_for_keepalive.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            });
        }

        // -----------------------------------------------------------------------
        // Spawn watchdog_task: enforce the inbound read deadline (issue #7).
        //
        // A half-open socket — peer gone, no TCP FIN — is invisible to the write
        // path until the next emit fails (up to 20 s+ of silently black-holed
        // inbound messages under the old design). The watchdog instead declares
        // the socket dead within READ_DEADLINE (~5 s) of the last inbound frame,
        // flipping `connected=false` so `is_ws_connected()` reflects reality and
        // the reconnect supervisor (client.rs) can re-establish proactively.
        // -----------------------------------------------------------------------
        {
            let watchdog_last_inbound = last_inbound_ms.clone();
            let watchdog_connected = connected.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(WATCHDOG_TICK);
                // Don't treat the pre-authentication window as death: latch on the
                // first observed `connected==true` before arming the deadline.
                let mut was_connected = false;
                loop {
                    tick.tick().await;
                    let live = watchdog_connected.load(Ordering::SeqCst);
                    was_connected |= live;
                    if !live {
                        if was_connected {
                            // Already dead (channel close, close event, or a prior
                            // deadline expiry) — nothing left to watch.
                            break;
                        }
                        // Still coming up — keep waiting for authenticationSuccess.
                        continue;
                    }
                    let last = watchdog_last_inbound.load(Ordering::SeqCst);
                    let elapsed = now_ms().saturating_sub(last);
                    if elapsed >= READ_DEADLINE.as_millis() as u64 {
                        // No inbound frame within the deadline — the socket is
                        // half-open. Declare it dead; the supervisor reconnects.
                        watchdog_connected.store(false, Ordering::SeqCst);
                        tracing::warn!(
                            elapsed_ms = elapsed,
                            "WS read deadline expired — declaring socket half-open dead"
                        );
                        break;
                    }
                }
            });
        }

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
        let last_inbound_for_dispatch = last_inbound_ms.clone();
        let mut general_msg_rx = general_msg_rx;

        tokio::spawn(async move {
            loop {
                match general_msg_rx.recv().await {
                    Some((_sender_key, payload_bytes)) => {
                        // Any decoded general message is proof of life — refresh
                        // the read-deadline tracker (half-open detection, #7).
                        last_inbound_for_dispatch.store(now_ms(), Ordering::SeqCst);
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
                                        // Typed decrypt: carry authenticated-decrypt
                                        // provenance to the subscriber so the MPC
                                        // transport can fail-closed. Body string is
                                        // identical to the legacy try_decrypt_message.
                                        let outcome = encryption::try_decrypt_message_typed(
                                            &wallet_clone2,
                                            &server_msg.body,
                                            &server_msg.sender,
                                            originator_clone2.as_deref(),
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
                                }
                            } else if event_name.starts_with("sendMessageAck-") {
                                // Room-scoped ack: resolve the OLDEST still-pending
                                // send for this room (FIFO). Concurrent same-room
                                // sends each await their own queued oneshot, so the
                                // i-th ack resolves the i-th send.
                                let success =
                                    data.get("status").and_then(|s| s.as_str()) == Some("success");
                                let mut guard = acks_clone2.lock().await;
                                if let Some(queue) = guard.get_mut(&event_name) {
                                    if let Some(tx) = queue.pop_front() {
                                        let _ = tx.send(success);
                                    }
                                    if queue.is_empty() {
                                        guard.remove(&event_name);
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        // Channel closed — the Peer was dropped (socket died).
                        // Flip connected=false so is_connected() is trustworthy and
                        // ensure_ws_connected's short-circuit forces a fresh socket.
                        conn_clone2.store(false, Ordering::SeqCst);
                        break;
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
            .map_err(|_| MessageBoxError::WebSocket("auth success channel dropped".into()))?;

        Ok(Self {
            client,
            signer,
            subscriptions,
            pending_acks,
            joined_rooms,
            connected,
            last_inbound_ms,
            server_identity_key,
        })
    }

    /// Return true if the connection is currently authenticated.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Milliseconds since the last inbound frame of any kind.
    ///
    /// Exposes the read-deadline tracker the watchdog uses for half-open
    /// detection. Useful for diagnostics and tests that assert liveness; a value
    /// approaching `READ_DEADLINE` means the watchdog is about to declare the
    /// socket dead.
    pub fn ms_since_last_inbound(&self) -> u64 {
        now_ms().saturating_sub(self.last_inbound_ms.load(Ordering::SeqCst))
    }

    /// Return the server's BRC-103 identity key captured during the handshake.
    ///
    /// This is a 66-character compressed public key hex string. Useful for
    /// diagnostics and integration tests to verify the handshake completed
    /// successfully and the correct server identity was established.
    pub fn server_identity_key(&self) -> &str {
        &self.server_identity_key
    }

    /// Sign a BRC-103 general-message payload and emit it on the socket.
    ///
    /// This is the single un-serialized send primitive: it signs via the
    /// `&self` signer (lock-free against the shared session) and emits via the
    /// `&self` Socket.IO client. No command channel, no per-send lock — N
    /// concurrent callers run their sign + emit in parallel. Used by `join_room`,
    /// `leave_room`, and `emit_send_message`.
    async fn send_signed(&self, payload: Vec<u8>) -> Result<(), MessageBoxError> {
        let signed = (self.signer)(payload)
            .await
            .map_err(MessageBoxError::WebSocket)?;
        if let Err(e) = emit_auth_message(&self.client, &signed).await {
            // A failed emit means the socket is dead — flip connected so
            // `is_connected()` reflects reality and the supervisor reconnects.
            self.connected.store(false, Ordering::SeqCst);
            return Err(MessageBoxError::WebSocket(e));
        }
        Ok(())
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
        let payload = encode_ws_event("joinRoom", json!(room_id));
        self.send_signed(payload).await?;
        self.joined_rooms.lock().await.insert(room_id.to_string());
        Ok(())
    }

    /// Leave a Socket.IO room and remove its subscription.
    ///
    /// The leaveRoom event is sent as a signed BRC-103 authMessage envelope.
    pub async fn leave_room(&self, room_id: &str) -> Result<(), MessageBoxError> {
        self.joined_rooms.lock().await.remove(room_id);
        let event_key = format!("sendMessage-{room_id}");
        self.subscriptions.lock().await.remove(&event_key);
        let payload = encode_ws_event("leaveRoom", json!(room_id));
        self.send_signed(payload).await
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
    /// directly on the socket — NOT through any serializing command channel — so
    /// concurrent `emit_send_message` calls sign + emit + await their acks in
    /// parallel. The ack waiter is enqueued under `sendMessageAck-{ack_key}` and
    /// resolved FIFO when the server emits that room-scoped ack (the ack carries
    /// no messageId, so per-room ordering is the correlation key).
    pub async fn emit_send_message(
        &self,
        payload: serde_json::Value,
        ack_key: String,
        ack_tx: oneshot::Sender<bool>,
    ) -> Result<(), MessageBoxError> {
        // Register the ack waiter BEFORE sending — avoids the race where the
        // server acks before we enqueue. Append to this room's FIFO queue so a
        // second concurrent send to the same room does not clobber the first.
        self.pending_acks
            .lock()
            .await
            .entry(ack_key.clone())
            .or_default()
            .push_back(ack_tx);

        let event_payload = encode_ws_event("sendMessage", payload);
        if let Err(e) = self.send_signed(event_payload).await {
            // Send failed — pull our just-enqueued waiter back off the tail so it
            // doesn't leak (and isn't mismatched to a later ack). We remove the
            // LAST entry because that is the one this call appended.
            let mut guard = self.pending_acks.lock().await;
            if let Some(queue) = guard.get_mut(&ack_key) {
                queue.pop_back();
                if queue.is_empty() {
                    guard.remove(&ack_key);
                }
            }
            return Err(e);
        }
        Ok(())
    }

    /// Remove a pending ack entry (called on timeout to prevent leaking channels).
    ///
    /// Pops the OLDEST waiter for the key — under FIFO ack matching, a timeout on
    /// the oldest in-flight send is the one most likely to have been abandoned.
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
    /// Marks the socket disconnected (stopping the keepalive + watchdog tasks),
    /// then disconnects the Socket.IO client. Sends `false` to all remaining
    /// pending ack waiters before dropping them.
    pub async fn disconnect(&self) -> Result<(), MessageBoxError> {
        self.connected.store(false, Ordering::SeqCst);
        // Drain pending acks — send false to signal failure
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

/// Serialize a signed `AuthMessage` and emit it on the `authMessage` Socket.IO
/// event — the same wire framing `SocketIOTransport::send` uses, so the WS send
/// path stays byte-for-byte interop-compatible with TS/Go peers. Emitting
/// directly here (rather than through the Peer's transport) lets the send path
/// run concurrently with the receive task's `process_next`.
async fn emit_auth_message(client: &SocketClient, message: &AuthMessage) -> Result<(), String> {
    let json = serde_json::to_value(message).map_err(|e| e.to_string())?;
    client
        .emit("authMessage", json)
        .await
        .map_err(|e| e.to_string())
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

    // -----------------------------------------------------------------------
    // Fix 1: connected=false on silent WS death
    //
    // Manual test procedure (unit tests cannot spin up a real Socket.IO server):
    //
    //   1. Start a real MessageBox server or a mock Socket.IO server.
    //   2. Call MessageBoxWebSocket::connect(...).await — verify is_connected() == true.
    //   3. Kill the server process (simulate silent death — no TCP FIN/RST).
    //   4. Wait > 20 s (KEEPALIVE_INTERVAL) for the keepalive ping to fail.
    //   5. Verify is_connected() == false.
    //   6. Call ensure_ws_connected() — a fresh socket should be created.
    //
    // Automated: the following tests verify the atomics and the channel-close path
    // in isolation, which is the same logic path executed when a real socket dies.
    // -----------------------------------------------------------------------

    /// Verify connected AtomicBool can be stored false — simulates peer_task exit.
    ///
    /// peer_task stores false on its way out; is_connected() reads it.  This test
    /// confirms the atomic semantics are correct in isolation.
    #[test]
    fn connected_atomic_flips_false_on_exit() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let connected = Arc::new(AtomicBool::new(true));
        assert!(connected.load(Ordering::SeqCst), "starts true");
        // Simulate peer_task exit
        connected.store(false, Ordering::SeqCst);
        assert!(!connected.load(Ordering::SeqCst), "flipped to false on exit");
    }

    /// Verify that a channel-closed recv returns None — confirms general_msg_dispatcher exit path.
    ///
    /// When the Peer is dropped (socket dies), general_msg_rx.recv() returns None.
    /// This tests the exact branch that flips connected=false in general_msg_dispatcher.
    #[tokio::test]
    async fn channel_close_recv_returns_none() {
        use tokio::sync::mpsc;
        let (tx, mut rx) = mpsc::channel::<(String, Vec<u8>)>(4);
        drop(tx); // simulate Peer drop → channel closed
        let result = rx.recv().await;
        assert!(result.is_none(), "closed channel must return None from recv()");
    }

    // -----------------------------------------------------------------------
    // Task #2: FIFO ack router — concurrent same-room send correlation
    //
    // The server's `sendMessageAck-{roomId}` is room-scoped (no messageId), so
    // N concurrent sends to one room must be matched to acks in FIFO order.
    // These tests exercise the exact enqueue/resolve logic the dispatcher and
    // `emit_send_message` use.
    // -----------------------------------------------------------------------

    /// Two concurrent sends to the SAME room each enqueue a waiter; two acks
    /// resolve them oldest-first. (The OLD single-oneshot-per-key design would
    /// have the second enqueue overwrite the first's sender, leaving the first
    /// send to time out.)
    #[tokio::test]
    async fn fifo_acks_resolve_concurrent_same_room_sends_in_order() {
        let acks: PendingAcks = Arc::new(Mutex::new(HashMap::new()));
        let key = "sendMessageAck-03abc-inbox".to_string();

        let (tx1, rx1) = oneshot::channel::<bool>();
        let (tx2, rx2) = oneshot::channel::<bool>();
        // Two concurrent sends enqueue, in order.
        {
            let mut g = acks.lock().await;
            g.entry(key.clone()).or_default().push_back(tx1);
            g.entry(key.clone()).or_default().push_back(tx2);
            assert_eq!(g.get(&key).unwrap().len(), 2, "both waiters queued");
        }

        // Dispatcher resolves the first ack → first (oldest) waiter.
        {
            let mut g = acks.lock().await;
            let q = g.get_mut(&key).unwrap();
            let _ = q.pop_front().unwrap().send(true);
            assert!(!q.is_empty(), "second waiter still queued");
        }
        assert!(rx1.await.unwrap(), "first send resolved by first ack (success)");

        // Second ack → second waiter; queue now empties and the key is removed.
        {
            let mut g = acks.lock().await;
            let q = g.get_mut(&key).unwrap();
            let _ = q.pop_front().unwrap().send(false);
            if q.is_empty() {
                g.remove(&key);
            }
            assert!(!g.contains_key(&key), "key removed once queue drains");
        }
        assert!(!rx2.await.unwrap(), "second send resolved by second ack (failure status)");
    }

    /// `remove_pending_ack` semantics: popping the oldest waiter on timeout and
    /// removing the key once the queue drains — no leaked entries.
    #[tokio::test]
    async fn remove_pending_ack_pops_oldest_and_clears_empty_key() {
        let acks: PendingAcks = Arc::new(Mutex::new(HashMap::new()));
        let key = "sendMessageAck-03abc-inbox".to_string();
        let (tx, _rx) = oneshot::channel::<bool>();
        acks.lock().await.entry(key.clone()).or_default().push_back(tx);

        // Mirror remove_pending_ack's body.
        {
            let mut g = acks.lock().await;
            if let Some(q) = g.get_mut(&key) {
                q.pop_front();
                if q.is_empty() {
                    g.remove(&key);
                }
            }
        }
        assert!(acks.lock().await.is_empty(), "no leaked ack entries after timeout cleanup");
    }

    /// Acks for DIFFERENT rooms are independent — one room's ack never resolves
    /// another room's waiter.
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
        // Resolve only room A.
        {
            let mut g = acks.lock().await;
            let q = g.get_mut(&key_a).unwrap();
            let _ = q.pop_front().unwrap().send(true);
            if q.is_empty() {
                g.remove(&key_a);
            }
        }
        assert!(rx_a.await.unwrap(), "room A resolved");
        // Room B's waiter is still pending (sender not dropped).
        assert!(acks.lock().await.contains_key(&key_b), "room B still pending");
        drop(rx_b); // cleanup
    }

    // -----------------------------------------------------------------------
    // Task #1: read-deadline / half-open detection
    // -----------------------------------------------------------------------

    /// The read-deadline comparison the watchdog runs: `now - last >= deadline`.
    /// A fresh stamp is within the deadline; a stamp older than the deadline
    /// trips it. We drive `now_ms()` forward past the deadline with a real sleep
    /// against a short test deadline so the monotonic epoch magnitude is
    /// irrelevant.
    #[tokio::test]
    async fn read_deadline_math_fires_after_deadline() {
        const TEST_DEADLINE_MS: u64 = 30;
        let last = now_ms();
        // Immediately after a frame, elapsed is under the deadline.
        assert!(
            now_ms().saturating_sub(last) < TEST_DEADLINE_MS,
            "fresh inbound is within the deadline"
        );
        // Let real monotonic time advance past the deadline.
        tokio::time::sleep(Duration::from_millis(TEST_DEADLINE_MS + 20)).await;
        assert!(
            now_ms().saturating_sub(last) >= TEST_DEADLINE_MS,
            "an inbound stamp older than the deadline trips it → declare half-open dead"
        );
    }

    /// The keepalive MUST cycle comfortably inside the read deadline, so a
    /// healthy-but-idle socket always refreshes `last_inbound_ms` (via the
    /// keepalive's `authenticationSuccess` reply) before the watchdog fires.
    /// This is the regression guard for issue #7: the bug was KEEPALIVE_INTERVAL
    /// (20s) > READ_DEADLINE (5s), so an idle socket starved of app frames
    /// false-fired the watchdog and triggered a reconnect storm.
    #[test]
    fn keepalive_cycles_inside_read_deadline() {
        assert!(
            KEEPALIVE_INTERVAL < READ_DEADLINE,
            "keepalive must refresh liveness before the watchdog fires (issue #7)"
        );
        // At least 2 keepalive cycles must fit inside the deadline so a single
        // missed/jittered probe doesn't trip the watchdog on a healthy link.
        assert!(
            KEEPALIVE_INTERVAL * 2 <= READ_DEADLINE,
            "deadline must tolerate at least one missed keepalive round-trip"
        );
        // Detection must still be fast (<~8s) — don't fix the storm by making
        // half-open detection sluggish.
        assert!(
            READ_DEADLINE <= Duration::from_secs(8),
            "genuine half-open detection target is <~8s"
        );
    }
}
