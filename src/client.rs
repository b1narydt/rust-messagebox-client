use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bsv::auth::clients::auth_fetch::AuthFetch;
use bsv::remittance::types::PeerMessage;
use bsv::services::overlay_tools::Network;
use bsv::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
use tokio::sync::{Mutex, OnceCell};
// `Mutex` guards WebSocket state, joined rooms, and the subscription registry.
// HTTP needs no lock: the transport is concurrency-safe (`&self`).

use crate::delivery::DeliveryMode;
use crate::error::MessageBoxError;
use crate::pinned_wallet::PinnedWallet;
use crate::transport::{RelayHttp, RelayResponse};
use crate::types::{
    AuthenticatedPeerMessage, ListMessagesParams, WsSendMessageData, WsSendMessagePayload,
};
use crate::websocket::CertificateProvider;

/// Internal callback type for live message subscriptions. Carries the
/// authenticated-decrypt provenance flag end-to-end (WS dispatch, reconnect
/// replay, HTTP poll backstop). The public `listen_for_live_messages` adapts a
/// caller's `Fn(PeerMessage)` onto this by dropping the flag; the public
/// `listen_for_live_messages_typed` exposes it directly.
type SubscriptionCallback = Arc<dyn Fn(AuthenticatedPeerMessage) + Send + Sync>;

/// Backoff bounds for the proactive reconnect supervisor.
const RECONNECT_BASE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);
const RECONNECT_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(10);

/// Everything needed to open the client's WebSocket. The reconnect
/// supervisor owns one, so it dials exactly as the first connect did.
struct WsDial<W> {
    url: String,
    identity_key: String,
    expected_relay_key: Option<String>,
    certificate_provider: Option<CertificateProvider>,
    wallet: W,
    originator: Option<String>,
}

impl<W> WsDial<W>
where
    W: WalletInterface + Clone + Send + Sync + 'static,
{
    /// Connect and authenticate, answering a certificate request with the
    /// provider when one is configured.
    ///
    /// With a relay identity pin the handshake runs on a [`PinnedWallet`] and
    /// a guarded provider, so no certificate is proved to a server that
    /// proved another key, and such a server, or one that proves a different
    /// key after the handshake, ends the connect with
    /// [`MessageBoxError::RelayIdentityMismatch`].
    async fn connect(&self) -> Result<crate::websocket::MessageBoxWebSocket, MessageBoxError> {
        use crate::websocket::MessageBoxWebSocket;
        let wallet = PinnedWallet::new(self.wallet.clone(), self.expected_relay_key.clone());
        let opened = match &self.certificate_provider {
            Some(provider) => {
                MessageBoxWebSocket::connect_with_certificate_provider(
                    &self.url,
                    &self.identity_key,
                    wallet.clone(),
                    self.originator.clone(),
                    wallet.guard_provider(provider.clone()),
                )
                .await
            }
            None => {
                MessageBoxWebSocket::connect(
                    &self.url,
                    &self.identity_key,
                    wallet.clone(),
                    self.originator.clone(),
                )
                .await
            }
        };
        let ws = match opened {
            Ok(ws) => ws,
            Err(e) => return Err(wallet.refusal().unwrap_or(e)),
        };
        if let Err(e) = crate::transport::check_relay_identity(
            self.expected_relay_key.as_deref(),
            Some(ws.server_identity_key()),
        ) {
            if let Err(close) = ws.disconnect().await {
                tracing::warn!(error = %close, "closing the mismatched relay socket failed");
            }
            return Err(e);
        }
        Ok(ws)
    }
}

/// Establish a fresh WebSocket connection and swap it into `ws_state`, replaying
/// joinRoom + re-subscribe for every active subscription.
///
/// Shared by `ensure_ws_connected` (lazy/on-demand connect) and the reconnect
/// supervisor (proactive heal). Lives as a free function — taking `Arc` handles
/// rather than `&self` — so the `'static` supervisor task can call it without a
/// self-reference. On success the new socket replaces whatever was in
/// `ws_state`; the old (dead) socket is dropped, tearing down its tasks. A
/// failed dial (including a relay identity mismatch) leaves `ws_state` as it
/// was and joins no room. A successful one bumps `connections`, which tells
/// each poll backstop to catch up once.
async fn reconnect_ws<W>(
    ws_state: &Arc<Mutex<Option<crate::websocket::MessageBoxWebSocket>>>,
    subscriptions: &Arc<Mutex<HashMap<String, SubscriptionCallback>>>,
    connections: &AtomicU64,
    dial: &WsDial<W>,
) -> Result<(), MessageBoxError>
where
    W: WalletInterface + Clone + Send + Sync + 'static,
{
    let ws = dial.connect().await?;

    // Replay subscriptions on the fresh socket so the general_msg_dispatcher
    // has callbacks registered for every active room. Without this, events
    // delivered to the reconnected socket are silently dropped.
    {
        let subs = subscriptions.lock().await;
        for (room_id, callback) in subs.iter() {
            let event_key = format!("sendMessage-{room_id}");
            // Re-join the room — ignore errors (server may already know us)
            if let Err(e) = ws.join_room(room_id).await {
                tracing::warn!(room_id, error = %e, "joinRoom replay failed on reconnect");
            } else {
                ws.subscribe(event_key, callback.clone()).await;
                tracing::info!(room_id, "replayed subscription on reconnected socket");
            }
        }
    }

    *ws_state.lock().await = Some(ws);
    connections.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

/// Authenticated HTTP client for the MessageBox protocol.
///
/// `MessageBoxClient<W>` shares a single `AuthFetch<W>` via a bare `Arc` (no
/// `Mutex`). `AuthFetch` is now concurrency-safe: every method takes `&self`,
/// so any number of requests can be in flight on one session simultaneously.
/// The client therefore never serializes HTTP round-trips — concurrent
/// `send`/`list`/`poll` calls on the same `MessageBoxClient` execute in
/// parallel, bounded only by the wallet and the network, not by a client-side
/// lock. (Previously `AuthFetch::fetch()` took `&mut self`, forcing an
/// `Arc<Mutex<AuthFetch>>` that funnelled all traffic through one lock and
/// capped throughput at ~35 req/s; that bottleneck is gone.)
pub struct MessageBoxClient<W: WalletInterface + Clone + 'static> {
    /// Base URL of the MessageBox server (trailing whitespace trimmed on construction).
    host: String,
    /// BRC-31 authenticated HTTP, behind the client's one HTTP door. Cheap to
    /// clone, so background polling tasks share the same session without a
    /// lock; N requests can be in flight at once.
    http: RelayHttp,
    /// Wallet retained for direct encrypt / decrypt calls in `http_ops`.
    wallet: W,
    /// Optional originator string forwarded to wallet operations.
    originator: Option<String>,
    /// Cached identity public key (hex) — populated on first call.
    identity_key: OnceCell<String>,
    /// The relay identity pin (normalised hex), set by
    /// [`with_expected_relay_key`](Self::with_expected_relay_key). `None`
    /// trusts whichever relay answers the host.
    expected_relay_key: Option<String>,
    /// Answers the relay's certificate request on the WebSocket handshake,
    /// set by [`with_certificate_provider`](Self::with_certificate_provider).
    certificate_provider: Option<CertificateProvider>,
    /// Ensures assert_initialized runs the full init path at most once.
    pub(crate) init_once: OnceCell<()>,
    /// Network preset for overlay tools (LookupResolver, TopicBroadcaster).
    /// Defaults to Mainnet; pass Network::Local for localhost integration tests.
    pub(crate) network: Network,
    /// WebSocket connection state (None until first live message call).
    ///
    /// `Arc` so the background reconnect supervisor task can share it and swap a
    /// freshly reconnected socket in without a self-reference.
    ws_state: Arc<Mutex<Option<crate::websocket::MessageBoxWebSocket>>>,
    /// Ensures the reconnect supervisor task is spawned at most once per client.
    reconnect_supervisor: OnceCell<()>,
    /// Counts successful WebSocket connects and reconnects (rooms rejoined).
    /// Each poll backstop lists once when it changes.
    ws_connections: Arc<AtomicU64>,
    /// The longest the poll backstop waits between lists while the WebSocket
    /// is connected.
    poll_interval: Duration,
    /// Tracks which message box rooms have been joined via join_room.
    /// Updated on join_room (insert) and leave_room (remove).
    /// Arc allows sharing with background polling tasks.
    joined_rooms: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Registry of active subscriptions: room_id → callback. Survives reconnects.
    /// Entries are added by listen_for_live_messages and removed by leave_room.
    /// On WS reconnect, ensure_ws_connected replays joinRoom + re-subscribes
    /// each entry on the fresh socket.
    subscriptions: Arc<Mutex<HashMap<String, SubscriptionCallback>>>,
}

impl<W: WalletInterface + Clone + 'static + Send + Sync> MessageBoxClient<W> {
    /// Construct a new `MessageBoxClient`.
    ///
    /// * `host` — Base URL of the MessageBox server.  Trailing whitespace is
    ///   trimmed so callers do not need to sanitize.
    /// * `wallet` — Any `WalletInterface` implementation.
    /// * `originator` — Optional originator string forwarded to wallet ops.
    /// * `network` — Network preset for overlay tools (use `Network::Local` for localhost).
    pub fn new(host: String, wallet: W, originator: Option<String>, network: Network) -> Self {
        MessageBoxClient {
            host: host.trim().to_string(),
            http: RelayHttp::new(Arc::new(AuthFetch::new(wallet.clone())), None),
            wallet,
            originator,
            identity_key: OnceCell::new(),
            expected_relay_key: None,
            certificate_provider: None,
            init_once: OnceCell::new(),
            network,
            ws_state: Arc::new(Mutex::new(None)),
            reconnect_supervisor: OnceCell::new(),
            ws_connections: Arc::new(AtomicU64::new(0)),
            poll_interval: DEFAULT_POLL_INTERVAL,
            joined_rooms: Arc::new(Mutex::new(std::collections::HashSet::new())),
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Convenience constructor defaulting to `Network::Mainnet`.
    pub fn new_mainnet(host: String, wallet: W, originator: Option<String>) -> Self {
        Self::new(host, wallet, originator, Network::Mainnet)
    }

    /// Pin the relay's identity key (hex; case and surrounding whitespace are
    /// ignored).
    ///
    /// Once pinned, the client talks only to its own host and trusts only a
    /// server there that proves this key:
    /// - it does not look up a recipient's relay on the overlay, and lists and
    ///   acknowledges on its own host alone. A call that names another host
    ///   (an `override_host`, or a `_from_host` / `_to_host` method) returns
    ///   [`MessageBoxError::RelayHostRefused`] before any request; hosts are
    ///   compared by scheme, host, port and path, ignoring case, a default
    ///   port and a trailing slash;
    /// - every HTTP response must come from a server that proved this key in
    ///   the BRC-103 handshake, or it is refused with
    ///   [`MessageBoxError::RelayIdentityMismatch`] before its body is used.
    ///   The request has still reached that server;
    /// - every WebSocket connect and reconnect checks the key the server
    ///   proved, and on a mismatch disconnects and returns that error. A live
    ///   send then fails with it rather than falling back to HTTP;
    /// - during either handshake the client proves certificates (from the
    ///   wallet or the [certificate provider](Self::with_certificate_provider))
    ///   only to a server that proved this key, and never pays a `402`
    ///   answer: the HTTP and WebSocket handshakes run on a wallet that
    ///   refuses `create_action`.
    ///
    /// Without a pin the client trusts whichever relay answers each host.
    pub fn with_expected_relay_key(mut self, identity_key: impl AsRef<str>) -> Self {
        let key = crate::transport::normalize_identity_key(identity_key.as_ref());
        let auth_wallet = PinnedWallet::new(self.wallet.clone(), Some(key.clone()));
        self.http = self
            .http
            .with_transport(Arc::new(AuthFetch::new(auth_wallet)))
            .with_pin(key.clone(), self.host.clone());
        self.expected_relay_key = Some(key);
        self
    }

    /// The host a call goes to: `explicit`, else this client's own host.
    ///
    /// A pinned client uses its own host, and refuses an explicit host that
    /// is not that host with [`MessageBoxError::RelayHostRefused`] (see
    /// [`with_expected_relay_key`](Self::with_expected_relay_key)).
    pub(crate) fn relay_host<'a>(
        &'a self,
        explicit: Option<&'a str>,
    ) -> Result<&'a str, MessageBoxError> {
        match explicit {
            Some(host) if self.expected_relay_key.is_some() => {
                if crate::transport::same_host(host, &self.host) {
                    Ok(self.host())
                } else {
                    Err(MessageBoxError::RelayHostRefused {
                        pinned: self.host.clone(),
                        requested: host.to_string(),
                    })
                }
            }
            Some(host) => Ok(host),
            None => Ok(self.host()),
        }
    }

    /// The relay identity pin, if one is set (normalised lowercase hex).
    pub fn expected_relay_key(&self) -> Option<&str> {
        self.expected_relay_key.as_deref()
    }

    /// Answer the relay's certificate request on every WebSocket connect and
    /// reconnect with `provider` (see [`CertificateProvider`]).
    ///
    /// A relay with its identity gate armed asks for one Account Details
    /// certificate during the handshake. Without a provider the WebSocket
    /// handshake fails on such a relay. HTTP requests have no provider hook:
    /// `AuthFetch` answers the same request from the wallet's
    /// `list_certificates`, so the wallet must implement it (see the README).
    pub fn with_certificate_provider(mut self, provider: CertificateProvider) -> Self {
        self.certificate_provider = Some(provider);
        self
    }

    /// Set the longest one send or list waits, in all, on the relay's rate
    /// limit (default 60 s).
    ///
    /// The relay charges HTTP sends, WebSocket sends and lists to one budget
    /// per identity and refuses past it with a wait (`retry_after`). The
    /// client then holds every send and list to that relay for the wait, and
    /// resends a refused send or list, same bytes and id, once it passes.
    /// When the wait would run past this limit the call returns
    /// [`MessageBoxError::RateLimited`] instead. `Duration::ZERO` never waits.
    pub fn with_rate_limit_wait(mut self, wait: Duration) -> Self {
        self.http = self.http.with_rate_limit_wait(wait);
        self
    }

    /// Set the longest the poll backstop of
    /// [`listen_for_live_messages`](Self::listen_for_live_messages) waits
    /// between lists while the WebSocket is connected (default 15 s).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// How this client dials its WebSocket at `override_host` or its own host.
    async fn ws_dial(&self, override_host: Option<&str>) -> Result<WsDial<W>, MessageBoxError> {
        Ok(WsDial {
            url: override_host.unwrap_or_else(|| self.host()).to_string(),
            identity_key: self.get_identity_key().await?,
            expected_relay_key: self.expected_relay_key.clone(),
            certificate_provider: self.certificate_provider.clone(),
            wallet: self.wallet.clone(),
            originator: self.originator.clone(),
        })
    }

    // -----------------------------------------------------------------------
    // Public getters (needed by http_ops)
    // -----------------------------------------------------------------------

    /// Return the trimmed host URL.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Return a reference to the underlying wallet.
    pub fn wallet(&self) -> &W {
        &self.wallet
    }

    /// Return the originator string, if any.
    pub fn originator(&self) -> Option<&str> {
        self.originator.as_deref()
    }

    /// Return the network preset used for overlay operations.
    pub fn network(&self) -> &Network {
        &self.network
    }

    // -----------------------------------------------------------------------
    // Identity key
    // -----------------------------------------------------------------------

    /// Return the wallet's identity public key as a DER hex string.
    ///
    /// The result is cached in a `OnceCell` — subsequent calls return the
    /// cached value without calling the wallet again.
    pub async fn get_identity_key(&self) -> Result<String, MessageBoxError> {
        if let Some(k) = self.identity_key.get() {
            return Ok(k.clone());
        }

        let result = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        let key = result.public_key.to_der_hex();
        // Ignore the error — if another caller set the cell first, we just use
        // the stored value.
        let _ = self.identity_key.set(key.clone());
        Ok(key)
    }

    // -----------------------------------------------------------------------
    // Initialization guard
    // -----------------------------------------------------------------------

    /// Ensure the client is initialized before performing any HTTP operation.
    ///
    /// Uses `init_once.get_or_try_init` so the full init path runs at most once
    /// even under concurrent callers — matching the TS `initializeConnection`
    /// pattern which defers work until first use.
    ///
    /// Init sequence:
    /// 1. Cache identity key.
    /// 2. Query overlay advertisements for this identity + host.
    /// 3. If no matching ad exists, call `anoint_host`.
    /// 4. CRITICAL TS PARITY: catch anoint errors and continue — TS logs
    ///    "Failed to anoint host, continuing with default functionality".
    pub(crate) async fn assert_initialized(&self) -> Result<(), MessageBoxError> {
        self.init_once
            .get_or_try_init(|| async {
                let identity_key = self.get_identity_key().await?;
                // Query existing advertisements for this identity+host pair.
                // unwrap_or_default() because query_advertisements never fails (TS parity).
                let ads = self
                    .query_advertisements(Some(&identity_key), Some(&self.host))
                    .await
                    .unwrap_or_default();
                if ads.iter().all(|ad| ad.host.trim() != self.host.trim()) {
                    // No matching advertisement — anoint this host.
                    // CRITICAL TS PARITY: catch anoint errors and continue.
                    // TS: "Failed to anoint host, continuing with default functionality"
                    if let Err(e) = self.anoint_host(&self.host).await {
                        eprintln!("Warning: failed to anoint host: {e}");
                    }
                }
                Ok::<(), MessageBoxError>(())
            })
            .await?;
        Ok(())
    }

    /// Initialize the client — ensures overlay advertisement exists.
    ///
    /// User-facing wrapper for `assert_initialized`. Safe to call multiple times —
    /// the init path runs exactly once due to `init_once` OnceCell semantics.
    ///
    /// `target_host`: when Some, uses that host for the anoint_host call instead of
    /// `self.host()`. Matches the TS `init(targetHost?)` signature.
    pub async fn init(&self, target_host: Option<&str>) -> Result<(), MessageBoxError> {
        match target_host {
            Some(host) => {
                // TS parity: if targetHost provided, anoint THAT host directly
                // instead of going through assert_initialized's self.host logic.
                self.init_once
                    .get_or_try_init(|| async {
                        let _identity_key = self.get_identity_key().await?;
                        // CRITICAL TS PARITY: catch anoint errors and continue.
                        if let Err(e) = self.anoint_host(host).await {
                            eprintln!("Warning: failed to anoint host: {e}");
                        }
                        Ok::<(), MessageBoxError>(())
                    })
                    .await?;
                Ok(())
            }
            None => self.assert_initialized().await,
        }
    }

    /// Ensure the WebSocket connection is established.
    ///
    /// User-facing wrapper for `ensure_ws_connected`. Mirrors the TS
    /// `initializeConnection` method. When `override_host` is Some, the WS
    /// connection uses that host instead of `self.host()`.
    pub async fn initialize_connection(
        &self,
        override_host: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        self.ensure_ws_connected(override_host).await
    }

    /// Returns a clone of the set of currently joined message box room names.
    ///
    /// Each entry is a raw room ID of the form `{identityKey}-{messageBox}`.
    /// Mirrors the TS `joinedRooms` Map accessor.
    pub fn get_joined_rooms(&self) -> std::collections::HashSet<String> {
        // Use blocking lock — this is only called from synchronous test contexts.
        // For async callers, they should be fine as the lock is never held across await.
        self.joined_rooms.blocking_lock().clone()
    }

    /// Returns `Some(true)` if a WebSocket connection is active, `None` otherwise.
    ///
    /// Sync test utility mirroring the TS `testSocket` accessor. Only callable from
    /// sync test contexts (e.g., unit tests) where `blocking_lock` is safe.
    #[cfg(test)]
    pub fn test_socket(&self) -> Option<bool> {
        let guard = self.ws_state.blocking_lock();
        guard.as_ref().map(|ws| ws.is_connected())
    }

    /// Returns the current WebSocket connection state.
    ///
    /// `None` = no WebSocket connected yet. `Some(true)` = connected and authenticated.
    /// `Some(false)` = connected but BRC-103 handshake not yet complete.
    ///
    /// Async version of `test_socket` — safe to call from integration tests and any
    /// async context. Mirrors the TS `testSocket` accessor.
    pub async fn is_ws_connected(&self) -> Option<bool> {
        let guard = self.ws_state.lock().await;
        guard.as_ref().map(|ws| ws.is_connected())
    }

    /// Join a Socket.IO room for a message box and track it in `joined_rooms`.
    ///
    /// Constructs the room ID as `{identityKey}-{messageBox}` (matching TS joinRoom).
    /// Ensures the WebSocket is connected before joining.
    /// No-op if the room is already joined (idempotent like TS joinRoom).
    pub async fn join_room(&self, message_box: &str) -> Result<(), MessageBoxError> {
        let identity_key = self.get_identity_key().await?;
        let room_id = format!("{identity_key}-{message_box}");

        self.ensure_ws_connected(None).await?;

        {
            let guard = self.ws_state.lock().await;
            if let Some(ref ws) = *guard {
                ws.join_room(&room_id).await?;
            }
        }

        self.joined_rooms.lock().await.insert(room_id);
        Ok(())
    }

    /// POST JSON bytes to `url` using BRC-31 authenticated transport. A
    /// non-2xx status is an error.
    ///
    /// The transport takes `&self` and is concurrency-safe, so this call holds
    /// no client-side lock — multiple `post_json` calls on the same client run
    /// in parallel.
    pub(crate) async fn post_json(
        &self,
        url: &str,
        body_bytes: Vec<u8>,
    ) -> Result<RelayResponse, MessageBoxError> {
        self.http.fetch_ok(url, "POST", Some(body_bytes)).await
    }

    /// POST a send or list to `url` on `host`, waiting out the relay's rate
    /// limit and resending the same bytes after a refusal, within the
    /// rate-limit wait ([`RelayHttp::fetch_budgeted`]).
    pub(crate) async fn post_budgeted(
        &self,
        host: &str,
        url: &str,
        body_bytes: Vec<u8>,
    ) -> Result<RelayResponse, MessageBoxError> {
        self.http.fetch_budgeted(host, url, body_bytes).await
    }

    /// POST JSON bytes to `url`, returning the response **regardless of HTTP
    /// status** so the caller can inspect the body on a non-2xx reply.
    pub(crate) async fn post_json_raw(
        &self,
        url: &str,
        body_bytes: Vec<u8>,
    ) -> Result<RelayResponse, MessageBoxError> {
        self.http.fetch_raw(url, "POST", Some(body_bytes)).await
    }

    /// Replace the HTTP transport (unit tests drive a scripted relay). Call it
    /// last: [`with_expected_relay_key`](Self::with_expected_relay_key)
    /// installs its own transport.
    #[cfg(test)]
    pub(crate) fn with_transport(
        mut self,
        transport: Arc<dyn crate::transport::HttpTransport>,
    ) -> Self {
        self.http = self.http.with_transport(transport);
        self
    }

    // -----------------------------------------------------------------------
    // WebSocket live messaging
    // -----------------------------------------------------------------------

    /// Ensure a WebSocket connection is established and authenticated.
    ///
    /// If no connection exists or the existing connection is no longer connected,
    /// creates a new `MessageBoxWebSocket` with the current identity key.
    /// `rust_socketio` handles the Socket.IO handshake and HTTP-to-WS upgrade
    /// internally — we pass the same base URL used for HTTP requests.
    async fn ensure_ws_connected(
        &self,
        override_host: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        // A pinned client opens and uses a socket only at its own host.
        self.relay_host(override_host)?;
        // Fast path: already connected.
        if self
            .ws_state
            .lock()
            .await
            .as_ref()
            .map(|ws| ws.is_connected())
            .unwrap_or(false)
        {
            // Still make sure the supervisor is watching this live socket.
            self.spawn_reconnect_supervisor(override_host).await?;
            return Ok(());
        }

        let dial = self.ws_dial(override_host).await?;
        reconnect_ws(
            &self.ws_state,
            &self.subscriptions,
            &self.ws_connections,
            &dial,
        )
        .await?;

        // Start the proactive reconnect supervisor (idempotent) so a later
        // half-open death is healed in the background, not on the next call.
        self.spawn_reconnect_supervisor(override_host).await?;
        Ok(())
    }

    /// Spawn the background reconnect supervisor exactly once.
    ///
    /// The supervisor watches the WS connection's `is_connected()` flag. When the
    /// watchdog (websocket.rs) flips it false on a half-open death — within
    /// ~READ_DEADLINE, not 20 s+ — the supervisor proactively re-establishes the
    /// socket with jittered backoff and replays joinRoom + re-subscribes every
    /// active subscription, WITHOUT waiting for the next send/receive call. This
    /// is what makes `is_ws_connected()` reflect reality and live delivery resume
    /// on its own after a transient partition.
    async fn spawn_reconnect_supervisor(
        &self,
        override_host: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        if self.reconnect_supervisor.get().is_some() {
            return Ok(());
        }
        let dial = self.ws_dial(override_host).await?;

        // OnceCell::set races are benign — only one initializer wins; the loser
        // simply skips spawning a duplicate.
        if self.reconnect_supervisor.set(()).is_err() {
            return Ok(());
        }

        let ws_state = self.ws_state.clone();
        let subscriptions = self.subscriptions.clone();
        let ws_connections = self.ws_connections.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                // Only reconnect if (a) a socket exists, (b) it is dead, and
                // (c) there is at least one active subscription to keep alive.
                // A fresh client with no live listeners should not hold a socket
                // open just because the supervisor is running.
                let needs_reconnect = {
                    let guard = ws_state.lock().await;
                    match guard.as_ref() {
                        Some(ws) => !ws.is_connected(),
                        None => false,
                    }
                };
                if !needs_reconnect {
                    continue;
                }
                if subscriptions.lock().await.is_empty() {
                    continue;
                }

                // Reconnect with jittered exponential backoff until it succeeds
                // or the listeners go away.
                let mut backoff = RECONNECT_BASE_BACKOFF;
                loop {
                    if subscriptions.lock().await.is_empty() {
                        break;
                    }
                    match reconnect_ws(&ws_state, &subscriptions, &ws_connections, &dial).await {
                        Ok(()) => {
                            tracing::info!("WS reconnected proactively after half-open death");
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, backoff_ms = backoff.as_millis() as u64, "proactive WS reconnect failed; retrying");
                            // Jitter: sleep backoff ± up to 25% to avoid
                            // thundering-herd reconnects across many clients.
                            let jitter = rand::random::<f64>() * 0.5 - 0.25; // [-0.25, +0.25)
                            let millis = backoff.as_millis() as f64 * (1.0 + jitter);
                            tokio::time::sleep(std::time::Duration::from_millis(
                                millis.max(1.0) as u64
                            ))
                            .await;
                            backoff = (backoff * 2).min(RECONNECT_MAX_BACKOFF);
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Listen for live messages on a message box via WebSocket.
    ///
    /// Joins the Socket.IO room `{identity_key}-{message_box}` and registers
    /// the provided callback. Messages can arrive via three paths, all funnelled
    /// through one shared dedup wrapper so the callback fires at most once per id:
    ///
    /// 1. **WebSocket push (primary):** the BRC-103 `general_msg_dispatcher` fires
    ///    the callback when the server broadcasts a signed `sendMessage-{roomId}`.
    /// 2. **WebSocket `on_any` (fallback):** the same callback, for servers that
    ///    emit raw (unsigned) room events.
    /// 3. **HTTP poll (backstop):** a background task that lists the box over
    ///    `/listMessages`. Lists cost the same relay rate budget as sends, so it
    ///    lists sparingly: while the WebSocket is connected, once on each
    ///    connect and reconnect (to catch up on what arrived while it was
    ///    down), then at most every 15 s
    ///    ([`with_poll_interval`](Self::with_poll_interval)); with no
    ///    connected WebSocket, after 1 s, doubling to 8 s. It waits out a
    ///    rate-limit refusal, and backs off after a failed list (up to 60 s),
    ///    including a list too large to accept, which it logs as an error;
    ///    live delivery carries on meanwhile. Stops when `leave_room` removes
    ///    the room from `joined_rooms`.
    ///
    /// All paths deliver `PeerMessage` with decrypted body to the same callback.
    ///
    /// Establishes a WebSocket connection if one is not already active.
    /// `override_host` is reserved for future multi-host WS routing.
    pub async fn listen_for_live_messages(
        &self,
        message_box: &str,
        on_message: Arc<dyn Fn(PeerMessage) + Send + Sync>,
        override_host: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        // Adapt the legacy `Fn(PeerMessage)` consumer onto the typed core by
        // dropping the authenticated-decrypt flag. Existing consumers (peerpay,
        // payment_requests, adapter) are unaffected — same `PeerMessage` delivery.
        let typed: Arc<dyn Fn(AuthenticatedPeerMessage) + Send + Sync> =
            Arc::new(move |m: AuthenticatedPeerMessage| {
                on_message(PeerMessage {
                    message_id: m.message_id,
                    sender: m.sender,
                    recipient: m.recipient,
                    message_box: m.message_box,
                    body: m.body,
                });
            });
        self.listen_for_live_messages_typed(message_box, typed, override_host)
            .await
    }

    /// Typed sibling of [`Self::listen_for_live_messages`] that delivers an
    /// [`AuthenticatedPeerMessage`] carrying the authenticated-decrypt provenance
    /// flag. Use this when a consumer must reject bodies that did not AEAD-decrypt
    /// against the claimed sender (the MPC transport's fail-closed boundary).
    ///
    /// Identical delivery semantics to `listen_for_live_messages` (WS primary,
    /// WS `on_any` fallback, HTTP poll backstop; exactly-once dedup; reconnect
    /// replay) — only the delivered type differs.
    pub async fn listen_for_live_messages_typed(
        &self,
        message_box: &str,
        on_message: Arc<dyn Fn(AuthenticatedPeerMessage) + Send + Sync>,
        override_host: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        let identity_key = self.get_identity_key().await?;
        let room_id = format!("{identity_key}-{message_box}");
        let event_key = format!("sendMessage-{room_id}");

        self.ensure_ws_connected(override_host).await?;

        // One user callback, three possible delivery paths (WS primary
        // dispatcher, WS `on_any` fallback, HTTP poll). Wrap once so a
        // `message_id` reaches the user at most once regardless of which path
        // wins the race.
        let deduped = exactly_once(on_message);

        let ws_callback = deduped.clone();

        {
            let guard = self.ws_state.lock().await;
            if let Some(ref ws) = *guard {
                ws.join_room(&room_id).await?;
                ws.subscribe(event_key.clone(), ws_callback.clone()).await;
            }
        }

        // Register in the subscription registry so ensure_ws_connected can replay
        // this subscription (with its dedup + activity wrappers) on any reconnect.
        self.subscriptions
            .lock()
            .await
            .insert(room_id.clone(), ws_callback.clone());

        self.joined_rooms.lock().await.insert(room_id.clone());

        // Spawn the HTTP poll backstop (see the cadence on `PollCadence`).
        let poll_http = self.http.clone();
        let poll_joined_rooms = self.joined_rooms.clone();
        let poll_ws_state = self.ws_state.clone();
        let poll_connections = self.ws_connections.clone();
        let poll_host = self.host.clone();
        let poll_message_box = message_box.to_string();
        let poll_identity_key = identity_key.clone();
        let poll_wallet = self.wallet.clone();
        let poll_originator = self.originator.clone();
        let poll_room_id = room_id.clone();
        let poll_callback = deduped;
        let mut cadence = PollCadence::new(
            self.poll_interval,
            self.ws_connections.load(Ordering::Acquire),
        );

        tokio::spawn(async move {
            loop {
                // Stop when the room is no longer active (leave_room was called)
                if !poll_joined_rooms.lock().await.contains(&poll_room_id) {
                    break;
                }

                let connected = poll_ws_state
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|ws| ws.is_connected());
                let live = connected.then(|| poll_connections.load(Ordering::Acquire));
                if !cadence.due(tokio::time::Instant::now(), live) {
                    tokio::time::sleep(POLL_TICK).await;
                    continue;
                }

                // The shared `deduped` callback suppresses anything WS already
                // delivered.
                let listed = poll_list_messages(
                    &poll_http,
                    &poll_host,
                    &poll_message_box,
                    &poll_identity_key,
                    &poll_wallet,
                    poll_originator.as_deref(),
                )
                .await;
                let failure = match listed {
                    Ok(messages) => {
                        for msg in messages {
                            poll_callback(msg);
                        }
                        None
                    }
                    Err(e) => {
                        // Only the list-size bound fails as Validation: the
                        // box holds more than one list may carry, and the
                        // relay does not paginate.
                        if matches!(e, MessageBoxError::Validation(_)) {
                            tracing::error!(
                                room_id = %poll_room_id,
                                error = %e,
                                "poll backstop cannot list this box; live delivery continues"
                            );
                        } else {
                            tracing::warn!(
                                room_id = %poll_room_id,
                                error = %e,
                                "poll backstop failed; message catch-up delayed"
                            );
                        }
                        Some(e)
                    }
                };
                cadence.listed(
                    tokio::time::Instant::now(),
                    live.is_some(),
                    failure.as_ref(),
                );
            }
        });

        Ok(())
    }

    /// Send a message via WebSocket with 10-second ack timeout and HTTP fallback.
    ///
    /// Mirrors TS `sendLiveMessage`: auto-connects if needed, joins the sender's
    /// own room, then emits. Falls back to HTTP, with the same message id, if
    /// the connection cannot be established, the emit fails, the relay refuses
    /// the send (`messageFailed`), or no ack names this message within 10 s.
    /// A pinned client whose socket meets a relay that proves another key
    /// returns [`MessageBoxError::RelayIdentityMismatch`] and sends nothing
    /// over HTTP. Before the emit it waits out a rate-limit hold on the relay, and returns
    /// [`MessageBoxError::RateLimited`] if that wait would pass
    /// [`with_rate_limit_wait`](Self::with_rate_limit_wait).
    ///
    /// TS parity: HTTP fallback resolves recipient's host via overlay before sending.
    /// The WS path connects to `self.host()` — overlay resolution affects the fallback path.
    ///
    /// Mirrors TS `sendLiveMessage(params, overrideHost?)` which accepts the full
    /// `SendMessageParams` including `skipEncryption`, `checkPermissions`, and `messageId`.
    ///
    /// - `skip_encryption`: when true, sends body as-is without BRC-78 encryption.
    /// - `check_permissions`: when true, the HTTP fallback path fetches quotes and pays fees.
    /// - `message_id`: when Some, uses caller-supplied ID instead of HMAC-derived ID.
    /// - `override_host`: when Some, the HTTP fallback sends to that host directly.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_live_message(
        &self,
        recipient: &str,
        message_box: &str,
        body: &str,
        skip_encryption: bool,
        check_permissions: bool,
        message_id: Option<&str>,
        override_host: Option<&str>,
    ) -> Result<DeliveryMode, MessageBoxError> {
        // If no host override, resolve the recipient's host via overlay.
        // If the recipient is on a DIFFERENT host than ours, we must use HTTP
        // (send_message with overlay resolution) since our WebSocket is only
        // connected to self.host.
        if override_host.is_none() {
            let resolved = self
                .resolve_host_for_recipient(recipient)
                .await
                .unwrap_or_else(|_| self.host().to_string());
            if resolved.trim() != self.host().trim() {
                // Recipient is on a different MessageBox server — use HTTP with overlay.
                // This is a persisted delivery (no live WS ack possible cross-host).
                let msg_id = self
                    .send_message(
                        recipient,
                        message_box,
                        body,
                        skip_encryption,
                        check_permissions,
                        message_id,
                        None,
                    )
                    .await?;
                return Ok(DeliveryMode::Persisted { message_id: msg_id });
            }
        }

        // Auto-connect or reconnect — if the WebSocket is disconnected, drop the
        // stale connection and establish a fresh one with a new BRC-103 handshake.
        // This handles proxy timeouts and server restarts without falling through
        // to the slower HTTP fallback path.
        {
            let guard = self.ws_state.lock().await;
            if guard.as_ref().map(|ws| !ws.is_connected()).unwrap_or(false) {
                drop(guard);
                // Stale connection — tear down and reconnect
                if let Err(e) = self.disconnect_web_socket().await {
                    eprintln!(
                        "Warning: stale WebSocket disconnect failed (proceeding to reconnect): {e}"
                    );
                }
            }
        }
        if let Err(e) = self.ensure_ws_connected(override_host).await {
            // A pinned client named another host, or the server at this host
            // is not the pinned relay: the send ends here, with nothing sent
            // over HTTP.
            if matches!(
                e,
                MessageBoxError::RelayIdentityMismatch { .. }
                    | MessageBoxError::RelayHostRefused { .. }
            ) {
                return Err(e);
            }
            eprintln!("Warning: WebSocket connection failed, falling back to HTTP: {e}");
            // Returns Persisted because no WS ack was received.
            let msg_id = self
                .send_persisted(
                    override_host,
                    recipient,
                    message_box,
                    body,
                    skip_encryption,
                    check_permissions,
                    message_id,
                )
                .await?;
            return Ok(DeliveryMode::Persisted { message_id: msg_id });
        }

        // Join sender's own room before send — TS calls joinRoom(messageBox) which
        // joins `${myIdentityKey}-${messageBox}`.
        let identity_key = self.get_identity_key().await?;
        let my_room = format!("{identity_key}-{message_box}");
        let joined = {
            let guard = self.ws_state.lock().await;
            match *guard {
                Some(ref ws) => ws.join_room(&my_room).await.is_ok(),
                None => false,
            }
        };
        if !joined {
            let msg_id = self
                .send_persisted(
                    override_host,
                    recipient,
                    message_box,
                    body,
                    skip_encryption,
                    check_permissions,
                    message_id,
                )
                .await?;
            return Ok(DeliveryMode::Persisted { message_id: msg_id });
        }

        // Encrypt (unless skip_encryption) and resolve message ID for the WebSocket path
        let encrypted = if skip_encryption {
            body.to_string()
        } else {
            crate::encryption::encrypt_body(self.wallet(), body, recipient, self.originator())
                .await?
        };
        let message_id = if let Some(id) = message_id {
            id.to_string()
        } else {
            crate::encryption::generate_message_id(
                self.wallet(),
                body,
                recipient,
                self.originator(),
            )
            .await?
        };

        // The relay lowercases the HTTP recipient but compares the WS room key
        // with the recipient exactly, and rooms are joined lowercase. Send both
        // lowercase so a mixed-case key reaches the recipient's room.
        let recipient_key = recipient.trim().to_ascii_lowercase();
        let data = WsSendMessageData {
            room_id: format!("{recipient_key}-{message_box}"),
            message: WsSendMessagePayload {
                message_id: message_id.clone(),
                recipient: recipient_key,
                body: encrypted,
            },
        };

        // A live send spends the same relay budget as HTTP, and a refusal on
        // the socket fails every pending live send, so wait out a known hold.
        self.http
            .wait_for_rate_limit(
                override_host.unwrap_or_else(|| self.host()),
                self.http.rate_limit_deadline(),
            )
            .await?;

        // Emit — hold the lock only for the emit, not while awaiting the answer.
        let emitted = {
            let guard = self.ws_state.lock().await;
            match *guard {
                Some(ref ws) => ws.emit_send_message(&data).await,
                None => Err(MessageBoxError::WebSocket("not connected".to_string())),
            }
        };
        let outcome = match emitted {
            Ok(ack) => ack.wait(LIVE_ACK_TIMEOUT).await,
            Err(e) => Err(e),
        };
        self.finish_live_send(
            outcome,
            override_host,
            recipient,
            message_box,
            body,
            skip_encryption,
            check_permissions,
            message_id,
        )
        .await
    }

    /// Turn the relay's answer to a live send into the delivery result.
    ///
    /// Accepted: [`DeliveryMode::Live`]. Anything else (refused, no answer in
    /// time, emit failed): send over HTTP with the SAME id already emitted
    /// over the WebSocket. The live push may have reached the receiver even
    /// though its answer was lost, and receivers dedup by message id, so a
    /// fresh id would arrive as a second logical message. The relay is not
    /// exactly-once: it collapses a resend only while the first row still
    /// exists (INSERT IGNORE), and an ack deletes that row.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finish_live_send(
        &self,
        outcome: Result<(), MessageBoxError>,
        override_host: Option<&str>,
        recipient: &str,
        message_box: &str,
        body: &str,
        skip_encryption: bool,
        check_permissions: bool,
        message_id: String,
    ) -> Result<DeliveryMode, MessageBoxError> {
        if let Err(reason) = outcome {
            tracing::debug!(%reason, %message_id, "live send not accepted; sending over HTTP");
            // A rate-limit refusal holds the relay, so the HTTP send below
            // waits it out instead of being refused too.
            self.http
                .hold_for_rate_limit(override_host.unwrap_or_else(|| self.host()), &reason);
            let http_id = self
                .send_persisted(
                    override_host,
                    recipient,
                    message_box,
                    body,
                    skip_encryption,
                    check_permissions,
                    Some(&message_id),
                )
                .await?;
            return Ok(DeliveryMode::Persisted {
                message_id: http_id,
            });
        }
        Ok(DeliveryMode::Live { message_id })
    }

    /// The HTTP send behind every live-send fallback: to `override_host` when
    /// given, else to the recipient's overlay-resolved host.
    #[allow(clippy::too_many_arguments)]
    async fn send_persisted(
        &self,
        override_host: Option<&str>,
        recipient: &str,
        message_box: &str,
        body: &str,
        skip_encryption: bool,
        check_permissions: bool,
        message_id: Option<&str>,
    ) -> Result<String, MessageBoxError> {
        match override_host {
            Some(host) => {
                self.send_message_to_host(
                    host,
                    recipient,
                    message_box,
                    body,
                    skip_encryption,
                    check_permissions,
                    message_id,
                    None,
                )
                .await
            }
            None => {
                self.send_message(
                    recipient,
                    message_box,
                    body,
                    skip_encryption,
                    check_permissions,
                    message_id,
                    None,
                )
                .await
            }
        }
    }

    /// Leave a Socket.IO room and remove its subscription.
    ///
    /// Mirrors TS `leaveRoom(messageBox)`. Constructs the room ID as
    /// `{identityKey}-{messageBox}` and emits `leaveRoom` to the server.
    /// No-op if the WebSocket is not connected.
    /// `override_host` is reserved for future multi-host WS routing.
    pub async fn leave_room(
        &self,
        message_box: &str,
        override_host: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        let _ = override_host;
        let identity_key = self.get_identity_key().await?;
        let room_id = format!("{identity_key}-{message_box}");
        // Tear down LOCAL subscription state FIRST and UNCONDITIONALLY, before the
        // WS emit. The HTTP poll backstop loop breaks only when `joined_rooms` no
        // longer contains the room, and reconnect-replay is driven by
        // `subscriptions`. Neither must depend on the WS `leaveRoom` emit
        // succeeding: if the socket is flaky at teardown (exactly when churn
        // peaks), gating removal on the emit would leave the per-box
        // `GET /listMessages` poll running forever and re-subscribing on
        // reconnect — the listener leak this teardown exists to close.
        self.joined_rooms.lock().await.remove(&room_id);
        self.subscriptions.lock().await.remove(&room_id);
        // Best-effort server-side leave. The local teardown above already stopped
        // the poll loop; the server also drops the room on disconnect. A failed
        // emit is surfaced to the caller but no longer leaves a leak behind.
        {
            let guard = self.ws_state.lock().await;
            if let Some(ref ws) = *guard {
                ws.leave_room(&room_id).await?;
            }
        }
        Ok(())
    }

    /// Disconnect the WebSocket connection and clear its state.
    ///
    /// Safe to call when no connection is active (no-op).
    pub async fn disconnect_web_socket(&self) -> Result<(), MessageBoxError> {
        let mut guard = self.ws_state.lock().await;
        if let Some(ws) = guard.take() {
            ws.disconnect().await?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal HTTP helpers
    // -----------------------------------------------------------------------

    /// GET `url` using BRC-31 authenticated transport. A non-2xx status is an
    /// error. The caller builds the full URL including query string.
    pub(crate) async fn get_json(&self, url: &str) -> Result<RelayResponse, MessageBoxError> {
        self.http.fetch_ok(url, "GET", None).await
    }
}

// ---------------------------------------------------------------------------
// Delivery callback wrappers
// ---------------------------------------------------------------------------

/// How long a live send waits for the relay to accept or refuse it before
/// it falls back to HTTP.
const LIVE_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Wrap a subscriber callback so each `message_id` is delivered **at most once**,
/// no matter which path produced it: the WS primary dispatcher, the WS `on_any`
/// fallback, or the HTTP poll backstop. Without this, a server that both pushes
/// and is polled (or an `on_any`/dispatcher race) fires the callback twice.
///
/// Dedup is bounded to the most recent 10,000 distinct ids (FIFO eviction), so a
/// duplicate separated from its original by more than 10,000 intervening ids can
/// still slip through — acceptable for the single-use-mailbox traffic this
/// serves. This suppresses duplicates only; delivery liveness comes from the
/// WS + poll paths, not from this wrapper.
fn exactly_once(
    inner: Arc<dyn Fn(AuthenticatedPeerMessage) + Send + Sync>,
) -> Arc<dyn Fn(AuthenticatedPeerMessage) + Send + Sync> {
    let seen = Arc::new(std::sync::Mutex::new(BoundedIdSet::new(10_000)));
    Arc::new(move |msg: AuthenticatedPeerMessage| {
        // Recover rather than panic on poison: a poisoned dedup set is harmless
        // (worst case one duplicate delivery), whereas panicking here would kill
        // the WS dispatcher or the spawned poll task and stop delivery entirely.
        let fresh = match seen.lock() {
            Ok(mut g) => g.insert(msg.message_id.clone()),
            Err(poisoned) => poisoned.into_inner().insert(msg.message_id.clone()),
        };
        if fresh {
            inner(msg);
        }
    })
}

/// How often the poll backstop wakes to decide whether to list.
const POLL_TICK: Duration = Duration::from_secs(1);
/// Default for [`MessageBoxClient::with_poll_interval`].
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(15);
/// Without a connected WebSocket the poll lists after `POLL_OFFLINE_MIN`,
/// doubling up to `POLL_OFFLINE_MAX`.
const POLL_OFFLINE_MIN: Duration = Duration::from_secs(1);
const POLL_OFFLINE_MAX: Duration = Duration::from_secs(8);
/// After a failed list the poll waits `POLL_ERROR_MIN`, doubling up to
/// `POLL_ERROR_MAX`, on top of its usual cadence.
const POLL_ERROR_MIN: Duration = Duration::from_secs(2);
const POLL_ERROR_MAX: Duration = Duration::from_secs(60);

/// When the poll backstop lists next.
///
/// Every list costs the relay rate budget that sends also spend (10 a
/// minute for an uncertified key), so the poll lists only:
/// - first thing, and once after every WebSocket connect or reconnect, to
///   catch up on what arrived while the socket was down;
/// - while the socket is connected, `live_interval` after the last list;
/// - with no connected socket, `POLL_OFFLINE_MIN` after the last list,
///   doubling to `POLL_OFFLINE_MAX`;
/// - never before a rate-limit refusal's `retry_after` has passed, or before
///   a growing back-off after a failed list.
struct PollCadence {
    live_interval: Duration,
    /// The connection count at the last catch-up.
    connections: u64,
    last_list: Option<tokio::time::Instant>,
    /// Lists in a row made with no connected socket.
    offline_streak: u32,
    error_wait: Option<Duration>,
    not_before: Option<tokio::time::Instant>,
}

impl PollCadence {
    fn new(live_interval: Duration, connections: u64) -> Self {
        Self {
            live_interval,
            connections,
            last_list: None,
            offline_streak: 0,
            error_wait: None,
            not_before: None,
        }
    }

    /// Whether to list now. `live` is the connection count while the
    /// WebSocket is connected, `None` while it is not.
    fn due(&mut self, now: tokio::time::Instant, live: Option<u64>) -> bool {
        if self.not_before.is_some_and(|t| now < t) {
            return false;
        }
        let Some(last) = self.last_list else {
            return true;
        };
        match live {
            Some(connections) if connections != self.connections => {
                self.connections = connections;
                true
            }
            Some(_) => now >= last + self.live_interval,
            None => now >= last + self.offline_wait(),
        }
    }

    /// The wait before the next list with no connected socket: 1 s after a
    /// connected list (or the first), then doubling up to `POLL_OFFLINE_MAX`.
    fn offline_wait(&self) -> Duration {
        let doublings = self.offline_streak.saturating_sub(1).min(31);
        POLL_OFFLINE_MIN
            .saturating_mul(1 << doublings)
            .min(POLL_OFFLINE_MAX)
    }

    /// Record a list made at `now` while the socket was `live`, and how it
    /// failed, if it did.
    fn listed(&mut self, now: tokio::time::Instant, live: bool, failure: Option<&MessageBoxError>) {
        self.last_list = Some(now);
        self.offline_streak = if live {
            0
        } else {
            self.offline_streak.saturating_add(1)
        };
        self.not_before = match failure {
            None => {
                self.error_wait = None;
                None
            }
            Some(MessageBoxError::RateLimited { retry_after, .. }) => Some(now + *retry_after),
            Some(_) => {
                let wait = self
                    .error_wait
                    .map_or(POLL_ERROR_MIN, |w| (w * 2).min(POLL_ERROR_MAX));
                self.error_wait = Some(wait);
                Some(now + wait)
            }
        };
    }
}

// ---------------------------------------------------------------------------
// Bounded dedup set
// ---------------------------------------------------------------------------

/// A bounded set with FIFO eviction for deduplicating message IDs.
///
/// Prevents unbounded memory growth in the HTTP polling fallback task.
/// When the set reaches `capacity`, the oldest entry is evicted before
/// inserting the new one.
struct BoundedIdSet {
    set: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl BoundedIdSet {
    fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "BoundedIdSet capacity must be at least 1");
        Self {
            set: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Insert an ID. Returns `true` if the ID was new (not previously seen).
    fn insert(&mut self, id: String) -> bool {
        if self.set.contains(&id) {
            return false;
        }
        if self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(id.clone());
        self.order.push_back(id);
        debug_assert_eq!(
            self.set.len(),
            self.order.len(),
            "BoundedIdSet internal invariant violated: set/deque size mismatch"
        );
        true
    }

    /// Returns the number of IDs currently tracked.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.order.len()
    }

    /// Returns true if the given ID is currently in the set.
    #[cfg(test)]
    fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }
}

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/// Poll `/listMessages` for a given message box using a shared authenticated HTTP client.
///
/// This is used by the background polling task spawned in `listen_for_live_messages`
/// to deliver messages as a fallback when the server does not broadcast via WS push.
///
/// Returns a `Vec<AuthenticatedPeerMessage>` with decrypted bodies (and their
/// authenticated-decrypt provenance), or an empty vec on error.
/// `accept_payments` is always false — the polling path does not handle delivery fees.
async fn poll_list_messages<W>(
    http: &RelayHttp,
    host: &str,
    message_box: &str,
    identity_key: &str,
    wallet: &W,
    originator: Option<&str>,
) -> Result<Vec<AuthenticatedPeerMessage>, MessageBoxError>
where
    W: WalletInterface + Clone + Send + Sync + 'static,
{
    let params = ListMessagesParams {
        message_box: message_box.to_string(),
    };
    let body_bytes = serde_json::to_vec(&params)?;
    let url = format!("{host}/listMessages");
    let response = http.fetch_budgeted(host, &url, body_bytes).await?;

    // Apply the same pre-deserialization page cap and single-pass success parser
    // as the public full/lite list paths.
    let list_response = crate::http_ops::parse_bounded_list_response(&response.body)?;

    let mut result = Vec::with_capacity(list_response.messages.len());
    for msg in list_response.messages {
        // Simple body extraction: if the body is a wrapped envelope, extract the message field.
        let plain_body = extract_plain_body(&msg.body);
        // Typed decrypt: carry authenticated-decrypt provenance through the poll
        // backstop so the MPC transport fails-closed identically on this path.
        let outcome = crate::encryption::try_decrypt_message_typed(
            wallet,
            &plain_body,
            &msg.sender,
            originator,
        )
        .await;

        result.push(AuthenticatedPeerMessage {
            message_id: msg.message_id,
            sender: msg.sender,
            recipient: identity_key.to_string(),
            message_box: message_box.to_string(),
            authenticated_decrypt: outcome.is_authenticated(),
            body: outcome.into_body(),
        });
    }

    Ok(result)
}

/// Extract the plain message body from a potentially server-wrapped envelope.
///
/// The server sometimes wraps messages as `{"message": "...", "payment": {...}}`.
/// This helper unwraps it. If the body isn't a wrapped envelope, returns it as-is.
fn extract_plain_body(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(message) = v.get("message") {
            return match message {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
        }
    }
    body.to_string()
}

/// Check if a successful (2xx) HTTP response body contains a server-level
/// error indicator (`{"status": "error", "description": "..."}`).
///
/// The MessageBox server can return HTTP 200 with a logical error payload —
/// this helper normalises that into `MessageBoxError::Auth`.
pub(crate) fn check_status_error(body: &[u8]) -> Result<(), MessageBoxError> {
    // Attempt a lightweight parse — ignore failures (malformed JSON is not
    // a server error in this sense).
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
        if v.get("status").and_then(|s| s.as_str()) == Some("error") {
            let description = v
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return Err(MessageBoxError::Auth(description));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ws_loopback_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::private_key::PrivateKey;
    use bsv::services::overlay_tools::Network;
    use bsv::wallet::error::WalletError;
    use bsv::wallet::interfaces::*;
    use bsv::wallet::proto_wallet::ProtoWallet;
    use std::sync::Arc;

    /// Thin Arc wrapper that makes ProtoWallet clone-able for test purposes.
    ///
    /// ProtoWallet does not implement Clone because it holds a non-Clone
    /// KeyDeriver.  Wrapping in Arc satisfies the Clone bound while sharing
    /// the same underlying wallet across the clone and the AuthFetch instance.
    #[derive(Clone)]
    pub(super) struct ArcWallet(Arc<ProtoWallet>, Option<Arc<CertificateProbe>>);

    /// One certificate the wallet lists, and a count of the proofs asked of
    /// it. A proof is counted, then refused.
    pub(super) struct CertificateProbe {
        certificate: Certificate,
        pub(super) proofs: std::sync::atomic::AtomicUsize,
    }

    impl ArcWallet {
        fn new() -> Self {
            let key = PrivateKey::from_random().expect("random key");
            ArcWallet(Arc::new(ProtoWallet::new(key)), None)
        }

        /// A wallet for a fixed private key (64 hex characters).
        pub(super) fn from_key_hex(key_hex: &str) -> Self {
            let key = PrivateKey::from_hex(key_hex).expect("private key hex");
            ArcWallet(Arc::new(ProtoWallet::new(key)), None)
        }

        /// A wallet for a fixed key that holds `certificate` and counts the
        /// proofs asked of it.
        pub(super) fn holding(
            key_hex: &str,
            certificate: Certificate,
        ) -> (Self, Arc<CertificateProbe>) {
            let probe = Arc::new(CertificateProbe {
                certificate,
                proofs: Default::default(),
            });
            let mut wallet = Self::from_key_hex(key_hex);
            wallet.1 = Some(probe.clone());
            (wallet, probe)
        }
    }

    // Delegate every WalletInterface method to the inner ProtoWallet.
    #[async_trait::async_trait]
    impl WalletInterface for ArcWallet {
        async fn create_action(
            &self,
            args: CreateActionArgs,
            orig: Option<&str>,
        ) -> Result<CreateActionResult, WalletError> {
            self.0.create_action(args, orig).await
        }
        async fn sign_action(
            &self,
            args: SignActionArgs,
            orig: Option<&str>,
        ) -> Result<SignActionResult, WalletError> {
            self.0.sign_action(args, orig).await
        }
        async fn abort_action(
            &self,
            args: AbortActionArgs,
            orig: Option<&str>,
        ) -> Result<AbortActionResult, WalletError> {
            self.0.abort_action(args, orig).await
        }
        async fn list_actions(
            &self,
            args: ListActionsArgs,
            orig: Option<&str>,
        ) -> Result<ListActionsResult, WalletError> {
            self.0.list_actions(args, orig).await
        }
        async fn internalize_action(
            &self,
            args: InternalizeActionArgs,
            orig: Option<&str>,
        ) -> Result<InternalizeActionResult, WalletError> {
            self.0.internalize_action(args, orig).await
        }
        async fn list_outputs(
            &self,
            args: ListOutputsArgs,
            orig: Option<&str>,
        ) -> Result<ListOutputsResult, WalletError> {
            self.0.list_outputs(args, orig).await
        }
        async fn relinquish_output(
            &self,
            args: RelinquishOutputArgs,
            orig: Option<&str>,
        ) -> Result<RelinquishOutputResult, WalletError> {
            self.0.relinquish_output(args, orig).await
        }
        async fn get_public_key(
            &self,
            args: GetPublicKeyArgs,
            orig: Option<&str>,
        ) -> Result<GetPublicKeyResult, WalletError> {
            self.0.get_public_key(args, orig).await
        }
        async fn reveal_counterparty_key_linkage(
            &self,
            args: RevealCounterpartyKeyLinkageArgs,
            orig: Option<&str>,
        ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
            self.0.reveal_counterparty_key_linkage(args, orig).await
        }
        async fn reveal_specific_key_linkage(
            &self,
            args: RevealSpecificKeyLinkageArgs,
            orig: Option<&str>,
        ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
            self.0.reveal_specific_key_linkage(args, orig).await
        }
        async fn encrypt(
            &self,
            args: EncryptArgs,
            orig: Option<&str>,
        ) -> Result<EncryptResult, WalletError> {
            self.0.encrypt(args, orig).await
        }
        async fn decrypt(
            &self,
            args: DecryptArgs,
            orig: Option<&str>,
        ) -> Result<DecryptResult, WalletError> {
            self.0.decrypt(args, orig).await
        }
        async fn create_hmac(
            &self,
            args: CreateHmacArgs,
            orig: Option<&str>,
        ) -> Result<CreateHmacResult, WalletError> {
            self.0.create_hmac(args, orig).await
        }
        async fn verify_hmac(
            &self,
            args: VerifyHmacArgs,
            orig: Option<&str>,
        ) -> Result<VerifyHmacResult, WalletError> {
            self.0.verify_hmac(args, orig).await
        }
        async fn create_signature(
            &self,
            args: CreateSignatureArgs,
            orig: Option<&str>,
        ) -> Result<CreateSignatureResult, WalletError> {
            self.0.create_signature(args, orig).await
        }
        async fn verify_signature(
            &self,
            args: VerifySignatureArgs,
            orig: Option<&str>,
        ) -> Result<VerifySignatureResult, WalletError> {
            self.0.verify_signature(args, orig).await
        }
        async fn acquire_certificate(
            &self,
            args: AcquireCertificateArgs,
            orig: Option<&str>,
        ) -> Result<Certificate, WalletError> {
            self.0.acquire_certificate(args, orig).await
        }
        async fn list_certificates(
            &self,
            args: ListCertificatesArgs,
            orig: Option<&str>,
        ) -> Result<ListCertificatesResult, WalletError> {
            match &self.1 {
                Some(probe) => Ok(ListCertificatesResult {
                    total_certificates: 1,
                    certificates: vec![CertificateResult {
                        certificate: probe.certificate.clone(),
                        keyring: None,
                        verifier: None,
                    }],
                }),
                None => self.0.list_certificates(args, orig).await,
            }
        }
        async fn prove_certificate(
            &self,
            args: ProveCertificateArgs,
            orig: Option<&str>,
        ) -> Result<ProveCertificateResult, WalletError> {
            if let Some(probe) = &self.1 {
                probe
                    .proofs
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.0.prove_certificate(args, orig).await
        }
        async fn relinquish_certificate(
            &self,
            args: RelinquishCertificateArgs,
            orig: Option<&str>,
        ) -> Result<RelinquishCertificateResult, WalletError> {
            self.0.relinquish_certificate(args, orig).await
        }
        async fn discover_by_identity_key(
            &self,
            args: DiscoverByIdentityKeyArgs,
            orig: Option<&str>,
        ) -> Result<DiscoverCertificatesResult, WalletError> {
            self.0.discover_by_identity_key(args, orig).await
        }
        async fn discover_by_attributes(
            &self,
            args: DiscoverByAttributesArgs,
            orig: Option<&str>,
        ) -> Result<DiscoverCertificatesResult, WalletError> {
            self.0.discover_by_attributes(args, orig).await
        }
        async fn is_authenticated(
            &self,
            orig: Option<&str>,
        ) -> Result<AuthenticatedResult, WalletError> {
            self.0.is_authenticated(orig).await
        }
        async fn wait_for_authentication(
            &self,
            orig: Option<&str>,
        ) -> Result<AuthenticatedResult, WalletError> {
            self.0.wait_for_authentication(orig).await
        }
        async fn get_height(&self, orig: Option<&str>) -> Result<GetHeightResult, WalletError> {
            self.0.get_height(orig).await
        }
        async fn get_header_for_height(
            &self,
            args: GetHeaderArgs,
            orig: Option<&str>,
        ) -> Result<GetHeaderResult, WalletError> {
            self.0.get_header_for_height(args, orig).await
        }
        async fn get_network(&self, orig: Option<&str>) -> Result<GetNetworkResult, WalletError> {
            self.0.get_network(orig).await
        }
        async fn get_version(&self, orig: Option<&str>) -> Result<GetVersionResult, WalletError> {
            self.0.get_version(orig).await
        }
    }

    /// `new()` must trim leading/trailing whitespace from the host URL.
    #[tokio::test]
    async fn new_trims_host_url() {
        let wallet = ArcWallet::new();
        let client = MessageBoxClient::new(
            "https://example.com ".to_string(),
            wallet,
            None,
            Network::Mainnet,
        );
        assert_eq!(client.host(), "https://example.com");
    }

    /// `get_identity_key` returns a non-empty hex string.
    #[tokio::test]
    async fn get_identity_key_returns_non_empty_hex() {
        let wallet = ArcWallet::new();
        let client = MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            Network::Mainnet,
        );
        let key = client.get_identity_key().await.expect("get_identity_key");
        assert!(!key.is_empty(), "identity key must be non-empty");
        assert!(
            key.chars().all(|c| c.is_ascii_hexdigit()),
            "identity key must be hex"
        );
    }

    /// `get_json` exists — compile check via type coercion to async fn pointer.
    ///
    /// We verify the method resolves without calling it (no live network needed).
    #[allow(dead_code)]
    fn get_json_compiles(client: &MessageBoxClient<ArcWallet>) {
        // If get_json does not exist or has wrong signature, this fn fails to compile.
        let _fut = client.get_json("https://example.com/test");
    }

    // -----------------------------------------------------------------------
    // Fix 2: Subscription registry tests
    // -----------------------------------------------------------------------

    /// Subscription registry starts empty on construction.
    #[tokio::test]
    async fn subscription_registry_starts_empty() {
        let wallet = ArcWallet::new();
        let client = MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            Network::Mainnet,
        );
        let subs = client.subscriptions.lock().await;
        assert!(subs.is_empty(), "subscriptions must be empty on new client");
    }

    /// Subscription registry can be populated and queried directly.
    ///
    /// This exercises the same path as listen_for_live_messages inserting into
    /// the registry. Full reconnect replay requires a live Socket.IO server.
    #[tokio::test]
    async fn subscription_registry_insert_and_lookup() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let wallet = ArcWallet::new();
        let client = MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet.clone(),
            None,
            Network::Mainnet,
        );
        let identity_key = client.get_identity_key().await.expect("identity key");

        // Simulate what listen_for_live_messages does: build room_id and insert callback.
        let room_id = format!("{identity_key}-test_inbox");
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();
        let callback: Arc<dyn Fn(crate::types::AuthenticatedPeerMessage) + Send + Sync> =
            Arc::new(move |_msg| {
                fired_clone.store(true, Ordering::SeqCst);
            });

        client
            .subscriptions
            .lock()
            .await
            .insert(room_id.clone(), callback.clone());

        // Verify it was stored
        let subs = client.subscriptions.lock().await;
        assert!(subs.contains_key(&room_id), "room_id must be in registry");
        assert_eq!(subs.len(), 1, "registry must have exactly one entry");

        // Verify the stored callback is callable
        let cb = subs.get(&room_id).cloned().expect("callback must exist");
        drop(subs);
        cb(crate::types::AuthenticatedPeerMessage {
            message_id: "test".to_string(),
            sender: "03sender".to_string(),
            recipient: identity_key.clone(),
            message_box: "test_inbox".to_string(),
            body: "hello".to_string(),
            authenticated_decrypt: true,
        });
        assert!(
            fired.load(Ordering::SeqCst),
            "callback must have been invoked"
        );
    }

    /// Subscription registry entry is removed when leave_room is called — compile check.
    ///
    /// Full removal requires ws_state to be Some (live connection). Here we verify
    /// the direct remove path on the registry in isolation.
    #[tokio::test]
    async fn subscription_registry_remove_on_leave() {
        let wallet = ArcWallet::new();
        let client = MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            Network::Mainnet,
        );
        let identity_key = client.get_identity_key().await.expect("identity key");
        let room_id = format!("{identity_key}-inbox");

        // Insert a dummy callback
        let cb: Arc<dyn Fn(crate::types::AuthenticatedPeerMessage) + Send + Sync> =
            Arc::new(|_| {});
        client
            .subscriptions
            .lock()
            .await
            .insert(room_id.clone(), cb);
        assert_eq!(client.subscriptions.lock().await.len(), 1, "inserted");

        // Remove it directly (simulates what leave_room does)
        client.subscriptions.lock().await.remove(&room_id);
        assert!(client.subscriptions.lock().await.is_empty(), "removed");
    }

    /// `check_status_error` returns Ok for success body.
    #[test]
    fn check_status_error_passes_success_body() {
        use super::check_status_error;
        let body = br#"{"status":"success","data":{}}"#;
        assert!(check_status_error(body).is_ok());
    }

    /// `check_status_error` returns Err for server error body.
    #[test]
    fn check_status_error_returns_err_for_error_body() {
        use super::check_status_error;
        let body = br#"{"status":"error","description":"permission denied"}"#;
        let err = check_status_error(body).unwrap_err();
        assert!(matches!(err, crate::error::MessageBoxError::Auth(_)));
        assert_eq!(err.to_string(), "auth error: permission denied");
    }

    /// `get_identity_key` returns the same value on a second call (OnceCell cache).
    #[tokio::test]
    async fn get_identity_key_caches_result() {
        let wallet = ArcWallet::new();
        let client = MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            Network::Mainnet,
        );
        let key1 = client.get_identity_key().await.expect("first call");
        let key2 = client.get_identity_key().await.expect("second call");
        assert_eq!(key1, key2, "OnceCell must return the same value on re-call");
    }

    /// `init_once` field is of type `OnceCell<()>` — compile check.
    ///
    /// The init_once field must be retained so assert_initialized can be wired
    /// through it in Phase 5. This test verifies the field type and existence.
    #[test]
    fn test_init_compiles() {
        let wallet = ArcWallet::new();
        let client = MessageBoxClient::new(
            "https://example.com".to_string(),
            wallet,
            None,
            Network::Mainnet,
        );
        // Verify the init_once field can be referenced and the public init() method exists.
        // If init_once were removed or its type changed, this compile-check fails.
        let _cell: &OnceCell<()> = &client.init_once;
        // Public init() must exist — verified by type resolution.
        // Verify init() exists and returns a Future — drop without awaiting.
        drop(client.init(None));
    }

    // -----------------------------------------------------------------------
    // BoundedIdSet tests
    // -----------------------------------------------------------------------

    /// BoundedIdSet rejects duplicate inserts.
    #[test]
    fn bounded_id_set_rejects_duplicates() {
        let mut set = super::BoundedIdSet::new(100);
        assert!(set.insert("a".to_string()), "first insert returns true");
        assert!(!set.insert("a".to_string()), "duplicate returns false");
        assert_eq!(set.len(), 1);
    }

    /// BoundedIdSet evicts oldest entries when at capacity.
    #[test]
    fn bounded_id_set_evicts_oldest() {
        let mut set = super::BoundedIdSet::new(3);
        set.insert("a".to_string());
        set.insert("b".to_string());
        set.insert("c".to_string());
        // At capacity — next insert should evict "a"
        assert!(set.insert("d".to_string()));
        assert!(!set.contains("a"), "oldest entry must be evicted");
        assert!(set.contains("b"));
        assert!(set.contains("c"));
        assert!(set.contains("d"));
        // "a" is now unknown — should be insertable again
        assert!(
            set.insert("a".to_string()),
            "evicted entry can be re-inserted"
        );
    }

    /// BoundedIdSet panics on capacity=0.
    #[test]
    #[should_panic(expected = "capacity must be at least 1")]
    fn bounded_id_set_rejects_zero_capacity() {
        super::BoundedIdSet::new(0);
    }

    fn peer_msg(id: &str) -> crate::types::AuthenticatedPeerMessage {
        crate::types::AuthenticatedPeerMessage {
            message_id: id.to_string(),
            sender: "03sender".to_string(),
            recipient: "02recipient".to_string(),
            message_box: "inbox".to_string(),
            body: "body".to_string(),
            authenticated_decrypt: true,
        }
    }

    #[test]
    fn exactly_once_delivers_each_message_id_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let inner: Arc<dyn Fn(crate::types::AuthenticatedPeerMessage) + Send + Sync> =
            Arc::new(move |_m| {
                c.fetch_add(1, Ordering::SeqCst);
            });
        let deduped = super::exactly_once(inner);

        // Same id arriving on three "paths" (WS dispatcher, WS on_any, poll).
        deduped(peer_msg("m1"));
        deduped(peer_msg("m1"));
        deduped(peer_msg("m1"));
        // A distinct id still gets through.
        deduped(peer_msg("m2"));

        assert_eq!(count.load(Ordering::SeqCst), 2, "m1 once + m2 once");
    }

    /// While the socket is connected the poll lists first thing, then once
    /// per reconnect, and otherwise only every `live_interval`.
    #[test]
    fn a_connected_poll_lists_on_each_connect_then_every_interval() {
        let s = std::time::Duration::from_secs;
        let t0 = tokio::time::Instant::now();
        let mut cadence = super::PollCadence::new(s(15), 1);

        assert!(cadence.due(t0, Some(1)), "first thing");
        cadence.listed(t0, true, None);
        assert!(!cadence.due(t0 + s(14), Some(1)));
        assert!(cadence.due(t0 + s(15), Some(1)), "the safety net");
        cadence.listed(t0 + s(15), true, None);
        assert!(cadence.due(t0 + s(16), Some(2)), "a reconnect catches up");
        cadence.listed(t0 + s(16), true, None);
        assert!(!cadence.due(t0 + s(17), Some(2)), "once per reconnect");
    }

    /// Without a socket the poll backs off 1 s doubling to 8 s; it waits out
    /// a rate-limit refusal, and failed lists back off to 60 s, never spin.
    #[test]
    fn a_poll_backs_off_offline_after_refusals_and_after_failures() {
        let s = std::time::Duration::from_secs;
        let just_before = |t: tokio::time::Instant| t - std::time::Duration::from_millis(1);
        let mut t = tokio::time::Instant::now();
        let mut cadence = super::PollCadence::new(s(15), 0);
        assert!(cadence.due(t, None));
        cadence.listed(t, false, None);
        for wait in [1, 2, 4, 8, 8] {
            assert!(!cadence.due(just_before(t + s(wait)), None), "{wait}s");
            t += s(wait);
            assert!(cadence.due(t, None), "{wait}s");
            cadence.listed(t, false, None);
        }

        let refused = MessageBoxError::RateLimited {
            retry_after: s(30),
            tier: None,
        };
        cadence.listed(t, false, Some(&refused));
        assert!(!cadence.due(just_before(t + s(30)), None));
        t += s(30);
        assert!(cadence.due(t, None));

        let too_big = MessageBoxError::Validation("listMessages response too large".into());
        for _ in 0..6 {
            cadence.listed(t, true, Some(&too_big));
        }
        assert!(!cadence.due(just_before(t + s(60)), Some(0)));
        assert!(cadence.due(t + s(60), Some(0)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn exactly_once_is_safe_under_concurrent_delivery() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // The deduped callback is shared across the WS dispatcher, on_any, and
        // the poll task concurrently. Hammer the same ids from many tasks and
        // assert each id is delivered exactly once.
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let inner: Arc<dyn Fn(crate::types::AuthenticatedPeerMessage) + Send + Sync> =
            Arc::new(move |_m| {
                c.fetch_add(1, Ordering::SeqCst);
            });
        let deduped = super::exactly_once(inner);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let cb = deduped.clone();
            handles.push(tokio::spawn(async move {
                for i in 0..100 {
                    cb(peer_msg(&format!("m{i}")));
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        // 100 distinct ids, each delivered exactly once despite 8 racing tasks.
        assert_eq!(count.load(Ordering::SeqCst), 100);
    }
}
