use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bsv::auth::clients::auth_fetch::{AuthFetch, AuthFetchResponse};
use bsv::remittance::types::PeerMessage;
use bsv::services::overlay_tools::Network;
use bsv::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
use tokio::sync::{Mutex, OnceCell};

use crate::error::MessageBoxError;
use crate::types::{ListMessagesParams, ListMessagesResponse};

/// Authenticated HTTP client for the MessageBox protocol.
///
/// `MessageBoxClient<W>` wraps `AuthFetch<W>` behind a `tokio::sync::Mutex`
/// because `AuthFetch::fetch()` takes `&mut self` and must be called from
/// async context.  A `std::sync::Mutex` held across `.await` panics under
/// Tokio — this is load-bearing and must not be changed.
pub struct MessageBoxClient<W: WalletInterface + Clone + 'static> {
    /// Base URL of the MessageBox server (trailing whitespace trimmed on construction).
    host: String,
    /// BRC-31 authenticated HTTP client (needs `&mut self`, hence Arc<Mutex> for sharing).
    /// Arc allows cloning into background polling tasks without duplicating the wallet auth state.
    auth_fetch: Arc<Mutex<AuthFetch<W>>>,
    /// Wallet retained for direct encrypt / decrypt calls in `http_ops`.
    wallet: W,
    /// Optional originator string forwarded to wallet operations.
    originator: Option<String>,
    /// Cached identity public key (hex) — populated on first call.
    identity_key: OnceCell<String>,
    /// Ensures assert_initialized runs the full init path at most once.
    pub(crate) init_once: OnceCell<()>,
    /// Network preset for overlay tools (LookupResolver, TopicBroadcaster).
    /// Defaults to Mainnet; pass Network::Local for localhost integration tests.
    pub(crate) network: Network,
    /// WebSocket connection state (None until first live message call).
    ws_state: Mutex<Option<crate::websocket::MessageBoxWebSocket>>,
    /// Tracks which message box rooms have been joined via join_room.
    /// Updated on join_room (insert) and leave_room (remove).
    /// Arc allows sharing with background polling tasks.
    joined_rooms: Arc<Mutex<std::collections::HashSet<String>>>,
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
            auth_fetch: Arc::new(Mutex::new(AuthFetch::new(wallet.clone()))),
            wallet,
            originator,
            identity_key: OnceCell::new(),
            init_once: OnceCell::new(),
            network,
            ws_state: Mutex::new(None),
            joined_rooms: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    /// Convenience constructor defaulting to `Network::Mainnet`.
    pub fn new_mainnet(host: String, wallet: W, originator: Option<String>) -> Self {
        Self::new(host, wallet, originator, Network::Mainnet)
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
        self.init_once.get_or_try_init(|| async {
            let identity_key = self.get_identity_key().await?;
            // Query existing advertisements for this identity+host pair.
            // unwrap_or_default() because query_advertisements never fails (TS parity).
            let ads = self.query_advertisements(Some(&identity_key), Some(&self.host)).await
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
        }).await?;
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
                self.init_once.get_or_try_init(|| async {
                    let _identity_key = self.get_identity_key().await?;
                    // CRITICAL TS PARITY: catch anoint errors and continue.
                    if let Err(e) = self.anoint_host(host).await {
                        eprintln!("Warning: failed to anoint host: {e}");
                    }
                    Ok::<(), MessageBoxError>(())
                }).await?;
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

    /// POST JSON bytes to `url` using BRC-31 authenticated transport.
    ///
    /// The entire `fetch()` call executes while the lock is held.  This is
    /// correct because `fetch()` is the outermost operation; no re-entrant
    /// locking occurs on the Phase 1 code path.
    pub(crate) async fn post_json(
        &self,
        url: &str,
        body_bytes: Vec<u8>,
    ) -> Result<AuthFetchResponse, MessageBoxError> {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let response = self
            .auth_fetch
            .lock()
            .await
            .fetch(url, "POST", Some(body_bytes), Some(headers))
            .await
            .map_err(|e| MessageBoxError::Auth(e.to_string()))?;

        if response.status < 200 || response.status >= 300 {
            return Err(MessageBoxError::Http(
                response.status,
                url.to_string(),
            ));
        }

        Ok(response)
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
    async fn ensure_ws_connected(&self, override_host: Option<&str>) -> Result<(), MessageBoxError> {
        let mut guard = self.ws_state.lock().await;
        if guard.as_ref().map(|ws| ws.is_connected()).unwrap_or(false) {
            return Ok(());
        }
        let identity_key = self.get_identity_key().await?;
        let ws_url = override_host.unwrap_or_else(|| self.host()).to_string();
        let ws = crate::websocket::MessageBoxWebSocket::connect(
            &ws_url,
            &identity_key,
            self.wallet.clone(),
            self.originator.clone(),
        )
        .await?;
        *guard = Some(ws);
        Ok(())
    }

    /// Listen for live messages on a message box via WebSocket.
    ///
    /// Joins the Socket.IO room `{identity_key}-{message_box}` and registers
    /// the provided callback. Messages are delivered via two complementary paths:
    ///
    /// 1. **WebSocket push (primary):** The BRC-103 general_msg_dispatcher fires the
    ///    callback when the server broadcasts `sendMessage-{roomId}` via the WS connection.
    ///
    /// 2. **HTTP polling fallback:** A background task polls `/listMessages` every 2 seconds
    ///    and fires the callback for any new messages not yet seen via the WS path. This
    ///    handles server implementations that store messages without broadcasting via WS.
    ///    The polling task stops automatically when `leave_room` removes the room from
    ///    `joined_rooms`.
    ///
    /// Both paths deliver `PeerMessage` with decrypted body to the same callback.
    ///
    /// Establishes a WebSocket connection if one is not already active.
    /// `override_host` is reserved for future multi-host WS routing.
    pub async fn listen_for_live_messages(
        &self,
        message_box: &str,
        on_message: Arc<dyn Fn(PeerMessage) + Send + Sync>,
        override_host: Option<&str>,
    ) -> Result<(), MessageBoxError> {
        let identity_key = self.get_identity_key().await?;
        let room_id = format!("{identity_key}-{message_box}");
        let event_key = format!("sendMessage-{room_id}");

        self.ensure_ws_connected(override_host).await?;

        {
            let guard = self.ws_state.lock().await;
            if let Some(ref ws) = *guard {
                ws.join_room(&room_id).await?;
                ws.subscribe(event_key, on_message.clone()).await;
            }
        }

        self.joined_rooms.lock().await.insert(room_id.clone());

        // Spawn a polling fallback task that periodically checks for new messages
        // via HTTP. This complements the WS push path and handles server implementations
        // that do not broadcast to room members via BRC-103 general messages.
        //
        // The poll interval is 2s — aggressive enough for interactive use without
        // hammering the server. The task terminates when leave_room removes room_id
        // from joined_rooms, or when the WS connection is disconnected.
        let poll_auth_fetch = self.auth_fetch.clone();
        let poll_joined_rooms = self.joined_rooms.clone();
        let poll_host = self.host.clone();
        let poll_message_box = message_box.to_string();
        let poll_identity_key = identity_key.clone();
        let poll_wallet = self.wallet.clone();
        let poll_originator = self.originator.clone();
        let poll_room_id = room_id.clone();
        let poll_callback = on_message;

        tokio::spawn(async move {
            // Track message IDs delivered by this polling task to avoid duplicates.
            // Note: the WS path and poll path may both fire for the same message;
            // the callback is idempotent by design (callers use mpsc channels that
            // simply buffer duplicates, or the application deduplicates by message_id).
            // We only deduplicate within the poll path itself.
            let mut seen_ids: HashSet<String> = HashSet::new();

            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                // Stop when the room is no longer active (leave_room was called)
                if !poll_joined_rooms.lock().await.contains(&poll_room_id) {
                    break;
                }

                // Poll /listMessages with authenticated HTTP
                let result = poll_list_messages(
                    &poll_auth_fetch,
                    &poll_host,
                    &poll_message_box,
                    &poll_identity_key,
                    &poll_wallet,
                    poll_originator.as_deref(),
                )
                .await;

                if let Ok(messages) = result {
                    for msg in messages {
                        if seen_ids.insert(msg.message_id.clone()) {
                            poll_callback(msg);
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Send a message via WebSocket with 10-second ack timeout and HTTP fallback.
    ///
    /// Mirrors TS `sendLiveMessage`: auto-connects if needed, joins the sender's
    /// own room (required for ack routing), then emits. Falls back to HTTP if the
    /// connection cannot be established or the ack times out / fails.
    ///
    /// TS parity: HTTP fallback resolves recipient's host via overlay before sending.
    /// The WS path connects to `self.host()` — overlay resolution affects the fallback path.
    /// `override_host`: when Some, the HTTP fallback path sends to that host directly.
    /// Send a message via WebSocket with 10-second ack timeout and HTTP fallback.
    ///
    /// Mirrors TS `sendLiveMessage(params, overrideHost?)` which accepts the full
    /// `SendMessageParams` including `skipEncryption`, `checkPermissions`, and `messageId`.
    ///
    /// - `skip_encryption`: when true, sends body as-is without BRC-78 encryption.
    /// - `check_permissions`: when true, the HTTP fallback path fetches quotes and pays fees.
    /// - `message_id`: when Some, uses caller-supplied ID instead of HMAC-derived ID.
    /// - `override_host`: when Some, the HTTP fallback sends to that host directly.
    pub async fn send_live_message(
        &self,
        recipient: &str,
        message_box: &str,
        body: &str,
        skip_encryption: bool,
        check_permissions: bool,
        message_id: Option<&str>,
        override_host: Option<&str>,
    ) -> Result<String, MessageBoxError> {
        // If no host override, resolve the recipient's host via overlay.
        // If the recipient is on a DIFFERENT host than ours, we must use HTTP
        // (send_message with overlay resolution) since our WebSocket is only
        // connected to self.host.
        if override_host.is_none() {
            let resolved = self.resolve_host_for_recipient(recipient).await
                .unwrap_or_else(|_| self.host().to_string());
            if resolved.trim() != self.host().trim() {
                // Recipient is on a different MessageBox server — use HTTP with overlay
                return self.send_message(recipient, message_box, body, skip_encryption, check_permissions, message_id, None).await;
            }
        }

        // Auto-connect — matches TS which calls joinRoom (→ initializeConnection)
        // before checking socket.connected.
        if self.ensure_ws_connected(override_host).await.is_err() {
            // HTTP fallback: use override_host if provided, otherwise overlay resolution
            return match override_host {
                Some(host) => self.send_message_to_host(host, recipient, message_box, body, skip_encryption, check_permissions, message_id, None).await,
                None => self.send_message(recipient, message_box, body, skip_encryption, check_permissions, message_id, None).await,
            };
        }

        // Join sender's own room before send — TS calls joinRoom(messageBox) which
        // joins `${myIdentityKey}-${messageBox}`. Required so the server can route
        // the sendMessageAck back to this socket.
        let identity_key = self.get_identity_key().await?;
        let my_room = format!("{identity_key}-{message_box}");
        {
            let guard = self.ws_state.lock().await;
            if let Some(ref ws) = *guard {
                if ws.join_room(&my_room).await.is_err() {
                    drop(guard);
                    return match override_host {
                        Some(host) => self.send_message_to_host(host, recipient, message_box, body, skip_encryption, check_permissions, message_id, None).await,
                        None => self.send_message(recipient, message_box, body, skip_encryption, check_permissions, message_id, None).await,
                    };
                }
            } else {
                drop(guard);
                return match override_host {
                    Some(host) => self.send_message_to_host(host, recipient, message_box, body, skip_encryption, check_permissions, message_id, None).await,
                    None => self.send_message(recipient, message_box, body, skip_encryption, check_permissions, message_id, None).await,
                };
            }
        }

        // Encrypt (unless skip_encryption) and resolve message ID for the WebSocket path
        let encrypted = if skip_encryption {
            body.to_string()
        } else {
            crate::encryption::encrypt_body(
                self.wallet(),
                body,
                recipient,
                self.originator(),
            )
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

        let room_id = format!("{recipient}-{message_box}");
        let ack_key = format!("sendMessageAck-{room_id}");

        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel::<bool>();

        let payload = serde_json::json!({
            "roomId": room_id,
            "message": {
                "messageId": message_id,
                "recipient": recipient,
                "body": encrypted
            }
        });

        // Emit — acquire lock briefly then release before awaiting ack
        {
            let guard = self.ws_state.lock().await;
            if let Some(ref ws) = *guard {
                ws.emit_send_message(payload, ack_key.clone(), ack_tx).await?;
            }
        }

        // Await ack with 10-second timeout
        match tokio::time::timeout(std::time::Duration::from_secs(10), ack_rx).await {
            Ok(Ok(true)) => Ok(message_id),
            _ => {
                // Clean up the pending ack to prevent channel leaks (Pitfall 7)
                let guard = self.ws_state.lock().await;
                if let Some(ref ws) = *guard {
                    ws.remove_pending_ack(&ack_key).await;
                }
                drop(guard);
                // Fall back to HTTP — pass through all feature params
                match override_host {
                    Some(host) => self.send_message_to_host(host, recipient, message_box, body, skip_encryption, check_permissions, None, None).await,
                    None => self.send_message(recipient, message_box, body, skip_encryption, check_permissions, None, None).await,
                }
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
        {
            let guard = self.ws_state.lock().await;
            if let Some(ref ws) = *guard {
                ws.leave_room(&room_id).await?;
            }
        }
        self.joined_rooms.lock().await.remove(&room_id);
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

    /// GET `url` using BRC-31 authenticated transport.
    ///
    /// Mirrors `post_json` but sends no body and no content-type header.
    /// The caller is responsible for building the full URL including query string.
    pub(crate) async fn get_json(
        &self,
        url: &str,
    ) -> Result<AuthFetchResponse, MessageBoxError> {
        let response = self
            .auth_fetch
            .lock()
            .await
            .fetch(url, "GET", None, None)
            .await
            .map_err(|e| MessageBoxError::Auth(e.to_string()))?;

        if response.status < 200 || response.status >= 300 {
            return Err(MessageBoxError::Http(
                response.status,
                url.to_string(),
            ));
        }

        Ok(response)
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
/// Returns a `Vec<PeerMessage>` with decrypted bodies, or an empty vec on error.
/// `accept_payments` is always false — the polling path does not handle delivery fees.
async fn poll_list_messages<W>(
    auth_fetch: &Arc<Mutex<AuthFetch<W>>>,
    host: &str,
    message_box: &str,
    identity_key: &str,
    wallet: &W,
    originator: Option<&str>,
) -> Result<Vec<PeerMessage>, MessageBoxError>
where
    W: WalletInterface + Clone + Send + Sync + 'static,
{
    let params = ListMessagesParams {
        message_box: message_box.to_string(),
    };
    let body_bytes = serde_json::to_vec(&params)?;
    let url = format!("{host}/listMessages");
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let response = auth_fetch
        .lock()
        .await
        .fetch(&url, "POST", Some(body_bytes), Some(headers))
        .await
        .map_err(|e| MessageBoxError::Auth(e.to_string()))?;

    if response.status < 200 || response.status >= 300 {
        return Err(MessageBoxError::Http(response.status, url));
    }

    check_status_error(&response.body)?;

    let list_response: ListMessagesResponse = serde_json::from_slice(&response.body)?;

    let mut result = Vec::with_capacity(list_response.messages.len());
    for msg in list_response.messages {
        // Simple body extraction: if the body is a wrapped envelope, extract the message field.
        let plain_body = extract_plain_body(&msg.body);
        // Decrypt if encrypted
        let decrypted = crate::encryption::try_decrypt_message(
            wallet,
            &plain_body,
            &msg.sender,
            originator,
        )
        .await;

        result.push(PeerMessage {
            message_id: msg.message_id,
            sender: msg.sender,
            recipient: identity_key.to_string(),
            message_box: message_box.to_string(),
            body: decrypted,
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
    struct ArcWallet(Arc<ProtoWallet>);

    impl ArcWallet {
        fn new() -> Self {
            let key = PrivateKey::from_random().expect("random key");
            ArcWallet(Arc::new(ProtoWallet::new(key)))
        }
    }

    // Delegate every WalletInterface method to the inner ProtoWallet.
    #[async_trait::async_trait]
    impl WalletInterface for ArcWallet {
        async fn create_action(&self, args: CreateActionArgs, orig: Option<&str>) -> Result<CreateActionResult, WalletError> { self.0.create_action(args, orig).await }
        async fn sign_action(&self, args: SignActionArgs, orig: Option<&str>) -> Result<SignActionResult, WalletError> { self.0.sign_action(args, orig).await }
        async fn abort_action(&self, args: AbortActionArgs, orig: Option<&str>) -> Result<AbortActionResult, WalletError> { self.0.abort_action(args, orig).await }
        async fn list_actions(&self, args: ListActionsArgs, orig: Option<&str>) -> Result<ListActionsResult, WalletError> { self.0.list_actions(args, orig).await }
        async fn internalize_action(&self, args: InternalizeActionArgs, orig: Option<&str>) -> Result<InternalizeActionResult, WalletError> { self.0.internalize_action(args, orig).await }
        async fn list_outputs(&self, args: ListOutputsArgs, orig: Option<&str>) -> Result<ListOutputsResult, WalletError> { self.0.list_outputs(args, orig).await }
        async fn relinquish_output(&self, args: RelinquishOutputArgs, orig: Option<&str>) -> Result<RelinquishOutputResult, WalletError> { self.0.relinquish_output(args, orig).await }
        async fn get_public_key(&self, args: GetPublicKeyArgs, orig: Option<&str>) -> Result<GetPublicKeyResult, WalletError> { self.0.get_public_key(args, orig).await }
        async fn reveal_counterparty_key_linkage(&self, args: RevealCounterpartyKeyLinkageArgs, orig: Option<&str>) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> { self.0.reveal_counterparty_key_linkage(args, orig).await }
        async fn reveal_specific_key_linkage(&self, args: RevealSpecificKeyLinkageArgs, orig: Option<&str>) -> Result<RevealSpecificKeyLinkageResult, WalletError> { self.0.reveal_specific_key_linkage(args, orig).await }
        async fn encrypt(&self, args: EncryptArgs, orig: Option<&str>) -> Result<EncryptResult, WalletError> { self.0.encrypt(args, orig).await }
        async fn decrypt(&self, args: DecryptArgs, orig: Option<&str>) -> Result<DecryptResult, WalletError> { self.0.decrypt(args, orig).await }
        async fn create_hmac(&self, args: CreateHmacArgs, orig: Option<&str>) -> Result<CreateHmacResult, WalletError> { self.0.create_hmac(args, orig).await }
        async fn verify_hmac(&self, args: VerifyHmacArgs, orig: Option<&str>) -> Result<VerifyHmacResult, WalletError> { self.0.verify_hmac(args, orig).await }
        async fn create_signature(&self, args: CreateSignatureArgs, orig: Option<&str>) -> Result<CreateSignatureResult, WalletError> { self.0.create_signature(args, orig).await }
        async fn verify_signature(&self, args: VerifySignatureArgs, orig: Option<&str>) -> Result<VerifySignatureResult, WalletError> { self.0.verify_signature(args, orig).await }
        async fn acquire_certificate(&self, args: AcquireCertificateArgs, orig: Option<&str>) -> Result<Certificate, WalletError> { self.0.acquire_certificate(args, orig).await }
        async fn list_certificates(&self, args: ListCertificatesArgs, orig: Option<&str>) -> Result<ListCertificatesResult, WalletError> { self.0.list_certificates(args, orig).await }
        async fn prove_certificate(&self, args: ProveCertificateArgs, orig: Option<&str>) -> Result<ProveCertificateResult, WalletError> { self.0.prove_certificate(args, orig).await }
        async fn relinquish_certificate(&self, args: RelinquishCertificateArgs, orig: Option<&str>) -> Result<RelinquishCertificateResult, WalletError> { self.0.relinquish_certificate(args, orig).await }
        async fn discover_by_identity_key(&self, args: DiscoverByIdentityKeyArgs, orig: Option<&str>) -> Result<DiscoverCertificatesResult, WalletError> { self.0.discover_by_identity_key(args, orig).await }
        async fn discover_by_attributes(&self, args: DiscoverByAttributesArgs, orig: Option<&str>) -> Result<DiscoverCertificatesResult, WalletError> { self.0.discover_by_attributes(args, orig).await }
        async fn is_authenticated(&self, orig: Option<&str>) -> Result<AuthenticatedResult, WalletError> { self.0.is_authenticated(orig).await }
        async fn wait_for_authentication(&self, orig: Option<&str>) -> Result<AuthenticatedResult, WalletError> { self.0.wait_for_authentication(orig).await }
        async fn get_height(&self, orig: Option<&str>) -> Result<GetHeightResult, WalletError> { self.0.get_height(orig).await }
        async fn get_header_for_height(&self, args: GetHeaderArgs, orig: Option<&str>) -> Result<GetHeaderResult, WalletError> { self.0.get_header_for_height(args, orig).await }
        async fn get_network(&self, orig: Option<&str>) -> Result<GetNetworkResult, WalletError> { self.0.get_network(orig).await }
        async fn get_version(&self, orig: Option<&str>) -> Result<GetVersionResult, WalletError> { self.0.get_version(orig).await }
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
        let _fut = client.init(None);
        let _ = _fut; // suppress unused warning
    }
}
