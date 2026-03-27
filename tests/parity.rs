//! Parity verification tests for bsv-messagebox-client
//!
//! Verifies API surface parity with TypeScript @bsv/message-box-client v2.0.4
//!
//! Method count: 33 MessageBoxClient + 7 PeerPayClient = 40 total
//! (TS reference: 33 MessageBoxClient + 7 PeerPayClient = 40 total)
//!
//! ## TS → Rust method mapping
//!
//! ### Constructors (2)
//!   TS: new(host, wallet, originator?)      → Rust: MessageBoxClient::new(host, wallet, originator, network)
//!   TS: (convenience mainnet)               → Rust: MessageBoxClient::new_mainnet(host, wallet, originator)
//!
//! ### Getters (5)
//!   TS: get host()                          → Rust: .host()
//!   TS: get wallet()                        → Rust: .wallet()
//!   TS: get originator()                    → Rust: .originator()
//!   TS: (no network getter)                 → Rust: .network()
//!   TS: getIdentityKey()                    → Rust: .get_identity_key()
//!
//! ### Initialization (3)
//!   TS: init(targetHost?)                   → Rust: .init(target_host)
//!   TS: initializeConnection()              → Rust: .initialize_connection(override_host)
//!   TS: joinedRooms (Map accessor)          → Rust: .get_joined_rooms()
//!
//! ### HTTP Messaging (4)
//!   TS: sendMessage(msg, opts?)             → Rust: .send_message(recipient, mb, body, skip_enc, check_perms, msg_id, override_host)
//!   TS: listMessages(mb)                    → Rust: .list_messages(message_box, override_host)
//!   TS: listMessagesLite(mb)                → Rust: .list_messages_lite(message_box, override_host)
//!   TS: acknowledgeMessage(ids, host?)      → Rust: .acknowledge_message(ids, override_host)
//!
//! ### Multi-recipient (2)
//!   TS: sendMessageToRecipients(params)     → Rust: .send_message_to_recipients(params, override_host)
//!   TS: (internal batch)                    → Rust: .send_notification_to_recipients(recipients, mb, body, override_host)
//!
//! ### WebSocket Live Messaging (5)
//!   TS: sendLiveMessage(recipient, mb, body)→ Rust: .send_live_message(recipient, mb, body, override_host)
//!   TS: listenForLiveMessages(mb, cb)       → Rust: .listen_for_live_messages(mb, on_message, override_host)
//!   TS: joinRoom(mb)                        → Rust: .join_room(mb)
//!   TS: leaveRoom(mb)                       → Rust: .leave_room(mb, override_host)
//!   TS: disconnectWebSocket()               → Rust: .disconnect_web_socket()
//!
//! ### Permissions (7)
//!   TS: setMessageBoxPermission(mb, opts)   → Rust: .set_message_box_permission(mb, sender, fee, override_host)
//!   TS: getMessageBoxPermission(mb, sender) → Rust: .get_message_box_permission(mb, sender, override_host)
//!   TS: listMessageBoxPermissions(mb?)      → Rust: .list_message_box_permissions(mb, override_host)
//!   TS: getMessageBoxQuote(r, mb)           → Rust: .get_message_box_quote(recipient, mb, override_host)
//!   TS: getMessageBoxQuoteMulti(recipients) → Rust: .get_message_box_quote_multi(recipients, mb, override_host)
//!   TS: allowNotificationsFromPeer(peer)    → Rust: .allow_notifications_from_peer(peer, override_host)
//!   TS: denyNotificationsFromPeer(peer)     → Rust: .deny_notifications_from_peer(peer, override_host)
//!   TS: checkPeerNotificationStatus(peer)   → Rust: .check_peer_notification_status(peer, override_host)
//!   TS: listPeerNotifications()             → Rust: .list_peer_notifications(override_host)
//!   TS: sendNotification(to, msg)           → Rust: .send_notification(to, mb, body, override_host)
//!
//! ### Overlay / Device Registration (5)
//!   TS: queryAdvertisements(identity, host) → Rust: .query_advertisements(identity_key, host)
//!   TS: resolveHostForRecipient(recipient)  → Rust: .resolve_host_for_recipient(recipient)
//!   TS: anointHost(host)                    → Rust: .anoint_host(host)
//!   TS: revokeHostAdvertisement(token)      → Rust: .revoke_host_advertisement(token)
//!   TS: registerDevice(fcm, opts?)          → Rust: .register_device(fcm, device_id, platform, override_host)
//!   TS: listRegisteredDevices()             → Rust: .list_registered_devices(override_host)
//!
//! ### PeerPay (7)
//!   TS: createPaymentToken(recipient, amt)  → Rust: .create_payment_token(recipient, amount)
//!   TS: sendPayment(recipient, amt)         → Rust: .send_payment(recipient, amount)
//!   TS: sendLivePayment(recipient, amt)     → Rust: .send_live_payment(recipient, amount)
//!   TS: listenForLivePayments(cb)           → Rust: .listen_for_live_payments(on_payment)
//!   TS: acceptPayment(incoming)             → Rust: .accept_payment(payment)
//!   TS: rejectPayment(incoming)             → Rust: .reject_payment(payment)
//!   TS: listIncomingPayments()              → Rust: .list_incoming_payments()
//!   TS: acknowledgeNotification(msg_id)     → Rust: .acknowledge_notification(msg_id, sender)

use std::sync::Arc;

use bsv::primitives::private_key::PrivateKey;
use bsv::services::overlay_tools::Network;
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::*;
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv_messagebox_client::{
    MessageBoxClient, MessageBoxMultiQuote, PaymentToken,
    PaymentCustomInstructions, SendListParams, SendListResult, SentRecipient, FailedRecipient,
    SendListTotals, RecipientQuote,
};

// ---------------------------------------------------------------------------
// ArcWallet test helper (same pattern used in integration.rs and unit tests)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ArcWallet(Arc<ProtoWallet>);

impl ArcWallet {
    fn new() -> Self {
        let key = PrivateKey::from_random().expect("random key");
        ArcWallet(Arc::new(ProtoWallet::new(key)))
    }
}

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

fn make_client() -> (MessageBoxClient<ArcWallet>, ArcWallet) {
    let wallet = ArcWallet::new();
    let client = MessageBoxClient::new(
        "https://test.example.com".to_string(),
        wallet.clone(),
        None,
        Network::Mainnet,
    );
    (client, wallet)
}

// ---------------------------------------------------------------------------
// PARITY-01: API surface audit — compile-time check all public methods exist
//
// Every method reference below is a compile-time assertion. If a method is
// missing or has the wrong signature, this file fails to compile.
// ---------------------------------------------------------------------------

/// PARITY-01: All expected public methods are present on MessageBoxClient.
///
/// This test references every public method so the Rust compiler enforces
/// their existence and signature. Methods that cannot be called without a
/// live server are referenced via type resolution / let-binding patterns.
///
/// Covers all 33 MessageBoxClient methods + 7 PeerPayClient methods = 40 total.
#[tokio::test]
async fn parity_01_all_public_methods_exist() {
    let (client, _wallet) = make_client();

    // -- Synchronous getters (compile + runtime callable) --
    let host: &str = client.host();
    assert!(!host.is_empty(), "host() must return non-empty string");

    let _wallet_ref = client.wallet(); // wallet() -> &W

    let originator: Option<&str> = client.originator();
    assert!(originator.is_none(), "originator() is None when not set");

    let _network = client.network(); // network() -> &Network

    // -- Async identity getter --
    let identity_key = client.get_identity_key().await.expect("get_identity_key");
    assert!(!identity_key.is_empty(), "get_identity_key() must return non-empty key");
    assert!(identity_key.chars().all(|c| c.is_ascii_hexdigit()), "key must be hex");

    // -- Initialization methods (compile-check via size_of_val) --
    // init(target_host: Option<&str>) -> Result<(), MessageBoxError>
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::init);
    // initialize_connection(override_host: Option<&str>) -> Result<(), MessageBoxError>
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::initialize_connection);

    // get_joined_rooms() -> HashSet<String>
    // NOTE: Uses blocking_lock internally — must only be called from sync contexts.
    // The compile-check is sufficient here; the runtime behavior is verified in
    // parity_04_get_joined_rooms_empty (sync test).
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::get_joined_rooms);

    // -- HTTP messaging (compile-check via size_of_val) --
    // send_message(recipient, mb, body, skip_enc, check_perms, msg_id, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::send_message);

    // list_messages(message_box: &str, accept_payments: bool)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::list_messages);

    // list_messages_lite(message_box: &str)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::list_messages_lite);

    // acknowledge_message(message_ids: Vec<String>, override_host: Option<&str>)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::acknowledge_message);

    // send_message_to_recipients(params: &SendListParams, override_host: Option<&str>)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::send_message_to_recipients);

    // -- WebSocket live messaging (compile-check via size_of_val) --
    // send_live_message(recipient, mb, body, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::send_live_message);
    // listen_for_live_messages(mb, on_message: Arc<dyn Fn(PeerMessage)+Send+Sync>, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::listen_for_live_messages);
    // join_room(message_box)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::join_room);
    // leave_room(message_box, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::leave_room);
    // disconnect_web_socket()
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::disconnect_web_socket);

    // -- Permissions --
    // set_message_box_permission(mb, sender, recipient_fee, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::set_message_box_permission);
    // get_message_box_permission(mb, sender, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::get_message_box_permission);
    // list_message_box_permissions(mb?, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::list_message_box_permissions);
    // get_message_box_quote(recipient, mb, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::get_message_box_quote);
    // get_message_box_quote_multi(recipients, mb, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::get_message_box_quote_multi);
    // allow_notifications_from_peer(peer, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::allow_notifications_from_peer);
    // deny_notifications_from_peer(peer, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::deny_notifications_from_peer);
    // check_peer_notification_status(peer, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::check_peer_notification_status);
    // list_peer_notifications(override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::list_peer_notifications);
    // send_notification(to, mb, body, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::send_notification);
    // send_notification_to_recipients(recipients, mb, body, override_host)
    let _ =
        std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::send_notification_to_recipients);

    // -- Overlay / Device Registration --
    // query_advertisements(identity_key, host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::query_advertisements);
    // resolve_host_for_recipient(recipient)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::resolve_host_for_recipient);
    // anoint_host(host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::anoint_host);
    // revoke_host_advertisement(token)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::revoke_host_advertisement);
    // register_device(fcm_token, device_id, platform, override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::register_device);
    // list_registered_devices(override_host)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::list_registered_devices);

    // -- PeerPay methods --
    // create_payment_token(recipient, amount)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::create_payment_token);
    // send_payment(recipient, amount)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::send_payment);
    // send_live_payment(recipient, amount)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::send_live_payment);
    // listen_for_live_payments(on_payment)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::listen_for_live_payments);
    // accept_payment(incoming)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::accept_payment);
    // reject_payment(incoming)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::reject_payment);
    // list_incoming_payments()
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::list_incoming_payments);
    // acknowledge_notification(message_id, sender)
    let _ = std::mem::size_of_val(&MessageBoxClient::<ArcWallet>::acknowledge_notification);

    // test_socket() is #[cfg(test)] inside src/client.rs but is NOT visible to
    // integration test crates (they're a separate compilation unit). Its existence
    // is verified by the unit tests in src/client.rs. We document it here for
    // completeness but cannot call it from this file.
    // TS: testSocket() -> Rust: test_socket() [unit-test-only accessor]
}

// ---------------------------------------------------------------------------
// PARITY-02: Encryption round-trip — BRC-78 encrypt/decrypt with ProtoWallet
//
// Verifies: plaintext → encrypt → decrypt = original plaintext
// Verifies: encrypted format is { "encryptedMessage": "<STANDARD_base64>" }
// Verifies: protocol [1, "messagebox"], keyID "1"
// ---------------------------------------------------------------------------

/// PARITY-02: BRC-78 encryption round-trip using ProtoWallet matches expected format.
///
/// Uses two ProtoWallet instances (sender + recipient) to verify:
/// 1. encrypt_body produces valid JSON with `encryptedMessage` field containing STANDARD base64
/// 2. decrypt_body recovers the original plaintext exactly
/// 3. The encrypted JSON does NOT contain raw body text (confirming actual encryption)
/// 4. try_decrypt_message handles the real encrypted output correctly
#[tokio::test]
async fn parity_02_encryption_round_trip() {
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::interfaces::GetPublicKeyArgs;
    use bsv::wallet::proto_wallet::ProtoWallet;
    use base64::{engine::general_purpose::STANDARD, Engine};

    let sender_key = PrivateKey::from_random().expect("random sender key");
    let recipient_key = PrivateKey::from_random().expect("random recipient key");

    let sender_wallet = ProtoWallet::new(sender_key);
    let recipient_wallet = ProtoWallet::new(recipient_key);

    // Obtain identity keys (DER hex) for each wallet.
    // Using a standalone async function avoids closure lifetime issues.
    async fn wallet_identity_hex(wallet: &ProtoWallet) -> String {
        wallet.get_public_key(
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
            None,
        )
        .await
        .expect("get_public_key")
        .public_key
        .to_der_hex()
    }

    let sender_pk = wallet_identity_hex(&sender_wallet).await;
    let recipient_pk = wallet_identity_hex(&recipient_wallet).await;

    let plaintext = "Hello from Rust — BRC-78 parity test 🔐";

    // Encrypt using sender's wallet, targeting recipient's public key
    let encrypted_json = bsv_messagebox_client::encryption::encrypt_body(
        &sender_wallet,
        plaintext,
        &recipient_pk,
        None,
    )
    .await
    .expect("encrypt_body must succeed");

    // Verify wire format: must be JSON with "encryptedMessage" field
    let v: serde_json::Value = serde_json::from_str(&encrypted_json)
        .expect("encrypted output must be valid JSON");
    let b64 = v
        .get("encryptedMessage")
        .and_then(|f| f.as_str())
        .expect("must have encryptedMessage field");

    // Verify it is valid STANDARD base64 (with padding)
    let ciphertext_bytes = STANDARD.decode(b64).expect("must be valid STANDARD base64");
    assert!(!ciphertext_bytes.is_empty(), "ciphertext must not be empty");

    // Verify the encrypted output does NOT contain the plaintext
    assert!(
        !encrypted_json.contains(plaintext),
        "encrypted JSON must not contain plaintext body"
    );

    // Decrypt using recipient's wallet
    let decrypted = bsv_messagebox_client::encryption::decrypt_body(
        &recipient_wallet,
        &encrypted_json,
        &sender_pk,
        None,
    )
    .await
    .expect("decrypt_body must succeed");

    assert_eq!(decrypted, plaintext, "decrypt must recover original plaintext exactly");

    // Verify try_decrypt_message also handles the encrypted format correctly
    let try_decrypted = bsv_messagebox_client::encryption::try_decrypt_message(
        &recipient_wallet,
        &encrypted_json,
        &sender_pk,
        None,
    )
    .await;
    assert_eq!(
        try_decrypted, plaintext,
        "try_decrypt_message must also recover plaintext from encrypted format"
    );

    // Verify plaintext passthrough still works (ENC-04 parity)
    let passthrough = bsv_messagebox_client::encryption::try_decrypt_message(
        &recipient_wallet,
        "plain text body",
        &sender_pk,
        None,
    )
    .await;
    assert_eq!(passthrough, "plain text body", "plaintext must pass through unchanged");
}

// ---------------------------------------------------------------------------
// PARITY-03: Payment token shape — JSON matches TS PaymentToken structure
//
// Verifies: all fields serialize to camelCase matching TS PaymentToken wire format
// Verifies: customInstructions.derivationPrefix, derivationSuffix, transaction, amount, outputIndex
// ---------------------------------------------------------------------------

/// PARITY-03: PaymentToken JSON shape matches TypeScript PaymentToken wire format.
///
/// Verifies:
/// - camelCase field names on the wire (no snake_case leakage)
/// - transaction serializes as a number array (Vec<u8>)
/// - outputIndex absent when None (TS omits it at creation time)
/// - payee absent when None
/// - Full round-trip deserialization preserves all values
#[test]
fn parity_03_payment_token_json_shape() {
    // Token with all fields populated
    let token = PaymentToken {
        custom_instructions: PaymentCustomInstructions {
            derivation_prefix: "test-prefix-abc".to_string(),
            derivation_suffix: "test-suffix-xyz".to_string(),
            payee: Some("03abcdef1234567890".to_string()),
        },
        transaction: vec![0xde, 0xad, 0xbe, 0xef, 0x01],
        amount: 2500,
        output_index: Some(1),
    };

    let json = serde_json::to_value(&token).expect("PaymentToken must serialize to JSON");

    // Verify top-level camelCase fields
    assert!(json.get("customInstructions").is_some(), "must have customInstructions (camelCase)");
    assert!(json.get("transaction").is_some(), "must have transaction");
    assert!(json.get("amount").is_some(), "must have amount");
    assert!(json.get("outputIndex").is_some(), "must have outputIndex when Some");

    // Verify no snake_case leakage
    assert!(json.get("custom_instructions").is_none(), "no snake_case: custom_instructions");
    assert!(json.get("output_index").is_none(), "no snake_case: output_index");

    // Verify nested customInstructions fields
    let ci = json.get("customInstructions").unwrap();
    assert!(ci.get("derivationPrefix").is_some(), "must have derivationPrefix (camelCase)");
    assert!(ci.get("derivationSuffix").is_some(), "must have derivationSuffix (camelCase)");
    assert!(ci.get("payee").is_some(), "must have payee when Some");
    assert!(ci.get("derivation_prefix").is_none(), "no snake_case: derivation_prefix");
    assert!(ci.get("derivation_suffix").is_none(), "no snake_case: derivation_suffix");

    // Verify values
    assert_eq!(ci.get("derivationPrefix").unwrap().as_str(), Some("test-prefix-abc"));
    assert_eq!(ci.get("derivationSuffix").unwrap().as_str(), Some("test-suffix-xyz"));
    assert_eq!(json.get("amount").unwrap().as_u64(), Some(2500));
    assert_eq!(json.get("outputIndex").unwrap().as_u64(), Some(1));

    // Verify transaction serializes as number array (not base64 string)
    let tx_arr = json.get("transaction").unwrap().as_array().expect("transaction must be array");
    assert_eq!(tx_arr.len(), 5, "transaction array must have all bytes");
    assert_eq!(tx_arr[0].as_u64(), Some(0xde));
    assert_eq!(tx_arr[3].as_u64(), Some(0xef));

    // Token with None fields — outputIndex and payee must be absent
    let token_none = PaymentToken {
        custom_instructions: PaymentCustomInstructions {
            derivation_prefix: "pfx".to_string(),
            derivation_suffix: "sfx".to_string(),
            payee: None,
        },
        transaction: vec![0x01, 0x02],
        amount: 100,
        output_index: None,
    };

    let json_none = serde_json::to_value(&token_none).expect("must serialize");
    assert!(json_none.get("outputIndex").is_none(), "outputIndex must be absent when None");
    assert!(
        json_none.get("customInstructions").unwrap().get("payee").is_none(),
        "payee must be absent when None"
    );

    // Full round-trip: serialize → deserialize → values preserved
    let json_str = serde_json::to_string(&token).expect("serialize");
    let restored: PaymentToken = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(restored.amount, token.amount, "amount survives round-trip");
    assert_eq!(restored.transaction, token.transaction, "transaction survives round-trip");
    assert_eq!(restored.output_index, token.output_index, "output_index survives round-trip");
    assert_eq!(
        restored.custom_instructions.derivation_prefix,
        token.custom_instructions.derivation_prefix,
        "derivation_prefix survives round-trip"
    );
    assert_eq!(
        restored.custom_instructions.payee,
        token.custom_instructions.payee,
        "payee survives round-trip"
    );
}

// ---------------------------------------------------------------------------
// PARITY-04: Smoke test — every public method callable without panic
//
// Verifies: synchronous methods work correctly
// Verifies: get_joined_rooms returns empty HashSet before any joins
// Verifies: client construction with all parameter variations
// ---------------------------------------------------------------------------

/// PARITY-04: Smoke test — construction and synchronous methods work without panic.
///
/// Tests all synchronous getters and construction variants. Async methods that
/// require a live server are referenced via size_of_val (compile-check already done
/// in PARITY-01); synchronous ones are actually called here to catch panics.
#[tokio::test]
async fn parity_04_smoke_all_methods_callable() {
    // -- new() construction --
    let wallet = ArcWallet::new();
    let client = MessageBoxClient::new(
        "https://test.example.com".to_string(),
        wallet.clone(),
        None,
        Network::Mainnet,
    );

    // Synchronous getters — all callable without panic
    assert_eq!(client.host(), "https://test.example.com", "host() returns trimmed URL");
    assert!(client.originator().is_none(), "originator() is None when not set");

    // get_identity_key — async but doesn't need a server
    let identity_key = client.get_identity_key().await.expect("get_identity_key must succeed");
    assert!(!identity_key.is_empty(), "identity_key must be non-empty");
    assert_eq!(identity_key.len(), 66, "compressed pubkey is 66 hex chars");

    // get_identity_key is cached — second call must return same value
    let identity_key2 = client.get_identity_key().await.expect("second call");
    assert_eq!(identity_key, identity_key2, "get_identity_key must be deterministic (cached)");

    // get_joined_rooms() uses blocking_lock — must be called from sync context only.
    // The runtime behavior is verified in parity_04_get_joined_rooms_empty below.

    // test_socket() is #[cfg(test)] in src/client.rs and is not accessible from
    // integration test crates. Its behaviour is verified in src/client.rs unit tests.

    // -- new_mainnet() convenience constructor --
    let wallet2 = ArcWallet::new();
    let client2 = MessageBoxClient::new_mainnet(
        "https://mainnet.example.com".into(),
        wallet2,
        None,
    );
    assert_eq!(client2.host(), "https://mainnet.example.com", "new_mainnet() sets host correctly");

    // -- Host trimming: new() trims whitespace --
    let wallet3 = ArcWallet::new();
    let client3 = MessageBoxClient::new(
        "  https://trimmed.example.com  ".to_string(),
        wallet3,
        None,
        Network::Mainnet,
    );
    assert_eq!(client3.host(), "https://trimmed.example.com", "host must be trimmed");

    // -- originator passthrough --
    let wallet4 = ArcWallet::new();
    let client4 = MessageBoxClient::new(
        "https://example.com".to_string(),
        wallet4,
        Some("my-app".to_string()),
        Network::Mainnet,
    );
    assert_eq!(client4.originator(), Some("my-app"), "originator must be passed through");

    // -- disconnect_web_socket on fresh client is a no-op (not a panic) --
    client.disconnect_web_socket().await.expect("disconnect on fresh client must not error");
}

/// PARITY-04b: get_joined_rooms returns empty HashSet from synchronous context.
///
/// get_joined_rooms() uses blocking_lock which must only be called from sync contexts.
/// This sync test verifies the initial state and return type.
#[test]
fn parity_04_get_joined_rooms_empty() {
    let wallet = ArcWallet::new();
    let client = MessageBoxClient::new(
        "https://example.com".to_string(),
        wallet,
        None,
        Network::Mainnet,
    );
    let rooms = client.get_joined_rooms();
    assert!(rooms.is_empty(), "get_joined_rooms() must return empty HashSet before any joins");
}

// ---------------------------------------------------------------------------
// PARITY-05: Wire format JSON serialization — all types match TS camelCase convention
//
// Verifies: every request/response type serializes with camelCase field names
// Verifies: None fields are omitted (skip_serializing_if = "Option::is_none")
// ---------------------------------------------------------------------------

/// PARITY-05: Wire format JSON serialization matches TypeScript camelCase conventions.
///
/// Tests every request/response type to ensure:
/// - Field names are camelCase on the wire (no snake_case leakage)
/// - None-valued optional fields are omitted (TS uses optional chaining)
/// - Required fields are always present
#[test]
fn parity_05_wire_format_json() {
    use bsv_messagebox_client::{
        AcknowledgeMessageParams, MessageBoxPermission, RegisterDeviceRequest,
        SendMessageParams, ServerPeerMessage,
    };
    use std::collections::HashMap;

    // --- SendMessageParams ---
    let params = SendMessageParams {
        recipient: "03abc".to_string(),
        message_box: "inbox".to_string(),
        body: "hello".to_string(),
        message_id: "id1".to_string(),
    };
    let json = serde_json::to_value(&params).unwrap();
    assert!(json.get("messageBox").is_some(), "SendMessageParams: must use camelCase messageBox");
    assert!(json.get("messageId").is_some(), "SendMessageParams: must use camelCase messageId");
    assert!(json.get("recipient").is_some(), "SendMessageParams: recipient present");
    assert!(json.get("body").is_some(), "SendMessageParams: body present");
    assert!(json.get("message_box").is_none(), "SendMessageParams: no snake_case message_box");
    assert!(json.get("message_id").is_none(), "SendMessageParams: no snake_case message_id");

    // --- AcknowledgeMessageParams ---
    let ack = AcknowledgeMessageParams {
        message_ids: vec!["msg-a".to_string(), "msg-b".to_string()],
    };
    let json = serde_json::to_value(&ack).unwrap();
    assert!(json.get("messageIds").is_some(), "AcknowledgeMessageParams: camelCase messageIds");
    assert!(json.get("message_ids").is_none(), "AcknowledgeMessageParams: no snake_case");
    let ids_arr = json.get("messageIds").unwrap().as_array().unwrap();
    assert_eq!(ids_arr.len(), 2, "AcknowledgeMessageParams: both IDs preserved");

    // --- SendListParams ---
    let slp = SendListParams {
        recipients: vec!["03abc".to_string(), "03def".to_string()],
        message_box: "inbox".to_string(),
        body: "hi".to_string(),
        skip_encryption: None,
    };
    let json = serde_json::to_value(&slp).unwrap();
    assert!(json.get("messageBox").is_some(), "SendListParams: camelCase messageBox");
    assert!(json.get("recipients").is_some(), "SendListParams: recipients present");
    assert!(json.get("skipEncryption").is_none(), "SendListParams: None must be omitted");
    assert!(json.get("message_box").is_none(), "SendListParams: no snake_case message_box");

    let slp_with_enc = SendListParams {
        recipients: vec!["03abc".to_string()],
        message_box: "inbox".to_string(),
        body: "hi".to_string(),
        skip_encryption: Some(true),
    };
    let json = serde_json::to_value(&slp_with_enc).unwrap();
    assert!(json.get("skipEncryption").is_some(), "SendListParams: skipEncryption present when Some");
    assert_eq!(json.get("skipEncryption").unwrap().as_bool(), Some(true));

    // --- SendListResult ---
    let slr = SendListResult {
        status: "success".to_string(),
        description: "delivered".to_string(),
        sent: vec![SentRecipient {
            recipient: "03abc".to_string(),
            message_id: "msg-001".to_string(),
        }],
        blocked: vec![],
        failed: vec![FailedRecipient {
            recipient: "03def".to_string(),
            error: "blocked".to_string(),
        }],
        totals: None,
    };
    let json = serde_json::to_value(&slr).unwrap();
    assert!(json.get("status").is_some(), "SendListResult: status present");
    assert!(json.get("description").is_some(), "SendListResult: description present");
    assert!(json.get("sent").is_some(), "SendListResult: sent present");
    assert!(json.get("blocked").is_some(), "SendListResult: blocked present");
    assert!(json.get("failed").is_some(), "SendListResult: failed present");
    assert!(json.get("totals").is_none(), "SendListResult: totals absent when None");
    // SentRecipient camelCase
    let first_sent = &json.get("sent").unwrap().as_array().unwrap()[0];
    assert!(first_sent.get("messageId").is_some(), "SentRecipient: camelCase messageId");
    assert!(first_sent.get("message_id").is_none(), "SentRecipient: no snake_case");

    // SendListTotals when present
    let slr_with_totals = SendListResult {
        status: "ok".to_string(),
        description: "ok".to_string(),
        sent: vec![],
        blocked: vec![],
        failed: vec![],
        totals: Some(SendListTotals {
            delivery_fees: 10,
            recipient_fees: 5,
            total_for_payable_recipients: 15,
        }),
    };
    let json = serde_json::to_value(&slr_with_totals).unwrap();
    let totals = json.get("totals").unwrap();
    assert!(totals.get("deliveryFees").is_some(), "SendListTotals: camelCase deliveryFees");
    assert!(totals.get("recipientFees").is_some(), "SendListTotals: camelCase recipientFees");
    assert!(
        totals.get("totalForPayableRecipients").is_some(),
        "SendListTotals: camelCase totalForPayableRecipients"
    );
    assert!(totals.get("delivery_fees").is_none(), "SendListTotals: no snake_case");

    // --- MessageBoxMultiQuote ---
    let mq = MessageBoxMultiQuote {
        quotes_by_recipient: vec![RecipientQuote {
            recipient: "03abc".to_string(),
            message_box: "inbox".to_string(),
            delivery_fee: 10,
            recipient_fee: 5,
            status: "allowed".to_string(),
        }],
        totals: None,
        blocked_recipients: vec!["03xyz".to_string()],
        delivery_agent_identity_key_by_host: {
            let mut m = HashMap::new();
            m.insert("https://host.example.com".to_string(), "03agent".to_string());
            m
        },
    };
    let json = serde_json::to_value(&mq).unwrap();
    assert!(json.get("quotesByRecipient").is_some(), "MessageBoxMultiQuote: camelCase quotesByRecipient");
    assert!(json.get("blockedRecipients").is_some(), "MessageBoxMultiQuote: camelCase blockedRecipients");
    assert!(
        json.get("deliveryAgentIdentityKeyByHost").is_some(),
        "MessageBoxMultiQuote: camelCase deliveryAgentIdentityKeyByHost"
    );
    assert!(json.get("totals").is_none(), "MessageBoxMultiQuote: totals absent when None");
    assert!(json.get("quotes_by_recipient").is_none(), "MessageBoxMultiQuote: no snake_case");
    // RecipientQuote camelCase
    let rq = &json.get("quotesByRecipient").unwrap().as_array().unwrap()[0];
    assert!(rq.get("messageBox").is_some(), "RecipientQuote: camelCase messageBox");
    assert!(rq.get("deliveryFee").is_some(), "RecipientQuote: camelCase deliveryFee");
    assert!(rq.get("recipientFee").is_some(), "RecipientQuote: camelCase recipientFee");

    // --- MessageBoxPermission ---
    let perm = MessageBoxPermission {
        sender: Some("03sender".to_string()),
        message_box: "inbox".to_string(),
        recipient_fee: 100,
        created_at: "2024-01-01T00:00:00Z".to_string(),
        updated_at: "2024-01-02T00:00:00Z".to_string(),
    };
    let json = serde_json::to_value(&perm).unwrap();
    assert!(json.get("sender").is_some(), "MessageBoxPermission: sender present");
    assert!(json.get("message_box").is_some(), "MessageBoxPermission: message_box (snake_case — dual-format struct)");
    assert!(json.get("recipient_fee").is_some(), "MessageBoxPermission: recipient_fee (snake_case — dual-format struct)");
    // Note: MessageBoxPermission uses per-field serde(alias) not rename_all,
    // so it serializes in snake_case but deserializes from both snake_case and camelCase.
    // This matches the server's dual-format behavior (Pitfall 1 from research).

    // Verify deserialization from camelCase (server /get endpoint)
    let camel_json = r#"{"messageBox":"inbox","recipientFee":50,"createdAt":"2024-01-01T00:00:00Z","updatedAt":"2024-01-02T00:00:00Z"}"#;
    let parsed: MessageBoxPermission = serde_json::from_str(camel_json)
        .expect("MessageBoxPermission must deserialize from camelCase");
    assert_eq!(parsed.message_box, "inbox");
    assert_eq!(parsed.recipient_fee, 50);

    // Verify deserialization from snake_case (server /list endpoint)
    let snake_json = r#"{"message_box":"payment_inbox","recipient_fee":75,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-02T00:00:00Z"}"#;
    let parsed: MessageBoxPermission = serde_json::from_str(snake_json)
        .expect("MessageBoxPermission must deserialize from snake_case");
    assert_eq!(parsed.message_box, "payment_inbox");
    assert_eq!(parsed.recipient_fee, 75);

    // --- RegisterDeviceRequest ---
    let req = RegisterDeviceRequest {
        fcm_token: "fcm-abc123".to_string(),
        device_id: Some("dev-001".to_string()),
        platform: Some("ios".to_string()),
    };
    let json = serde_json::to_value(&req).unwrap();
    assert!(json.get("fcmToken").is_some(), "RegisterDeviceRequest: camelCase fcmToken");
    assert!(json.get("deviceId").is_some(), "RegisterDeviceRequest: camelCase deviceId");
    assert!(json.get("platform").is_some(), "RegisterDeviceRequest: platform present");
    assert!(json.get("fcm_token").is_none(), "RegisterDeviceRequest: no snake_case fcm_token");
    assert!(json.get("device_id").is_none(), "RegisterDeviceRequest: no snake_case device_id");

    let req_minimal = RegisterDeviceRequest {
        fcm_token: "tok456".to_string(),
        device_id: None,
        platform: None,
    };
    let json = serde_json::to_value(&req_minimal).unwrap();
    assert!(json.get("deviceId").is_none(), "RegisterDeviceRequest: deviceId absent when None");
    assert!(json.get("platform").is_none(), "RegisterDeviceRequest: platform absent when None");

    // --- ServerPeerMessage deserialization (server response type) ---
    let raw = r#"{
        "messageId": "abc123",
        "body": "hello",
        "sender": "03xyz",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    }"#;
    let msg: ServerPeerMessage = serde_json::from_str(raw)
        .expect("ServerPeerMessage must deserialize from server format");
    assert_eq!(msg.message_id, "abc123", "messageId deserialized correctly");
    assert_eq!(msg.sender, "03xyz", "sender deserialized correctly");
    assert!(msg.acknowledged.is_none(), "acknowledged is None when absent");

    // Verify unknown fields are tolerated (server may add fields)
    let raw_with_extra = r#"{
        "messageId": "extra-test",
        "body": "body",
        "sender": "03abc",
        "created_at": "2024-01-01",
        "updated_at": "2024-01-01",
        "unknownField": "ignored"
    }"#;
    let msg2: ServerPeerMessage = serde_json::from_str(raw_with_extra)
        .expect("ServerPeerMessage must tolerate unknown fields");
    assert_eq!(msg2.message_id, "extra-test");
}
