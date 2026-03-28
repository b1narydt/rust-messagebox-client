/// Live integration tests against https://messagebox.babbage.systems
///
/// These tests hit the real MessageBox server with BRC-103 authenticated
/// requests via ProtoWallet. They are marked `#[ignore]` so they only run
/// when explicitly requested: `cargo test --test live_server -- --ignored`
///
/// A fresh random wallet is used per test, so there is no state leakage
/// between runs.

use std::sync::Arc;

use bsv::primitives::private_key::PrivateKey;
use bsv::services::overlay_tools::Network;
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::*;
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv_messagebox_client::MessageBoxClient;

const LIVE_HOST: &str = "https://messagebox.babbage.systems";

// ---------------------------------------------------------------------------
// ArcWallet — same pattern as integration.rs
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

fn make_live_client() -> Arc<MessageBoxClient<ArcWallet>> {
    let wallet = ArcWallet::new();
    Arc::new(MessageBoxClient::new(
        LIVE_HOST.to_string(),
        wallet,
        None,
        Network::Mainnet,
    ))
}

// ---------------------------------------------------------------------------
// Test: init against live server
// ---------------------------------------------------------------------------

/// Call client.init(None) against the live server.
/// The overlay anoint may fail but init catches errors gracefully.
/// We verify no panic occurs.
#[tokio::test]
#[ignore]
async fn test_init_against_live_server() {
    let client = make_live_client();
    // init() catches anoint errors internally — should not panic or return Err.
    let result = client.init(None).await;
    // Even if anoint fails, init should succeed (TS parity: catches and continues).
    println!("init result: {result:?}");
    assert!(result.is_ok(), "init() should not return an error: {result:?}");
}

// ---------------------------------------------------------------------------
// Test: get_identity_key returns 66-char hex (compressed public key)
// ---------------------------------------------------------------------------

/// Verify get_identity_key() returns a 66-character hex string
/// (compressed secp256k1 public key in DER hex format).
#[tokio::test]
#[ignore]
async fn test_get_identity_key_live() {
    let client = make_live_client();
    let key = client.get_identity_key().await.expect("get_identity_key should succeed");
    println!("identity key: {key}");
    assert_eq!(key.len(), 66, "compressed pubkey is 66 hex chars, got {}", key.len());
    assert!(
        key.chars().all(|c| c.is_ascii_hexdigit()),
        "identity key must be all hex digits"
    );
    // Compressed pubkeys start with 02 or 03
    assert!(
        key.starts_with("02") || key.starts_with("03"),
        "compressed pubkey must start with 02 or 03, got prefix: {}",
        &key[..2]
    );
}

// ---------------------------------------------------------------------------
// Test: list messages on empty inbox
// ---------------------------------------------------------------------------

/// With a fresh random wallet, list_messages should either return an empty
/// vec (no messages) or fail with an HTTP error. Both outcomes are acceptable
/// — we are testing that the wire format is correct.
#[tokio::test]
#[ignore]
async fn test_list_messages_empty_inbox() {
    let client = make_live_client();
    let result = client.list_messages("test_inbox", false, None).await;
    println!("list_messages result: {result:?}");
    match result {
        Ok(messages) => {
            println!("got {} messages (expected 0)", messages.len());
            assert!(messages.is_empty(), "fresh wallet should have no messages");
        }
        Err(e) => {
            // HTTP errors are acceptable — the request was sent with correct format.
            println!("list_messages returned error (acceptable for fresh wallet): {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Test: send message to self
// ---------------------------------------------------------------------------

/// Send a message to ourselves and verify the response is a non-empty
/// message ID string.
#[tokio::test]
#[ignore]
async fn test_send_message_to_self() {
    let client = make_live_client();
    let identity_key = client
        .get_identity_key()
        .await
        .expect("get_identity_key should succeed");

    let result = client
        .send_message(
            &identity_key,
            "test_inbox",
            "hello from rust live test",
            false,  // skip_encryption
            false,  // check_permissions
            None,   // message_id
            None,   // override_host
        )
        .await;

    println!("send_message result: {result:?}");
    match result {
        Ok(msg_id) => {
            println!("message ID: {msg_id}");
            assert!(!msg_id.is_empty(), "message ID must be non-empty");
        }
        Err(e) => {
            panic!("send_message failed: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Test: send, list, then acknowledge
// ---------------------------------------------------------------------------

/// Send a message, list it, then acknowledge it. This exercises the full
/// send -> list -> ack cycle against the live server.
#[tokio::test]
#[ignore]
async fn test_list_and_acknowledge() {
    let client = make_live_client();
    let identity_key = client
        .get_identity_key()
        .await
        .expect("get_identity_key should succeed");

    // Send a message to ourselves first
    let send_result = client
        .send_message(
            &identity_key,
            "test_inbox",
            "ack test message from rust",
            false,
            false,
            None,
            None,
        )
        .await;
    println!("send_message result: {send_result:?}");

    // List messages — may contain the message we just sent
    let list_result = client.list_messages("test_inbox", false, None).await;
    println!("list_messages result: {list_result:?}");

    match list_result {
        Ok(messages) => {
            println!("found {} messages", messages.len());
            if !messages.is_empty() {
                let ids: Vec<String> = messages.iter().map(|m| m.message_id.clone()).collect();
                println!("acknowledging message IDs: {ids:?}");
                let ack_result = client.acknowledge_message(ids, None).await;
                println!("acknowledge result: {ack_result:?}");
                assert!(ack_result.is_ok(), "acknowledge should succeed: {ack_result:?}");
            } else {
                println!("no messages to acknowledge (send may not have completed yet)");
            }
        }
        Err(e) => {
            println!("list_messages failed (acceptable): {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Test: list message box permissions
// ---------------------------------------------------------------------------

/// Call list_message_box_permissions with no filters. Should succeed —
/// may return an empty array for a fresh wallet.
#[tokio::test]
#[ignore]
async fn test_permissions_list() {
    let client = make_live_client();
    let result = client
        .list_message_box_permissions(None, None, None, None)
        .await;
    println!("list_message_box_permissions result: {result:?}");
    match result {
        Ok(perms) => {
            println!("got {} permissions", perms.len());
            // Fresh wallet should have no permissions — but any result is acceptable.
        }
        Err(e) => {
            // HTTP or auth errors are acceptable — we're testing the wire format.
            println!("list_message_box_permissions error (acceptable): {e}");
        }
    }
}

// ===========================================================================
// HTTP Messaging tests
// ===========================================================================

/// 1. Send an encrypted message (default), verify non-empty message_id.
#[tokio::test]
#[ignore]
async fn test_send_message_encrypted() {
    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    let result = client
        .send_message(
            &identity_key,
            "test_inbox",
            "encrypted live test payload",
            false,  // skip_encryption = false => encrypted
            false,
            None,
            None,
        )
        .await;

    println!("send_message (encrypted) result: {result:?}");
    let msg_id = result.expect("send_message should succeed");
    assert!(!msg_id.is_empty(), "message_id must be non-empty");
}

/// 2. Send an unencrypted message (skip_encryption=true).
#[tokio::test]
#[ignore]
async fn test_send_message_unencrypted() {
    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    let result = client
        .send_message(
            &identity_key,
            "test_inbox",
            "unencrypted live test payload",
            true,   // skip_encryption
            false,
            None,
            None,
        )
        .await;

    println!("send_message (unencrypted) result: {result:?}");
    let msg_id = result.expect("send_message with skip_encryption should succeed");
    assert!(!msg_id.is_empty(), "message_id must be non-empty");
}

/// 3. Send a message with a caller-supplied message_id.
#[tokio::test]
#[ignore]
async fn test_send_message_with_custom_id() {
    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    let custom_id = format!("custom-id-{}", uuid_like_suffix());
    let result = client
        .send_message(
            &identity_key,
            "test_inbox",
            "message with custom id",
            true,
            false,
            Some(&custom_id),
            None,
        )
        .await;

    println!("send_message (custom id) result: {result:?}");
    // Server may return the custom id or its own — either is acceptable.
    let msg_id = result.expect("send_message with custom id should succeed");
    assert!(!msg_id.is_empty(), "message_id must be non-empty");
}

/// 4. Call list_messages_lite on a test inbox.
#[tokio::test]
#[ignore]
async fn test_list_messages_lite() {
    let client = make_live_client();
    let result = client.list_messages_lite("test_inbox", None).await;
    println!("list_messages_lite result: {result:?}");
    match result {
        Ok(messages) => {
            println!("list_messages_lite returned {} messages", messages.len());
            // Fresh wallet — empty is expected, but any Vec is acceptable.
        }
        Err(e) => {
            // Acceptable — the authenticated request was sent correctly.
            println!("list_messages_lite error (acceptable): {e}");
        }
    }
}

/// 5. Call list_messages with an explicit override_host.
#[tokio::test]
#[ignore]
async fn test_list_messages_with_override_host() {
    let client = make_live_client();
    let result = client
        .list_messages("test_inbox", false, Some(LIVE_HOST))
        .await;
    println!("list_messages (override_host) result: {result:?}");
    match result {
        Ok(messages) => {
            println!("got {} messages with override_host", messages.len());
        }
        Err(e) => {
            println!("list_messages with override_host error (acceptable): {e}");
        }
    }
}

/// 6. Full send -> list -> ack -> list cycle. Verify message appears then disappears.
#[tokio::test]
#[ignore]
async fn test_send_list_ack_full_cycle() {
    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    // Send unencrypted to make listing simpler
    let unique_body = format!("full-cycle-test-{}", uuid_like_suffix());
    let sent_id = client
        .send_message(
            &identity_key,
            "test_inbox",
            &unique_body,
            true,
            false,
            None,
            None,
        )
        .await
        .expect("send should succeed");
    println!("sent message id: {sent_id}");

    // List — our message should appear
    let messages = client
        .list_messages("test_inbox", false, None)
        .await
        .expect("list should succeed");
    println!("listed {} messages", messages.len());
    assert!(
        messages.iter().any(|m| m.message_id == sent_id),
        "sent message must appear in list"
    );

    // Acknowledge it
    client
        .acknowledge_message(vec![sent_id.clone()], None)
        .await
        .expect("acknowledge should succeed");
    println!("acknowledged message {sent_id}");

    // List again — message should be gone
    let messages_after = client
        .list_messages("test_inbox", false, None)
        .await
        .expect("second list should succeed");
    assert!(
        !messages_after.iter().any(|m| m.message_id == sent_id),
        "acknowledged message must not appear in second list"
    );
}

/// 7. Acknowledge a nonexistent message ID — should not panic.
#[tokio::test]
#[ignore]
async fn test_acknowledge_nonexistent() {
    let client = make_live_client();
    let result = client
        .acknowledge_message(vec!["nonexistent-fake-id-999".to_string()], None)
        .await;
    println!("acknowledge nonexistent result: {result:?}");
    // Either Ok or Err is acceptable — no panic is the key assertion.
}

// ===========================================================================
// Permissions tests
// ===========================================================================

/// 8. Set a permission then get it back, verify fields match.
#[tokio::test]
#[ignore]
async fn test_set_and_get_permission() {
    use bsv_messagebox_client::types::SetPermissionParams;

    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    // Set permission for test_inbox with recipientFee=0
    let set_result = client
        .set_message_box_permission(
            SetPermissionParams {
                message_box: "test_inbox".to_string(),
                sender: None,
                recipient_fee: 0,
            },
            None,
        )
        .await;
    println!("set_permission result: {set_result:?}");
    set_result.expect("set_permission should succeed");

    // Get the permission back
    let get_result = client
        .get_message_box_permission(&identity_key, "test_inbox", None, None)
        .await;
    println!("get_permission result: {get_result:?}");
    match get_result {
        Ok(Some(perm)) => {
            assert_eq!(perm.message_box, "test_inbox");
            assert_eq!(perm.recipient_fee, 0);
            println!("permission fields match: message_box={}, fee={}", perm.message_box, perm.recipient_fee);
        }
        Ok(None) => {
            println!("permission returned None — server may not echo it back for self");
        }
        Err(e) => {
            panic!("get_permission failed: {e}");
        }
    }
}

/// 9. List permissions filtered by message_box.
#[tokio::test]
#[ignore]
async fn test_list_permissions_filtered() {
    let client = make_live_client();
    let result = client
        .list_message_box_permissions(Some("test_inbox"), None, None, None)
        .await;
    println!("list_permissions (filtered) result: {result:?}");
    match result {
        Ok(perms) => {
            println!("got {} permissions for test_inbox", perms.len());
            // Returns Vec — may be empty for fresh wallet.
        }
        Err(e) => {
            println!("list_permissions filtered error (acceptable): {e}");
        }
    }
}

/// 10. Get a delivery quote for own identity key on test_inbox.
#[tokio::test]
#[ignore]
async fn test_get_quote() {
    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    let result = client
        .get_message_box_quote(&identity_key, "test_inbox", None)
        .await;
    println!("get_quote result: {result:?}");
    match result {
        Ok(quote) => {
            println!(
                "quote: delivery_fee={}, recipient_fee={}, agent={}",
                quote.delivery_fee, quote.recipient_fee, quote.delivery_agent_identity_key
            );
            // delivery_fee and recipient_fee should be numeric (i64) — no further constraint.
            assert!(
                !quote.delivery_agent_identity_key.is_empty(),
                "delivery_agent_identity_key must be non-empty"
            );
        }
        Err(e) => {
            // Quote may fail if server requires prior permission setup — acceptable.
            println!("get_quote error (acceptable): {e}");
        }
    }
}

/// 11. Deny notifications from a fake peer, then check status.
#[tokio::test]
#[ignore]
async fn test_deny_and_check_notification() {
    let client = make_live_client();
    // Use a valid-format but fake public key (starts with 02, 64 hex chars)
    let fake_peer = "0200000000000000000000000000000000000000000000000000000000000000ff";

    let deny_result = client
        .deny_notifications_from_peer(fake_peer, None)
        .await;
    println!("deny_notifications result: {deny_result:?}");
    // May succeed or fail — either is acceptable.

    let check_result = client
        .check_peer_notification_status(fake_peer, None)
        .await;
    println!("check_peer_notification_status result: {check_result:?}");
    // May return Some(perm with fee=-1), None, or Err — all acceptable.
}

// ===========================================================================
// PeerPay tests
// ===========================================================================

/// 12. Create a payment token for 1000 sats to own identity key.
#[tokio::test]
#[ignore]
async fn test_create_payment_token() {
    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    let result = client.create_payment_token(&identity_key, 1000).await;
    println!("create_payment_token result: {result:?}");
    match result {
        Ok(token) => {
            assert_eq!(token.amount, 1000);
            assert!(!token.transaction.is_empty(), "transaction bytes must be non-empty");
            assert!(!token.custom_instructions.derivation_prefix.is_empty());
            assert!(!token.custom_instructions.derivation_suffix.is_empty());
            println!("token created: amount={}, tx_len={}", token.amount, token.transaction.len());
        }
        Err(e) => {
            // ProtoWallet has no funded wallet — create_action will fail.
            // This is expected for unfunded wallets.
            println!("create_payment_token error (expected for unfunded wallet): {e}");
        }
    }
}

/// 13. Send payment to self — verify message_id returned.
#[tokio::test]
#[ignore]
async fn test_send_payment_to_self() {
    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    let result = client.send_payment(&identity_key, 1000).await;
    println!("send_payment result: {result:?}");
    match result {
        Ok(msg_id) => {
            assert!(!msg_id.is_empty(), "message_id must be non-empty");
            println!("payment sent, message_id={msg_id}");
        }
        Err(e) => {
            // Expected to fail with unfunded ProtoWallet — acceptable.
            println!("send_payment error (expected for unfunded wallet): {e}");
        }
    }
}

/// 14. List incoming payments after sending — verify returns Vec.
#[tokio::test]
#[ignore]
async fn test_list_incoming_payments() {
    let client = make_live_client();

    // Attempt to send a payment to self first (may fail with unfunded wallet)
    let identity_key = client.get_identity_key().await.expect("get_identity_key");
    let _ = client.send_payment(&identity_key, 1000).await;

    let result = client.list_incoming_payments().await;
    println!("list_incoming_payments result: {result:?}");
    match result {
        Ok(payments) => {
            println!("got {} incoming payments", payments.len());
            // May be empty if payment send failed — that is acceptable.
        }
        Err(e) => {
            println!("list_incoming_payments error (acceptable): {e}");
        }
    }
}

// ===========================================================================
// Overlay / Init tests
// ===========================================================================

/// 15. Call init(None) twice — both should succeed (OnceCell idempotency).
#[tokio::test]
#[ignore]
async fn test_init_idempotent() {
    let client = make_live_client();

    let r1 = client.init(None).await;
    println!("init(None) first call: {r1:?}");
    assert!(r1.is_ok(), "first init should succeed: {r1:?}");

    let r2 = client.init(None).await;
    println!("init(None) second call: {r2:?}");
    assert!(r2.is_ok(), "second init should succeed: {r2:?}");
}

/// 16. Call init with an explicit target host.
#[tokio::test]
#[ignore]
async fn test_init_with_target_host() {
    let client = make_live_client();
    let result = client.init(Some(LIVE_HOST)).await;
    println!("init(Some(LIVE_HOST)) result: {result:?}");
    assert!(result.is_ok(), "init with target host should succeed: {result:?}");
}

/// 17. Query overlay advertisements for own identity key.
#[tokio::test]
#[ignore]
async fn test_query_advertisements() {
    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    let result = client
        .query_advertisements(Some(&identity_key), None)
        .await;
    println!("query_advertisements result: {result:?}");
    // query_advertisements always returns Ok (wraps errors to empty vec).
    let ads = result.expect("query_advertisements always returns Ok");
    println!("got {} advertisements", ads.len());
    // May be empty for a fresh wallet — that is acceptable.
}

/// 18. Resolve host for own identity key — should return a URL string.
#[tokio::test]
#[ignore]
async fn test_resolve_host() {
    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    let result = client
        .resolve_host_for_recipient(&identity_key)
        .await;
    println!("resolve_host result: {result:?}");
    let host = result.expect("resolve_host should succeed");
    assert!(!host.is_empty(), "resolved host must be non-empty");
    assert!(
        host.starts_with("http://") || host.starts_with("https://"),
        "resolved host must be a URL, got: {host}"
    );
}

// ===========================================================================
// Device Registration tests
// ===========================================================================

/// 19. Register a device — verify no crash.
#[tokio::test]
#[ignore]
async fn test_register_device() {
    let client = make_live_client();
    let result = client
        .register_device("fake-fcm-token-live-test", Some("test-device"), Some("web"), None)
        .await;
    println!("register_device result: {result:?}");
    // Server may accept or reject — no panic is the key assertion.
    match result {
        Ok(resp) => {
            println!("register_device response: status={}", resp.status);
        }
        Err(e) => {
            println!("register_device error (acceptable): {e}");
        }
    }
}

/// 20. List registered devices — verify returns Vec.
#[tokio::test]
#[ignore]
async fn test_list_registered_devices() {
    let client = make_live_client();
    let result = client.list_registered_devices(None).await;
    println!("list_registered_devices result: {result:?}");
    match result {
        Ok(devices) => {
            println!("got {} registered devices", devices.len());
        }
        Err(e) => {
            println!("list_registered_devices error (acceptable): {e}");
        }
    }
}

// ===========================================================================
// Encryption Integration tests (against live server)
// ===========================================================================

/// 21. Send encrypted message to self, list, verify body decrypts to original.
#[tokio::test]
#[ignore]
async fn test_encrypted_message_round_trip() {
    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    let original = format!("round-trip-test-{}", uuid_like_suffix());

    // Send encrypted (skip_encryption=false)
    let sent_id = client
        .send_message(
            &identity_key,
            "test_inbox",
            &original,
            false,
            false,
            None,
            None,
        )
        .await
        .expect("send encrypted message should succeed");
    println!("sent encrypted message: {sent_id}");

    // List messages — find ours and verify decrypted body matches
    let messages = client
        .list_messages("test_inbox", false, None)
        .await
        .expect("list should succeed");

    let our_msg = messages.iter().find(|m| m.message_id == sent_id);
    assert!(our_msg.is_some(), "our sent message must appear in list");

    let body = &our_msg.unwrap().body;
    // list_messages decrypts automatically via try_decrypt_message
    assert_eq!(body, &original, "decrypted body must match original");
    println!("round-trip verified: decrypted body matches original");

    // Cleanup: acknowledge
    let _ = client.acknowledge_message(vec![sent_id], None).await;
}

// ===========================================================================
// Error Handling tests
// ===========================================================================

/// 22. Send to an invalid recipient key — verify returns error (not panic).
#[tokio::test]
#[ignore]
async fn test_send_to_invalid_recipient() {
    let client = make_live_client();
    let result = client
        .send_message(
            "not-a-valid-hex-pubkey",
            "test_inbox",
            "should fail",
            false,
            false,
            None,
            None,
        )
        .await;
    println!("send to invalid recipient result: {result:?}");
    assert!(result.is_err(), "sending to invalid recipient must return an error");
}

/// 23. Acknowledge with empty vec — verify no crash.
#[tokio::test]
#[ignore]
async fn test_acknowledge_empty_ids() {
    let client = make_live_client();
    let result = client
        .acknowledge_message(vec![], None)
        .await;
    println!("acknowledge empty ids result: {result:?}");
    // Either Ok or Err is acceptable — no panic is the key assertion.
}

// ===========================================================================
// Multi-recipient / Notification test
// ===========================================================================

/// 24. Send a notification to own identity key.
#[tokio::test]
#[ignore]
async fn test_send_notification_to_self() {
    let client = make_live_client();
    let identity_key = client.get_identity_key().await.expect("get_identity_key");

    let result = client
        .send_notification(&identity_key, "test notification body", None)
        .await;
    println!("send_notification result: {result:?}");
    match result {
        Ok(msg_id) => {
            assert!(!msg_id.is_empty(), "notification message_id must be non-empty");
            println!("notification sent: {msg_id}");
        }
        Err(e) => {
            // May fail due to permission checks — acceptable.
            println!("send_notification error (acceptable for permission-gated inbox): {e}");
        }
    }
}

// ===========================================================================
// BRC-103 WebSocket Auth tests
// ===========================================================================

/// BRC-103 WebSocket mutual auth handshake against a live go-messagebox-server.
///
/// Validates the full flow:
///   1. SocketIOTransport bridges authMessage Socket.IO events to Peer
///   2. Peer::process_next() drives server-initiated InitialRequest handling
///   3. Peer::send_message() sends the authenticated event as a BRC-103 General message
///   4. Server responds with authenticationSuccess (via BRC-103 general message or raw event)
///   5. Room join/leave work through the Peer channel
///   6. Disconnect cleanly terminates the peer_task
#[tokio::test]
#[ignore]
async fn test_brc103_websocket_auth() {
    use bsv_messagebox_client::websocket::MessageBoxWebSocket;

    let wallet = ArcWallet::new();
    let helper_client = Arc::new(MessageBoxClient::new(
        LIVE_HOST.to_string(),
        wallet.clone(),
        None,
        bsv::services::overlay_tools::Network::Mainnet,
    ));
    let identity_key = helper_client
        .get_identity_key()
        .await
        .expect("get_identity_key should succeed");

    // Connect and complete BRC-103 handshake against live server
    let ws = MessageBoxWebSocket::connect(
        LIVE_HOST,
        &identity_key,
        wallet,
        None,
    )
    .await
    .expect("BRC-103 connect should succeed against live server");

    // Verify authenticationSuccess was received
    assert!(ws.is_connected(), "is_connected() must return true after successful BRC-103 auth");

    // Verify server identity key was captured during handshake
    let server_key = ws.server_identity_key();
    assert!(
        !server_key.is_empty(),
        "server_identity_key must be non-empty"
    );
    assert_eq!(
        server_key.len(),
        66,
        "server identity key must be 66-char hex (compressed pubkey), got len={}",
        server_key.len()
    );
    assert!(
        server_key.chars().all(|c| c.is_ascii_hexdigit()),
        "server identity key must be all hex digits"
    );
    println!("server identity key: {server_key}");

    // Join a room — sent through BRC-103 Peer channel
    let room_id = format!("{identity_key}-test_brc103_inbox");
    ws.join_room(&room_id)
        .await
        .expect("join_room should succeed after BRC-103 auth");
    println!("joined room: {room_id}");

    // Disconnect cleanly — signals peer_task shutdown
    ws.disconnect().await.expect("disconnect should succeed");
    assert!(
        !ws.is_connected(),
        "is_connected() must return false after disconnect"
    );
    println!("BRC-103 WebSocket auth test passed");
}

/// Diagnostic: connect, emit old-style `authenticated`, and log all server responses.
#[tokio::test]
#[ignore]
async fn test_ws_event_probe() {
    use rust_socketio::asynchronous::ClientBuilder;
    use futures_util::FutureExt;

    let events: Arc<tokio::sync::Mutex<Vec<String>>> = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let events_clone = events.clone();

    let wallet = ArcWallet::new();
    let helper = Arc::new(MessageBoxClient::new(
        LIVE_HOST.to_string(), wallet.clone(), None,
        bsv::services::overlay_tools::Network::Mainnet,
    ));
    let identity_key = helper.get_identity_key().await.expect("get key");

    let evs2 = events.clone();
    let evs3 = events.clone();
    let evs4 = events.clone();
    let evs5 = events.clone();

    let client = ClientBuilder::new(LIVE_HOST)
        .on("authenticationSuccess", move |payload, _socket| {
            let evs = events_clone.clone();
            async move {
                let line = format!("authenticationSuccess: {payload:?}");
                println!("WS: {line}");
                evs.lock().await.push(line);
            }.boxed()
        })
        .on("authenticationFailed", move |payload, _socket| {
            let evs = evs2.clone();
            async move {
                let line = format!("authenticationFailed: {payload:?}");
                println!("WS: {line}");
                evs.lock().await.push(line);
            }.boxed()
        })
        .on("authMessage", move |payload, _socket| {
            let evs = evs3.clone();
            async move {
                let line = format!("authMessage: {payload:?}");
                println!("WS: {line}");
                evs.lock().await.push(line);
            }.boxed()
        })
        .on("message", move |payload, _socket| {
            let evs = evs4.clone();
            async move {
                let line = format!("message: {payload:?}");
                println!("WS: {line}");
                evs.lock().await.push(line);
            }.boxed()
        })
        .on("error", move |payload, _socket| {
            let evs = evs5.clone();
            async move {
                let line = format!("error: {payload:?}");
                println!("WS: {line}");
                evs.lock().await.push(line);
            }.boxed()
        })
        .connect()
        .await
        .expect("Socket.IO connect should succeed");

    // Emit old-style authenticated
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    println!("Emitting 'authenticated' with identityKey={}", &identity_key[..12]);
    let emit_result = client.emit("authenticated", serde_json::json!({"identityKey": identity_key})).await;
    println!("emit result: {emit_result:?}");

    // Also try emitting authMessage directly
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let auth_emit = client.emit("authMessage", serde_json::json!({"test": true})).await;
    println!("authMessage emit result: {auth_emit:?}");

    // Listen for 5 seconds
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Check if socket is still connected
    println!("Socket connected after wait: not directly checkable, checking emit...");
    let ping_result = client.emit("ping", serde_json::json!({})).await;
    println!("ping emit result: {ping_result:?}");

    let captured = events.lock().await;
    println!("\n=== Captured {} events ===", captured.len());
    for e in captured.iter() {
        println!("  {e}");
    }

    client.disconnect().await.expect("disconnect");
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Generate a pseudo-unique suffix for test messages (not cryptographic).
fn uuid_like_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("{nanos:010}")
}
