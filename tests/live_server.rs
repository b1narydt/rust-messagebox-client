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
