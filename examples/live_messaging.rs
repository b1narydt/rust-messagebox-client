//! WebSocket live messaging between two peers.
//!
//! Run: cargo run --example live_messaging
//!
//! This example demonstrates BRC-103 authenticated WebSocket live messaging.
//! Client A subscribes to a message box, then Client B sends a live message.
//! The message is delivered via the hybrid pipeline: Socket.IO push with HTTP
//! polling fallback (the Babbage server uses polling as its primary delivery path).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bsv::primitives::private_key::PrivateKey;
use bsv::remittance::types::PeerMessage;
use bsv::services::overlay_tools::Network;
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::*;
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv_messagebox_client::{DeliveryMode, MessageBoxClient};
use tokio::sync::mpsc;

const LIVE_HOST: &str = "https://messagebox.babbage.systems";

// ---------------------------------------------------------------------------
// ArcWallet — wraps Arc<ProtoWallet> to satisfy W: Clone on MessageBoxClient.
// ProtoWallet is non-Clone; Arc provides shared ownership without duplication.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ArcWallet(Arc<ProtoWallet>);

impl ArcWallet {
    fn new() -> Self {
        let key = PrivateKey::from_random().expect("random key");
        ArcWallet(Arc::new(ProtoWallet::new(key)))
    }
}

#[async_trait]
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create two independent clients with separate wallets.
    let client_a = Arc::new(MessageBoxClient::new(
        LIVE_HOST.to_string(),
        ArcWallet::new(),
        None,
        Network::Mainnet,
    ));
    let client_b = Arc::new(MessageBoxClient::new(
        LIVE_HOST.to_string(),
        ArcWallet::new(),
        None,
        Network::Mainnet,
    ));

    let key_a = client_a.get_identity_key().await?;
    println!("Client A key: {}...", &key_a[..12]);

    // Channel to receive messages delivered to Client A.
    let (msg_tx, mut msg_rx) = mpsc::channel::<PeerMessage>(4);

    // Client A subscribes to "demo_live_inbox".
    // listen_for_live_messages establishes the BRC-103 authenticated WebSocket
    // connection and joins the room key_a-demo_live_inbox on the server.
    println!("Client A subscribing to demo_live_inbox...");
    let tx = msg_tx.clone();
    client_a
        .listen_for_live_messages(
            "demo_live_inbox",
            Arc::new(move |msg: PeerMessage| {
                println!("[Callback] received: sender={}..., body={}", &msg.sender[..12.min(msg.sender.len())], msg.body);
                // try_send works from both sync and async contexts.
                let _ = tx.try_send(msg);
            }),
            None,
        )
        .await?;

    // Wait 3s for the BRC-103 joinRoom to propagate to the server.
    println!("Waiting 3s for subscription to settle...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Client B sends a live message to Client A.
    // send_live_message attempts WebSocket delivery (10s ack timeout) and falls
    // back to HTTP if the ack is not received in time.
    println!("Client B sending live message...");
    let delivery = client_b
        .send_live_message(
            &key_a,              // recipient identity key
            "demo_live_inbox",   // message box name
            "Live hello!",       // body
            false,               // skip_encryption
            false,               // check_permissions
            None,                // message_id
            None,                // override_host
        )
        .await?;
    match &delivery {
        DeliveryMode::Live { message_id } => {
            println!("Message sent live (WS ack received). ID: {message_id}");
        }
        DeliveryMode::Persisted { message_id } => {
            println!("Message persisted via HTTP fallback (WS ack timed out). ID: {message_id}");
        }
    }

    // Wait up to 15s for Client A to receive the message via the polling fallback.
    println!("Waiting for Client A to receive...");
    match tokio::time::timeout(Duration::from_secs(15), msg_rx.recv()).await {
        Ok(Some(msg)) => {
            println!("Client A received: sender={}..., body={}", &msg.sender[..12.min(msg.sender.len())], msg.body);
        }
        Ok(None) => println!("Channel closed without a message."),
        Err(_) => println!("Timeout: no message received within 15s."),
    }

    // Disconnect both clients' WebSocket connections.
    client_a.disconnect_web_socket().await?;
    client_b.disconnect_web_socket().await?;
    println!("Done.");

    Ok(())
}
