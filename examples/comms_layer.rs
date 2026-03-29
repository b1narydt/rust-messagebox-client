//! RemittanceAdapter usage — CommsLayer trait implementation.
//!
//! Run: cargo run --example comms_layer
//!
//! This example demonstrates the RemittanceAdapter integration pattern.
//! RemittanceAdapter wraps MessageBoxClient in an Arc and implements the
//! CommsLayer trait from the BSV SDK, enabling MessageBox to be used as the
//! transport layer for a RemittanceManager.

use std::sync::Arc;

use async_trait::async_trait;
use bsv::primitives::private_key::PrivateKey;
use bsv::remittance::CommsLayer;
use bsv::services::overlay_tools::Network;
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::*;
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv_messagebox_client::{MessageBoxClient, RemittanceAdapter};

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
    // MessageBoxClient must be wrapped in Arc to share ownership with RemittanceAdapter.
    let client = Arc::new(MessageBoxClient::new(
        LIVE_HOST.to_string(),
        ArcWallet::new(),
        None,
        Network::Mainnet,
    ));

    let identity_key = client.get_identity_key().await?;
    println!("Identity key: {}...", &identity_key[..12]);

    // RemittanceAdapter wraps the Arc<MessageBoxClient> and implements CommsLayer.
    // This is the integration point for RemittanceManager in downstream consumers.
    let adapter = RemittanceAdapter::new(client.clone());

    // Cast to Arc<dyn CommsLayer + Send + Sync> — the type expected by RemittanceManager.
    // This verifies the trait object is constructible from the concrete adapter.
    let comms: Arc<dyn CommsLayer + Send + Sync> = Arc::new(adapter);

    // Use CommsLayer::send_message — delegates to MessageBoxClient::send_message
    // with overlay host resolution when host_override is None.
    println!("Sending via CommsLayer::send_message...");
    match comms.send_message(&identity_key, "demo_comms_inbox", "Hello via CommsLayer!", None).await {
        Ok(msg_id) => println!("Sent. Message ID: {msg_id}"),
        Err(e) => println!("send_message failed (acceptable for ProtoWallet): {e}"),
    }

    // Use CommsLayer::list_messages — delegates to MessageBoxClient::list_messages_lite.
    // Returns Vec<PeerMessage> with PeerMessage.recipient populated from the identity key
    // (not from the server response, which does not carry a recipient field).
    println!("Listing via CommsLayer::list_messages...");
    match comms.list_messages("demo_comms_inbox", None).await {
        Ok(messages) => {
            println!("Found {} messages.", messages.len());
            for msg in &messages {
                println!("  ID: {}, sender: {}...", msg.message_id, &msg.sender[..12.min(msg.sender.len())]);
            }
        }
        Err(e) => println!("list_messages returned error (acceptable for empty inbox): {e}"),
    }

    println!("Done.");

    Ok(())
}
