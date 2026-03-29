//! PeerPay payment token creation (unfunded — uses ProtoWallet).
//!
//! Run: cargo run --example payments
//!
//! ProtoWallet cannot create real Bitcoin transactions, so this example
//! demonstrates the PeerPay API surface and expected call patterns.
//! For funded payments, replace ArcWallet with ArcHttpWallet backed by a
//! BSV Desktop wallet running on localhost:3321.

use std::sync::Arc;

use async_trait::async_trait;
use bsv::primitives::private_key::PrivateKey;
use bsv::services::overlay_tools::Network;
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::*;
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv_messagebox_client::MessageBoxClient;

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
    // Create two clients: payer and payee.
    let payer = MessageBoxClient::new(
        LIVE_HOST.to_string(),
        ArcWallet::new(),
        None,
        Network::Mainnet,
    );
    let payee = MessageBoxClient::new(
        LIVE_HOST.to_string(),
        ArcWallet::new(),
        None,
        Network::Mainnet,
    );

    let payee_key = payee.get_identity_key().await?;
    println!("Payee key: {}...", &payee_key[..12]);

    // create_payment_token derives a P2PKH locking script using protocol
    // [2, "3241645161d8"] (PeerPay protocol) and calls create_action to fund it.
    // ProtoWallet.create_action is a stub that returns an error — use HttpWalletJson
    // backed by BSV Desktop for a funded round-trip.
    println!("Attempting create_payment_token (ProtoWallet — will fail at create_action)...");
    match payer.create_payment_token(&payee_key, 5000).await {
        Ok(token) => {
            println!("Payment token created:");
            println!("  transaction: {} bytes", token.transaction.len());
            println!("  derivation prefix: {}", token.custom_instructions.derivation_prefix);
            println!("  derivation suffix: {}", token.custom_instructions.derivation_suffix);
            println!("  amount: {} satoshis", token.amount);
        }
        Err(e) => {
            println!("create_payment_token failed (expected with ProtoWallet): {e}");
            println!();
            println!("With a funded wallet (HttpWalletJson + BSV Desktop), the full lifecycle is:");
            println!("  1. payer.send_payment(&payee_key, 5000).await?");
            println!("     // Creates and sends a PaymentToken in a MessageBox message");
            println!();
            println!("  2. payee.list_incoming_payments().await?");
            println!("     // Lists pending IncomingPayment structs from the inbox");
            println!();
            println!("  3. payee.accept_payment(&payments[0]).await?");
            println!("     // Internalizes the UTXO into the payee's wallet");
            println!();
            println!("  4. payer.reject_payment(&payments[0]).await?");
            println!("     // Refund to payer minus 1000 sat fee (TS parity)");
        }
    }

    Ok(())
}
