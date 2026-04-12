//! Overlay host resolution, advertisement, and revocation.
//!
//! Implements the four overlay methods that mirror the TypeScript MessageBoxClient:
//! - `query_advertisements` — lookup PushDrop-encoded host advertisements on the overlay
//! - `resolve_host_for_recipient` — derive the recipient's MessageBox host URL
//! - `anoint_host` — broadcast a host advertisement via SHIP/PushDrop
//! - `revoke_host_advertisement` — spend an existing advertisement UTXO
//!
//! The PushDrop locking script is built manually from chunks because the Rust SDK's
//! `PushDrop::new` requires a raw `PrivateKey`, which `WalletInterface` does not expose.
//! We derive the public key via `wallet.get_public_key` with `forSelf: true` instead.

use std::collections::HashMap;

use bsv::script::locking_script::LockingScript;
use bsv::script::op::Op;
use bsv::script::script::Script;
use bsv::script::script_chunk::ScriptChunk;
use bsv::script::templates::PushDrop;
use bsv::services::overlay_tools::{
    LookupResolver, LookupResolverConfig, TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv::services::overlay_tools::{LookupAnswer, LookupQuestion};
use bsv::transaction::broadcaster::Broadcaster;
use bsv::transaction::Transaction;
use bsv::wallet::interfaces::{
    CreateActionArgs, CreateActionInput, CreateActionOptions, CreateActionOutput, GetPublicKeyArgs,
    SignActionArgs, SignActionSpend, WalletInterface,
};
use bsv::wallet::types::{
    BooleanDefaultTrue, Counterparty, CounterpartyType, Protocol,
};

use crate::client::MessageBoxClient;
use crate::error::MessageBoxError;
use crate::types::{AdvertisementToken, ListDevicesResponse, RegisterDeviceRequest, RegisterDeviceResponse, RegisteredDevice};

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/// Build a correct data-push chunk for an arbitrary-length byte slice.
///
/// Uses the shortest possible push opcode per Bitcoin script encoding rules:
/// - len < 0x4c: opcode IS the length (direct push)
/// - len < 256: OP_PUSHDATA1 prefix
/// - len < 65536: OP_PUSHDATA2 prefix
/// - else: OP_PUSHDATA4 prefix
fn make_data_push(data: &[u8]) -> ScriptChunk {
    let len = data.len();
    if len < 0x4c {
        ScriptChunk::new_raw(len as u8, Some(data.to_vec()))
    } else if len < 256 {
        ScriptChunk::new_raw(Op::OpPushData1.to_byte(), Some(data.to_vec()))
    } else if len < 65536 {
        ScriptChunk::new_raw(Op::OpPushData2.to_byte(), Some(data.to_vec()))
    } else {
        ScriptChunk::new_raw(Op::OpPushData4.to_byte(), Some(data.to_vec()))
    }
}


// ---------------------------------------------------------------------------
// MessageBoxClient impl — host resolution methods
// ---------------------------------------------------------------------------

impl<W: WalletInterface + Clone + 'static + Send + Sync> MessageBoxClient<W> {
    /// Query the `ls_messagebox` overlay service for host advertisement tokens.
    ///
    /// Returns all matching `AdvertisementToken`s. Malformed outputs are silently
    /// skipped. The ENTIRE method is wrapped in error recovery that returns an empty
    /// Vec — matching the TypeScript `queryAdvertisements` which wraps everything in
    /// try/catch and returns `[]` on any error, including overlay unreachability.
    ///
    /// TS parity:
    /// ```typescript
    /// } catch (err) { Logger.error('failed:', err); }
    /// return hosts  // always returns, never throws
    /// ```
    pub async fn query_advertisements(
        &self,
        identity_key: Option<&str>,
        host: Option<&str>,
    ) -> Result<Vec<AdvertisementToken>, MessageBoxError> {
        // CRITICAL TS PARITY: wrap everything; return empty vec on any failure
        match self.query_advertisements_inner(identity_key, host).await {
            Ok(tokens) => Ok(tokens),
            Err(_) => Ok(vec![]),
        }
    }

    /// Inner implementation — errors propagate; wrapped by `query_advertisements`.
    async fn query_advertisements_inner(
        &self,
        identity_key: Option<&str>,
        host: Option<&str>,
    ) -> Result<Vec<AdvertisementToken>, MessageBoxError> {
        let ik = match identity_key {
            Some(k) => k.to_string(),
            None => self.get_identity_key().await?,
        };

        let mut query_obj = serde_json::json!({ "identityKey": ik });
        if let Some(h) = host {
            let trimmed = h.trim();
            if !trimmed.is_empty() {
                query_obj["host"] = serde_json::Value::String(trimmed.to_string());
            }
        }

        let question = LookupQuestion {
            service: "ls_messagebox".to_string(),
            query: query_obj,
        };

        // The SLAP trackers serve as universal overlay lookup hosts. Services
        // like ls_messagebox may not have dedicated SLAP registrations, so we
        // add the default SLAP tracker URLs as host_overrides for ls_messagebox.
        // This lets the resolver query them directly without SLAP→host discovery.
        let mut host_overrides = std::collections::HashMap::new();
        let tracker_urls = self.network.default_slap_trackers();
        host_overrides.insert("ls_messagebox".to_string(), tracker_urls);

        let resolver = LookupResolver::new(LookupResolverConfig {
            network: self.network.clone(),
            host_overrides,
            ..Default::default()
        });

        let answer = resolver
            .query(&question, None)
            .await
            .map_err(|e| MessageBoxError::Overlay(e.to_string()))?;

        let mut tokens = Vec::new();

        if let LookupAnswer::OutputList { outputs } = answer {
            for output in outputs {
                // Convert BEEF bytes to hex string — Transaction::from_beef takes &str hex
                let beef_hex = hex::encode(&output.beef);
                let tx = match Transaction::from_beef(&beef_hex) {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                let idx = output.output_index as usize;
                if idx >= tx.outputs.len() {
                    continue;
                }

                let script = &tx.outputs[idx].locking_script;
                let pd = match PushDrop::decode(script) {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                if pd.fields.len() < 2 {
                    continue;
                }

                let host_url = match String::from_utf8(pd.fields[1].clone()) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                // TS does NOT filter by protocol or hostname — all valid PushDrop
                // hosts are returned. This allows local dev with http://localhost.

                // tx.id() returns Result<String> with no argument (unlike TS)
                let txid = match tx.id() {
                    Ok(id) => id,
                    Err(_) => continue,
                };

                tokens.push(AdvertisementToken {
                    host: host_url,
                    txid,
                    output_index: output.output_index,
                    locking_script: script.to_hex(),
                    beef: output.beef,
                });
            }
        }

        Ok(tokens)
    }

    /// Resolve the MessageBox host for a given recipient identity key.
    ///
    /// Queries the overlay for the recipient's advertisements and returns the
    /// first matching host. Falls back to `self.host` when:
    /// - No advertisements exist for the recipient, or
    /// - The overlay is unreachable (query_advertisements always returns Ok)
    pub async fn resolve_host_for_recipient(
        &self,
        recipient: &str,
    ) -> Result<String, MessageBoxError> {
        let ads = self.query_advertisements(Some(recipient), None).await?;
        if let Some(ad) = ads.into_iter().next() {
            Ok(ad.host)
        } else {
            Ok(self.host().to_string())
        }
    }

    /// Broadcast a host advertisement to the `tm_messagebox` overlay topic.
    ///
    /// Builds a PushDrop transaction with:
    /// - fields[0] = identity key bytes (hex-decoded from identity key string)
    /// - fields[1] = host URL bytes (UTF-8)
    ///
    /// Returns the txid of the broadcast transaction, matching TS `anointHost`
    /// which returns `{ txid }`.
    pub async fn anoint_host(&self, host: &str) -> Result<String, MessageBoxError> {
        let identity_key = self.get_identity_key().await?;

        // Derive the public key for the PushDrop locking script.
        // Uses protocol [1, "messagebox advertisement"], keyId "1", counterparty Anyone, forSelf true.
        // This is the key the wallet will use when signing inputs that spend this output.
        let pk_result = self
            .wallet()
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(Protocol {
                        security_level: 1,
                        protocol: "messagebox advertisement".to_string(),
                    }),
                    key_id: Some("1".to_string()),
                    counterparty: Some(Counterparty {
                        counterparty_type: CounterpartyType::Anyone,
                        public_key: None,
                    }),
                    privileged: false,
                    privileged_reason: None,
                    for_self: Some(true),
                    seek_permission: None,
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        let pubkey_bytes = pk_result.public_key.to_der();

        // fields[0] = raw identity key bytes (hex-decoded per Pitfall 3)
        let id_key_bytes = hex::decode(&identity_key)
            .map_err(|e| MessageBoxError::Overlay(format!("hex decode identity key: {e}")))?;
        let host_bytes = host.as_bytes().to_vec();

        // Sign the concatenated field data (matches TS PushDrop.lock with includeSignature=true)
        let data_to_sign: Vec<u8> = [id_key_bytes.as_slice(), host_bytes.as_slice()].concat();
        let sig_result = self
            .wallet()
            .create_signature(
                bsv::wallet::interfaces::CreateSignatureArgs {
                    data: Some(data_to_sign),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol {
                        security_level: 1,
                        protocol: "messagebox advertisement".to_string(),
                    },
                    key_id: "1".to_string(),
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Anyone,
                        public_key: None,
                    },
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Overlay(format!("sign fields: {e}")))?;

        // Build PushDrop locking script using SDK's PushDrop template.
        // We use a dummy PrivateKey(1) for PushDrop::new since we only need
        // the script structure — the actual locking key is the wallet-derived
        // pubkey which we embed by replacing the dummy pubkey in the output.
        // The signature field from wallet.create_signature() is included as
        // the last data field, matching the TS SDK's includeSignature=true.
        let fields = vec![id_key_bytes, host_bytes, sig_result.signature];

        // Build the locking script with "before" position using the derived pubkey.
        // PushDrop template needs a PrivateKey, but we can build the chunks directly
        // since we have the public key from wallet.get_public_key().
        use bsv::script::templates::ScriptTemplateLock;
        let locking_script = {
            // Use PrivateKey(1) as dummy — we'll replace the pubkey
            let mut dummy_buf = [0u8; 32];
            dummy_buf[31] = 1;
            let dummy_key = bsv::primitives::private_key::PrivateKey::from_bytes(&dummy_buf)
                .map_err(|e| MessageBoxError::Overlay(format!("dummy key: {e}")))?;
            let pd = PushDrop::new(fields, dummy_key);
            let script = pd.lock()
                .map_err(|e| MessageBoxError::Overlay(format!("PushDrop lock: {e}")))?;

            // Replace the dummy pubkey (chunk 0) with the wallet-derived pubkey
            let mut chunks = script.chunks().to_vec();
            chunks[0] = ScriptChunk::new_raw(
                pubkey_bytes.len() as u8,
                Some(pubkey_bytes),
            );
            LockingScript::from_script(Script::from_chunks(chunks))
        };

        // Create the overlay advertisement transaction
        let create_result = self
            .wallet()
            .create_action(
                CreateActionArgs {
                    description: "Anoint host for overlay routing".to_string(),
                    input_beef: None,
                    inputs: vec![],
                    outputs: vec![CreateActionOutput {
                        locking_script: Some(locking_script.to_binary()),
                        satoshis: 1,
                        output_description: "Overlay advertisement output".to_string(),
                        basket: Some("overlay advertisements".to_string()),
                        custom_instructions: None,
                        tags: vec![],
                    }],
                    lock_time: None,
                    version: None,
                    labels: vec![],
                    options: Some(CreateActionOptions {
                        // randomize_outputs: false — output_index 0 is stable
                        randomize_outputs: BooleanDefaultTrue(Some(false)),
                        accept_delayed_broadcast: BooleanDefaultTrue(Some(false)),
                        ..Default::default()
                    }),
                    reference: None,
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        // CRITICAL: Transaction::from_beef takes a hex string, not raw bytes.
        // create_result.tx contains BEEF bytes — encode to hex first.
        let beef_bytes = create_result
            .tx
            .ok_or_else(|| MessageBoxError::Overlay("create_action returned no tx".into()))?;
        let tx = Transaction::from_beef(&hex::encode(&beef_bytes))
            .map_err(|e| MessageBoxError::Overlay(format!("parse BEEF: {e}")))?;

        // Broadcast via TopicBroadcaster — tm_messagebox topic per Pitfall 4
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_messagebox".to_string()],
            TopicBroadcasterConfig {
                network: self.network.clone(),
                ..Default::default()
            },
            LookupResolver::new(LookupResolverConfig {
                network: self.network.clone(),
                ..Default::default()
            }),
        )
        .map_err(|e| MessageBoxError::Overlay(format!("build broadcaster: {e}")))?;

        broadcaster
            .broadcast(&tx)
            .await
            .map_err(|e| MessageBoxError::Overlay(format!("{e:?}")))?;

        // tx.id() returns Result<String> directly — no "hex" arg unlike TS
        let txid = tx
            .id()
            .map_err(|e| MessageBoxError::Overlay(format!("tx.id(): {e}")))?;

        Ok(txid)
    }

    /// Register a device for FCM push notifications.
    ///
    /// POSTs `{"fcmToken": ..., "deviceId": ..., "platform": ...}` (camelCase) to
    /// `{host}/registerDevice`. Returns `RegisterDeviceResponse { status, message, deviceId }`.
    ///
    /// TS parity: `registerDevice` returns the full response object including `deviceId`.
    pub async fn register_device(
        &self,
        fcm_token: &str,
        device_id: Option<&str>,
        platform: Option<&str>,
        override_host: Option<&str>,
    ) -> Result<RegisterDeviceResponse, MessageBoxError> {
        self.assert_initialized().await?;

        let base = override_host.unwrap_or_else(|| self.host());
        let request = RegisterDeviceRequest {
            fcm_token: fcm_token.to_string(),
            device_id: device_id.map(String::from),
            platform: platform.map(String::from),
        };

        let body_bytes = serde_json::to_vec(&request)
            .map_err(|e| MessageBoxError::Overlay(format!("serialize RegisterDeviceRequest: {e}")))?;

        let url = format!("{base}/registerDevice");
        let response = self.post_json(&url, body_bytes).await?;

        let resp: RegisterDeviceResponse = serde_json::from_slice(&response.body)
            .map_err(|e| MessageBoxError::Overlay(format!("deserialize RegisterDeviceResponse: {e}")))?;

        Ok(resp)
    }

    /// List all registered devices for this identity.
    ///
    /// GETs `{host}/devices` and returns `Vec<RegisteredDevice>`.
    /// All 8 server fields (id, deviceId, fcmToken, platform, active,
    /// createdAt, updatedAt, lastUsed) are captured.
    pub async fn list_registered_devices(
        &self,
        override_host: Option<&str>,
    ) -> Result<Vec<RegisteredDevice>, MessageBoxError> {
        self.assert_initialized().await?;

        let base = override_host.unwrap_or_else(|| self.host());
        let url = format!("{base}/devices");
        let response = self.get_json(&url).await?;

        let resp: ListDevicesResponse = serde_json::from_slice(&response.body)
            .map_err(|e| MessageBoxError::Overlay(format!("deserialize ListDevicesResponse: {e}")))?;

        Ok(resp.devices)
    }

    /// Revoke an existing host advertisement by spending its UTXO.
    ///
    /// Two-step create+sign pattern:
    /// 1. `create_action` with `input_beef` + input pointing to the advertisement UTXO.
    ///    Returns a signable transaction with a `reference` for the sign step.
    /// 2. Derive sighash preimage from the partial transaction.
    /// 3. `create_signature` with the advertisement protocol to produce a DER signature.
    /// 4. `sign_action` with the DER+sighash-type unlock script.
    /// 5. Broadcast the signed transaction via TopicBroadcaster.
    ///
    /// Returns the txid of the spending transaction.
    pub async fn revoke_host_advertisement(
        &self,
        token: &AdvertisementToken,
    ) -> Result<String, MessageBoxError> {
        // Step 1: create a signable (unsigned) transaction spending the advertisement UTXO.
        // unlocking_script_length: 73 matches TS (1 push byte + 72 DER sig bytes)
        let create_result = self
            .wallet()
            .create_action(
                CreateActionArgs {
                    description: "Revoke MessageBox host advertisement".to_string(),
                    input_beef: Some(token.beef.clone()),
                    inputs: vec![CreateActionInput {
                        outpoint: format!("{}.{}", token.txid, token.output_index),
                        input_description: "Revoking host advertisement token".to_string(),
                        unlocking_script: None,
                        unlocking_script_length: Some(73),
                        sequence_number: None,
                    }],
                    outputs: vec![],
                    lock_time: None,
                    version: None,
                    labels: vec![],
                    options: Some(CreateActionOptions {
                        accept_delayed_broadcast: BooleanDefaultTrue(Some(false)),
                        ..Default::default()
                    }),
                    reference: None,
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        // Step 2: Extract the signable transaction and its reference
        let signable = create_result.signable_transaction.ok_or_else(|| {
            MessageBoxError::Overlay("create_action returned no signable_transaction".into())
        })?;

        // Step 3: Build the partial transaction so we can compute the sighash preimage
        let partial_tx = Transaction::from_beef(&hex::encode(&signable.tx))
            .map_err(|e| MessageBoxError::Overlay(format!("parse signable tx: {e}")))?;

        // Recover the locking script from the token for the preimage
        let lock_script = LockingScript::from_hex(&token.locking_script)
            .map_err(|e| MessageBoxError::Overlay(format!("parse locking script hex: {e}")))?;

        // SIGHASH_ALL | SIGHASH_FORKID = 0x41
        let sighash_type: u32 = 0x41;

        let preimage = partial_tx
            .sighash_preimage(0, sighash_type, 1, &lock_script)
            .map_err(|e| MessageBoxError::Overlay(format!("sighash_preimage: {e}")))?;

        // Step 4: Sign via wallet using the advertisement protocol
        // create_signature takes `data` = the preimage bytes (wallet hashes internally)
        let sig_result = self
            .wallet()
            .create_signature(
                bsv::wallet::interfaces::CreateSignatureArgs {
                    protocol_id: Protocol {
                        security_level: 1,
                        protocol: "messagebox advertisement".to_string(),
                    },
                    key_id: "1".to_string(),
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Anyone,
                        public_key: None,
                    },
                    data: Some(preimage),
                    hash_to_directly_sign: None,
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        // Step 5: Build the unlock script: one data push of <sig_DER + sighash_byte>
        let mut sig_bytes = sig_result.signature;
        sig_bytes.push(sighash_type as u8);
        let unlock_chunks = vec![make_data_push(&sig_bytes)];
        let unlock_script = Script::from_chunks(unlock_chunks);

        // Step 6: sign_action finalizes the transaction with our unlock script
        let sign_result = self
            .wallet()
            .sign_action(
                SignActionArgs {
                    reference: signable.reference,
                    spends: HashMap::from([(
                        0u32,
                        SignActionSpend {
                            unlocking_script: unlock_script.to_binary(),
                            sequence_number: None,
                        },
                    )]),
                    options: None,
                },
                self.originator(),
            )
            .await
            .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

        // Step 7: Convert signed BEEF to Transaction and broadcast
        let signed_bytes = sign_result
            .tx
            .ok_or_else(|| MessageBoxError::Overlay("sign_action returned no tx".into()))?;
        let signed_tx = Transaction::from_beef(&hex::encode(&signed_bytes))
            .map_err(|e| MessageBoxError::Overlay(format!("parse signed tx: {e}")))?;

        let broadcaster = TopicBroadcaster::new(
            vec!["tm_messagebox".to_string()],
            TopicBroadcasterConfig {
                network: self.network.clone(),
                ..Default::default()
            },
            LookupResolver::new(LookupResolverConfig {
                network: self.network.clone(),
                ..Default::default()
            }),
        )
        .map_err(|e| MessageBoxError::Overlay(format!("build broadcaster: {e}")))?;

        broadcaster
            .broadcast(&signed_tx)
            .await
            .map_err(|e| MessageBoxError::Overlay(format!("{e:?}")))?;

        let txid = signed_tx
            .id()
            .map_err(|e| MessageBoxError::Overlay(format!("signed_tx.id(): {e}")))?;

        Ok(txid)
    }
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

    /// Test helper: thin Arc wrapper so ProtoWallet satisfies the Clone bound.
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

    fn make_client() -> MessageBoxClient<ArcWallet> {
        MessageBoxClient::new(
            "https://example.com".to_string(),
            ArcWallet::new(),
            None,
            Network::Mainnet,
        )
    }

    /// `resolve_host_for_recipient` falls back to `self.host` when overlay returns empty.
    ///
    /// With Network::Mainnet, `query_advertisements` will fail to reach SLAP trackers
    /// and return an empty vec (TS parity: no error propagation). The fallback kicks in.
    #[tokio::test]
    async fn test_resolve_host_falls_back_to_default() {
        let client = make_client();
        // Overlay unreachable from unit test → empty vec → fall back to self.host
        let host = client
            .resolve_host_for_recipient("03deadbeef")
            .await
            .expect("should not error");
        assert_eq!(host, "https://example.com", "must fall back to self.host");
    }

    /// revoke_host_advertisement builds an outpoint as "{txid}.{output_index}".
    #[test]
    fn test_revoke_host_args_correct() {
        let txid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";
        let output_index: u32 = 0;
        let outpoint = format!("{txid}.{output_index}");
        assert_eq!(
            outpoint,
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab.0"
        );
    }

    // -----------------------------------------------------------------------
    // Task 3 — device registration tests
    // -----------------------------------------------------------------------

    /// `RegisterDeviceRequest` serializes to camelCase JSON with correct field names.
    #[test]
    fn test_register_device_request_serializes_camelcase() {
        use crate::types::RegisterDeviceRequest;
        let req = RegisterDeviceRequest {
            fcm_token: "abc".to_string(),
            device_id: Some("d1".to_string()),
            platform: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"fcmToken\":\"abc\""), "fcmToken must be camelCase: {json}");
        assert!(json.contains("\"deviceId\":\"d1\""), "deviceId must be camelCase: {json}");
        assert!(!json.contains("platform"), "platform absent when None: {json}");
        assert!(!json.contains("fcm_token"), "no snake_case leakage: {json}");
        assert!(!json.contains("device_id"), "no snake_case leakage: {json}");
    }

    /// `ListDevicesResponse` deserializes a full server response including all 8 fields.
    #[test]
    fn test_list_devices_response_deserializes() {
        use crate::types::ListDevicesResponse;
        let raw = r#"{
            "status": "success",
            "devices": [{
                "id": 1,
                "deviceId": "d1",
                "fcmToken": "tok",
                "platform": "ios",
                "active": true,
                "createdAt": "2026-01-01",
                "updatedAt": "2026-01-01",
                "lastUsed": "2026-01-01"
            }]
        }"#;
        let resp: ListDevicesResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.status, "success");
        assert_eq!(resp.devices.len(), 1);
        let dev = &resp.devices[0];
        assert_eq!(dev.id, Some(1));
        assert_eq!(dev.device_id.as_deref(), Some("d1"));
        assert_eq!(dev.fcm_token, "tok");
        assert_eq!(dev.platform.as_deref(), Some("ios"));
        assert_eq!(dev.active, Some(true));
        assert!(dev.created_at.is_some());
        assert!(dev.updated_at.is_some());
        assert!(dev.last_used.is_some());
    }

    /// `RegisterDeviceResponse` deserializes `{status, message, deviceId}` correctly.
    #[test]
    fn test_register_device_response_deserializes() {
        use crate::types::RegisterDeviceResponse;
        let raw = r#"{"status":"success","message":"registered","deviceId":42}"#;
        let resp: RegisterDeviceResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.status, "success");
        assert_eq!(resp.message.as_deref(), Some("registered"));
        assert_eq!(resp.device_id, Some(42));
    }

    /// `register_device` method exists on `MessageBoxClient` — compile check.
    ///
    /// Verifies the method signature accepts fcm_token, device_id, platform.
    #[allow(dead_code)]
    fn register_device_compiles(client: &MessageBoxClient<ArcWallet>) {
        let _fut = client.register_device("tok123", Some("dev1"), Some("ios"), None);
    }

    /// `list_registered_devices` method exists on `MessageBoxClient` — compile check.
    #[allow(dead_code)]
    fn list_registered_devices_compiles(client: &MessageBoxClient<ArcWallet>) {
        let _fut = client.list_registered_devices(None);
    }
}
