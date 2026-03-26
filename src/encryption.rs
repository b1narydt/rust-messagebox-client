use base64::{engine::general_purpose::STANDARD, Engine};
use bsv::primitives::public_key::PublicKey;
use bsv::wallet::interfaces::{
    CreateHmacArgs, DecryptArgs, EncryptArgs, WalletInterface,
};
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};

use crate::error::MessageBoxError;

/// BRC-78 encrypt a message body for a recipient.
///
/// Returns a JSON string: `{"encryptedMessage":"<STANDARD_base64_ciphertext>"}`.
/// Must use STANDARD base64 (with padding) for TS interop — URL-safe or unpadded variants
/// produce different output that the TS client cannot decrypt.
pub async fn encrypt_body<W: WalletInterface>(
    wallet: &W,
    body: &str,
    recipient_pubkey_hex: &str,
    originator: Option<&str>,
) -> Result<String, MessageBoxError> {
    let pk = PublicKey::from_string(recipient_pubkey_hex)
        .map_err(|e| MessageBoxError::Encryption(e.to_string()))?;

    let result = wallet
        .encrypt(
            EncryptArgs {
                protocol_id: Protocol {
                    security_level: 1,
                    protocol: "messagebox".to_string(),
                },
                key_id: "1".to_string(),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Other,
                    public_key: Some(pk),
                },
                plaintext: body.as_bytes().to_vec(),
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            originator,
        )
        .await
        .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

    // STANDARD base64 with padding — required for TS interop
    let b64 = STANDARD.encode(&result.ciphertext);
    Ok(serde_json::json!({"encryptedMessage": b64}).to_string())
}

/// BRC-78 decrypt an encrypted message body from a sender.
///
/// Parses `encrypted_json` expecting `{"encryptedMessage":"<base64>"}`,
/// base64-decodes the ciphertext, and decrypts using the sender's public key.
pub async fn decrypt_body<W: WalletInterface>(
    wallet: &W,
    encrypted_json: &str,
    sender_pubkey_hex: &str,
    originator: Option<&str>,
) -> Result<String, MessageBoxError> {
    let v: serde_json::Value = serde_json::from_str(encrypted_json)?;
    let b64 = v["encryptedMessage"]
        .as_str()
        .ok_or_else(|| MessageBoxError::Encryption("missing encryptedMessage field".to_string()))?;

    let ciphertext = STANDARD
        .decode(b64)
        .map_err(|e| MessageBoxError::Encryption(format!("base64 decode: {e}")))?;

    let pk = PublicKey::from_string(sender_pubkey_hex)
        .map_err(|e| MessageBoxError::Encryption(e.to_string()))?;

    let result = wallet
        .decrypt(
            DecryptArgs {
                protocol_id: Protocol {
                    security_level: 1,
                    protocol: "messagebox".to_string(),
                },
                key_id: "1".to_string(),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Other,
                    public_key: Some(pk),
                },
                ciphertext,
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            originator,
        )
        .await
        .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

    String::from_utf8(result.plaintext)
        .map_err(|e| MessageBoxError::Encryption(format!("utf-8 decode: {e}")))
}

/// Try to decrypt a message body, with graceful fallback for plaintext.
///
/// Handles three cases (matching TS `listMessagesLite` lines 1442-1452):
/// 1. JSON with a `"message"` wrapper key: unwrap first, then check inner content.
/// 2. JSON with `"encryptedMessage"` key: decrypt.
/// 3. Anything else (no encryptedMessage key, or not JSON): return original body unchanged.
///
/// Does NOT panic on parse failure — always returns a String.
///
/// NOTE: PARITY — passes `originator: None` inside when called from list_messages_lite.
/// This matches a latent TS bug where listMessagesLite omits originator.
pub async fn try_decrypt_message<W: WalletInterface>(
    wallet: &W,
    raw_body: &str,
    sender_pubkey_hex: &str,
    originator: Option<&str>,
) -> String {
    // Try to parse as JSON and inspect the content
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw_body) {
        // Case 1: payment envelope wrapper — unwrap and recurse into inner content
        if let Some(inner) = v.get("message") {
            let inner_str = if inner.is_string() {
                inner.as_str().unwrap().to_string()
            } else {
                inner.to_string()
            };
            // Recursively handle the unwrapped inner body
            return Box::pin(try_decrypt_message(wallet, &inner_str, sender_pubkey_hex, originator)).await;
        }

        // Case 2: encrypted body
        if v.get("encryptedMessage").is_some() {
            return decrypt_body(wallet, raw_body, sender_pubkey_hex, originator)
                .await
                .unwrap_or_else(|_| raw_body.to_string());
        }
    }

    // Case 3: plaintext passthrough (ENC-04)
    raw_body.to_string()
}

/// Generate a deterministic HMAC-based message ID for idempotency.
///
/// CRITICAL: The TS uses `JSON.stringify(message.body)` as the HMAC data (line 917).
/// For a plain string body, this means the data is the JSON-encoded string
/// (e.g., `"hello"` becomes `"\"hello\""` with surrounding quotes).
/// Use `serde_json::to_string(body)` to replicate this behavior exactly.
pub async fn generate_message_id<W: WalletInterface>(
    wallet: &W,
    body: &str,
    recipient_pubkey_hex: &str,
    originator: Option<&str>,
) -> Result<String, MessageBoxError> {
    // Replicate TS JSON.stringify(body) — wraps the string in JSON quotes
    let json_body = serde_json::to_string(body)?;

    let pk = PublicKey::from_string(recipient_pubkey_hex)
        .map_err(|e| MessageBoxError::Encryption(e.to_string()))?;

    let result = wallet
        .create_hmac(
            CreateHmacArgs {
                protocol_id: Protocol {
                    security_level: 1,
                    protocol: "messagebox".to_string(),
                },
                key_id: "1".to_string(),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Other,
                    public_key: Some(pk),
                },
                data: json_body.as_bytes().to_vec(),
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            originator,
        )
        .await
        .map_err(|e| MessageBoxError::Wallet(e.to_string()))?;

    // Hex-encode matching TS: Array.from(hmac).map(b => b.toString(16).padStart(2,'0')).join('')
    Ok(result.hmac.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::interfaces::GetPublicKeyArgs;
    use bsv::wallet::proto_wallet::ProtoWallet;

    fn make_wallet() -> ProtoWallet {
        let key = PrivateKey::from_random().expect("random key");
        ProtoWallet::new(key)
    }

    async fn identity_hex(wallet: &ProtoWallet) -> String {
        wallet
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
                None,
            )
            .await
            .expect("get_public_key")
            .public_key
            .to_der_hex()
    }

    #[tokio::test]
    async fn encrypt_body_produces_valid_json_with_base64() {
        let sender = make_wallet();
        let receiver = make_wallet();
        let receiver_pk = identity_hex(&receiver).await;

        let encrypted = encrypt_body(&sender, "hello world", &receiver_pk, None)
            .await
            .expect("encrypt_body");

        let v: serde_json::Value = serde_json::from_str(&encrypted).expect("valid json");
        let b64 = v["encryptedMessage"].as_str().expect("encryptedMessage field");
        // Must be valid STANDARD base64 (with padding)
        STANDARD.decode(b64).expect("valid STANDARD base64");
    }

    #[tokio::test]
    async fn encrypt_decrypt_round_trip() {
        let sender = make_wallet();
        let receiver = make_wallet();
        let sender_pk = identity_hex(&sender).await;
        let receiver_pk = identity_hex(&receiver).await;

        let message = "The quick brown fox jumps over the lazy dog — unicode: 日本語 🦊";
        let encrypted = encrypt_body(&sender, message, &receiver_pk, None)
            .await
            .expect("encrypt");
        let decrypted = decrypt_body(&receiver, &encrypted, &sender_pk, None)
            .await
            .expect("decrypt");

        assert_eq!(decrypted, message);
    }

    #[tokio::test]
    async fn try_decrypt_plaintext_passthrough() {
        let wallet = make_wallet();
        let other = make_wallet();
        let other_pk = identity_hex(&other).await;

        let result = try_decrypt_message(&wallet, "plain text body", &other_pk, None).await;
        assert_eq!(result, "plain text body");
    }

    #[tokio::test]
    async fn try_decrypt_json_without_encrypted_message_passthrough() {
        let wallet = make_wallet();
        let other = make_wallet();
        let other_pk = identity_hex(&other).await;

        let input = r#"{"foo":"bar","baz":42}"#;
        let result = try_decrypt_message(&wallet, input, &other_pk, None).await;
        assert_eq!(result, input);
    }

    #[tokio::test]
    async fn try_decrypt_with_encrypted_body_decrypts() {
        let sender = make_wallet();
        let receiver = make_wallet();
        let sender_pk = identity_hex(&sender).await;
        let receiver_pk = identity_hex(&receiver).await;

        let message = "secret message content";
        let encrypted = encrypt_body(&sender, message, &receiver_pk, None)
            .await
            .expect("encrypt");

        let result = try_decrypt_message(&receiver, &encrypted, &sender_pk, None).await;
        assert_eq!(result, message);
    }

    #[tokio::test]
    async fn try_decrypt_unwraps_payment_envelope_and_decrypts() {
        let sender = make_wallet();
        let receiver = make_wallet();
        let sender_pk = identity_hex(&sender).await;
        let receiver_pk = identity_hex(&receiver).await;

        let message = "payment wrapped message";
        let encrypted = encrypt_body(&sender, message, &receiver_pk, None)
            .await
            .expect("encrypt");

        // Simulate payment envelope: {"message": "<encrypted_json>", "payment": {...}}
        let wrapped = serde_json::json!({
            "message": encrypted,
            "payment": {"txid": "abc123"}
        })
        .to_string();

        let result = try_decrypt_message(&receiver, &wrapped, &sender_pk, None).await;
        assert_eq!(result, message);
    }

    #[tokio::test]
    async fn generate_message_id_returns_64_char_hex() {
        let wallet = make_wallet();
        let other = make_wallet();
        let other_pk = identity_hex(&other).await;

        let id = generate_message_id(&wallet, "test body", &other_pk, None)
            .await
            .expect("generate_message_id");

        assert_eq!(id.len(), 64, "HMAC hex should be 64 chars (32 bytes)");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "all hex chars");
        assert!(id.chars().all(|c| !c.is_uppercase()), "lowercase hex");
    }

    #[tokio::test]
    async fn generate_message_id_is_deterministic() {
        let wallet = make_wallet();
        let other = make_wallet();
        let other_pk = identity_hex(&other).await;

        let id1 = generate_message_id(&wallet, "same body", &other_pk, None)
            .await
            .expect("first call");
        let id2 = generate_message_id(&wallet, "same body", &other_pk, None)
            .await
            .expect("second call");

        assert_eq!(id1, id2, "same inputs must produce same HMAC");
    }
}
