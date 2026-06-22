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

/// Outcome of [`try_decrypt_message_typed`] — distinguishes a body that genuinely
/// AEAD-decrypted from one that was merely passed through (plaintext or a
/// fail-open decrypt failure).
///
/// SECURITY (fail-closed boundary support): `try_decrypt_message` returns a bare
/// `String` and is **fail-OPEN** — on AEAD-decrypt failure it returns the raw
/// encrypted envelope, and for non-encrypted bodies it returns the raw plaintext.
/// Callers that require sender provenance (e.g. the MPC transport, whose messages
/// are ALWAYS sent encrypted) cannot tell those apart from a real decrypt. This
/// typed sibling preserves that distinction so the caller can reject anything that
/// did not authenticate-decrypt against the claimed sender's key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecryptOutcome {
    /// The encrypted-envelope branch ran and `decrypt_body` returned `Ok` — the
    /// body genuinely AEAD-decrypted against the claimed sender. The inner string
    /// is the recovered plaintext.
    Decrypted(String),
    /// The body was NOT authenticated-decrypted: either a non-encrypted passthrough
    /// (Case 3) or an `{"encryptedMessage":...}` body whose `decrypt_body` failed
    /// (the Case-2 fail-open branch). The inner string is the raw body verbatim,
    /// byte-for-byte identical to what `try_decrypt_message` would return.
    Plaintext(String),
}

impl DecryptOutcome {
    /// The recovered/passthrough body string, regardless of authenticity. Equals
    /// exactly what [`try_decrypt_message`] returns for the same inputs.
    pub fn into_body(self) -> String {
        match self {
            DecryptOutcome::Decrypted(s) | DecryptOutcome::Plaintext(s) => s,
        }
    }

    /// `true` iff the body genuinely AEAD-decrypted (the `Decrypted` variant).
    pub fn is_authenticated(&self) -> bool {
        matches!(self, DecryptOutcome::Decrypted(_))
    }
}

/// Typed sibling of [`try_decrypt_message`] that additionally surfaces whether the
/// body genuinely AEAD-decrypted.
///
/// Returns [`DecryptOutcome::Decrypted`] ONLY when the encrypted-envelope branch
/// (`{"encryptedMessage":...}`) ran AND `decrypt_body` returned `Ok`. Returns
/// [`DecryptOutcome::Plaintext`] for the Case-3 non-encrypted passthrough AND for
/// the Case-2 decrypt-failure fail-open branch.
///
/// The returned body string is byte-for-byte identical to [`try_decrypt_message`]
/// for the same inputs, so this is a strict superset — callers that only need the
/// string can call `.into_body()`.
pub async fn try_decrypt_message_typed<W: WalletInterface>(
    wallet: &W,
    raw_body: &str,
    sender_pubkey_hex: &str,
    originator: Option<&str>,
) -> DecryptOutcome {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw_body) {
        // Case 1: payment envelope wrapper — unwrap and recurse. Authenticity of
        // the OUTER wrapper is irrelevant; the inner recursion decides.
        if let Some(inner) = v.get("message") {
            let inner_str = if inner.is_string() {
                inner.as_str().unwrap().to_string()
            } else {
                inner.to_string()
            };
            return Box::pin(try_decrypt_message_typed(
                wallet,
                &inner_str,
                sender_pubkey_hex,
                originator,
            ))
            .await;
        }

        // Case 2: encrypted body — Decrypted only on a genuine Ok, else fail-open Plaintext.
        if v.get("encryptedMessage").is_some() {
            return match decrypt_body(wallet, raw_body, sender_pubkey_hex, originator).await {
                Ok(plaintext) => DecryptOutcome::Decrypted(plaintext),
                Err(_) => DecryptOutcome::Plaintext(raw_body.to_string()),
            };
        }
    }

    // Case 3: plaintext passthrough — not authenticated.
    DecryptOutcome::Plaintext(raw_body.to_string())
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
    async fn typed_decrypt_plaintext_body_is_plaintext_outcome() {
        // A valid-shaped plaintext WireMessage body must NOT be reported as
        // authenticated — this is the bypass the fail-closed boundary defends.
        let wallet = make_wallet();
        let other = make_wallet();
        let other_pk = identity_hex(&other).await;

        let body = r#"{"sender":0,"is_broadcast":true,"msg":{"round":1}}"#;
        let outcome = try_decrypt_message_typed(&wallet, body, &other_pk, None).await;
        assert_eq!(outcome, DecryptOutcome::Plaintext(body.to_string()));
        assert!(!outcome.is_authenticated());
        assert_eq!(outcome.into_body(), body);
    }

    #[tokio::test]
    async fn typed_decrypt_non_json_plaintext_is_plaintext_outcome() {
        let wallet = make_wallet();
        let other = make_wallet();
        let other_pk = identity_hex(&other).await;

        let outcome = try_decrypt_message_typed(&wallet, "plain text", &other_pk, None).await;
        assert!(!outcome.is_authenticated());
    }

    #[tokio::test]
    async fn typed_decrypt_failed_aead_fails_open_to_plaintext_outcome() {
        // An {"encryptedMessage":...} body that does NOT decrypt under our key must
        // be reported Plaintext (fail-open string parity) but NOT authenticated.
        let wallet = make_wallet();
        let other = make_wallet();
        let other_pk = identity_hex(&other).await;

        let body = r#"{"encryptedMessage":"AAAAbase64ciphertext=="}"#;
        let outcome = try_decrypt_message_typed(&wallet, body, &other_pk, None).await;
        assert!(!outcome.is_authenticated(), "garbage ciphertext must not authenticate");
        // String parity with try_decrypt_message (fail-open returns raw body).
        let legacy = try_decrypt_message(&wallet, body, &other_pk, None).await;
        assert_eq!(outcome.into_body(), legacy);
    }

    #[tokio::test]
    async fn typed_decrypt_round_trip_is_decrypted_outcome() {
        let sender = make_wallet();
        let receiver = make_wallet();
        let sender_pk = identity_hex(&sender).await;
        let receiver_pk = identity_hex(&receiver).await;

        let message = "secret authenticated content";
        let encrypted = encrypt_body(&sender, message, &receiver_pk, None)
            .await
            .expect("encrypt");

        let outcome = try_decrypt_message_typed(&receiver, &encrypted, &sender_pk, None).await;
        assert_eq!(outcome, DecryptOutcome::Decrypted(message.to_string()));
        assert!(outcome.is_authenticated());
    }

    #[tokio::test]
    async fn typed_decrypt_payment_envelope_round_trip_is_decrypted() {
        let sender = make_wallet();
        let receiver = make_wallet();
        let sender_pk = identity_hex(&sender).await;
        let receiver_pk = identity_hex(&receiver).await;

        let message = "wrapped authenticated content";
        let encrypted = encrypt_body(&sender, message, &receiver_pk, None)
            .await
            .expect("encrypt");
        let wrapped = serde_json::json!({"message": encrypted, "payment": {"txid": "abc"}})
            .to_string();

        let outcome = try_decrypt_message_typed(&receiver, &wrapped, &sender_pk, None).await;
        assert_eq!(outcome, DecryptOutcome::Decrypted(message.to_string()));
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
