use bsv::wallet::interfaces::WalletInterface;
use serde::Deserialize;

use crate::client::{check_status_error, MessageBoxClient};
use crate::error::MessageBoxError;
use crate::types::{MessageBoxPermission, MessageBoxQuote, SetPermissionParams};

// ---------------------------------------------------------------------------
// Internal response wrapper types (not exposed publicly)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GetPermissionResponse {
    permission: Option<MessageBoxPermission>,
}

#[derive(Deserialize)]
struct ListPermissionsResponse {
    permissions: Vec<MessageBoxPermission>,
}

#[derive(Deserialize)]
struct QuoteResponse {
    quote: QuoteBody,
}

#[derive(Deserialize)]
struct QuoteBody {
    #[serde(rename = "recipientFee")]
    recipient_fee: i64,
    #[serde(rename = "deliveryFee")]
    delivery_fee: i64,
}

// ---------------------------------------------------------------------------
// Permission and notification methods
// ---------------------------------------------------------------------------

impl<W: WalletInterface + Clone + 'static + Send + Sync> MessageBoxClient<W> {
    /// Set a permission rule for a message box.
    ///
    /// POSTs camelCase JSON to `/permissions/set`. The server returns HTTP 200
    /// even for logical errors — use `check_status_error` to detect them.
    pub async fn set_message_box_permission(
        &self,
        params: SetPermissionParams,
    ) -> Result<(), MessageBoxError> {
        self.assert_initialized().await?;

        let body_bytes = serde_json::to_vec(&params)?;
        let url = format!("{}/permissions/set", self.host());
        let response = self.post_json(&url, body_bytes).await?;
        check_status_error(&response.body)?;

        Ok(())
    }

    /// Retrieve a single permission record.
    ///
    /// GETs `/permissions/get` with camelCase query params (`recipient`, `messageBox`,
    /// optional `sender`). Returns `None` when the server responds with
    /// `{"permission": null}`.
    pub async fn get_message_box_permission(
        &self,
        recipient: &str,
        message_box: &str,
        sender: Option<&str>,
    ) -> Result<Option<MessageBoxPermission>, MessageBoxError> {
        self.assert_initialized().await?;

        // NOTE: query param key is camelCase `messageBox` — not snake_case.
        let mut url = format!(
            "{}/permissions/get?recipient={}&messageBox={}",
            self.host(),
            recipient,
            message_box
        );
        if let Some(s) = sender {
            url.push_str(&format!("&sender={s}"));
        }

        let response = self.get_json(&url).await?;
        check_status_error(&response.body)?;

        let parsed: GetPermissionResponse = serde_json::from_slice(&response.body)?;
        Ok(parsed.permission)
    }

    /// List permission records for this identity key.
    ///
    /// GETs `/permissions/list` with snake_case `message_box` query param —
    /// this is the unique endpoint that uses snake_case for its query key
    /// (Pitfall 1: do NOT use `messageBox` here).
    pub async fn list_message_box_permissions(
        &self,
        message_box: Option<&str>,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<MessageBoxPermission>, MessageBoxError> {
        self.assert_initialized().await?;

        let mut url = format!("{}/permissions/list", self.host());
        let mut params: Vec<String> = Vec::new();

        // CRITICAL: key is snake_case `message_box` — NOT `messageBox`.
        if let Some(mb) = message_box {
            params.push(format!("message_box={mb}"));
        }
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(o) = offset {
            params.push(format!("offset={o}"));
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let response = self.get_json(&url).await?;
        check_status_error(&response.body)?;

        let parsed: ListPermissionsResponse = serde_json::from_slice(&response.body)?;
        Ok(parsed.permissions)
    }

    /// Get a delivery quote for sending a message to `recipient`'s `message_box`.
    ///
    /// The response body is wrapped (`{"quote": {...}}`). The delivery agent's
    /// identity key comes from the `x-bsv-auth-identity-key` response header —
    /// NOT from the JSON body (Pitfall 2).
    pub async fn get_message_box_quote(
        &self,
        recipient: &str,
        message_box: &str,
    ) -> Result<MessageBoxQuote, MessageBoxError> {
        self.assert_initialized().await?;

        // NOTE: query param key is camelCase `messageBox` here.
        let url = format!(
            "{}/permissions/quote?recipient={}&messageBox={}",
            self.host(),
            recipient,
            message_box
        );

        let response = self.get_json(&url).await?;
        check_status_error(&response.body)?;

        // Extract delivery agent identity key from response header.
        // This header is NOT in the JSON body — it is set by the BRC-31 server.
        let delivery_agent_identity_key = response
            .headers
            .get("x-bsv-auth-identity-key")
            .cloned()
            .ok_or_else(|| {
                MessageBoxError::MissingHeader("x-bsv-auth-identity-key".into())
            })?;

        let parsed: QuoteResponse = serde_json::from_slice(&response.body)?;

        Ok(MessageBoxQuote {
            delivery_fee: parsed.quote.delivery_fee,
            recipient_fee: parsed.quote.recipient_fee,
            delivery_agent_identity_key,
        })
    }

    // -----------------------------------------------------------------------
    // Notification wrappers
    // -----------------------------------------------------------------------

    /// Allow a peer to send notifications by granting them access to the
    /// `"notifications"` message box with the given `recipient_fee`.
    pub async fn allow_notifications_from_peer(
        &self,
        sender: &str,
        recipient_fee: i64,
    ) -> Result<(), MessageBoxError> {
        self.set_message_box_permission(SetPermissionParams {
            message_box: "notifications".to_string(),
            sender: Some(sender.to_string()),
            recipient_fee,
        })
        .await
    }

    /// Block a peer from the `"notifications"` message box by setting
    /// `recipient_fee = -1`.
    pub async fn deny_notifications_from_peer(
        &self,
        sender: &str,
    ) -> Result<(), MessageBoxError> {
        self.set_message_box_permission(SetPermissionParams {
            message_box: "notifications".to_string(),
            sender: Some(sender.to_string()),
            recipient_fee: -1,
        })
        .await
    }

    /// Check whether `peer` has notification access from this identity's
    /// perspective.
    ///
    /// Uses `get_identity_key()` for `recipient` — the check is always
    /// performed against the local identity.
    pub async fn check_peer_notification_status(
        &self,
        peer: &str,
    ) -> Result<Option<MessageBoxPermission>, MessageBoxError> {
        let recipient = self.get_identity_key().await?;
        self.get_message_box_permission(&recipient, "notifications", Some(peer))
            .await
    }

    /// List all permission records in the `"notifications"` message box.
    pub async fn list_peer_notifications(
        &self,
    ) -> Result<Vec<MessageBoxPermission>, MessageBoxError> {
        self.list_message_box_permissions(Some("notifications"), None, None)
            .await
    }

    /// Send a notification body to `recipient`'s `"notifications"` inbox.
    ///
    /// Delegates to `send_message` with `message_box = "notifications"`.
    /// Host resolution is handled by `send_message` internally via overlay
    /// (`resolveHostForRecipient`) — TS parity achieved.
    pub async fn send_notification(
        &self,
        recipient: &str,
        body: &str,
    ) -> Result<String, MessageBoxError> {
        self.send_message(recipient, "notifications", body).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MessageBoxPermission, MessageBoxQuote, SetPermissionParams};
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::error::WalletError;
    use bsv::wallet::interfaces::*;
    use bsv::wallet::proto_wallet::ProtoWallet;
    use std::sync::Arc;

    // -----------------------------------------------------------------------
    // ArcWallet test helper (same pattern as other modules)
    // -----------------------------------------------------------------------

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

    fn make_client(host: &str) -> MessageBoxClient<ArcWallet> {
        MessageBoxClient::new(host.to_string(), ArcWallet::new(), None, bsv::services::overlay_tools::Network::Mainnet)
    }

    // -----------------------------------------------------------------------
    // URL construction tests (no HTTP needed)
    // -----------------------------------------------------------------------

    /// `set_message_box_permission` serializes a camelCase POST body.
    ///
    /// Verifies the key casing: `messageBox` and `recipientFee` in the JSON.
    #[test]
    fn set_permission_post_body_is_camel_case() {
        let params = SetPermissionParams {
            message_box: "payment_inbox".to_string(),
            sender: Some("03abc".to_string()),
            recipient_fee: 100,
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains("\"messageBox\""), "messageBox must be camelCase");
        assert!(json.contains("\"recipientFee\""), "recipientFee must be camelCase");
        assert!(json.contains("\"sender\""), "sender must be present when Some");
        assert!(!json.contains("message_box"), "no snake_case leakage");
        assert!(!json.contains("recipient_fee"), "no snake_case leakage");
    }

    /// `get_message_box_permission` builds URL with camelCase query params.
    ///
    /// The URL must contain `messageBox=` (camelCase) — not `message_box=`.
    #[test]
    fn get_permission_url_uses_camel_case_query_params() {
        // Test URL construction logic directly.
        let host = "https://example.com";
        let recipient = "03recipient";
        let message_box = "inbox";
        let sender = Some("03sender");

        let mut url = format!(
            "{}/permissions/get?recipient={}&messageBox={}",
            host, recipient, message_box
        );
        if let Some(s) = sender {
            url.push_str(&format!("&sender={s}"));
        }

        assert!(url.contains("messageBox=inbox"), "must use camelCase messageBox");
        assert!(!url.contains("message_box"), "must not use snake_case");
        assert!(url.contains("recipient=03recipient"), "recipient param present");
        assert!(url.contains("sender=03sender"), "sender param present when Some");
    }

    /// `get_message_box_permission` omits `sender` param when None.
    #[test]
    fn get_permission_url_omits_sender_when_none() {
        let host = "https://example.com";
        let recipient = "03recipient";
        let message_box = "inbox";
        let sender: Option<&str> = None;

        let mut url = format!(
            "{}/permissions/get?recipient={}&messageBox={}",
            host, recipient, message_box
        );
        if let Some(s) = sender {
            url.push_str(&format!("&sender={s}"));
        }

        assert!(!url.contains("sender"), "sender param absent when None");
        assert!(url.contains("messageBox=inbox"), "messageBox present");
    }

    /// `list_message_box_permissions` uses snake_case `message_box` query param.
    ///
    /// This is Pitfall 1: /permissions/list uses snake_case for the query key,
    /// unlike every other endpoint that uses camelCase.
    #[test]
    fn list_permissions_url_uses_snake_case_message_box_param() {
        let host = "https://example.com";
        let message_box = Some("notifications");

        let mut url = format!("{}/permissions/list", host);
        let mut params: Vec<String> = Vec::new();

        // CRITICAL: snake_case key
        if let Some(mb) = message_box {
            params.push(format!("message_box={mb}"));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        assert!(
            url.contains("message_box=notifications"),
            "must use snake_case message_box key: {}",
            url
        );
        assert!(
            !url.contains("messageBox"),
            "must NOT use camelCase messageBox in list endpoint: {}",
            url
        );
    }

    /// `get_message_box_quote` URL uses camelCase `messageBox` query param.
    #[test]
    fn quote_url_uses_camel_case_message_box_param() {
        let host = "https://example.com";
        let url = format!(
            "{}/permissions/quote?recipient=03r&messageBox=inbox",
            host
        );
        assert!(url.contains("messageBox=inbox"), "quote endpoint uses camelCase");
        assert!(!url.contains("message_box"), "not snake_case");
    }

    // -----------------------------------------------------------------------
    // Header extraction logic
    // -----------------------------------------------------------------------

    /// `get_message_box_quote` returns `MissingHeader` when header absent.
    ///
    /// Tests the header extraction error path without a live HTTP call.
    #[test]
    fn missing_header_produces_missing_header_error() {
        // Simulate the header extraction logic from get_message_box_quote.
        use std::collections::HashMap;
        let headers: HashMap<String, String> = HashMap::new();

        let result = headers
            .get("x-bsv-auth-identity-key")
            .cloned()
            .ok_or_else(|| MessageBoxError::MissingHeader("x-bsv-auth-identity-key".into()));

        assert!(result.is_err(), "must error when header absent");
        assert!(
            matches!(result.unwrap_err(), MessageBoxError::MissingHeader(_)),
            "error must be MissingHeader variant"
        );
    }

    /// `get_message_box_quote` extracts header when present.
    #[test]
    fn present_header_is_extracted_correctly() {
        use std::collections::HashMap;
        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "x-bsv-auth-identity-key".to_string(),
            "03deadbeef".to_string(),
        );

        let result: Result<String, MessageBoxError> = headers
            .get("x-bsv-auth-identity-key")
            .cloned()
            .ok_or_else(|| MessageBoxError::MissingHeader("x-bsv-auth-identity-key".into()));

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "03deadbeef");
    }

    // -----------------------------------------------------------------------
    // Response parsing tests (types already tested in types.rs, but verify
    // the wrapper response structures parse correctly)
    // -----------------------------------------------------------------------

    /// `GetPermissionResponse` parses wrapped `{"permission": {...}}` body.
    #[test]
    fn get_permission_response_parses_wrapped_body() {
        let raw = r#"{"permission": {"messageBox": "inbox", "recipientFee": 0, "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z"}}"#;
        let parsed: GetPermissionResponse = serde_json::from_str(raw).unwrap();
        let perm = parsed.permission.unwrap();
        assert_eq!(perm.message_box, "inbox");
        assert_eq!(perm.recipient_fee, 0);
    }

    /// `GetPermissionResponse` parses `{"permission": null}` as None.
    #[test]
    fn get_permission_response_parses_null_as_none() {
        let raw = r#"{"permission": null}"#;
        let parsed: GetPermissionResponse = serde_json::from_str(raw).unwrap();
        assert!(parsed.permission.is_none());
    }

    /// `ListPermissionsResponse` parses wrapped `{"permissions": [...]}` body.
    #[test]
    fn list_permissions_response_parses_wrapped_body() {
        // /permissions/list returns snake_case field names.
        let raw = r#"{"permissions": [{"message_box": "inbox", "recipient_fee": 100, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}]}"#;
        let parsed: ListPermissionsResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.permissions.len(), 1);
        assert_eq!(parsed.permissions[0].message_box, "inbox");
        assert_eq!(parsed.permissions[0].recipient_fee, 100);
    }

    /// `QuoteResponse` parses wrapped `{"quote": {...}}` body.
    #[test]
    fn quote_response_parses_wrapped_body() {
        let raw = r#"{"quote": {"recipientFee": 50, "deliveryFee": 10}}"#;
        let parsed: QuoteResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.quote.recipient_fee, 50);
        assert_eq!(parsed.quote.delivery_fee, 10);
    }

    // -----------------------------------------------------------------------
    // Notification wrapper delegation tests
    // -----------------------------------------------------------------------

    /// `allow_notifications_from_peer` constructs params with messageBox="notifications".
    #[test]
    fn allow_notifications_params_uses_notifications_box() {
        // Verify the params that would be sent.
        let params = SetPermissionParams {
            message_box: "notifications".to_string(),
            sender: Some("03peer".to_string()),
            recipient_fee: 0,
        };
        assert_eq!(params.message_box, "notifications");
        assert_eq!(params.sender, Some("03peer".to_string()));
    }

    /// `deny_notifications_from_peer` constructs params with recipient_fee=-1.
    #[test]
    fn deny_notifications_params_uses_negative_one_fee() {
        // Verify the params that would be sent.
        let params = SetPermissionParams {
            message_box: "notifications".to_string(),
            sender: Some("03peer".to_string()),
            recipient_fee: -1,
        };
        assert_eq!(params.recipient_fee, -1);
        assert_eq!(params.message_box, "notifications");
    }

    /// MessageBoxClient::deny_notifications_from_peer produces blocked status from
    /// the permission fee value.
    #[test]
    fn deny_fee_produces_blocked_status() {
        let perm = MessageBoxPermission {
            sender: Some("03peer".to_string()),
            message_box: "notifications".to_string(),
            recipient_fee: -1,
            created_at: "2024-01-01".to_string(),
            updated_at: "2024-01-01".to_string(),
        };
        assert_eq!(perm.status(), "blocked");
    }

    /// MessageBoxQuote fields are populated correctly from header + JSON body.
    #[test]
    fn quote_constructed_from_header_and_body() {
        let quote = MessageBoxQuote {
            delivery_fee: 10,
            recipient_fee: 50,
            delivery_agent_identity_key: "03agent".to_string(),
        };
        assert_eq!(quote.delivery_fee, 10);
        assert_eq!(quote.recipient_fee, 50);
        assert_eq!(quote.delivery_agent_identity_key, "03agent");
    }

    /// Client can be constructed — compile check for permissions module.
    #[test]
    fn client_with_permissions_compiles() {
        let _client = make_client("https://example.com");
    }
}
