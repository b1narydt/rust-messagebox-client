//! The client's WebSocket guards against a real relay socket: authsocket's own
//! server (socketioxide behind axum) on a loopback port, as authsocket's
//! end-to-end tests boot it. The server stands in for the relay: it runs the
//! BRC-103 handshake and the joinRoom rule, records each `sendMessage` and
//! acks it the way the relay does.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use authsocket::peer_session::VerifiedEvent;
use authsocket::server::{
    AuthSocketServer, CertificateAuthorizationDecision, SharedAuthSocketServer,
};
use authsocket::server_io::{attach, emit_signed_to_socket, AppDispatcher};
use bsv::auth::certificates::master::default_get_revocation_outpoint;
use bsv::auth::certificates::{MasterCertificate, VerifiableCertificate};
use bsv::auth::types::RequestedCertificateSet;
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::services::overlay_tools::Network;
use bsv::wallet::interfaces::{CertificateType, GetPublicKeyArgs, SerialNumber, WalletInterface};
use bsv::wallet::proto_wallet::ProtoWallet;
use serde_json::{json, Value};
use socketioxide::extract::SocketRef;
use socketioxide::SocketIo;
use tokio::sync::mpsc;

use super::tests::ArcWallet;
use super::MessageBoxClient;
use crate::delivery::DeliveryMode;
use crate::error::MessageBoxError;
use crate::websocket::CertificateProvider;

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000011";
const CLIENT_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000022";
const OTHER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000033";

/// How long a negative check waits for something that should not arrive.
const SETTLE: Duration = Duration::from_millis(300);

async fn identity_of(key_hex: &str) -> String {
    ProtoWallet::new(PrivateKey::from_hex(key_hex).expect("key"))
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
        .expect("identity")
        .public_key
        .to_der_hex()
}

/// Fail the test instead of hanging when the socket never answers.
async fn within<T>(work: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), work)
        .await
        .expect("timed out")
}

fn client(url: &str) -> MessageBoxClient<ArcWallet> {
    MessageBoxClient::new(
        url.to_string(),
        ArcWallet::from_key_hex(CLIENT_KEY),
        None,
        Network::Local,
    )
}

/// Records every `sendMessage` and acks it with `sendMessageAck-{roomId}`,
/// as the relay does for an accepted live send.
struct AckSends {
    sends: mpsc::UnboundedSender<Value>,
}

#[async_trait::async_trait]
impl AppDispatcher<ProtoWallet> for AckSends {
    async fn dispatch(
        &self,
        _io: &SocketIo,
        server: &AuthSocketServer<ProtoWallet>,
        socket: &SocketRef,
        event: VerifiedEvent,
    ) {
        if event.event_name != "sendMessage" {
            return;
        }
        let room = event.data["roomId"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let ack = json!({ "status": "success", "messageId": event.data["message"]["messageId"] });
        let _ = self.sends.send(event.data);
        emit_signed_to_socket(socket, server, &format!("sendMessageAck-{room}"), &ack).await;
    }
}

struct Relay {
    url: String,
    core: SharedAuthSocketServer<ProtoWallet>,
    sends: mpsc::UnboundedReceiver<Value>,
}

impl Relay {
    /// Serve `core` on an ephemeral loopback port, proving `SERVER_KEY`.
    async fn boot(core: AuthSocketServer<ProtoWallet>) -> Self {
        let core = Arc::new(core);
        let (layer, io) = SocketIo::new_layer();
        let (sends_tx, sends) = mpsc::unbounded_channel();
        attach(
            &io,
            core.clone(),
            || {
                Ok(ProtoWallet::new(
                    PrivateKey::from_hex(SERVER_KEY).expect("server key"),
                ))
            },
            Arc::new(AckSends { sends: sends_tx }),
        );
        let app = axum::Router::new().layer(layer);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        Relay {
            url: format!("http://{addr}"),
            core,
            sends,
        }
    }

    /// Wait until the server has admitted a socket to `room`.
    async fn wait_for_member(&self, room: &str) {
        within(async {
            while self.core.room_members(room).is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
    }

    /// The next send the relay has recorded, after giving a stray one time
    /// to land.
    async fn settled_send(&mut self) -> Option<Value> {
        tokio::time::sleep(SETTLE).await;
        self.sends.try_recv().ok()
    }
}

/// A client pinned to another key refuses the relay that proves `SERVER_KEY`
/// and never joins a room on it. Pinned to `SERVER_KEY`, it joins.
#[tokio::test]
async fn ws_pin_refuses_a_relay_that_proves_another_key() {
    let relay = Relay::boot(AuthSocketServer::new()).await;
    let server_key = identity_of(SERVER_KEY).await;
    let room = format!("{}-inbox", identity_of(CLIENT_KEY).await);

    let pinned_elsewhere = client(&relay.url).with_expected_relay_key(identity_of(OTHER_KEY).await);
    match within(pinned_elsewhere.join_room("inbox")).await {
        Err(MessageBoxError::RelayIdentityMismatch { observed, .. }) => {
            assert_eq!(observed.as_deref(), Some(server_key.as_str()));
        }
        other => panic!("expected RelayIdentityMismatch, got {other:?}"),
    }
    // joinRoom is fire-and-forget: give a stray one time to land.
    tokio::time::sleep(SETTLE).await;
    assert!(
        relay.core.room_members(&room).is_empty(),
        "the refused relay admitted a joinRoom"
    );

    let pinned_here = client(&relay.url).with_expected_relay_key(&server_key);
    within(pinned_here.join_room("inbox"))
        .await
        .expect("pinned to the key the relay proves");
    relay.wait_for_member(&room).await;
    pinned_here
        .disconnect_web_socket()
        .await
        .expect("disconnect");
}

/// A live send to a mixed-case recipient key reaches the relay with the key
/// lowercased, in the room id and in the message.
#[tokio::test]
async fn ws_send_lowercases_the_recipient() {
    let mut relay = Relay::boot(AuthSocketServer::new()).await;
    let recipient = identity_of(OTHER_KEY).await;
    let sender = client(&relay.url);

    let mode = within(sender.send_live_message(
        &recipient.to_ascii_uppercase(),
        "inbox",
        "hello",
        true,
        false,
        Some("id-upper"),
        Some(&relay.url),
    ))
    .await
    .expect("live send");
    assert!(matches!(mode, DeliveryMode::Live { .. }), "{mode:?}");

    let sent = relay.sends.try_recv().expect("the relay saw the send");
    assert_eq!(sent["roomId"], format!("{recipient}-inbox"));
    assert_eq!(sent["message"]["recipient"], recipient);
    sender.disconnect_web_socket().await.expect("disconnect");
}

/// A live send first waits out a known rate-limit hold on the relay. When
/// the hold outlasts the rate-limit wait it returns `RateLimited` and emits
/// nothing.
#[tokio::test]
async fn ws_send_emits_nothing_while_the_relay_is_held() {
    let mut relay = Relay::boot(AuthSocketServer::new()).await;
    let recipient = identity_of(OTHER_KEY).await;
    let sender = client(&relay.url).with_rate_limit_wait(Duration::ZERO);
    sender.http.hold_for_rate_limit(
        &relay.url,
        &MessageBoxError::RateLimited {
            retry_after: Duration::from_secs(60),
            tier: None,
        },
    );

    let result = within(sender.send_live_message(
        &recipient,
        "inbox",
        "hello",
        true,
        false,
        Some("id-held"),
        Some(&relay.url),
    ))
    .await;
    assert!(
        matches!(result, Err(MessageBoxError::RateLimited { .. })),
        "{result:?}"
    );
    assert!(
        relay.settled_send().await.is_none(),
        "a held send reached the relay"
    );
    sender.disconnect_web_socket().await.expect("disconnect");
}

/// The relay's certificate request on the WebSocket handshake is answered by
/// the configured provider, and the client then joins its room.
#[tokio::test]
async fn ws_answers_the_certificate_request_with_the_provider() {
    let server_key = identity_of(SERVER_KEY).await;
    let core = AuthSocketServer::new();
    core.set_certificates_to_request(membership_request(server_key));
    core.set_certificate_authorizer(|_, _| async { CertificateAuthorizationDecision::Accept });
    let relay = Relay::boot(core).await;
    let room = format!("{}-inbox", identity_of(CLIENT_KEY).await);

    let asked = Arc::new(AtomicBool::new(false));
    let asked_by_relay = asked.clone();
    let provider: CertificateProvider = Arc::new(move |verifier, _requested| {
        asked_by_relay.store(true, Ordering::SeqCst);
        Box::pin(async move {
            Ok(vec![
                membership_certificate(CLIENT_KEY, SERVER_KEY, &verifier).await,
            ])
        })
    });
    let member = client(&relay.url).with_certificate_provider(provider);

    within(member.join_room("inbox"))
        .await
        .expect("certificate-gated connect");
    assert!(asked.load(Ordering::SeqCst), "the provider was not asked");
    relay.wait_for_member(&room).await;
    member.disconnect_web_socket().await.expect("disconnect");
}

/// One `membership` field of certificate type `[7; 32]` from `certifier`.
fn membership_request(certifier: String) -> RequestedCertificateSet {
    let mut requested = RequestedCertificateSet {
        certifiers: vec![certifier],
        ..RequestedCertificateSet::default()
    };
    requested.insert(
        "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=".to_string(),
        vec!["membership".to_string()],
    );
    requested
}

/// A `membership: active` certificate for `subject_key`, signed by
/// `certifier_key`, with the field revealed to `verifier`.
async fn membership_certificate(
    subject_key: &str,
    certifier_key: &str,
    verifier: &str,
) -> VerifiableCertificate {
    let subject_wallet = ProtoWallet::new(PrivateKey::from_hex(subject_key).expect("subject"));
    let subject = PublicKey::from_string(&identity_of(subject_key).await).expect("subject key");
    let certifier_wallet =
        ProtoWallet::new(PrivateKey::from_hex(certifier_key).expect("certifier"));
    let fields = [("membership".to_string(), "active".to_string())]
        .into_iter()
        .collect();
    let master = MasterCertificate::issue_certificate_for_subject(
        &CertificateType([7; 32]),
        &subject,
        fields,
        &certifier_wallet,
        default_get_revocation_outpoint,
        Some(SerialNumber([9; 32])),
    )
    .await
    .expect("issue membership certificate");
    let keyring = master
        .create_keyring_for_verifier(
            &PublicKey::from_string(verifier).expect("verifier key"),
            &["membership".to_string()],
            &master.certificate.certifier,
            &subject_wallet,
        )
        .await
        .expect("create verifier keyring");
    VerifiableCertificate::new(master.certificate, keyring)
}
