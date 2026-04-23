/// Result of a [`send_live_message`](crate::client::MessageBoxClient::send_live_message) call.
///
/// The WebSocket path waits up to 10 seconds for a `sendMessageAck`
/// event from the server. If the ack arrives, the message was
/// relayed to any live subscribers and delivery is `Live`. If the ack
/// times out, the client falls back to the HTTP POST /sendMessage
/// endpoint, which persists the message durably — the message IS
/// stored, but no live push was confirmed (recipients must poll or
/// be subscribed). Use `Live` when your protocol requires the peer
/// to have received the message in real time.
#[derive(Debug, Clone)]
pub enum DeliveryMode {
    /// Delivered via WebSocket — server acked within the 10s window.
    Live { message_id: String },
    /// Persisted via HTTP fallback — WS ack timed out. Recipient must
    /// poll or already be subscribed to receive it.
    Persisted { message_id: String },
}

impl DeliveryMode {
    /// Return the server-assigned message ID, regardless of delivery mode.
    pub fn message_id(&self) -> &str {
        match self {
            Self::Live { message_id } | Self::Persisted { message_id } => message_id,
        }
    }

    /// Return true if the message was acked live via WS.
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live { .. })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// DeliveryMode::message_id returns the correct ID for both variants.
    #[test]
    fn delivery_mode_message_id_both_variants() {
        let live = DeliveryMode::Live {
            message_id: "live-msg-001".to_string(),
        };
        assert_eq!(live.message_id(), "live-msg-001", "Live variant message_id");
        assert!(live.is_live(), "Live variant is_live() must be true");

        let persisted = DeliveryMode::Persisted {
            message_id: "http-msg-002".to_string(),
        };
        assert_eq!(
            persisted.message_id(),
            "http-msg-002",
            "Persisted variant message_id"
        );
        assert!(!persisted.is_live(), "Persisted variant is_live() must be false");
    }

    /// DeliveryMode implements Clone — both variants clone without panic.
    #[test]
    fn delivery_mode_clone() {
        let live = DeliveryMode::Live {
            message_id: "abc".to_string(),
        };
        let cloned = live.clone();
        assert_eq!(live.message_id(), cloned.message_id());

        let persisted = DeliveryMode::Persisted {
            message_id: "xyz".to_string(),
        };
        let cloned_p = persisted.clone();
        assert_eq!(persisted.message_id(), cloned_p.message_id());
    }

    /// DeliveryMode implements Debug — both variants format without panic.
    #[test]
    fn delivery_mode_debug() {
        let live = DeliveryMode::Live {
            message_id: "dbg-live".to_string(),
        };
        let s = format!("{live:?}");
        assert!(s.contains("Live"), "Debug output must mention variant");

        let persisted = DeliveryMode::Persisted {
            message_id: "dbg-persisted".to_string(),
        };
        let s2 = format!("{persisted:?}");
        assert!(s2.contains("Persisted"), "Debug output must mention variant");
    }
}
