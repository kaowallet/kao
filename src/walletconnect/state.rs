//! UI-shaped view of WalletConnect state.
//!
//! [`WcState`] is the dashboard's read model: connection status, live
//! sessions for the Settings list, and the queue of pending modals
//! (proposals and request approvals). The App writes into it as engine
//! events land; the dashboard's `view` reads it. Wrapped in
//! `Arc<RwLock<...>>` and shared between the two so a settle event
//! re-renders without rebuilding the dashboard — mirrors the existing
//! contacts pattern.
//!
//! This is deliberately separate from the engine's own session map: the
//! engine owns the canonical state (it can reply to the relay), the UI
//! holds a snapshot suitable for display. A settle event copies the
//! settled session into both.

use std::collections::{BTreeMap, VecDeque};

use crate::walletconnect::crypto::Topic;
use crate::walletconnect::protocol::{NamespaceProposal, NamespaceSettled, PeerMetadata};

/// Single source of WC state shared between App and dashboard.
#[derive(Debug, Default, Clone)]
pub struct WcState {
    pub status: WcStatus,
    pub sessions: Vec<UiSession>,
    /// Modal the user is currently looking at, if any. Pulled off the
    /// front of `queue` when the previous modal is dismissed.
    pub current_modal: Option<WcModal>,
    /// Behind-the-scenes queue of pending modals. The header on the
    /// active modal renders `"1 of N"` when this is non-empty.
    pub queue: VecDeque<WcModal>,
    /// Latest non-fatal error from the engine (subscription or dispatch
    /// path). Shown as a one-line banner under the paste field.
    pub last_error: Option<String>,
}

/// Coarse connection state surfaced as a colored pip + label on the
/// paste-URI row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum WcStatus {
    /// No bootstrap installed yet — App hasn't called
    /// [`super::runtime::install_bootstrap`].
    #[default]
    Idle,
    /// Worker received bootstrap and is opening the WebSocket.
    Connecting,
    /// Engine is live, ready for commands.
    Connected,
    /// Connect attempt failed. Subscription will re-mount on the next
    /// user event and retry.
    Failed(String),
}

/// Pending modal — either a sessionPropose awaiting accept/reject or an
/// in-session request awaiting approval.
#[derive(Debug, Clone)]
pub enum WcModal {
    Proposal(UiProposal),
    Request(UiRequest),
}

/// `wc_sessionPropose` projected into UI-friendly form. Carries the engine's
/// `proposal_id` so the dashboard's accept/reject can address it back to
/// the engine.
#[derive(Debug, Clone)]
pub struct UiProposal {
    pub proposal_id: u64,
    pub peer: PeerMetadata,
    pub required: BTreeMap<String, NamespaceProposal>,
    pub optional: BTreeMap<String, NamespaceProposal>,
}

/// `wc_sessionRequest` projected into UI form.
#[derive(Debug, Clone)]
pub struct UiRequest {
    pub request_id: u64,
    /// Session this request arrived on. Held so a future "approve from
    /// the activity feed" path can find the right session without
    /// re-walking by request_id, even though the WC modal itself
    /// only needs the peer and method/params.
    #[allow(dead_code)]
    pub session_topic: Topic,
    pub peer: PeerMetadata,
    pub chain_id: String,
    pub method: String,
    pub params: serde_json::Value,
}

/// Live session, post-settle. Used by the Sessions list in Settings and by
/// the modal header to show "from {peer.name}" on inbound requests.
#[derive(Debug, Clone)]
pub struct UiSession {
    pub topic: Topic,
    pub peer: PeerMetadata,
    pub namespaces: BTreeMap<String, NamespaceSettled>,
    /// Unix seconds. The Sessions pane renders this as "expires in 6d 14h".
    pub expiry: u64,
}

impl WcState {
    /// Enqueue a modal. If nothing is currently shown, promotes it to the
    /// active slot immediately so the dashboard renders it on the next
    /// view tick without a separate Tick message.
    pub fn enqueue(&mut self, modal: WcModal) {
        if self.current_modal.is_none() {
            self.current_modal = Some(modal);
        } else {
            self.queue.push_back(modal);
        }
    }

    /// Pop the current modal and promote the next from the queue. Returns
    /// the dismissed modal so the caller can react if it cares (e.g., the
    /// reject path needs the modal's id for the engine command).
    pub fn pop_current(&mut self) -> Option<WcModal> {
        let dismissed = self.current_modal.take();
        if dismissed.is_some() {
            self.current_modal = self.queue.pop_front();
        }
        dismissed
    }

    /// Total backlog count for the modal header — `current_modal` + queue.
    pub fn queue_len(&self) -> usize {
        usize::from(self.current_modal.is_some()) + self.queue.len()
    }

    /// Find a session by topic. Used by the Sessions pane and by the modal
    /// rendering ("from dApp X") to look up peer metadata on the request.
    /// `dead_code` allow: callers land with the per-method modal UX in a
    /// follow-up; the helper is the natural shape for that lookup.
    #[allow(dead_code)]
    pub fn session(&self, topic: &Topic) -> Option<&UiSession> {
        self.sessions.iter().find(|s| s.topic == *topic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str) -> PeerMetadata {
        PeerMetadata {
            name: name.to_string(),
            description: String::new(),
            url: String::new(),
            icons: vec![],
            redirect: None,
        }
    }

    fn proposal(id: u64) -> WcModal {
        WcModal::Proposal(UiProposal {
            proposal_id: id,
            peer: peer("d"),
            required: BTreeMap::new(),
            optional: BTreeMap::new(),
        })
    }

    #[test]
    fn enqueue_promotes_when_no_current() {
        let mut s = WcState::default();
        s.enqueue(proposal(1));
        assert!(s.current_modal.is_some());
        assert_eq!(s.queue.len(), 0);
        assert_eq!(s.queue_len(), 1);
    }

    #[test]
    fn enqueue_queues_when_current_is_set() {
        let mut s = WcState::default();
        s.enqueue(proposal(1));
        s.enqueue(proposal(2));
        s.enqueue(proposal(3));
        assert_eq!(s.queue.len(), 2);
        assert_eq!(s.queue_len(), 3);
    }

    #[test]
    fn pop_promotes_next_from_queue() {
        let mut s = WcState::default();
        s.enqueue(proposal(1));
        s.enqueue(proposal(2));
        let _ = s.pop_current();
        // Now the second proposal is active and queue is empty.
        match &s.current_modal {
            Some(WcModal::Proposal(p)) => assert_eq!(p.proposal_id, 2),
            _ => panic!("expected proposal 2"),
        }
        assert_eq!(s.queue.len(), 0);
        assert_eq!(s.queue_len(), 1);
    }

    #[test]
    fn pop_with_nothing_active_is_a_noop() {
        let mut s = WcState::default();
        assert!(s.pop_current().is_none());
        assert_eq!(s.queue_len(), 0);
    }
}
