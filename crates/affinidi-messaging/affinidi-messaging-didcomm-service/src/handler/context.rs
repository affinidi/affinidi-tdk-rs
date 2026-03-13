use std::sync::Arc;

use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};

/// Per-message context passed to handlers and middleware.
///
/// `sender_did` is `None` when the message was anoncrypt'd (no `from` field).
#[derive(Clone)]
pub struct HandlerContext {
    pub atm: ATM,
    pub profile: Arc<ATMProfile>,
    pub sender_did: Option<String>,
    pub message_id: String,
    pub thread_id: String,
    pub parent_thread_id: Option<String>,
}
