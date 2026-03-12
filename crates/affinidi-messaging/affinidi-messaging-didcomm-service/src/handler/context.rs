use std::sync::Arc;

use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};

#[derive(Clone)]
pub struct HandlerContext {
    pub atm: ATM,
    pub profile: Arc<ATMProfile>,
    pub sender_did: String,
    pub message_id: String,
    pub thread_id: Option<String>,
    pub parent_thread_id: Option<String>,
}
