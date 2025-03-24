//! Generates a DIDComm error message response to be sent back if errors occur
//! Mainly useful for WebSocket transport where an inbound message causes an error
//! and we want to communicate that back to the sender

use std::time::SystemTime;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::ProblemReport;
use serde_json::json;
use uuid::Uuid;

use crate::{SharedData, database::session::Session};

use super::ProcessMessageResponse;

/// Create an ephemeral error response to the sender of the message
/// Will override live_streaming status as this is an error message
/// - `state` - The shared data state
/// - `session` - The session of the sender
/// - `did_hash` - The DID hash of the sender
/// - `thid` - The thread ID of the message
/// - `problem` - The problem report to send
/// - `store_message` - Store message in a queue? or attempt live_delivery only?
pub(crate) fn generate_error_response(
    state: &SharedData,
    session: &Session,
    thid: &str,
    problem: ProblemReport,
    store_message: bool,
) -> Result<ProcessMessageResponse, MediatorError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Build the message
    let error_msg = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/report-problem/2.0/problem-report".to_owned(),
        json!(problem),
    )
    .pthid(thid.to_owned())
    .to(session.did.clone())
    .header("ack".into(), json!([thid.to_owned()]))
    .from(state.config.mediator_did.clone())
    .created_time(now)
    .expires_time(now + 300)
    .finalize();

    Ok(ProcessMessageResponse {
        store_message,
        force_live_delivery: false,
        data: super::WrapperType::Message(error_msg),
        forward_message: false,
    })
}
