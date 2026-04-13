use std::sync::Arc;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::ATM;
use affinidi_messaging_sdk::profiles::ATMProfile;
use serde_json::Value;
use tracing::{trace, warn};

use crate::error::{DIDCommServiceError, TransportError};
use crate::handler::HandlerContext;
use crate::problem_report::{ProblemReport, ServiceProblemReport};
use crate::utils::new_message_id;

pub const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

pub fn build_response(
    ctx: &HandlerContext,
    response_type: String,
    body: Value,
) -> Result<Message, DIDCommServiceError> {
    let sender = ctx
        .sender_did
        .as_deref()
        .ok_or(TransportError::MissingSenderDid)?;

    let mut builder = Message::build(new_message_id(), response_type, body)
        .from(ctx.profile.inner.did.clone())
        .to(sender.to_string())
        .thid(ctx.thread_id.clone());

    if let Some(ref parent_id) = ctx.parent_thread_id {
        builder = builder.header("pthid".into(), Value::String(parent_id.clone()));
    }

    Ok(builder.finalize())
}

pub fn build_problem_report(
    ctx: &HandlerContext,
    report: &ProblemReport,
) -> Result<Message, DIDCommServiceError> {
    build_response(ctx, PROBLEM_REPORT_TYPE.to_string(), report.to_body())
}

pub async fn send_response(
    ctx: &HandlerContext,
    message: Message,
) -> Result<(), DIDCommServiceError> {
    let message_id = message.id.clone();
    let recipient = ctx
        .sender_did
        .as_deref()
        .ok_or(TransportError::MissingSenderDid)?;

    let (packed_msg, _) = ctx
        .atm
        .pack_encrypted(
            &message,
            recipient,
            Some(&ctx.profile.inner.did),
            Some(&ctx.profile.inner.did),
        )
        .await?;

    let mediator_did = ctx
        .profile
        .to_tdk_profile()
        .mediator
        .ok_or_else(|| DIDCommServiceError::MissingMediator(ctx.profile.inner.alias.clone()))?;

    let sending_result = ctx
        .atm
        .forward_and_send_message(
            &ctx.profile,
            false,
            &packed_msg,
            Some(&message_id),
            &mediator_did,
            recipient,
            None,
            None,
            false,
        )
        .await;

    if let Err(sending_error) = sending_result {
        warn!(profile = %ctx.profile.inner.alias, error = ?sending_error, "Failed to send response");
        return Err(TransportError::Send(sending_error).into());
    }

    trace!(profile = %ctx.profile.inner.alias, "Response sent successfully");
    Ok(())
}

pub async fn send_problem_report(
    ctx: &HandlerContext,
    report: &ProblemReport,
) -> Result<(), DIDCommServiceError> {
    let message = build_problem_report(ctx, report)?;
    send_response(ctx, message).await
}

/// Send a proactive (unsolicited) DIDComm message through an ATM connection.
///
/// Unlike [`send_response`] which derives the recipient from the handler
/// context, this takes an explicit recipient DID and uses the profile's DID
/// as the sender for encryption.
///
/// **Important:** The message is always encrypted using the profile's DID as
/// the sender, regardless of what `message.from` is set to. If `message.from`
/// differs from the profile's DID, recipients will see a mismatch between the
/// plaintext `from` header and the authenticated sender from the encryption
/// layer, and will likely reject the message. Callers should ensure
/// `message.from` matches the profile's DID (or is left unset).
pub(crate) async fn send_message(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    message: Message,
    recipient_did: &str,
) -> Result<(), DIDCommServiceError> {
    let sender_did = &profile.inner.did;
    let message_id = message.id.clone();

    if let Some(ref from) = message.from
        && from != sender_did
    {
        warn!(
            profile = %profile.inner.alias,
            message_from = %from,
            profile_did = %sender_did,
            "message.from does not match the profile DID — \
             the message will be encrypted as the profile DID \
             and recipients will likely reject it"
        );
    }

    let (packed_msg, _) = atm
        .pack_encrypted(&message, recipient_did, Some(sender_did), Some(sender_did))
        .await?;

    let mediator_did = profile
        .to_tdk_profile()
        .mediator
        .ok_or_else(|| DIDCommServiceError::MissingMediator(profile.inner.alias.clone()))?;

    let sending_result = atm
        .forward_and_send_message(
            profile,
            false,
            &packed_msg,
            Some(&message_id),
            &mediator_did,
            recipient_did,
            None,
            None,
            false,
        )
        .await;

    if let Err(sending_error) = sending_result {
        warn!(profile = %profile.inner.alias, error = ?sending_error, "Failed to send message");
        return Err(TransportError::Send(sending_error).into());
    }

    trace!(profile = %profile.inner.alias, "Message sent successfully");
    Ok(())
}
