use std::time::SystemTime;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{
    ProblemReport, ProblemReportScope, ProblemReportSorter,
};
use http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info, span};
use uuid::Uuid;

use crate::{
    database::session::Session,
    messages::{ProcessMessageResponse, WrapperType},
};

// Reads the body of an incoming trust-ping and whether to generate a return ping message
#[derive(Deserialize)]
struct Ping {
    response_requested: bool, // Defaults to true
}

impl Default for Ping {
    fn default() -> Self {
        Self {
            response_requested: true,
        }
    }
}

/// Process a trust-ping message and generates a response if needed
pub(crate) fn process(
    msg: &Message,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "trust_ping",
        session_id = session.session_id.as_str()
    )
    .entered();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if let Some(expires) = msg.expires_time
        && expires <= now
    {
        return Err(MediatorError::MediatorError(
            31,
            session.session_id.to_string(),
            Some(msg.id.to_string()),
            Box::new(ProblemReport::new(
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.expired".into(),
                "Message has expired: {1}".into(),
                vec![expires.to_string()],
                None,
            )),
            StatusCode::BAD_REQUEST.as_u16(),
            "Message has expired".to_string(),
        ));
    }

    let to = if let Some(to) = &msg.to {
        if let Some(first) = to.first() {
            first.to_owned()
        } else {
            return Err(MediatorError::MediatorError(
                51,
                session.session_id.to_string(),
                Some(msg.id.clone()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "message.to".into(),
                    "Invalid to: header, couldn't get first DID from the field.".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Invalid to: header, couldn't get first DID from the field.".to_string(),
            ));
        }
    } else {
        return Err(MediatorError::MediatorError(
            51,
            session.session_id.to_string(),
            Some(msg.id.clone()),
            Box::new(ProblemReport::new(
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "message.to".into(),
                "Missing to: header in message".into(),
                vec![],
                None,
            )),
            StatusCode::BAD_REQUEST.as_u16(),
            "Missing to: header in message".to_string(),
        ));
    };
    debug!("To: {}", to);

    let respond: bool = if let Ok(body) = serde_json::from_value::<Ping>(msg.body.to_owned()) {
        body.response_requested
    } else {
        true
    };
    debug!("Response requested: {}", respond);

    info!(
        "ping received from: ({}) Respond?({})",
        msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
        respond
    );

    if respond {
        let from = if let Some(from) = &msg.from {
            from.to_owned()
        } else {
            return Err(MediatorError::MediatorError(
                50,
                session.session_id.to_string(),
                Some(msg.id.clone()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "message.anonymous".into(),
                    "Anonymous Trust-Ping is asking for a response, this is an invalid request!"
                        .into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Anonymous Trust-Ping is asking for a response, this is an invalid request!"
                    .to_string(),
            ));
        };

        // Build the message (we swap from and to)
        let response_msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/trust-ping/2.0/ping".to_owned(),
            json!({}),
        )
        .thid(msg.id.clone())
        .to(from)
        .from(to)
        .created_time(now)
        .expires_time(now + 300)
        .finalize();

        debug!("response_msg: {:?}", response_msg);

        Ok(ProcessMessageResponse {
            store_message: true,
            force_live_delivery: false,
            data: WrapperType::Message(Box::new(response_msg)),
            forward_message: false,
        })
    } else {
        debug!("No response requested");
        Ok(ProcessMessageResponse::default())
    }
}
