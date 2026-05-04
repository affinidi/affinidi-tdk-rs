use crate::common::time::unix_timestamp_secs;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info, span};
use uuid::Uuid;

use crate::{
    common::session::Session,
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
    let now = unix_timestamp_secs();

    if let Some(expires) = msg.expires_time
        && expires <= now
    {
        return Err(MediatorError::problem_with_log(
            31,
            &session.session_id,
            Some(msg.id.to_string()),
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "message.expired",
            "Message has expired: {1}",
            vec![expires.to_string()],
            StatusCode::BAD_REQUEST,
            "Message has expired",
        ));
    }

    let to = if let Some(to) = &msg.to {
        if let Some(first) = to.first() {
            first.to_owned()
        } else {
            return Err(MediatorError::problem(
                51,
                &session.session_id,
                Some(msg.id.clone()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "message.to",
                "Invalid to: header, couldn't get first DID from the field.",
                vec![],
                StatusCode::BAD_REQUEST,
            ));
        }
    } else {
        return Err(MediatorError::problem(
            51,
            &session.session_id,
            Some(msg.id.clone()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "message.to",
            "Missing to: header in message",
            vec![],
            StatusCode::BAD_REQUEST,
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
            return Err(MediatorError::problem(
                50,
                &session.session_id,
                Some(msg.id.clone()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "message.anonymous",
                "Trust-Ping requires a from: header when response_requested is true",
                vec![],
                StatusCode::BAD_REQUEST,
            ));
        };

        // Build the message (we swap from and to)
        let response_msg = Message::build(
            Uuid::new_v4().to_string(),
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
