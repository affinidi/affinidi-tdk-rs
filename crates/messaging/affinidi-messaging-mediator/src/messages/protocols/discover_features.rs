use crate::common::time::unix_timestamp_secs;
use crate::{
    SharedData,
    database::session::Session,
    messages::{ProcessMessageResponse, WrapperType},
};
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use http::StatusCode;
use tracing::{debug, info, span};

/// Process a Discover Features queries message and generates a response
pub(crate) fn process(
    msg: &Message,
    session: &Session,
    state: &SharedData,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "discover_features_query",
        session_id = session.session_id.as_str()
    )
    .entered();
    let now = unix_timestamp_secs();

    if let Some(expires) = msg.expires_time
        && expires <= now
    {
        return Err(MediatorError::problem_with_log(
            31,
            session.session_id.to_string(),
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
                session.session_id.to_string(),
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
            session.session_id.to_string(),
            Some(msg.id.clone()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "message.to",
            "Missing to: header in message",
            vec![],
            StatusCode::BAD_REQUEST,
        ));
    };

    let from = if let Some(from) = &msg.from {
        from.to_owned()
    } else {
        return Err(MediatorError::problem(
            50,
            session.session_id.to_string(),
            Some(msg.id.clone()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "message.anonymous",
            "Discover Features requires a from: header to generate a response",
            vec![],
            StatusCode::BAD_REQUEST,
        ));
    };

    info!(
        "Discover Features query received from: ({})",
        msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
    );

    let response_msg = match state
        .discover_features
        .generate_disclosure_message(&to, &from, msg, None)
    {
        Ok(response) => response,
        Err(e) => {
            return Err(MediatorError::problem_with_log(
                89,
                session.session_id.to_string(),
                Some(msg.id.clone()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.discover_features.queries.parse",
                "Couldn't parse message body: {1}",
                vec![e.to_string()],
                StatusCode::BAD_REQUEST,
                "Couldn't parse message body",
            ));
        }
    };

    debug!("response_msg: {:?}", response_msg);

    Ok(ProcessMessageResponse {
        store_message: true,
        force_live_delivery: false,
        data: WrapperType::Message(Box::new(response_msg)),
        forward_message: false,
    })
}
