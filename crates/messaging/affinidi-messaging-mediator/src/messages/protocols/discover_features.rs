use crate::{
    SharedData,
    database::session::Session,
    messages::{ProcessMessageResponse, WrapperType},
};
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{
    ProblemReport, ProblemReportScope, ProblemReportSorter,
};
use http::StatusCode;
use std::time::SystemTime;
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
                "Anonymous Trust-Ping is asking for a response, this is an invalid request!".into(),
                vec![],
                None,
            )),
            StatusCode::BAD_REQUEST.as_u16(),
            "Anonymous Trust-Ping is asking for a response, this is an invalid request!"
                .to_string(),
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
            return Err(MediatorError::MediatorError(
                89,
                session.session_id.to_string(),
                Some(msg.id.clone()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.discover_features.queries.parse".into(),
                    "Couldn't parse message body: {1}".into(),
                    vec![e.to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Couldn't parse message body".to_string(),
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
