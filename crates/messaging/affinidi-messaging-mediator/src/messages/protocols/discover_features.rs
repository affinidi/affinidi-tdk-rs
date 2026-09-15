use crate::{
    SharedData,
    common::session::Session,
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
    let now = state.clock.unix_secs();

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

/// Every DIDComm **v2** protocol this mediator serves, as advertised over
/// `discover-features/2.0`.
///
/// This is the mediator's public protocol contract, and deliberately the single
/// place it is written down: `server` builds its `DiscoverFeatures` state from
/// this list, so what a client discovers and what this constant says cannot
/// drift apart.
///
/// # What is absent, and why it will not quietly appear
///
/// There is no `coordinate-mediation` entry, and the absence is structural
/// rather than an oversight — see `docs/mediation-and-routing.md`. DIDComm v2
/// routing is DID-addressed: a `routing/2.0` forward names its next hop as a
/// DID, which hashes straight into the recipient's account lookup. There is no
/// verkey indirection for a keylist to populate, so a v2 client has no keylist
/// to register and never needed one.
///
/// The keylist that *does* exist here is DIDComm **v1** only
/// ([`crate::messages::v1_mediation`]), because a v1 envelope carries no DID:
/// the recipient is identified by verkey, so the mediator must hold the
/// verkey→account mapping itself. That is exactly the mapping a v2 DID makes
/// unnecessary.
///
/// External transport bindings rely on this (issue #755).
/// `coordinate_mediation_is_not_advertised` below exists so that adding v2
/// mediation is a deliberate act — amending a contract others have built on —
/// rather than an incidental change that silently invalidates it.
pub(crate) const ADVERTISED_PROTOCOLS: &[&str] = &[
    "https://didcomm.org/discover-features/2.0",
    "https://didcomm.org/routing/2.0",
    "https://didcomm.org/trust-ping/2.0",
    "https://didcomm.org/out-of-band/2.0",
    "https://didcomm.org/messagepickup/3.0",
    "https://affinidi.com/atm/1.0/authenticate",
    "https://didcomm.org/mediator/1.0/admin-management",
    "https://didcomm.org/mediator/1.0/account-management",
    "https://didcomm.org/mediator/1.0/acl-management",
    "https://didcomm.org/report-problem/2.0",
];

#[cfg(test)]
mod advertised_protocol_tests {
    use super::ADVERTISED_PROTOCOLS;

    /// The contract answered in issue #755: DIDComm v2 on this mediator is
    /// DID-addressed and has no keylist, so a v2 client — a `did:key` client in
    /// particular — has nothing to register before it can receive.
    ///
    /// If v2 coordinate-mediation is ever implemented, this is where that
    /// decision surfaces. Do not just delete it: the absence is documented in
    /// `docs/mediation-and-routing.md` and depended on by external transport
    /// bindings, so adding mediation means amending both.
    #[test]
    fn coordinate_mediation_is_not_advertised() {
        let offending: Vec<_> = ADVERTISED_PROTOCOLS
            .iter()
            .filter(|p| {
                let p = p.to_ascii_lowercase();
                p.contains("coordinate-mediation") || p.contains("coordinatemediation")
            })
            .collect();

        assert!(
            offending.is_empty(),
            "v2 coordinate-mediation is now advertised ({offending:?}), but \
             docs/mediation-and-routing.md tells clients v2 needs no keylist. Amend the \
             documented contract and notify the consumers relying on it (issue #755) \
             before letting this land."
        );
    }

    /// The other half of the contract: the protocols that make DID-addressed
    /// delivery work are actually offered. Without this, the test above would
    /// pass just as happily against an empty list.
    #[test]
    fn did_addressed_delivery_protocols_are_advertised() {
        for required in [
            "https://didcomm.org/routing/2.0",
            "https://didcomm.org/messagepickup/3.0",
            "https://didcomm.org/discover-features/2.0",
        ] {
            assert!(
                ADVERTISED_PROTOCOLS.contains(&required),
                "{required} must be advertised: it is how a v2 client is delivered to, and \
                 collects its mail, without a keylist"
            );
        }
    }

    #[test]
    fn advertised_protocols_have_no_duplicates() {
        let mut sorted = ADVERTISED_PROTOCOLS.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(
            before,
            sorted.len(),
            "duplicate entry in ADVERTISED_PROTOCOLS"
        );
    }
}
