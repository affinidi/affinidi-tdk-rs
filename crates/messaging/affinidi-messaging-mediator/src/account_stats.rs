//! Counting each message against the accounts it was between.
//!
//! A message the mediator accepts is counted once for the account that sent
//! it and once for the account it is addressed to, with its size and the wire
//! it travelled in. The counters are the mediator's own — a console reads
//! them instead of totting up a live feed, so they cover the account's whole
//! life rather than one monitor session.
//!
//! **Counted where the message is stored**, not at ingress. Storing is the
//! point at which the mediator has accepted the message *for an account*, and
//! it is where both parties are known, so the two sides can never disagree.
//!
//! **The mediator's own traffic with an account is not counted.** A Trust
//! Task answer is stored for the account like any other message, so counting
//! it would let a console inflate the very numbers it is displaying — poll
//! once a second and an idle account looks busy. These counters are about
//! what an account exchanges with its correspondents, which is the same line
//! the traffic monitor draws when it leaves a subscriber's own management
//! traffic out of its feed.
//!
//! Counting is best-effort: a failed write is logged and never fails the
//! message. Nothing is counted for an account the mediator does not serve,
//! which the store enforces rather than the caller.

use affinidi_messaging_mediator_common::types::accounts::{
    AccountStatsDelta, StatsDirection, StatsWire,
};
use affinidi_messaging_mediator_common::types::messages::MessageProtocol;
use tracing::debug;

use crate::SharedData;

/// Count one stored message against its sender and its recipient.
///
/// `body` is the message as stored, which is what names the wire: the same
/// derivation the monitor's `stored` event uses. A DIDComm v1 envelope is
/// JSON, so it counts as `didcomm` there and here alike — the split is by
/// stored form, not by the ingress route.
pub(crate) async fn count_stored(
    state: &SharedData,
    from_did_hash: Option<&str>,
    to_did_hash: &str,
    body: &str,
) {
    let mediator = sha256::digest(state.config.mediator_did.as_str());
    if from_did_hash == Some(mediator.as_str()) || to_did_hash == mediator {
        return;
    }
    let wire = match MessageProtocol::detect(body) {
        MessageProtocol::DidComm => StatsWire::DidComm,
        MessageProtocol::Tsp => StatsWire::Tsp,
        _ => StatsWire::Other,
    };
    let bytes = body.len() as u64;

    bump(
        state,
        to_did_hash,
        AccountStatsDelta::new(StatsDirection::Received, wire, bytes),
    )
    .await;
    if let Some(from) = from_did_hash {
        bump(
            state,
            from,
            AccountStatsDelta::new(StatsDirection::Sent, wire, bytes),
        )
        .await;
    }
}

async fn bump(state: &SharedData, did_hash: &str, delta: AccountStatsDelta) {
    if let Err(e) = state.database.account_stats_bump(did_hash, delta).await {
        debug!("couldn't count a message against {did_hash}: {e}");
    }
}
