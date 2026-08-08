//! Coordinate Mediation 1.0 (Aries RFC 0211).
//!
//! How an edge agent asks a mediator to route for it, and tells the mediator
//! which keys to route to:
//!
//! ```text
//! recipient                                mediator
//!    │  mediate-request  ───────────────────▶ │
//!    │ ◀─────────────── mediate-grant        │  { endpoint, routing_keys }
//!    │  keylist-update (add K) ─────────────▶ │
//!    │ ◀─────────── keylist-update-response  │  per-key result
//!    │  keylist-query  ─────────────────────▶ │
//!    │ ◀───────────────────────── keylist    │
//! ```
//!
//! The keys registered by `keylist-update` are exactly what a
//! `routing/1.0/forward` later addresses, so this protocol is what populates a
//! mediator's verkey → account index.
//!
//! # `recipient_key` has two spellings
//!
//! RFC 0211 specifies `did:key`, but bare base58 predates it and is still
//! widely sent — Credo normalises on receipt and chooses its outbound form from
//! `useDidKeyInProtocols`. Every key field here is therefore parsed with
//! [`Verkey::parse`], which accepts both, and comparisons happen on the decoded
//! [`Verkey`] rather than the string. Comparing the strings drops half the
//! ecosystem; see [`crate::identity::Verkey::parse`].
//!
//! This crate emits **base58** by default ([`KeyFormat`]), the form every
//! Aries-lineage agent understands including pre-`did:key` ones — the same
//! asymmetry that makes `did:sov` the default message-type prefix.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::DIDCommV1Error;
use crate::identity::Verkey;
use crate::message::{MessageV1, TypeFormat, types_match};

/// `mediate-request` — ask a mediator to route.
pub const MEDIATE_REQUEST_TYPE: &str =
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/coordinate-mediation/1.0/mediate-request";
/// `mediate-grant` — permission given, with the routing information to use.
pub const MEDIATE_GRANT_TYPE: &str =
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/coordinate-mediation/1.0/mediate-grant";
/// `mediate-deny` — permission refused.
pub const MEDIATE_DENY_TYPE: &str =
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/coordinate-mediation/1.0/mediate-deny";
/// `keylist-update` — register or drop routing keys.
pub const KEYLIST_UPDATE_TYPE: &str =
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/coordinate-mediation/1.0/keylist-update";
/// `keylist-update-response` — per-key outcome of a `keylist-update`.
pub const KEYLIST_UPDATE_RESPONSE_TYPE: &str =
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/coordinate-mediation/1.0/keylist-update-response";
/// `keylist-query` — ask which keys the mediator holds.
pub const KEYLIST_QUERY_TYPE: &str =
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/coordinate-mediation/1.0/keylist-query";
/// `keylist` — the answer to a `keylist-query`.
pub const KEYLIST_TYPE: &str =
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/coordinate-mediation/1.0/keylist";

/// How to spell a key on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum KeyFormat {
    /// Bare base58btc. The default: understood by every Aries-lineage agent,
    /// including those predating RFC 0211's `did:key` guidance.
    #[default]
    Base58,
    /// `did:key:z6Mk…`, as RFC 0211 specifies.
    DidKey,
}

impl KeyFormat {
    fn render(&self, verkey: &Verkey) -> String {
        match self {
            KeyFormat::Base58 => verkey.to_base58(),
            KeyFormat::DidKey => verkey.to_did_key(),
        }
    }
}

/// Whether to add or remove a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum KeylistAction {
    Add,
    Remove,
}

/// Per-key outcome of a `keylist-update`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KeylistResult {
    /// The update was applied.
    Success,
    /// The update was a no-op (adding a key already held, removing one not
    /// held). Distinct from `Success` so a client can tell "I did that" from
    /// "that was already true".
    NoChange,
    /// The request was malformed or not permitted — e.g. removing a key owned
    /// by a different account.
    ClientError,
    /// The mediator failed to apply the update.
    ServerError,
}

/// One requested key change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeylistUpdate {
    /// The key, decoded from either spelling.
    pub recipient_key: Verkey,
    pub action: KeylistAction,
}

/// One applied key change, as reported back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeylistUpdated {
    pub recipient_key: Verkey,
    pub action: KeylistAction,
    pub result: KeylistResult,
}

/// Build a `mediate-request`. It carries no fields of its own.
pub fn mediate_request() -> Result<MessageV1, DIDCommV1Error> {
    MessageV1::new(MEDIATE_REQUEST_TYPE, json!({}))
}

/// Build a `mediate-grant` in reply to `request_id`.
///
/// `endpoint` is the URL the recipient should publish for inbound traffic, and
/// `routing_keys` are the keys senders must forward through to reach it.
pub fn mediate_grant(
    request_id: &str,
    endpoint: &str,
    routing_keys: &[Verkey],
    format: KeyFormat,
) -> Result<MessageV1, DIDCommV1Error> {
    let keys: Vec<Value> = routing_keys
        .iter()
        .map(|k| Value::String(format.render(k)))
        .collect();
    Ok(MessageV1::new(
        MEDIATE_GRANT_TYPE,
        json!({ "endpoint": endpoint, "routing_keys": keys }),
    )?
    .thid(request_id))
}

/// Build a `mediate-deny` in reply to `request_id`.
pub fn mediate_deny(request_id: &str) -> Result<MessageV1, DIDCommV1Error> {
    Ok(MessageV1::new(MEDIATE_DENY_TYPE, json!({}))?.thid(request_id))
}

/// Read the `updates` of a `keylist-update`.
///
/// An entry whose `recipient_key` cannot be decoded is an error rather than a
/// silent skip: dropping it would leave the client believing a key was
/// registered when it was not.
pub fn parse_keylist_update(msg: &MessageV1) -> Result<Vec<KeylistUpdate>, DIDCommV1Error> {
    let updates = msg
        .body
        .get("updates")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            DIDCommV1Error::InvalidMessage("keylist-update has no `updates` array".into())
        })?;

    updates
        .iter()
        .map(|entry| {
            let key = entry
                .get("recipient_key")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    DIDCommV1Error::InvalidMessage(
                        "keylist-update entry has no `recipient_key`".into(),
                    )
                })?;
            let action = entry.get("action").and_then(Value::as_str).ok_or_else(|| {
                DIDCommV1Error::InvalidMessage("keylist-update entry has no `action`".into())
            })?;
            let action = match action {
                "add" => KeylistAction::Add,
                "remove" => KeylistAction::Remove,
                other => {
                    return Err(DIDCommV1Error::InvalidMessage(format!(
                        "unknown keylist-update action `{other}`"
                    )));
                }
            };
            Ok(KeylistUpdate {
                recipient_key: Verkey::parse(key)?,
                action,
            })
        })
        .collect()
}

/// Build a `keylist-update` requesting `updates`.
pub fn keylist_update(
    updates: &[KeylistUpdate],
    format: KeyFormat,
) -> Result<MessageV1, DIDCommV1Error> {
    let entries: Vec<Value> = updates
        .iter()
        .map(|u| {
            json!({
                "recipient_key": format.render(&u.recipient_key),
                "action": u.action,
            })
        })
        .collect();
    MessageV1::new(KEYLIST_UPDATE_TYPE, json!({ "updates": entries }))
}

/// Build a `keylist-update-response` in reply to `request_id`.
///
/// The member is `updated`, not `updates` — a detail worth pinning, since the
/// request and the response differ by one letter and a client that finds
/// neither reports the whole update as failed.
pub fn keylist_update_response(
    request_id: &str,
    updated: &[KeylistUpdated],
    format: KeyFormat,
) -> Result<MessageV1, DIDCommV1Error> {
    let entries: Vec<Value> = updated
        .iter()
        .map(|u| {
            json!({
                "recipient_key": format.render(&u.recipient_key),
                "action": u.action,
                "result": u.result,
            })
        })
        .collect();
    Ok(
        MessageV1::new(KEYLIST_UPDATE_RESPONSE_TYPE, json!({ "updated": entries }))?
            .thid(request_id),
    )
}

/// Build a `keylist` in reply to `request_id`.
pub fn keylist(
    request_id: &str,
    keys: &[Verkey],
    format: KeyFormat,
) -> Result<MessageV1, DIDCommV1Error> {
    let entries: Vec<Value> = keys
        .iter()
        .map(|k| json!({ "recipient_key": format.render(k) }))
        .collect();
    Ok(MessageV1::new(KEYLIST_TYPE, json!({ "keys": entries }))?.thid(request_id))
}

/// Which coordinate-mediation message this is, if any.
///
/// Matching goes through [`types_match`], so both document-URI spellings are
/// recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoordinateMediation {
    MediateRequest,
    MediateGrant,
    MediateDeny,
    KeylistUpdate,
    KeylistUpdateResponse,
    KeylistQuery,
    Keylist,
}

impl CoordinateMediation {
    /// Classify `msg`, or `None` if it is not a coordinate-mediation message.
    pub fn classify(msg: &MessageV1) -> Option<Self> {
        for (typ, kind) in [
            (MEDIATE_REQUEST_TYPE, Self::MediateRequest),
            (MEDIATE_GRANT_TYPE, Self::MediateGrant),
            (MEDIATE_DENY_TYPE, Self::MediateDeny),
            (KEYLIST_UPDATE_TYPE, Self::KeylistUpdate),
            (KEYLIST_UPDATE_RESPONSE_TYPE, Self::KeylistUpdateResponse),
            (KEYLIST_QUERY_TYPE, Self::KeylistQuery),
            (KEYLIST_TYPE, Self::Keylist),
        ] {
            if types_match(&msg.typ, typ) {
                return Some(kind);
            }
        }
        None
    }
}

/// Re-render every message type in this protocol into the given document-URI
/// form. Convenience for a peer that prefers `https://didcomm.org`.
pub fn with_type_format(msg: MessageV1, format: TypeFormat) -> MessageV1 {
    msg.with_type_format(format)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verkey(seed: u8) -> Verkey {
        Verkey::from_bytes([seed; 32])
    }

    #[test]
    fn mediate_grant_wire_shape() {
        let msg = mediate_grant(
            "req-1",
            "https://mediator.example/inbound",
            &[verkey(1)],
            KeyFormat::Base58,
        )
        .unwrap();

        let wire: Value = serde_json::from_slice(&msg.to_json().unwrap()).unwrap();
        assert_eq!(wire["@type"], MEDIATE_GRANT_TYPE);
        assert_eq!(wire["endpoint"], "https://mediator.example/inbound");
        assert_eq!(wire["routing_keys"][0], verkey(1).to_base58());
        assert_eq!(
            wire["~thread"]["thid"], "req-1",
            "the grant must thread to the request"
        );
    }

    #[test]
    fn mediate_grant_can_emit_did_key_routing_keys() {
        let msg = mediate_grant(
            "req-1",
            "https://x/inbound",
            &[verkey(1)],
            KeyFormat::DidKey,
        )
        .unwrap();
        let wire: Value = serde_json::from_slice(&msg.to_json().unwrap()).unwrap();
        assert_eq!(wire["routing_keys"][0], verkey(1).to_did_key());
    }

    /// The interop property: a `keylist-update` written in either key spelling
    /// must parse to the same keys.
    #[test]
    fn keylist_update_parses_both_key_spellings() {
        let key = verkey(7);

        for spelling in [key.to_base58(), key.to_did_key()] {
            let msg = MessageV1::new(
                KEYLIST_UPDATE_TYPE,
                json!({ "updates": [{ "recipient_key": spelling, "action": "add" }] }),
            )
            .unwrap();

            let parsed = parse_keylist_update(&msg).unwrap();
            assert_eq!(parsed.len(), 1);
            assert_eq!(parsed[0].recipient_key, key);
            assert_eq!(parsed[0].action, KeylistAction::Add);
        }
    }

    #[test]
    fn keylist_update_round_trips() {
        let updates = vec![
            KeylistUpdate {
                recipient_key: verkey(1),
                action: KeylistAction::Add,
            },
            KeylistUpdate {
                recipient_key: verkey(2),
                action: KeylistAction::Remove,
            },
        ];
        let msg = keylist_update(&updates, KeyFormat::Base58).unwrap();
        assert_eq!(parse_keylist_update(&msg).unwrap(), updates);
    }

    /// A malformed entry must fail the parse, not be skipped — a silent skip
    /// would leave the client believing a key was registered when it was not.
    #[test]
    fn malformed_keylist_entries_are_errors_not_skips() {
        for body in [
            json!({ "updates": [{ "action": "add" }] }),
            json!({ "updates": [{ "recipient_key": "not-a-key", "action": "add" }] }),
            json!({ "updates": [{ "recipient_key": "z", "action": "sideways" }] }),
            json!({ "no_updates": [] }),
        ] {
            let msg = MessageV1::new(KEYLIST_UPDATE_TYPE, body).unwrap();
            assert!(parse_keylist_update(&msg).is_err());
        }
    }

    /// The response member is `updated`, not `updates`.
    #[test]
    fn keylist_update_response_uses_the_updated_member() {
        let msg = keylist_update_response(
            "req-1",
            &[KeylistUpdated {
                recipient_key: verkey(4),
                action: KeylistAction::Add,
                result: KeylistResult::Success,
            }],
            KeyFormat::Base58,
        )
        .unwrap();

        let wire: Value = serde_json::from_slice(&msg.to_json().unwrap()).unwrap();
        assert!(
            wire.get("updates").is_none(),
            "the request member is `updates`"
        );
        assert_eq!(wire["updated"][0]["recipient_key"], verkey(4).to_base58());
        assert_eq!(wire["updated"][0]["action"], "add");
        assert_eq!(wire["updated"][0]["result"], "success");
        assert_eq!(wire["~thread"]["thid"], "req-1");
    }

    /// `result` is snake_case on the wire; `no_change` in particular must not
    /// serialise as `NoChange`.
    #[test]
    fn keylist_results_serialise_in_snake_case() {
        for (result, expected) in [
            (KeylistResult::Success, "success"),
            (KeylistResult::NoChange, "no_change"),
            (KeylistResult::ClientError, "client_error"),
            (KeylistResult::ServerError, "server_error"),
        ] {
            assert_eq!(serde_json::to_value(result).unwrap(), json!(expected));
        }
    }

    #[test]
    fn classifies_every_message_in_both_type_spellings() {
        for (typ, expected) in [
            (MEDIATE_REQUEST_TYPE, CoordinateMediation::MediateRequest),
            (MEDIATE_GRANT_TYPE, CoordinateMediation::MediateGrant),
            (MEDIATE_DENY_TYPE, CoordinateMediation::MediateDeny),
            (KEYLIST_UPDATE_TYPE, CoordinateMediation::KeylistUpdate),
            (
                KEYLIST_UPDATE_RESPONSE_TYPE,
                CoordinateMediation::KeylistUpdateResponse,
            ),
            (KEYLIST_QUERY_TYPE, CoordinateMediation::KeylistQuery),
            (KEYLIST_TYPE, CoordinateMediation::Keylist),
        ] {
            let legacy = MessageV1::new(typ, json!({})).unwrap();
            assert_eq!(CoordinateMediation::classify(&legacy), Some(expected));

            // Credo emits the https://didcomm.org form by default.
            let modern = legacy.with_type_format(TypeFormat::DidCommOrg);
            assert!(modern.typ.starts_with("https://didcomm.org/"));
            assert_eq!(
                CoordinateMediation::classify(&modern),
                Some(expected),
                "both document-URI spellings must classify identically"
            );
        }
    }

    #[test]
    fn does_not_classify_unrelated_messages() {
        let basic = crate::protocols::basic_message::BasicMessage::new("hi")
            .unwrap()
            .finalize();
        assert_eq!(CoordinateMediation::classify(&basic), None);
    }

    #[test]
    fn keylist_lists_keys_and_threads_to_the_query() {
        let msg = keylist("q-1", &[verkey(1), verkey(2)], KeyFormat::Base58).unwrap();
        let wire: Value = serde_json::from_slice(&msg.to_json().unwrap()).unwrap();
        assert_eq!(wire["keys"][0]["recipient_key"], verkey(1).to_base58());
        assert_eq!(wire["keys"][1]["recipient_key"], verkey(2).to_base58());
        assert_eq!(wire["~thread"]["thid"], "q-1");
    }

    #[test]
    fn deny_threads_to_the_request() {
        let msg = mediate_deny("req-9").unwrap();
        assert_eq!(msg.explicit_thid(), Some("req-9"));
        assert_eq!(
            CoordinateMediation::classify(&msg),
            Some(CoordinateMediation::MediateDeny)
        );
    }
}
