//! Speaking the 0.2 messaging tasks to mediators that may only serve 0.1.
//!
//! Seven tasks have a 0.2 that changes the wire without extending 0.1:
//! `ping`, `account/{get,list,add,update}`, `audit/list` and `message/status`.
//! The SDK speaks 0.2 and returns only the generated 0.2 types. A mediator from
//! before 0.47.0 serves 0.1 only, so for it the request is relabelled 0.1 and
//! the 0.1 reply is converted into the 0.2 shape and parsed as the 0.2 type.
//! Callers never see 0.1.
//!
//! **Which version a mediator speaks** is learnt once per mediator DID:
//!
//! - Over DIDComm the SDK sends 0.2. A mediator that does not serve it refuses
//!   at once with the problem report `…protocol.trust_task.unsupported`,
//!   before any handler runs, so the request is safely re-sent as 0.1 (under a
//!   fresh id) and the mediator is remembered as 0.1-only.
//! - Over TSP an older mediator does not refuse: a type it does not serve is
//!   filed as ordinary mail and never answered. So the SDK asks the mediator's
//!   `/readyz` for its version once and sends 0.2 only to 0.47.0 or later, the
//!   first release that serves 0.2. If the version cannot be read it sends
//!   0.1, which every current mediator serves.
//!
//! What moves (the specs' "Changes from 0.1"):
//!
//! | Task | Request | Response |
//! |---|---|---|
//! | `messaging/ping` | — | `serverTime` → `respondedAt` |
//! | `messaging/account/{get,add,update}` | — | `account.lastReceivedAt` / `lastAuthenticatedAt`: Unix seconds → RFC 3339 |
//! | `messaging/account/list` | — | the same, on each of `accounts` |
//! | `audit/list` | `limit` → `pageSize` | `cursor` → `nextCursor`; `truncated` removed |
//! | `messaging/message/status` | — | `statuses[].at` → `reachedAt` |

use chrono::{DateTime, SecondsFormat};
use serde_json::{Map, Value};

/// The first mediator release that serves the 0.2 tasks.
pub(crate) const FIRST_MEDIATOR_SERVING_V0_2: (u64, u64, u64) = (0, 47, 0);

/// What a mediator is known to serve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MediatorSpeaks {
    V0_2,
    V0_1Only,
}

/// A task the SDK speaks at 0.2, with a 0.1 fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Current {
    Ping,
    AccountGet,
    AccountList,
    AccountAdd,
    AccountUpdate,
    AuditList,
    MessageStatus,
}

/// Whether `code` is the mediator's refusal of a Trust Task type it does not
/// serve. The refusal comes before any handler runs, so nothing was done.
pub(crate) fn is_unsupported_type(code: &str) -> bool {
    code.ends_with("protocol.trust_task.unsupported")
}

/// `major.minor.patch` of a mediator version string, ignoring any pre-release
/// or build suffix.
pub(crate) fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

/// What a mediator reporting `version` serves.
pub(crate) fn speaks_from_version(version: Option<&str>) -> MediatorSpeaks {
    match version.and_then(parse_version) {
        Some(v) if v >= FIRST_MEDIATOR_SERVING_V0_2 => MediatorSpeaks::V0_2,
        _ => MediatorSpeaks::V0_1Only,
    }
}

impl Current {
    /// Rewrite a 0.2 request document as the 0.1 one, in place.
    pub(crate) fn to_v0_1_request(self, doc: &mut Value) -> Result<(), String> {
        let ty = doc
            .get("type")
            .and_then(Value::as_str)
            .ok_or("the request has no type")?;
        let v0_1 = ty
            .strip_suffix("/0.2")
            .map(|base| format!("{base}/0.1"))
            .ok_or_else(|| format!("{ty} is not a 0.2 type"))?;
        doc["type"] = Value::String(v0_1);
        if self == Current::AuditList
            && let Some(payload) = doc.get_mut("payload").and_then(Value::as_object_mut)
        {
            rename(payload, "limit", "pageSize");
        }
        Ok(())
    }

    /// Rewrite a 0.1 reply document as the 0.2 one, in place. A document that
    /// is not the 0.1 `#response` (an error, say) is left alone.
    pub(crate) fn to_v0_2_reply(self, doc: &mut Value) -> Result<(), String> {
        let Some(ty) = doc.get("type").and_then(Value::as_str) else {
            return Ok(());
        };
        let Some(base) = ty.strip_suffix("/0.1#response") else {
            return Ok(());
        };
        doc["type"] = Value::String(format!("{base}/0.2#response"));
        let payload = doc
            .get_mut("payload")
            .and_then(Value::as_object_mut)
            .ok_or("the 0.1 reply has no payload object")?;
        match self {
            Current::Ping => rename(payload, "serverTime", "respondedAt"),
            Current::AccountGet | Current::AccountAdd | Current::AccountUpdate => {
                if let Some(account) = payload.get_mut("account").and_then(Value::as_object_mut) {
                    activity_instants_to_rfc3339(account)?;
                }
            }
            Current::AccountList => {
                if let Some(accounts) = payload.get_mut("accounts").and_then(Value::as_array_mut) {
                    for account in accounts.iter_mut().filter_map(Value::as_object_mut) {
                        activity_instants_to_rfc3339(account)?;
                    }
                }
            }
            Current::AuditList => {
                payload.remove("truncated");
                rename(payload, "cursor", "nextCursor");
            }
            Current::MessageStatus => {
                if let Some(statuses) = payload.get_mut("statuses").and_then(Value::as_array_mut) {
                    for status in statuses.iter_mut().filter_map(Value::as_object_mut) {
                        rename(status, "at", "reachedAt");
                    }
                }
            }
        }
        Ok(())
    }
}

fn rename(obj: &mut Map<String, Value>, from: &str, to: &str) {
    if let Some(v) = obj.remove(from) {
        obj.insert(to.to_string(), v);
    }
}

/// 0.1 carries an account's activity instants as Unix seconds; 0.2 as RFC 3339.
fn activity_instants_to_rfc3339(account: &mut Map<String, Value>) -> Result<(), String> {
    for key in ["lastReceivedAt", "lastAuthenticatedAt"] {
        let rfc3339 = match account.get(key) {
            None => continue,
            Some(Value::Null) => {
                account.remove(key);
                continue;
            }
            Some(Value::Number(n)) => {
                let secs = n
                    .as_i64()
                    .ok_or_else(|| format!("{key} is not a whole number of seconds"))?;
                DateTime::from_timestamp(secs, 0)
                    .ok_or_else(|| format!("{key} is out of range"))?
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
            }
            Some(other) => return Err(format!("{key} is {other}, not Unix seconds")),
        };
        account.insert(key.to_string(), Value::String(rfc3339));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::audit;
    use crate::tasks::messaging::{message, ping};
    use serde_json::json;
    use trust_tasks_rs::TrustTask;

    const BASE: &str = "https://trusttasks.org/spec/messaging/ping";

    fn reply(base: &str, payload: Value) -> Value {
        json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000002",
            "type": format!("{base}/0.1#response"),
            "threadId": "urn:uuid:00000000-0000-4000-8000-000000000001",
            "payload": payload,
        })
    }

    #[test]
    fn the_version_gate_is_0_47_0() {
        assert_eq!(speaks_from_version(Some("0.47.0")), MediatorSpeaks::V0_2);
        assert_eq!(
            speaks_from_version(Some("0.47.3-rc.1")),
            MediatorSpeaks::V0_2
        );
        assert_eq!(speaks_from_version(Some("1.0.0")), MediatorSpeaks::V0_2);
        assert_eq!(
            speaks_from_version(Some("0.46.0")),
            MediatorSpeaks::V0_1Only
        );
        assert_eq!(
            speaks_from_version(Some("nonsense")),
            MediatorSpeaks::V0_1Only
        );
        assert_eq!(speaks_from_version(None), MediatorSpeaks::V0_1Only);
    }

    #[test]
    fn the_mediator_refusal_is_recognised() {
        assert!(is_unsupported_type("e.p.protocol.trust_task.unsupported"));
        assert!(!is_unsupported_type("e.p.message.trust_task.rejected"));
    }

    #[test]
    fn a_request_is_relabelled_0_1() {
        let mut doc = json!({"type": format!("{BASE}/0.2"), "payload": {"nonce": "n"}});
        Current::Ping.to_v0_1_request(&mut doc).unwrap();
        assert_eq!(doc["type"], format!("{BASE}/0.1"));

        let mut audit = json!({
            "type": "https://trusttasks.org/spec/audit/list/0.2",
            "payload": {"limit": 10, "cursor": "c"},
        });
        Current::AuditList.to_v0_1_request(&mut audit).unwrap();
        assert_eq!(audit["payload"], json!({"pageSize": 10, "cursor": "c"}));
    }

    #[test]
    fn a_0_1_ping_reply_parses_as_0_2() {
        let mut doc = reply(
            BASE,
            json!({"status": "ok", "nonce": "n", "protocols": ["didcomm"],
                   "serverTime": "2026-10-27T10:00:00Z"}),
        );
        Current::Ping.to_v0_2_reply(&mut doc).unwrap();
        assert_eq!(doc["type"], format!("{BASE}/0.2#response"));
        let typed: TrustTask<ping::v0_2::Response> = serde_json::from_value(doc).unwrap();
        assert_eq!(
            typed.payload.responded_at.to_rfc3339(),
            "2026-10-27T10:00:00+00:00"
        );
    }

    #[test]
    fn a_0_1_audit_reply_parses_as_0_2() {
        let mut doc = reply(
            "https://trusttasks.org/spec/audit/list",
            json!({"entries": [], "cursor": "next", "truncated": true}),
        );
        Current::AuditList.to_v0_2_reply(&mut doc).unwrap();
        assert_eq!(doc["payload"], json!({"entries": [], "nextCursor": "next"}));
        let _: TrustTask<audit::list::v0_2::Response> = serde_json::from_value(doc).unwrap();
    }

    #[test]
    fn a_0_1_message_status_reply_parses_as_0_2() {
        let mut doc = reply(
            "https://trusttasks.org/spec/messaging/message/status",
            json!({"statuses": [{"msgId": "m1", "state": "delivered",
                                 "at": "2026-10-27T10:00:00Z"}]}),
        );
        Current::MessageStatus.to_v0_2_reply(&mut doc).unwrap();
        let typed: TrustTask<message::status::v0_2::Response> =
            serde_json::from_value(doc).unwrap();
        assert!(typed.payload.statuses[0].reached_at.is_some());
    }

    #[test]
    fn account_activity_instants_become_rfc3339() {
        let mut account = Map::new();
        account.insert("lastReceivedAt".into(), json!(1_793_095_200));
        account.insert("lastAuthenticatedAt".into(), Value::Null);
        activity_instants_to_rfc3339(&mut account).unwrap();
        assert_eq!(account["lastReceivedAt"], "2026-10-27T10:00:00Z");
        assert!(!account.contains_key("lastAuthenticatedAt"));
        account.insert("lastAuthenticatedAt".into(), json!("yesterday"));
        assert!(activity_instants_to_rfc3339(&mut account).is_err());
    }

    #[test]
    fn an_error_reply_is_left_alone() {
        let err = json!({
            "type": "https://trusttasks.org/spec/trust-task-error/0.1",
            "payload": {"code": "malformedRequest"},
        });
        let mut doc = err.clone();
        Current::Ping.to_v0_2_reply(&mut doc).unwrap();
        assert_eq!(doc, err);
    }
}
