//! Runtime configuration overrides — what `config/patch` changes.
//!
//! An override is a `limits.<field>` key and a new value. Overrides are kept in
//! the store ([`MediatorStore::config_overrides_get`]) and layered over the
//! file/env configuration at every start, so a patch survives a restart. A
//! **live** key also takes effect at once: the request path reads it through
//! [`LiveLimits`] rather than the startup [`Config`](super::Config). A
//! **restart** key is read by something built once at startup (a rate
//! limiter, a body-size layer, the streaming task), so its override is stored
//! and applies from the next start — `config/patch` reports it as
//! `pendingRestart`, never as applied.
//!
//! Anything not listed in [`PATCHABLE`] is refused: keys the store itself is
//! sized from before it opens (`message_size`, `pubsub_buffer`), and anything
//! outside `limits`.
//!
//! [`MediatorStore::config_overrides_get`]: affinidi_messaging_mediator_common::store::MediatorStore::config_overrides_get

use std::sync::{Arc, RwLock};

use serde_json::{Map, Value};

use super::limits::LimitsConfig;

/// When a patched key takes effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyClass {
    /// Now: the request path reads it through [`LiveLimits`].
    Live,
    /// At the next start: something built once at startup reads it.
    Restart,
}

/// The keys `config/patch` accepts, as `limits.<field>`, with when each takes
/// effect.
pub const PATCHABLE: &[(&str, KeyClass)] = &[
    ("limits.queued_send_messages_soft", KeyClass::Live),
    ("limits.queued_send_messages_hard", KeyClass::Live),
    ("limits.queued_send_messages_per_peer", KeyClass::Live),
    ("limits.queued_receive_messages_soft", KeyClass::Live),
    ("limits.queued_receive_messages_hard", KeyClass::Live),
    ("limits.message_expiry_seconds", KeyClass::Live),
    ("limits.listed_messages", KeyClass::Live),
    ("limits.deleted_messages", KeyClass::Live),
    ("limits.to_recipients", KeyClass::Live),
    ("limits.to_keys_per_recipient", KeyClass::Live),
    ("limits.attachments_max_count", KeyClass::Live),
    ("limits.access_list_limit", KeyClass::Live),
    ("limits.oob_invite_ttl", KeyClass::Live),
    ("limits.forward_task_queue", KeyClass::Live),
    // The streaming task captures this when it starts.
    ("limits.delivered_expiry_seconds", KeyClass::Restart),
    // Connection and rate limiting, and the HTTP/WS body-size layers, are
    // built once at startup.
    ("limits.max_websocket_connections", KeyClass::Restart),
    (
        "limits.max_websocket_connections_per_did",
        KeyClass::Restart,
    ),
    ("limits.ws_send_buffer", KeyClass::Restart),
    ("limits.rate_limit_per_ip", KeyClass::Restart),
    ("limits.rate_limit_burst", KeyClass::Restart),
    ("limits.did_rate_limit_per_second", KeyClass::Restart),
    ("limits.did_rate_limit_burst", KeyClass::Restart),
    ("limits.http_size", KeyClass::Restart),
    ("limits.ws_size", KeyClass::Restart),
];

/// When `key` takes effect, or `None` when it cannot be patched.
pub fn class_of(key: &str) -> Option<KeyClass> {
    PATCHABLE
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, class)| *class)
}

/// `limits` with `key` (a [`PATCHABLE`] key) set to `value`, checked: the
/// value must have the field's type and range, and the queue limits must stay
/// coherent (a soft limit no higher than its hard limit). The error is the
/// reason to report.
pub fn with_override(
    limits: &LimitsConfig,
    key: &str,
    value: &Value,
) -> Result<LimitsConfig, String> {
    if class_of(key).is_none() {
        return Err("not a patchable configuration key".into());
    }
    let field = key.strip_prefix("limits.").unwrap_or(key);
    let mut object = serde_json::to_value(limits).map_err(|e| e.to_string())?;
    object[field] = value.clone();
    let candidate: LimitsConfig =
        serde_json::from_value(object).map_err(|e| format!("invalid value: {e}"))?;
    check_coherent(&candidate)?;
    Ok(candidate)
}

/// The cross-field rules a patch must not break. A negative queue limit means
/// "unlimited", so it is exempt.
fn check_coherent(limits: &LimitsConfig) -> Result<(), String> {
    let pairs = [
        (
            "queued_send_messages_soft",
            limits.queued_send_messages_soft,
            "queued_send_messages_hard",
            limits.queued_send_messages_hard,
        ),
        (
            "queued_receive_messages_soft",
            limits.queued_receive_messages_soft,
            "queued_receive_messages_hard",
            limits.queued_receive_messages_hard,
        ),
    ];
    for (soft_name, soft, hard_name, hard) in pairs {
        if soft >= 0 && hard >= 0 && soft > hard {
            return Err(format!(
                "{soft_name} ({soft}) would exceed {hard_name} ({hard})"
            ));
        }
    }
    Ok(())
}

/// Apply stored `overrides` onto `limits` at startup. An override that no
/// longer applies (an unknown key, a bad value) is skipped and returned with
/// its reason so the caller can log it: a stale override must not stop the
/// mediator starting.
pub fn overlay(limits: &mut LimitsConfig, overrides: &Map<String, Value>) -> Vec<(String, String)> {
    let mut skipped = Vec::new();
    for (key, value) in overrides {
        match with_override(limits, key, value) {
            Ok(next) => *limits = next,
            Err(reason) => skipped.push((key.clone(), reason)),
        }
    }
    skipped
}

/// Parse the stored overrides document; an absent or malformed one is empty.
pub fn parse_stored(stored: Option<&str>) -> Map<String, Value> {
    stored
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

/// The limits the request path reads, swapped whole by `config/patch`. Cheap
/// to clone; a read is a lock and an `Arc` clone, never a copy of the limits.
///
/// It also keeps the **baseline**: the file/env limits before any override,
/// which is what a key returns to when its override is removed.
#[derive(Clone, Debug)]
pub struct LiveLimits {
    baseline: Arc<LimitsConfig>,
    current: Arc<RwLock<Arc<LimitsConfig>>>,
}

impl LiveLimits {
    /// `baseline` is the configuration before overrides; `effective` is what
    /// is in force (the baseline with the stored overrides layered over it).
    pub fn new(baseline: LimitsConfig, effective: LimitsConfig) -> Self {
        Self {
            baseline: Arc::new(baseline),
            current: Arc::new(RwLock::new(Arc::new(effective))),
        }
    }

    /// The file/env limits, before any override.
    pub fn baseline(&self) -> &LimitsConfig {
        &self.baseline
    }

    /// The limits now in effect.
    pub fn get(&self) -> Arc<LimitsConfig> {
        self.current
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    /// Put `limits` into effect.
    pub fn set(&self, limits: LimitsConfig) {
        let next = Arc::new(limits);
        match self.current.write() {
            Ok(mut g) => *g = next,
            Err(poisoned) => *poisoned.into_inner() = next,
        }
    }
}

/// `target` with each of `keys` (a `limits.<field>` key) copied from `from`.
pub fn with_fields_from(
    target: &LimitsConfig,
    from: &LimitsConfig,
    keys: &[String],
) -> LimitsConfig {
    let (Ok(mut t), Ok(f)) = (serde_json::to_value(target), serde_json::to_value(from)) else {
        return target.clone();
    };
    for key in keys {
        let field = key.strip_prefix("limits.").unwrap_or(key);
        if let Some(v) = f.get(field) {
            t[field] = v.clone();
        }
    }
    serde_json::from_value(t).unwrap_or_else(|_| target.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_patchable_key_is_applied_with_its_type_and_an_unknown_one_is_not() {
        let base = LimitsConfig::default();
        let next = with_override(&base, "limits.queued_send_messages_hard", &json!(5000)).unwrap();
        assert_eq!(next.queued_send_messages_hard, 5000);

        assert!(with_override(&base, "limits.message_size", &json!(1)).is_err());
        assert!(with_override(&base, "security.use_ssl", &json!(false)).is_err());
        assert!(
            with_override(&base, "limits.listed_messages", &json!("many"))
                .unwrap_err()
                .starts_with("invalid value")
        );
        assert!(with_override(&base, "limits.listed_messages", &json!(-1)).is_err());
    }

    #[test]
    fn a_soft_limit_may_not_exceed_its_hard_limit_unless_unlimited() {
        let base = LimitsConfig::default(); // send soft 2000, hard 10000
        let err =
            with_override(&base, "limits.queued_send_messages_hard", &json!(100)).unwrap_err();
        assert!(err.contains("would exceed"), "{err}");
        // -1 is unlimited: always coherent.
        assert!(with_override(&base, "limits.queued_send_messages_hard", &json!(-1)).is_ok());
    }

    #[test]
    fn a_stale_stored_override_is_skipped_not_fatal() {
        let mut limits = LimitsConfig::default();
        let stored = parse_stored(Some(
            r#"{"limits.listed_messages": 7, "limits.gone_away": 1, "limits.to_recipients": "x"}"#,
        ));
        let skipped = overlay(&mut limits, &stored);
        assert_eq!(limits.listed_messages, 7);
        let keys: Vec<&str> = skipped.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"limits.gone_away") && keys.contains(&"limits.to_recipients"));
        assert!(parse_stored(Some("not json")).is_empty());
        assert!(parse_stored(None).is_empty());
    }

    #[test]
    fn fields_are_copied_by_key_and_others_left_alone() {
        let target = LimitsConfig::default();
        let from = LimitsConfig {
            listed_messages: 9,
            to_recipients: 9,
            ..Default::default()
        };
        let out = with_fields_from(&target, &from, &["limits.listed_messages".into()]);
        assert_eq!(out.listed_messages, 9);
        assert_eq!(out.to_recipients, target.to_recipients);
    }

    #[test]
    fn live_limits_swap_whole() {
        let live = LiveLimits::new(LimitsConfig::default(), LimitsConfig::default());
        let before = live.get();
        let mut next = (*before).clone();
        next.listed_messages = 3;
        live.set(next);
        assert_eq!(live.get().listed_messages, 3);
        assert_eq!(before.listed_messages, 100, "a reader's snapshot is stable");
    }

    #[test]
    fn every_patchable_key_names_a_real_field() {
        let fields = serde_json::to_value(LimitsConfig::default()).unwrap();
        for (key, _) in PATCHABLE {
            let field = key.strip_prefix("limits.").unwrap();
            assert!(
                fields.get(field).is_some(),
                "{key} is not a LimitsConfig field"
            );
        }
    }
}
