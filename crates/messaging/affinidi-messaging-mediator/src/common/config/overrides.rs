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
//! sized from before it opens (`message_size`, `pubsub_buffer`), keys whose
//! tightening loses data (`delivered_expiry_seconds`), and anything outside
//! `limits`.
//!
//! # A patch can tighten, never loosen
//!
//! The file/env configuration is the operator's policy, and it bounds what an
//! account can do: `account/update`, for one, clamps a per-account queue limit
//! to the hard limit. A runtime patch must not be a way round that. So every
//! patched value is held between a floor and a ceiling ([`Patchable`]):
//!
//! - the **floor** keeps a protection on: `0` and `-1`, which mean "unlimited"
//!   or "disabled" for some limits, are below it;
//! - the **ceiling** is the operator's configured value, or an absolute cap
//!   where that value is itself unlimited.
//!
//! Every limit here is stricter the lower it is, so a patch can make the
//! mediator stricter than configured, or restore it, but never looser.
//! Raising a limit is the operator's call: change the configuration and
//! restart. The same bounds apply to stored overrides at startup, so if the
//! operator lowers the configured value, it wins.
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

/// One key `config/patch` accepts.
#[derive(Clone, Copy, Debug)]
pub struct Patchable {
    /// `limits.<field>`.
    pub key: &'static str,
    pub class: KeyClass,
    /// The lowest value accepted: above any "unlimited" or "disabled" value.
    pub floor: i64,
    /// The highest value accepted when the configured value is itself
    /// unlimited. Otherwise the configured value is the ceiling.
    pub cap: i64,
}

const fn key(key: &'static str, class: KeyClass, floor: i64, cap: i64) -> Patchable {
    Patchable {
        key,
        class,
        floor,
        cap,
    }
}

const HOUR: i64 = 3_600;
const YEAR: i64 = 365 * 24 * HOUR;
const MIB: i64 = 1_048_576;

/// The keys `config/patch` accepts, with when each takes effect and its bounds.
pub const PATCHABLE: &[Patchable] = &[
    key(
        "limits.queued_send_messages_soft",
        KeyClass::Live,
        1,
        1_000_000,
    ),
    key(
        "limits.queued_send_messages_hard",
        KeyClass::Live,
        1,
        1_000_000,
    ),
    key(
        "limits.queued_send_messages_per_peer",
        KeyClass::Live,
        1,
        1_000_000,
    ),
    key(
        "limits.queued_receive_messages_soft",
        KeyClass::Live,
        1,
        1_000_000,
    ),
    key(
        "limits.queued_receive_messages_hard",
        KeyClass::Live,
        1,
        1_000_000,
    ),
    // A shorter expiry discards queued mail sooner; an hour is the least a
    // patch may leave a client to collect it.
    key("limits.message_expiry_seconds", KeyClass::Live, HOUR, YEAR),
    key("limits.listed_messages", KeyClass::Live, 1, 10_000),
    key("limits.deleted_messages", KeyClass::Live, 1, 10_000),
    key("limits.to_recipients", KeyClass::Live, 1, 10_000),
    key("limits.to_keys_per_recipient", KeyClass::Live, 1, 10_000),
    key("limits.attachments_max_count", KeyClass::Live, 1, 1_000),
    key("limits.access_list_limit", KeyClass::Live, 1, 1_000_000),
    key("limits.oob_invite_ttl", KeyClass::Live, 60, YEAR),
    key("limits.forward_task_queue", KeyClass::Live, 1, 10_000_000),
    // Connection and rate limiting, and the HTTP/WS body-size layers, are
    // built once at startup. For these, 0 means unlimited.
    key(
        "limits.max_websocket_connections",
        KeyClass::Restart,
        1,
        1_000_000,
    ),
    key(
        "limits.max_websocket_connections_per_did",
        KeyClass::Restart,
        1,
        10_000,
    ),
    key("limits.ws_send_buffer", KeyClass::Restart, MIB, 1_024 * MIB),
    key("limits.rate_limit_per_ip", KeyClass::Restart, 1, 100_000),
    key("limits.rate_limit_burst", KeyClass::Restart, 1, 100_000),
    key(
        "limits.did_rate_limit_per_second",
        KeyClass::Restart,
        1,
        100_000,
    ),
    key("limits.did_rate_limit_burst", KeyClass::Restart, 1, 100_000),
    key("limits.http_size", KeyClass::Restart, 64 * 1_024, 256 * MIB),
    key("limits.ws_size", KeyClass::Restart, 64 * 1_024, 256 * MIB),
];

fn patchable(key: &str) -> Option<&'static Patchable> {
    PATCHABLE.iter().find(|p| p.key == key)
}

/// When `key` takes effect, or `None` when it cannot be patched.
pub fn class_of(key: &str) -> Option<KeyClass> {
    patchable(key).map(|p| p.class)
}

/// The value of `key`'s field in `limits`, as a number.
fn field_value(limits: &LimitsConfig, key: &str) -> Option<i64> {
    let field = key.strip_prefix("limits.")?;
    serde_json::to_value(limits).ok()?.get(field)?.as_i64()
}

/// Check `value` against `key`'s floor and ceiling, where the ceiling is the
/// operator's configured value in `baseline` unless that is unlimited (below
/// the floor), when it is the key's absolute cap.
fn check_bounds(p: &Patchable, value: &Value, baseline: &LimitsConfig) -> Result<(), String> {
    let n = value
        .as_i64()
        .ok_or_else(|| "invalid value: expected a whole number".to_string())?;
    let configured = field_value(baseline, p.key).unwrap_or(p.cap);
    let ceiling = if configured >= p.floor {
        configured.min(p.cap)
    } else {
        p.cap
    };
    if n < p.floor {
        return Err(format!(
            "{n} is below the least allowed ({}): a patch cannot switch this limit off",
            p.floor
        ));
    }
    if n > ceiling {
        return Err(if ceiling == configured {
            format!(
                "{n} is above the configured value ({configured}): a patch can tighten a \
                 limit but not raise it; change the configuration to raise it"
            )
        } else {
            format!("{n} is above the most allowed ({ceiling})")
        });
    }
    Ok(())
}

/// `limits` with `key` (a [`PATCHABLE`] key) set to `value`, checked: the
/// value must be a whole number within the key's bounds against `baseline` (the
/// operator's configuration, see the module docs), have the field's type, and
/// keep the queue limits coherent (a soft limit no higher than its hard limit).
/// The error is the reason to report.
pub fn with_override(
    limits: &LimitsConfig,
    baseline: &LimitsConfig,
    key: &str,
    value: &Value,
) -> Result<LimitsConfig, String> {
    let Some(p) = patchable(key) else {
        return Err("not a patchable configuration key".into());
    };
    check_bounds(p, value, baseline)?;
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
    // Bounded by the configuration the overrides are layered over.
    let baseline = limits.clone();
    let mut skipped = Vec::new();
    for (key, value) in overrides {
        match with_override(limits, &baseline, key, value) {
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
    /// Held across a patch's read-modify-write of the stored overrides.
    patch: Arc<tokio::sync::Mutex<()>>,
}

impl LiveLimits {
    /// `baseline` is the configuration before overrides; `effective` is what
    /// is in force (the baseline with the stored overrides layered over it).
    pub fn new(baseline: LimitsConfig, effective: LimitsConfig) -> Self {
        Self {
            baseline: Arc::new(baseline),
            current: Arc::new(RwLock::new(Arc::new(effective))),
            patch: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Exclusive right to change the configuration: hold it across reading
    /// the stored overrides, writing them back and putting the result into
    /// effect. Every writer of the stored overrides takes it, so two changes
    /// can't interleave and lose one another's keys.
    pub async fn lock_for_patch(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.patch.lock().await
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
        let next = with_override(
            &base,
            &base,
            "limits.queued_send_messages_hard",
            &json!(5000),
        )
        .unwrap();
        assert_eq!(next.queued_send_messages_hard, 5000);

        assert!(with_override(&base, &base, "limits.message_size", &json!(1)).is_err());
        assert!(with_override(&base, &base, "security.use_ssl", &json!(false)).is_err());
        assert!(
            with_override(&base, &base, "limits.listed_messages", &json!("many"))
                .unwrap_err()
                .starts_with("invalid value")
        );
        assert!(
            with_override(&base, &base, "limits.delivered_expiry_seconds", &json!(10)).is_err(),
            "tightening delivered expiry loses data, so it is not patchable"
        );
    }

    #[test]
    fn a_patch_can_tighten_a_limit_but_not_loosen_it_or_switch_it_off() {
        let base = LimitsConfig::default(); // listed 100, send hard 10000
        assert!(with_override(&base, &base, "limits.listed_messages", &json!(10)).is_ok());
        let err = with_override(&base, &base, "limits.listed_messages", &json!(101)).unwrap_err();
        assert!(err.contains("above the configured value"), "{err}");
        // The disabled / unlimited values are below every floor.
        for (key, off) in [
            ("limits.queued_send_messages_hard", -1),
            ("limits.rate_limit_per_ip", 0),
            ("limits.max_websocket_connections", 0),
        ] {
            let err = with_override(&base, &base, key, &json!(off)).unwrap_err();
            assert!(err.contains("switch this limit off"), "{key}: {err}");
        }
        let err =
            with_override(&base, &base, "limits.message_expiry_seconds", &json!(60)).unwrap_err();
        assert!(err.contains("below the least"), "{err}");
    }

    #[test]
    fn an_unlimited_configured_value_is_bounded_by_the_absolute_cap() {
        // did_rate_limit_per_second defaults to 0: unlimited. Enabling it is
        // tightening, up to the cap.
        let base = LimitsConfig::default();
        assert_eq!(base.did_rate_limit_per_second, 0);
        assert!(
            with_override(&base, &base, "limits.did_rate_limit_per_second", &json!(50)).is_ok()
        );
        let err = with_override(
            &base,
            &base,
            "limits.did_rate_limit_per_second",
            &json!(100_001),
        )
        .unwrap_err();
        assert!(err.contains("above the most allowed"), "{err}");
    }

    #[test]
    fn a_soft_limit_may_not_exceed_its_hard_limit() {
        let base = LimitsConfig::default(); // send soft 2000, hard 10000
        let err = with_override(
            &base,
            &base,
            "limits.queued_send_messages_hard",
            &json!(100),
        )
        .unwrap_err();
        assert!(err.contains("would exceed"), "{err}");
    }

    #[test]
    fn a_stale_stored_override_is_skipped_not_fatal() {
        let mut limits = LimitsConfig::default();
        // An operator who lowers the configured value below a stored override
        // wins: the override is now above the configuration and is skipped.
        let stored = parse_stored(Some(
            r#"{"limits.listed_messages": 7, "limits.gone_away": 1, "limits.to_recipients": "x", "limits.deleted_messages": 500}"#,
        ));
        let skipped = overlay(&mut limits, &stored);
        assert_eq!(limits.listed_messages, 7);
        assert_eq!(limits.deleted_messages, 100, "the configured value stands");
        let keys: Vec<&str> = skipped.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys.len(), 3, "{skipped:?}");
        assert!(keys.contains(&"limits.gone_away") && keys.contains(&"limits.to_recipients"));
        assert!(keys.contains(&"limits.deleted_messages"));
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
        for p in PATCHABLE {
            let field = p.key.strip_prefix("limits.").unwrap();
            assert!(
                fields.get(field).is_some(),
                "{} is not a LimitsConfig field",
                p.key
            );
            assert!(p.floor >= 1 && p.floor <= p.cap, "{}", p.key);
        }
    }
}
