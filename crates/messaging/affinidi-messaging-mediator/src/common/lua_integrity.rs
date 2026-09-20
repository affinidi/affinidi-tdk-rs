//! Startup check that the Redis stored-function library a deployment loads is
//! the one this binary was built against.
//!
//! # The failure this catches
//!
//! `load_scripts` issues `FUNCTION LOAD REPLACE` from the path in
//! `database.functions_file`, and fails loudly if Redis rejects it. So "did
//! the library load" is already answered, and answering it again would be
//! worth nothing.
//!
//! The failure that is *not* answered is loading the wrong one. Redis accepts
//! an older `atm-functions.lua` perfectly happily: the function names are
//! stable across releases and only the bodies change, so every call still
//! succeeds and simply does less than the mediator believes it does. Nothing
//! errors, nothing is logged, and the mediator runs indefinitely with a
//! capability it thinks it has.
//!
//! The worked example is the per-relationship queue gate. It depends on the
//! library writing a `PEER_Q` hash on store and decrementing it on delete. A
//! library from before that was added never writes it, so `peer_queue_count`
//! reads 0 for every relationship for ever, and the gate that exists to stop
//! one sender monopolising a recipient silently never fires. The mediator
//! looks healthy. The check it advertises is simply absent.
//!
//! # Why the check is the file's content
//!
//! Two weaker checks were considered and rejected:
//!
//! - **Presence of the library** — already guaranteed by `load_scripts`, and
//!   true in the failure above.
//! - **The set of function names Redis reports** — identical between versions,
//!   because the drift is in the bodies. It would have reported healthy for
//!   exactly the case that matters.
//!
//! So the check compares the file about to be loaded against the copy compiled
//! into this binary. That is the only comparison that distinguishes "the right
//! library" from "a library", and it tracks future edits to the Lua
//! automatically: `include_str!` re-reads the shipped file at every build, so
//! a change to the stored functions updates the expectation in the same commit
//! that makes it.
//!
//! # It reports, it does not refuse
//!
//! A mismatch logs at `error`, drives
//! [`REDIS_FUNCTIONS_MATCH_BUILD`](crate::common::metrics::names::REDIS_FUNCTIONS_MATCH_BUILD)
//! to 0, and shows as `degraded` on `/readyz` — 200, still in rotation. It
//! does not stop the mediator starting.
//!
//! **The reason is what the stale library actually costs, not the
//! inconvenience of a failed boot.** `limits.queue.peer` is a fairness and
//! resource-exhaustion control, not an authorization one. With an old library
//! loaded that gate is inert, but the sender-total and recipient-total gates
//! still apply and *nothing becomes reachable that was not already* — the
//! failure is degraded fairness, not unauthorized access. That is what makes
//! failing open defensible here, and it is deliberately narrower than "a
//! refusal to boot would be an outage", which would equally justify failing
//! open on an authorization check, where it would be wrong.
//!
//! The same reasoning fixes the readiness state: `degraded` keeps the instance
//! serving and flags the condition, which is the existing meaning of that
//! state rather than a new one invented here. Had this needed 503
//! `not_ready`, the argument above would not hold and the check would belong
//! at boot instead.

use sha256::digest;

/// The stored-function library this binary was built against.
///
/// Read from the shipped `conf/atm-functions.lua` at compile time, so it can
/// never drift from the source tree the binary came from.
const BUILT_AGAINST: &str = include_str!("../../conf/atm-functions.lua");

/// Outcome of comparing the deployment's library against the built-in one.
///
/// Three states, not two, and the third is the point. A check that folds "I
/// looked and it differs" together with "I could not look" produces one value
/// meaning two things — one benign, one not — which is the failure mode that
/// makes a metric worse than no metric. Fail-open is only as good as its
/// report, so the report has to distinguish them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LuaIntegrity {
    /// The file matches what this binary expects.
    Match,
    /// The file loaded, but it is not the one this binary was built against.
    Mismatch {
        /// Short digest of the file the deployment is loading.
        found: String,
        /// Short digest of the library compiled into this binary.
        expected: String,
    },
    /// The check could not be performed — the path is unreadable, missing, or
    /// not something this process can open. **Not** evidence of a mismatch,
    /// and deliberately not reported as one.
    Unknown {
        /// Why the file could not be read, for the log line.
        reason: String,
    },
}

impl LuaIntegrity {
    /// Value for [`REDIS_FUNCTIONS_MATCH_BUILD`]: 1 match, 0 mismatch, -1
    /// could-not-check.
    ///
    /// `-1` rather than a second metric so a dashboard cannot plot the gauge
    /// and silently omit the case where it is uninformative — an alert on
    /// `== 0` keeps meaning "wrong library", and `< 0` is visibly a different
    /// condition rather than a gap in the series.
    ///
    /// [`REDIS_FUNCTIONS_MATCH_BUILD`]: crate::common::metrics::names::REDIS_FUNCTIONS_MATCH_BUILD
    fn gauge_value(&self) -> f64 {
        match self {
            LuaIntegrity::Match => 1.0,
            LuaIntegrity::Mismatch { .. } => 0.0,
            LuaIntegrity::Unknown { .. } => -1.0,
        }
    }

    /// Whether this outcome should show as `degraded` on `/readyz`.
    pub fn is_healthy(&self) -> bool {
        matches!(self, LuaIntegrity::Match)
    }
}

/// Normalise before hashing so a checkout with CRLF line endings, or an editor
/// that added a trailing newline, is not reported as a different library.
///
/// Deliberately conservative: it normalises line endings and trailing
/// whitespace and nothing else. Anything that changes a statement changes the
/// digest, which is the entire point — a normaliser clever enough to ignore
/// "harmless" differences would eventually ignore a real one.
fn normalise(source: &str) -> String {
    source
        .replace("\r\n", "\n")
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

/// Twelve hex characters — enough to tell two libraries apart in a log line
/// without pasting a full digest into it.
fn short_digest(source: &str) -> String {
    digest(normalise(source)).chars().take(12).collect()
}

/// Compare `loaded` (the contents of the configured `functions_file`) against
/// the library compiled into this binary.
pub fn check(loaded: &str) -> LuaIntegrity {
    let found = short_digest(loaded);
    let expected = short_digest(BUILT_AGAINST);
    if found == expected {
        LuaIntegrity::Match
    } else {
        LuaIntegrity::Mismatch { found, expected }
    }
}

/// Run the check against the file at `path`, publish the gauge, log, and
/// return the outcome so the caller can surface it on `/readyz`.
///
/// A file that cannot be read is reported as [`LuaIntegrity::Unknown`], never
/// as a mismatch: the caller loads the same path immediately afterwards and
/// will fail properly there, and inventing a mismatch would put a misleading
/// digest in the log for what is really a missing file.
pub fn check_and_report(path: &str) -> LuaIntegrity {
    let outcome = match std::fs::read_to_string(path) {
        Ok(loaded) => check(&loaded),
        Err(e) => LuaIntegrity::Unknown {
            reason: e.to_string(),
        },
    };

    metrics::gauge!(crate::common::metrics::names::REDIS_FUNCTIONS_MATCH_BUILD)
        .set(outcome.gauge_value());

    match &outcome {
        LuaIntegrity::Match => {
            tracing::info!(
                functions_file = %path,
                "stored-function library matches this build"
            );
        }
        LuaIntegrity::Mismatch { found, expected } => {
            tracing::error!(
                functions_file = %path,
                found = %found,
                expected = %expected,
                "stored-function library does NOT match this build — it will load and every \
                 call will succeed, but functions whose bodies changed since that copy will \
                 silently do less than this mediator expects (a library predating the \
                 per-relationship queue accounting never writes PEER_Q, so peer_queue_count \
                 reads 0 and limits.queue.peer never fires). Point database.functions_file at \
                 this release's conf/atm-functions.lua and restart."
            );
        }
        LuaIntegrity::Unknown { reason } => {
            tracing::warn!(
                functions_file = %path,
                reason = %reason,
                "could not read the stored-function file to check it against this build — \
                 this is NOT a mismatch, it is an unperformed check, and the gauge reports \
                 -1 rather than a verdict it did not reach"
            );
        }
    }

    outcome
}

/// Component name under which the outcome is published to `/readyz`.
pub const COMPONENT: &str = "redis_stored_functions";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_library_matches_itself() {
        assert_eq!(check(BUILT_AGAINST), LuaIntegrity::Match);
    }

    #[test]
    fn line_endings_and_trailing_whitespace_are_not_a_mismatch() {
        let crlf = BUILT_AGAINST.replace('\n', "\r\n");
        assert_eq!(check(&crlf), LuaIntegrity::Match);
        let padded = format!("{BUILT_AGAINST}\n\n");
        assert_eq!(check(&padded), LuaIntegrity::Match);
    }

    /// The regression this whole module exists for: a library that has lost
    /// the per-relationship accounting still defines every function name, so
    /// only a content check can tell it apart.
    #[test]
    fn a_library_missing_peer_accounting_is_a_mismatch() {
        let stale: String = BUILT_AGAINST
            .lines()
            .filter(|l| !l.contains("PEER_Q"))
            .collect::<Vec<_>>()
            .join("\n");
        // It still looks like a complete library by name.
        assert!(stale.contains("store_message"));
        assert!(stale.contains("delete_message"));
        // But it is not the one we were built against.
        assert!(matches!(check(&stale), LuaIntegrity::Mismatch { .. }));
    }

    #[test]
    fn mismatch_reports_both_digests_so_the_log_can_be_acted_on() {
        match check("-- not the library at all") {
            LuaIntegrity::Mismatch { found, expected } => {
                assert_ne!(found, expected);
                assert_eq!(found.len(), 12);
                assert_eq!(expected.len(), 12);
            }
            other => panic!("an unrelated file must not match: {other:?}"),
        }
    }

    /// An unreadable file is an *unperformed check*, not a verdict. Folding it
    /// into `Mismatch` would raise a false alarm naming a digest that was
    /// never computed; folding it into `Match` would report healthy for a file
    /// nobody read. It gets its own state and its own gauge value.
    #[test]
    fn a_file_that_cannot_be_read_is_unknown_not_a_mismatch() {
        let outcome = check_and_report("/nonexistent/atm-functions.lua");
        assert!(matches!(outcome, LuaIntegrity::Unknown { .. }));
        assert_eq!(outcome.gauge_value(), -1.0);
        assert!(!outcome.is_healthy());
    }

    /// The three states map to three distinct gauge values, so an alert on
    /// `== 0` keeps meaning "wrong library" and cannot be tripped by a check
    /// that never ran.
    #[test]
    fn each_state_has_its_own_gauge_value() {
        assert_eq!(LuaIntegrity::Match.gauge_value(), 1.0);
        assert_eq!(
            LuaIntegrity::Mismatch {
                found: "a".into(),
                expected: "b".into()
            }
            .gauge_value(),
            0.0
        );
        assert_eq!(
            LuaIntegrity::Unknown {
                reason: "boom".into()
            }
            .gauge_value(),
            -1.0
        );
    }

    /// Only a match is healthy — both failure states show as `degraded` on
    /// `/readyz`, and neither fails readiness.
    #[test]
    fn only_a_match_is_healthy() {
        assert!(LuaIntegrity::Match.is_healthy());
        assert!(
            !LuaIntegrity::Mismatch {
                found: "a".into(),
                expected: "b".into()
            }
            .is_healthy()
        );
        assert!(
            !LuaIntegrity::Unknown {
                reason: "boom".into()
            }
            .is_healthy()
        );
    }

    #[test]
    fn checking_the_shipped_file_on_disk_reports_a_match() {
        // The path the default config ships, resolved from this source file
        // rather than the working directory.
        let shipped = concat!(env!("CARGO_MANIFEST_DIR"), "/conf/atm-functions.lua");
        assert_eq!(check_and_report(shipped), LuaIntegrity::Match);
    }
}
