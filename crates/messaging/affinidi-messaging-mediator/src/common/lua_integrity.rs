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
//! A mismatch logs at `error` and drives
//! [`REDIS_FUNCTIONS_MATCH_BUILD`](crate::common::metrics::names::REDIS_FUNCTIONS_MATCH_BUILD)
//! to 0; it does not stop the mediator starting. An operator who has
//! deliberately customised the library, or who is mid-rollout between two
//! releases, should get a loud warning rather than a node that will not boot —
//! refusing to start would turn an observability gap into an outage, which is
//! the wrong trade for a check whose entire purpose is to make a silent
//! problem visible.

use sha256::digest;

/// The stored-function library this binary was built against.
///
/// Read from the shipped `conf/atm-functions.lua` at compile time, so it can
/// never drift from the source tree the binary came from.
const BUILT_AGAINST: &str = include_str!("../../conf/atm-functions.lua");

/// Outcome of comparing the deployment's library against the built-in one.
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

/// Run the check against the file at `path`, publish the gauge, and log.
///
/// A file that cannot be read is *not* reported as a mismatch — the caller
/// loads the same path immediately afterwards and will fail properly there,
/// and inventing a mismatch here would put a misleading digest in the log for
/// what is really a missing file.
pub fn check_and_report(path: &str) {
    let Ok(loaded) = std::fs::read_to_string(path) else {
        tracing::debug!(
            functions_file = %path,
            "could not read the stored-function file for the integrity check; \
             leaving it to the loader to report"
        );
        return;
    };

    match check(&loaded) {
        LuaIntegrity::Match => {
            metrics::gauge!(crate::common::metrics::names::REDIS_FUNCTIONS_MATCH_BUILD).set(1.0);
            tracing::info!(
                functions_file = %path,
                "stored-function library matches this build"
            );
        }
        LuaIntegrity::Mismatch { found, expected } => {
            metrics::gauge!(crate::common::metrics::names::REDIS_FUNCTIONS_MATCH_BUILD).set(0.0);
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
    }
}

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
            LuaIntegrity::Match => panic!("an unrelated file must not match"),
        }
    }
}
