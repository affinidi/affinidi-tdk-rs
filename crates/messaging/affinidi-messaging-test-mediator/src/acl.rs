//! Typed ACL presets for the test-mediator fixture.
//!
//! The production mediator config parses ACL settings from a comma-
//! separated string ruleset (e.g. `"ALLOW_ALL"`, `"DENY_ALL"`,
//! `"MODE_EXPLICIT_DENY, LOCAL, RECEIVE_MESSAGES"`). That format is
//! convenient in `mediator.toml` but error-prone in test code: typos
//! turn into runtime parse errors that only surface when the test
//! actually spins up the fixture.
//!
//! This module exposes the same presets as plain Rust functions
//! returning a [`MediatorACLSet`]. Each function mirrors the
//! corresponding arm of `MediatorACLSet::from_string_ruleset` exactly,
//! constructed via the public bit-setter API. Use these for the common
//! cases; for fine-grained ACLs, build a `MediatorACLSet` directly
//! with `MediatorACLSet::default()` plus the bit setters.
//!
//! ```ignore
//! use affinidi_messaging_test_mediator::{TestMediator, acl};
//!
//! let mediator = TestMediator::builder()
//!     .global_acl_default(acl::deny_all())     // typed, no string parsing
//!     .spawn().await?;
//!
//! let alice = mediator
//!     .add_user_with_acl("alice", acl::allow_all())
//!     .await?;
//! ```
//!
//! Any failure returned from the underlying bit-setters surfaces as
//! [`crate::TestMediatorError::Acl`]. In practice the presets here
//! cannot fail — they pass `admin = true` to every setter — but we
//! propagate the type signature so the construction stays honest.

use crate::{AccessListModeType, MediatorACLSet, TestMediatorError};

/// Equivalent of the production `"ALLOW_ALL"` preset.
///
/// - `mode = ExplicitDeny` (denylist semantics)
/// - `local = true` (DID can complete WS upgrade)
/// - every send/receive/forward/invite/anon-receive flag granted
/// - every self-management flag enabled (DID can change its own ACL,
///   queue limits, access list)
///
/// This is what `add_user` mints for every test user today, and what
/// most happy-path tests want.
pub fn allow_all() -> MediatorACLSet {
    let mut acls = MediatorACLSet::default();
    apply_allow_all(&mut acls)
        .expect("allow_all preset is infallible: every setter is invoked with admin=true");
    acls
}

/// Equivalent of the production `"DENY_ALL"` preset.
///
/// - `mode = ExplicitAllow` (allowlist semantics)
/// - `local = false`
/// - every send/receive/forward/invite/anon-receive flag denied
/// - no self-management — only an admin can change anything
///
/// Use for testing the strict-allowlist deployment shape, or as the
/// `global_acl_default` to verify the mediator rejects unregistered
/// DIDs.
pub fn deny_all() -> MediatorACLSet {
    let mut acls = MediatorACLSet::default();
    apply_deny_all(&mut acls)
        .expect("deny_all preset is infallible: every setter is invoked with admin=true");
    acls
}

// ─── Internal helpers — kept as `Result` so the preset bodies match
// the production `from_string_ruleset` arms exactly and any future
// behavior change in the bit setters surfaces here, not silently. ──

fn apply_allow_all(acls: &mut MediatorACLSet) -> Result<(), TestMediatorError> {
    acls.set_access_list_mode(AccessListModeType::ExplicitDeny, true, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_local(true);
    acls.set_send_messages(true, true, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_receive_messages(true, true, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_send_forwarded(true, true, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_receive_forwarded(true, true, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_create_invites(true, true, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_anon_receive(true, true, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_self_manage_list(true);
    acls.set_self_manage_send_queue_limit(true);
    acls.set_self_manage_receive_queue_limit(true);
    Ok(())
}

fn apply_deny_all(acls: &mut MediatorACLSet) -> Result<(), TestMediatorError> {
    acls.set_access_list_mode(AccessListModeType::ExplicitAllow, false, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_local(false);
    acls.set_send_messages(false, false, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_receive_messages(false, false, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_send_forwarded(false, false, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_receive_forwarded(false, false, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_create_invites(false, false, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_anon_receive(false, false, true)
        .map_err(TestMediatorError::Acl)?;
    acls.set_self_manage_list(false);
    acls.set_self_manage_send_queue_limit(false);
    acls.set_self_manage_receive_queue_limit(false);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `allow_all()` and `deny_all()` should produce the same bitmask
    /// the production `from_string_ruleset` parser does. Locks the
    /// invariant in case either side drifts.
    #[test]
    fn allow_all_matches_production_ruleset() {
        let typed = allow_all();
        let parsed = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        assert_eq!(typed.to_u64(), parsed.to_u64());
    }

    #[test]
    fn deny_all_matches_production_ruleset() {
        let typed = deny_all();
        let parsed = MediatorACLSet::from_string_ruleset("DENY_ALL").unwrap();
        assert_eq!(typed.to_u64(), parsed.to_u64());
    }
}
