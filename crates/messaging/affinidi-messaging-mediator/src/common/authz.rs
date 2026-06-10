//! Central authorization checks for the mediator.
//!
//! Every permission decision should flow through this module so the
//! semantics live in one greppable, unit-tested place rather than being
//! re-derived inline at each handler. Today it owns:
//!
//! - [`require_capability`] — does a DID's [`MediatorACLSet`] grant a given
//!   [`Capability`]? The single source for per-capability gating.
//! - [`authentication_check`] — the pre-auth "can this DID connect?" check
//!   (resolves the ACL set from the session, the store, or the configured
//!   default, then applies the blocked gate).
//!
//! Access-list (sender↔recipient) checks and the remaining handler/routing
//! ACL sites migrate here in the following tasks; the capability vocabulary
//! below is intentionally complete ahead of every call site adopting it.

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use tracing::debug;

use crate::{SharedData, common::session::Session};

/// A single permission a DID's [`MediatorACLSet`] may or may not grant.
///
/// Mirrors the capability bits in `MediatorACLSet` (the `*_change`
/// self-management flags are not gating capabilities and are handled by the
/// admin-protocol layer, not here).
// Not every variant is wired to a call site yet — the handler/routing ACL
// checks adopt them in tasks T8/T9. Defining the full vocabulary now keeps
// the authz surface in one place.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Capability {
    /// The DID is not blocked from the mediator.
    NotBlocked,
    /// The DID may store messages locally (LOCAL bit).
    Local,
    /// The DID may send messages.
    SendMessages,
    /// The DID may receive messages.
    ReceiveMessages,
    /// The DID may send forwarded (routed) messages.
    SendForwarded,
    /// The DID may receive forwarded (routed) messages.
    ReceiveForwarded,
    /// The DID may create out-of-band invitations.
    CreateInvites,
    /// The DID may receive anonymous (no authenticated sender) messages.
    AnonReceive,
}

/// Returned when an ACL set does not grant a required [`Capability`].
/// Callers map this to their layer's error type (`AuthError`,
/// `MediatorError` problem report, …) so the HTTP/DIDComm surface is
/// unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CapabilityDenied(pub Capability);

/// Whether `acls` grants `capability`. The single definition of what each
/// capability means in terms of the ACL bits.
pub(crate) fn grants(acls: &MediatorACLSet, capability: Capability) -> bool {
    match capability {
        Capability::NotBlocked => !acls.get_blocked(),
        Capability::Local => acls.get_local(),
        Capability::SendMessages => acls.get_send_messages().0,
        Capability::ReceiveMessages => acls.get_receive_messages().0,
        Capability::SendForwarded => acls.get_send_forwarded().0,
        Capability::ReceiveForwarded => acls.get_receive_forwarded().0,
        Capability::CreateInvites => acls.get_create_invites().0,
        Capability::AnonReceive => acls.get_anon_receive().0,
    }
}

/// Require that `acls` grants `capability`, returning [`CapabilityDenied`]
/// otherwise. Callers translate the error into their own response type.
pub(crate) fn require_capability(
    acls: &MediatorACLSet,
    capability: Capability,
) -> Result<(), CapabilityDenied> {
    if grants(acls, capability) {
        Ok(())
    } else {
        Err(CapabilityDenied(capability))
    }
}

/// Pre-authentication check: is `did_hash` allowed to connect to the
/// mediator, and is it already known?
///
/// Resolves the ACL set from the provided `session` if any, else from the
/// store, else the configured `global_acl_default`, then applies the
/// blocked gate. Returns `(allowed, known)`:
/// - `allowed` is `true` when the DID is not blocked;
/// - `known` is `true` when the DID already had a session or stored ACL.
///
/// (Relocated from the former `acl_checks::ACLCheck` trait so all auth-time
/// permission logic lives in one module.)
pub(crate) async fn authentication_check(
    shared: &SharedData,
    did_hash: &str,
    session: Option<&Session>,
) -> Result<(bool, bool), MediatorError> {
    let mut known = false;
    let acls = if let Some(session) = session {
        known = true;
        session.acls.clone()
    } else {
        let acls = shared
            .database
            .get_did_acls(
                &[did_hash.to_string()],
                shared.config.security.mediator_acl_mode.clone(),
            )
            .await?;
        if let Some(acl) = acls.acl_response.first() {
            debug!(did_hash, acl = acl.acls.to_hex_string(), "ACL found");
            known = true;
            acl.acls.clone()
        } else {
            debug!(did_hash, "No ACL set, using default");
            shared.config.security.global_acl_default.clone()
        }
    };

    Ok((grants(&acls, Capability::NotBlocked), known))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an ACL set granting everything (ALLOW_ALL), then we revoke
    /// individual capabilities to test the gate.
    fn allow_all() -> MediatorACLSet {
        MediatorACLSet::from_string_ruleset("ALLOW_ALL").expect("ALLOW_ALL ruleset")
    }

    /// Build an ACL set granting nothing (DENY_ALL).
    fn deny_all() -> MediatorACLSet {
        MediatorACLSet::from_string_ruleset("DENY_ALL").expect("DENY_ALL ruleset")
    }

    const ALL: &[Capability] = &[
        Capability::NotBlocked,
        Capability::Local,
        Capability::SendMessages,
        Capability::ReceiveMessages,
        Capability::SendForwarded,
        Capability::ReceiveForwarded,
        Capability::CreateInvites,
        Capability::AnonReceive,
    ];

    #[test]
    fn allow_all_grants_every_capability() {
        let acls = allow_all();
        for &cap in ALL {
            assert!(grants(&acls, cap), "ALLOW_ALL should grant {cap:?}");
            assert!(
                require_capability(&acls, cap).is_ok(),
                "{cap:?} should be allowed"
            );
        }
    }

    #[test]
    fn deny_all_denies_capabilities_but_is_not_blocked() {
        // DENY_ALL withholds every send/receive/forward/invite capability,
        // but does NOT set the blocked bit — a denied DID is simply
        // unprivileged, not blocked.
        let acls = deny_all();
        for &cap in ALL {
            if cap == Capability::NotBlocked {
                assert!(
                    grants(&acls, cap),
                    "DENY_ALL should not set the blocked bit"
                );
                continue;
            }
            assert!(!grants(&acls, cap), "DENY_ALL should deny {cap:?}");
            assert_eq!(
                require_capability(&acls, cap),
                Err(CapabilityDenied(cap)),
                "{cap:?} should be denied"
            );
        }
    }

    #[test]
    fn blocked_did_fails_not_blocked() {
        let mut acls = allow_all();
        acls.set_blocked(true);
        assert!(!grants(&acls, Capability::NotBlocked));
        assert_eq!(
            require_capability(&acls, Capability::NotBlocked),
            Err(CapabilityDenied(Capability::NotBlocked))
        );
        // Blocking does not clear the other capability bits — `NotBlocked`
        // is the gate that must be checked separately.
        assert!(grants(&acls, Capability::SendMessages));
    }

    #[test]
    fn each_capability_is_gated_independently() {
        // Granting exactly one capability (from DENY_ALL) must satisfy only
        // that capability's gate.
        type Setter = fn(&mut MediatorACLSet);
        let setters: &[(Capability, Setter)] = &[
            (Capability::Local, |a| a.set_local(true)),
            (Capability::SendMessages, |a| {
                a.set_send_messages(true, false, true).unwrap()
            }),
            (Capability::ReceiveMessages, |a| {
                a.set_receive_messages(true, false, true).unwrap()
            }),
            (Capability::SendForwarded, |a| {
                a.set_send_forwarded(true, false, true).unwrap()
            }),
            (Capability::ReceiveForwarded, |a| {
                a.set_receive_forwarded(true, false, true).unwrap()
            }),
            (Capability::CreateInvites, |a| {
                a.set_create_invites(true, false, true).unwrap()
            }),
            (Capability::AnonReceive, |a| {
                a.set_anon_receive(true, false, true).unwrap()
            }),
        ];
        for (granted, set) in setters {
            let mut acls = deny_all();
            set(&mut acls);
            assert!(grants(&acls, *granted), "{granted:?} should be granted");
            for &other in ALL {
                if other == *granted || other == Capability::NotBlocked {
                    continue;
                }
                assert!(
                    !grants(&acls, other),
                    "granting {granted:?} must not grant {other:?}"
                );
            }
        }
    }
}
