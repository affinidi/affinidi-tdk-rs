//! Central authorization checks for the mediator.
//!
//! Every permission decision should flow through this module so the
//! semantics live in one greppable, unit-tested place rather than being
//! re-derived inline at each handler. Today it owns:
//!
//! - [`require_capability`] — does a DID's [`MediatorACLSet`] grant a given
//!   [`Capability`]? The single source for per-capability gating.
//! - [`check_access_list`] — may a given sender deliver to a given
//!   recipient, under that recipient's allowlist/denylist mode?
//! - [`effective_acls`] — the ACL set governing a DID: its stored ACLs, or
//!   the configured `global_acl_default` when it has no account record.
//! - [`authentication_check`] — the pre-auth "can this DID connect?" check
//!   (resolves the ACL set from the session, the store, or the configured
//!   default, then applies the blocked gate).
//! - [`acl_change_ok`] — may a non-admin apply this ACL change to itself?
//!
//! Every handler, routing and storage ACL gate now resolves through this
//! module; see `docs/acls.md` for the operator-facing model these functions
//! implement. Keep it that way — the capability enum below has no
//! `#[allow(dead_code)]` precisely so a capability that nothing enforces
//! shows up as a warning rather than as a silently inert permission bit.

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::MediatorStore;
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use tracing::debug;

use crate::{SharedData, common::session::Session};

/// A single permission a DID's [`MediatorACLSet`] may or may not grant.
///
/// Mirrors the capability bits in `MediatorACLSet` (the `*_change`
/// self-management flags are not gating capabilities and are handled by the
/// admin-protocol layer, not here).
///
/// Every variant is wired to at least one call site, and there is
/// deliberately no `#[allow(dead_code)]` here: an unused variant means a
/// capability the mediator advertises but never enforces. That is precisely
/// how `ReceiveMessages` stayed inert — settable, reported over the wire and
/// documented, but consulted by nothing. Let the dead-code warning fire.
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

/// Returned when a recipient's access list denies a sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AccessListDenied;

/// Whether `sender_hash` may deliver to `recipient_hash` under the
/// recipient's access list (interpreted as an allowlist or denylist per the
/// recipient's ACL mode). The single wrapper over the store's
/// `access_list_allowed`, so the allow/deny verdict and its error mapping
/// live alongside the rest of the authz vocabulary. `sender_hash` is `None`
/// for an anonymous sender.
pub(crate) async fn check_access_list(
    store: &dyn MediatorStore,
    recipient_hash: &str,
    sender_hash: Option<&str>,
) -> Result<(), AccessListDenied> {
    if store.access_list_allowed(recipient_hash, sender_hash).await {
        Ok(())
    } else {
        Err(AccessListDenied)
    }
}

/// The ACL set that actually governs `did_hash`: its stored ACLs, or the
/// mediator's `global_acl_default` when the DID has no account record.
///
/// Every ACL decision about a DID the mediator may not have registered yet
/// must resolve it this way — an unknown DID is governed by the default,
/// not by "no permissions". Centralised here so the fallback can't drift
/// between the sender-side, recipient-side and routing gates.
pub(crate) async fn effective_acls(
    shared: &SharedData,
    did_hash: &str,
) -> Result<MediatorACLSet, MediatorError> {
    Ok(shared
        .database
        .get_did_acl(did_hash)
        .await?
        .unwrap_or_else(|| shared.config.security.global_acl_default.clone()))
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

/// A capability whose ACL entry is a `(value, self_change)` pair.
type CapabilityPair = (&'static str, fn(&MediatorACLSet) -> (bool, bool));

/// A flag with no self-change bit of its own — admin-only, always.
type AdminOnlyFlag = (&'static str, fn(&MediatorACLSet) -> bool);

/// The capabilities a DID may change itself when the matching `self_change`
/// bit is set. `access_list_mode` is the same shape but its value is an enum
/// rather than a `bool`, so it is checked separately below.
const SELF_CHANGEABLE: &[CapabilityPair] = &[
    ("send_messages", |a| a.get_send_messages()),
    ("receive_messages", |a| a.get_receive_messages()),
    ("send_forwarded", |a| a.get_send_forwarded()),
    ("receive_forwarded", |a| a.get_receive_forwarded()),
    ("create_invites", |a| a.get_create_invites()),
    ("anon_receive", |a| a.get_anon_receive()),
];

/// Flags with no `self_change` bit of their own: only an admin may ever
/// change them. `blocked` and `local` are the mediator's own gates (a DID
/// must not be able to unblock itself or grant itself an inbox), and the
/// `self_manage_*` flags are what *delegate* self-service in the first
/// place — a DID that could set them would be granting itself the authority
/// the operator withheld.
const ADMIN_ONLY: &[AdminOnlyFlag] = &[
    ("blocked", |a| a.get_blocked()),
    ("local", |a| a.get_local()),
    ("self_manage_list", |a| a.get_self_manage_list()),
    ("self_manage_send_queue_limit", |a| {
        a.get_self_manage_send_queue_limit()
    }),
    ("self_manage_receive_queue_limit", |a| {
        a.get_self_manage_receive_queue_limit()
    }),
];

/// Validate a self-initiated ACL change: for each capability, a DID may
/// only flip the value when its `self_change` flag is set, may never flip
/// the `self_change` flag itself, and may never touch an admin-only flag
/// (only an admin can do either). Returns `None` when the change is
/// permitted, or `Some(errors)` describing each disallowed modification.
///
/// The tables above are deliberately exhaustive over `MediatorACLSet`: every
/// field is either self-changeable under its own bit or admin-only. The
/// `every_acl_field_is_classified` test pins that, because an unclassified
/// field silently becomes self-service — which is exactly how `local`,
/// `blocked` and the three `self_manage_*` flags went unchecked here while
/// the Trust Task path (`ensure_self_manageable`) refused them.
///
/// (Relocated from the mediator admin-protocol handler so every permission
/// decision — capability gates and self-change authorization alike — lives
/// in this module.)
pub(crate) fn acl_change_ok(
    current_acls: &MediatorACLSet,
    new_acls: &MediatorACLSet,
) -> Option<Vec<String>> {
    let mut errors = Vec::new();

    for (name, get) in SELF_CHANGEABLE {
        let (current_value, current_self_change) = get(current_acls);
        let (new_value, new_self_change) = get(new_acls);

        if current_value != new_value && !current_self_change {
            errors.push(format!("{name} not allowed to change"));
        }
        if current_self_change != new_self_change {
            errors.push(format!("{name}:self_change can't modify!"));
        }
    }

    let (current_mode, current_mode_self_change) = current_acls.get_access_list_mode();
    let (new_mode, new_mode_self_change) = new_acls.get_access_list_mode();
    if current_mode != new_mode && !current_mode_self_change {
        errors.push("access_list_mode not allowed to change".to_string());
    }
    if current_mode_self_change != new_mode_self_change {
        errors.push("access_list_mode:self_change can't modify!".to_string());
    }

    for (name, get) in ADMIN_ONLY {
        if get(current_acls) != get(new_acls) {
            errors.push(format!("{name} is admin-only and can't be changed"));
        }
    }

    if errors.is_empty() {
        None
    } else {
        Some(errors)
    }
}

/// Outcome of checking an admin message's `created_time` against the
/// admin-message TTL.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AdminTtlStatus {
    /// Within the allowed window — accept.
    Ok,
    /// `created_time` is too old (or in the future) — reject as expired; the
    /// value is carried for the problem report.
    Expired(u64),
    /// No `created_time` header — reject as missing.
    Missing,
}

/// Validate an admin message's `created_time` against `admin_messages_expiry`,
/// bounding replay of captured admin messages.
///
/// This is deliberately independent of `block_remote_admin_msgs`: admin
/// messages are *always* subject to the replay-bounding TTL, whether or not
/// the mediator also requires a signature on remote admin messages. A
/// `created_time` in the future is rejected too (clock skew / forgery).
pub(crate) fn admin_message_ttl_status(
    created_time: Option<u64>,
    expiry: u64,
    now: u64,
) -> AdminTtlStatus {
    match created_time {
        Some(ct) if ct.saturating_add(expiry) <= now || ct > now => AdminTtlStatus::Expired(ct),
        Some(_) => AdminTtlStatus::Ok,
        None => AdminTtlStatus::Missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;

    #[test]
    fn admin_ttl_accepts_fresh_and_rejects_stale_future_and_missing() {
        let now = 1_000_000;
        let expiry = 3;

        // Fresh: created within the window.
        assert_eq!(
            admin_message_ttl_status(Some(now), expiry, now),
            AdminTtlStatus::Ok
        );
        assert_eq!(
            admin_message_ttl_status(Some(now - 2), expiry, now),
            AdminTtlStatus::Ok
        );

        // Stale: created_time + expiry <= now (the boundary is inclusive).
        assert_eq!(
            admin_message_ttl_status(Some(now - 3), expiry, now),
            AdminTtlStatus::Expired(now - 3)
        );
        assert_eq!(
            admin_message_ttl_status(Some(now - 100), expiry, now),
            AdminTtlStatus::Expired(now - 100)
        );

        // Future created_time is rejected (clock skew / forgery).
        assert_eq!(
            admin_message_ttl_status(Some(now + 1), expiry, now),
            AdminTtlStatus::Expired(now + 1)
        );

        // Missing header.
        assert_eq!(
            admin_message_ttl_status(None, expiry, now),
            AdminTtlStatus::Missing
        );

        // The verdict never depends on `block_remote_admin_msgs` — it isn't an
        // input here, so admin replay is bounded regardless of that flag. With
        // `expiry == 0` every admin message (created_time == now) is expired.
        assert_eq!(
            admin_message_ttl_status(Some(now), 0, now),
            AdminTtlStatus::Expired(now)
        );
    }

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

    // ─── acl_change_ok (non-admin self-service) ──────────────────────────────

    /// The highest bit position `MediatorACLSet` assigns a meaning to
    /// (`self_manage_receive_queue_limit`).
    const HIGHEST_ACL_BIT: u32 = 18;

    #[test]
    fn identical_acls_are_never_a_change() {
        let acls = MediatorACLSet::from_u64(0);
        assert_eq!(acl_change_ok(&acls, &acls), None);
        let allow = allow_all();
        assert_eq!(acl_change_ok(&allow, &allow), None);
    }

    /// Every meaningful bit must be refused for an account holding no
    /// self-change rights. This is the exhaustiveness guard: a field that
    /// falls out of both `SELF_CHANGEABLE` and `ADMIN_ONLY` becomes silently
    /// self-service, which is the bug this test exists to prevent.
    #[test]
    fn every_acl_field_is_classified() {
        // Base: all bits clear — no capability, no self-change right.
        let current = MediatorACLSet::from_u64(0);
        for bit in 0..=HIGHEST_ACL_BIT {
            let new_acls = MediatorACLSet::from_u64(1_u64 << bit);
            assert!(
                acl_change_ok(&current, &new_acls).is_some(),
                "bit {bit} is not gated for a non-admin — it is in neither \
                 SELF_CHANGEABLE nor ADMIN_ONLY"
            );
        }
    }

    /// A non-admin may never change `blocked`, `local`, or the three
    /// `self_manage_*` flags: none of them has a self-change bit, so the
    /// only authority that can flip them is an admin. Regression test —
    /// these five were unchecked here while the Trust Task path refused
    /// them, letting a standard DID grant itself an inbox (`local`), the
    /// right to edit its own access list (`self_manage_list`), or clear its
    /// own `blocked` bit.
    #[test]
    fn non_admin_cannot_change_admin_only_flags() {
        // Start from ALLOW_ALL so every *self-change* bit is set: the only
        // thing that can refuse these flags is the admin-only rule itself.
        let current = allow_all();

        for (name, get) in ADMIN_ONLY {
            let mut new_acls = current.clone();
            match *name {
                "blocked" => new_acls.set_blocked(!get(&current)),
                "local" => new_acls.set_local(!get(&current)),
                "self_manage_list" => new_acls.set_self_manage_list(!get(&current)),
                "self_manage_send_queue_limit" => {
                    new_acls.set_self_manage_send_queue_limit(!get(&current))
                }
                "self_manage_receive_queue_limit" => {
                    new_acls.set_self_manage_receive_queue_limit(!get(&current))
                }
                other => panic!("unclassified admin-only flag: {other}"),
            }

            let errors = acl_change_ok(&current, &new_acls)
                .unwrap_or_else(|| panic!("{name} must be refused for a non-admin"));
            assert!(
                errors.iter().any(|e| e.contains(name)),
                "expected an error naming {name}, got {errors:?}"
            );
        }
    }

    #[test]
    fn capability_flips_only_when_its_self_change_bit_is_set() {
        // ALLOW_ALL grants every capability *and* every self-change bit, so
        // revoking a capability from oneself is permitted.
        let current = allow_all();
        let mut new_acls = current.clone();
        new_acls.set_send_messages(false, true, false).unwrap();
        assert_eq!(acl_change_ok(&current, &new_acls), None);

        // The shipped default grants capabilities but no self-change bits,
        // so the same flip is refused.
        let current =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES")
                .expect("shipped default ruleset");
        let mut new_acls = current.clone();
        new_acls.set_send_messages(false, false, true).unwrap();
        let errors = acl_change_ok(&current, &new_acls).expect("must be refused");
        assert!(
            errors
                .iter()
                .any(|e| e == "send_messages not allowed to change"),
            "got {errors:?}"
        );
    }

    /// A DID may never widen its own authority by setting the self-change
    /// bits, even when it currently holds them.
    #[test]
    fn self_change_bits_are_never_self_modifiable() {
        let current = allow_all();
        let mut new_acls = current.clone();
        // Keep the value, drop the self-change right.
        new_acls
            .set_receive_messages(current.get_receive_messages().0, false, true)
            .unwrap();
        let errors = acl_change_ok(&current, &new_acls).expect("must be refused");
        assert!(
            errors
                .iter()
                .any(|e| e == "receive_messages:self_change can't modify!"),
            "got {errors:?}"
        );
    }

    /// The access-list mode is a self-changeable capability like the others,
    /// but its value is an enum rather than a `bool` so it is checked on its
    /// own path — cover it explicitly.
    #[test]
    fn access_list_mode_follows_its_self_change_bit() {
        let current = MediatorACLSet::from_u64(0);
        let mut new_acls = current.clone();
        new_acls
            .set_access_list_mode(AccessListModeType::ExplicitDeny, false, true)
            .unwrap();
        let errors = acl_change_ok(&current, &new_acls).expect("must be refused");
        assert!(
            errors
                .iter()
                .any(|e| e == "access_list_mode not allowed to change"),
            "got {errors:?}"
        );

        // With the self-change bit set, the same flip is allowed.
        let mut current = MediatorACLSet::from_u64(0);
        current
            .set_access_list_mode(AccessListModeType::ExplicitAllow, true, true)
            .unwrap();
        let mut new_acls = current.clone();
        new_acls
            .set_access_list_mode(AccessListModeType::ExplicitDeny, true, true)
            .unwrap();
        assert_eq!(acl_change_ok(&current, &new_acls), None);
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
