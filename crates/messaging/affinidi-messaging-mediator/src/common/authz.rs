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
//! - [`check_permissions`] — may this session act on these DIDs (admin, or
//!   its own DID only), with the admin-signature check where configured?
//!
//! Every handler, routing and storage ACL gate now resolves through this
//! module; see `docs/acls.md` for the operator-facing model these functions
//! implement. Keep it that way — the capability enum below has no
//! `#[allow(dead_code)]` precisely so a capability that nothing enforces
//! shows up as a warning rather than as a silently inert permission bit.

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::MediatorStore;
use affinidi_messaging_sdk::protocols::mediator::{accounts::AccountType, acls::MediatorACLSet};
use subtle::ConstantTimeEq;
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

/// Check that the sender (identified by JWS signature or authcrypt key ID)
/// matches the session DID. The `sender_kid` is a key ID like `did:...#key-N`.
pub(crate) fn check_admin_signature(session: &Session, sender_kid: &Option<String>) -> bool {
    match sender_kid {
        Some(kid) => kid
            .split_once('#')
            .is_some_and(|(did, _)| did == session.did),
        None => false,
    }
}

/// Whether a session may act on `dids`: an admin account may act on any DID,
/// any other account only on its own (exactly one DID hash, its own). With
/// `check_admin_signing`, an admin must also have signed as the session DID.
pub(crate) fn check_permissions(
    session: &Session,
    dids: &[String],
    check_admin_signing: bool,
    sign_by: &Option<String>,
) -> bool {
    // If we need to check message signature for an admin request
    if check_admin_signing
        && (session.account_type == AccountType::Admin
            || session.account_type == AccountType::RootAdmin)
        && !check_admin_signature(session, sign_by)
    {
        return false;
    }

    session.account_type == AccountType::RootAdmin
        || session.account_type == AccountType::Admin
        || dids.len() == 1
            && dids[0]
                .as_bytes()
                .ct_eq(session.did_hash.as_bytes())
                .unwrap_u8()
                == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha256::digest;

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

    // --- check_admin_signature tests ---

    #[test]
    fn admin_sig_jws_matching_did() {
        let session = Session {
            did: "did:example:alice".to_string(),
            ..Default::default()
        };
        assert!(check_admin_signature(
            &session,
            &Some("did:example:alice#key-0".to_string())
        ));
    }

    #[test]
    fn admin_sig_authcrypt_kid_matching_did() {
        // Authcrypt sender identified by encrypted_from_kid (same format as JWS)
        let session = Session {
            did: "did:webvh:Qmc572jbs:webvh.example.com:vta".to_string(),
            ..Default::default()
        };
        assert!(check_admin_signature(
            &session,
            &Some("did:webvh:Qmc572jbs:webvh.example.com:vta#key-1".to_string())
        ));
    }

    #[test]
    fn admin_sig_mismatched_did() {
        let session = Session {
            did: "did:example:alice".to_string(),
            ..Default::default()
        };
        assert!(!check_admin_signature(
            &session,
            &Some("did:example:mallory#key-0".to_string())
        ));
    }

    #[test]
    fn admin_sig_none_is_anonymous() {
        let session = Session {
            did: "did:example:alice".to_string(),
            ..Default::default()
        };
        assert!(!check_admin_signature(&session, &None));
    }

    #[test]
    fn admin_sig_kid_without_fragment_rejected() {
        let session = Session {
            did: "did:example:alice".to_string(),
            ..Default::default()
        };
        // A key ID without a # fragment is malformed and should be rejected
        assert!(!check_admin_signature(
            &session,
            &Some("did:example:alice".to_string())
        ));
    }

    // --- check_permissions tests ---

    #[test]
    fn perms_admin_any_dids_no_signing_check() {
        let session = Session {
            did: "did:example:admin".to_string(),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:someone_else")];
        assert!(check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn perms_root_admin_any_dids() {
        let session = Session {
            did: "did:example:root".to_string(),
            did_hash: digest("did:example:root"),
            account_type: AccountType::RootAdmin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:other")];
        assert!(check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn perms_standard_own_did() {
        let session = Session {
            did: "did:example:alice".to_string(),
            did_hash: digest("did:example:alice"),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![digest("did:example:alice")];
        assert!(check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn perms_standard_wrong_did_rejected() {
        let session = Session {
            did: "did:example:alice".to_string(),
            did_hash: digest("did:example:alice"),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![digest("did:example:bob")];
        assert!(!check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn perms_standard_multiple_dids_rejected() {
        let session = Session {
            did: "did:example:alice".to_string(),
            did_hash: digest("did:example:alice"),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![digest("did:example:alice"), digest("did:example:bob")];
        assert!(!check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn perms_admin_with_jws_signing_check_matching() {
        let session = Session {
            did: "did:example:admin".to_string(),
            did_hash: digest("did:example:admin"),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:admin")];
        assert!(check_permissions(
            &session,
            &dids,
            true,
            &Some("did:example:admin#key-0".to_string())
        ));
    }

    #[test]
    fn perms_admin_with_authcrypt_kid_signing_check() {
        // When check_admin_signing is true and sender is identified by authcrypt kid
        let session = Session {
            did: "did:example:admin".to_string(),
            did_hash: digest("did:example:admin"),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:admin")];
        // This simulates passing encrypted_from_kid as the sender identity
        assert!(check_permissions(
            &session,
            &dids,
            true,
            &Some("did:example:admin#key-1".to_string())
        ));
    }

    #[test]
    fn perms_admin_signing_check_wrong_did_rejected() {
        let session = Session {
            did: "did:example:admin".to_string(),
            did_hash: digest("did:example:admin"),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:admin")];
        assert!(!check_permissions(
            &session,
            &dids,
            true,
            &Some("did:example:mallory#key-0".to_string())
        ));
    }

    #[test]
    fn perms_admin_signing_check_none_rejected() {
        // Anonymous message to admin endpoint should fail when signing check enabled
        let session = Session {
            did: "did:example:admin".to_string(),
            did_hash: digest("did:example:admin"),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:admin")];
        assert!(!check_permissions(&session, &dids, true, &None));
    }

    #[test]
    fn perms_standard_no_signing_check_ignores_sender() {
        // Standard account with check_admin_signing=false: sender_kid is irrelevant
        let session = Session {
            did: "did:example:alice".to_string(),
            did_hash: digest("did:example:alice"),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![digest("did:example:alice")];
        assert!(check_permissions(&session, &dids, false, &None));
        assert!(check_permissions(
            &session,
            &dids,
            false,
            &Some("did:example:mallory#key-0".to_string())
        ));
    }
}
