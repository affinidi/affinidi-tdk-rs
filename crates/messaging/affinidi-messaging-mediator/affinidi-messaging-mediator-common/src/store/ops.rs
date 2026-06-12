//! Backend-agnostic decision logic for the store layer.
//!
//! The storage backends reduce to persistence primitives; the *decisions*
//! they share — authorization checks and the like — live here as pure,
//! unit-tested functions so they cannot drift between backends. `FjallStore`
//! and `MemoryStore` previously each carried their own copy of these checks.
//!
//! The Redis backend performs the equivalent checks server-side in Lua and is
//! necessarily separate (Lua can't call Rust), so these functions cover the
//! in-process Rust backends; the conformance suite (`store_conformance`) is
//! what keeps Redis aligned with them.

use crate::store::types::DeletionAuthority;
use crate::types::acls::{AccessListModeType, MediatorACLSet};

/// Whether `authority` may delete a message addressed to `to_did_hash` and
/// (optionally) from `from_did_hash`.
///
/// - [`DeletionAuthority::Admin`] always may — the message-expiry processor and
///   account removal delete on the owner's behalf.
/// - [`DeletionAuthority::Owner`] may only delete a message it is a party to:
///   its DID hash must be the recipient or the (non-anonymous) sender.
pub fn delete_message_permitted(
    authority: &DeletionAuthority,
    to_did_hash: &str,
    from_did_hash: Option<&str>,
) -> bool {
    match authority {
        DeletionAuthority::Admin { .. } => true,
        DeletionAuthority::Owner { did_hash } => {
            did_hash == to_did_hash || from_did_hash == Some(did_hash.as_str())
        }
    }
}

/// A prospective sender, from the recipient's access-control perspective.
pub enum Sender {
    /// An anonymous sender (no authenticated DID).
    Anonymous,
    /// A known (authenticated) sender, with whether it is currently on the
    /// recipient's access list.
    Known { on_access_list: bool },
}

/// Whether `sender` is allowed to deliver a message to a recipient whose
/// ACLs are `recipient_acls`.
///
/// - [`Sender::Anonymous`] is allowed iff the recipient's `anon_receive`
///   ACL bit is set.
/// - [`Sender::Known`] is judged by the recipient's access-list mode:
///   `ExplicitAllow` admits only senders on the list; `ExplicitDeny` admits
///   everyone except those on the list.
///
/// The caller is responsible for the (backend-specific) lookups that produce
/// `recipient_acls` and the `on_access_list` membership flag; this function
/// is the pure decision the in-process backends previously each inlined.
pub fn access_list_allowed(recipient_acls: &MediatorACLSet, sender: Sender) -> bool {
    match sender {
        Sender::Anonymous => recipient_acls.get_anon_receive().0,
        Sender::Known { on_access_list } => match recipient_acls.get_access_list_mode().0 {
            AccessListModeType::ExplicitAllow => on_access_list,
            AccessListModeType::ExplicitDeny => !on_access_list,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(h: &str) -> DeletionAuthority {
        DeletionAuthority::Owner {
            did_hash: h.to_string(),
        }
    }
    fn admin(h: &str) -> DeletionAuthority {
        DeletionAuthority::Admin {
            admin_did_hash: h.to_string(),
        }
    }

    #[test]
    fn admin_may_delete_anything() {
        assert!(delete_message_permitted(
            &admin("anyone"),
            "to",
            Some("from")
        ));
        assert!(delete_message_permitted(&admin("anyone"), "to", None));
    }

    #[test]
    fn owner_must_be_a_party_to_the_message() {
        // The recipient may delete.
        assert!(delete_message_permitted(&owner("to"), "to", Some("from")));
        // The sender may delete.
        assert!(delete_message_permitted(&owner("from"), "to", Some("from")));
        // An unrelated third party may not.
        assert!(!delete_message_permitted(
            &owner("other"),
            "to",
            Some("from")
        ));
    }

    #[test]
    fn anonymous_message_only_the_recipient_qualifies() {
        // With no sender, only the recipient is a party.
        assert!(delete_message_permitted(&owner("to"), "to", None));
        assert!(!delete_message_permitted(&owner("from"), "to", None));
    }

    fn acls(mode: AccessListModeType, anon_receive: bool) -> MediatorACLSet {
        let mut a = MediatorACLSet::default();
        // admin = true so the change is always permitted in the test.
        a.set_access_list_mode(mode, false, true).unwrap();
        a.set_anon_receive(anon_receive, false, true).unwrap();
        a
    }

    #[test]
    fn explicit_allow_admits_only_listed_known_senders() {
        let a = acls(AccessListModeType::ExplicitAllow, false);
        assert!(access_list_allowed(
            &a,
            Sender::Known {
                on_access_list: true
            }
        ));
        assert!(!access_list_allowed(
            &a,
            Sender::Known {
                on_access_list: false
            }
        ));
    }

    #[test]
    fn explicit_deny_admits_everyone_except_listed() {
        let a = acls(AccessListModeType::ExplicitDeny, false);
        assert!(!access_list_allowed(
            &a,
            Sender::Known {
                on_access_list: true
            }
        ));
        assert!(access_list_allowed(
            &a,
            Sender::Known {
                on_access_list: false
            }
        ));
    }

    #[test]
    fn anonymous_sender_follows_the_anon_receive_bit() {
        // Mode is irrelevant for anonymous senders — only the anon_receive bit.
        assert!(access_list_allowed(
            &acls(AccessListModeType::ExplicitAllow, true),
            Sender::Anonymous
        ));
        assert!(!access_list_allowed(
            &acls(AccessListModeType::ExplicitAllow, false),
            Sender::Anonymous
        ));
        assert!(access_list_allowed(
            &acls(AccessListModeType::ExplicitDeny, true),
            Sender::Anonymous
        ));
    }
}
