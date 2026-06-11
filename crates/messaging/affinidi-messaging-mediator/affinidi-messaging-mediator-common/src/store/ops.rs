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
}
