/*!
 * Attestation Revocation List (ARL) — serial-number-based revocation.
 *
 * An ARL maintains a set of revoked credential identifiers. Similar to
 * X.509 Certificate Revocation Lists (CRLs).
 *
 * Use when:
 * - The number of revoked credentials is small relative to total issued
 * - You need to track revocation metadata (reason, timestamp)
 *
 * For large-scale privacy-preserving revocation, prefer `BitstringStatusList`.
 */

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// An Attestation Revocation List containing identifiers of revoked credentials.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevocationList {
    /// Set of revoked credential identifiers (serial numbers or URIs).
    revoked: HashSet<String>,
}

impl RevocationList {
    /// Create a new empty revocation list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a credential identifier to the revocation list.
    pub fn revoke(&mut self, credential_id: impl Into<String>) {
        self.revoked.insert(credential_id.into());
    }

    /// Remove a credential identifier from the revocation list (un-revoke).
    ///
    /// Returns `true` if the identifier was present and removed.
    pub fn unrevoke(&mut self, credential_id: &str) -> bool {
        self.revoked.remove(credential_id)
    }

    /// Check if a credential is revoked.
    pub fn is_revoked(&self, credential_id: &str) -> bool {
        self.revoked.contains(credential_id)
    }

    /// Get the number of revoked credentials.
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Check if the revocation list is empty.
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Get an iterator over revoked credential identifiers.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.revoked.iter().map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_list_is_empty() {
        let list = RevocationList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn revoke_and_check() {
        let mut list = RevocationList::new();
        list.revoke("urn:uuid:12345");

        assert!(list.is_revoked("urn:uuid:12345"));
        assert!(!list.is_revoked("urn:uuid:67890"));
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn unrevoke() {
        let mut list = RevocationList::new();
        list.revoke("urn:uuid:12345");
        assert!(list.is_revoked("urn:uuid:12345"));

        let removed = list.unrevoke("urn:uuid:12345");
        assert!(removed);
        assert!(!list.is_revoked("urn:uuid:12345"));
    }

    #[test]
    fn unrevoke_nonexistent() {
        let mut list = RevocationList::new();
        assert!(!list.unrevoke("urn:uuid:nonexistent"));
    }

    #[test]
    fn duplicate_revoke_is_idempotent() {
        let mut list = RevocationList::new();
        list.revoke("urn:uuid:12345");
        list.revoke("urn:uuid:12345");
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn serialization_roundtrip() {
        let mut list = RevocationList::new();
        list.revoke("urn:uuid:aaa");
        list.revoke("urn:uuid:bbb");

        let json = serde_json::to_string(&list).unwrap();
        let parsed: RevocationList = serde_json::from_str(&json).unwrap();

        assert!(parsed.is_revoked("urn:uuid:aaa"));
        assert!(parsed.is_revoked("urn:uuid:bbb"));
        assert_eq!(parsed.len(), 2);
    }
}
