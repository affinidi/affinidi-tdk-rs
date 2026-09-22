//! Friendly names for account hashes.
//!
//! The mediator never holds a DID. It knows an account only by
//! `sha256(did)`: lowercase hex of the SHA-256 digest of the DID string, the
//! same function over a TSP VID. That hash is what every mediator view shows.
//! An [`AddressBook`] turns it back into something readable: you give it a DID
//! and a nickname, it hashes the DID, and anything showing that hash can show
//! the nickname.
//!
//! On disk it is a JSON list, easy to edit by hand:
//!
//! ```json
//! [
//!   { "name": "alice's phone", "did": "did:peer:2.Vz6Mk…" },
//!   { "name": "old relay", "did": "36c23eba…4584 (a bare 64-hex hash)" }
//! ]
//! ```
//!
//! An entry may give a bare account hash in place of a DID, for an account
//! whose DID you don't know.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One named account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressEntry {
    /// What to show in place of the hash.
    pub name: String,
    /// The DID, or the account hash itself when the DID is not known.
    pub did: String,
}

impl AddressEntry {
    /// The account hash this entry names.
    pub fn hash(&self) -> String {
        account_hash(&self.did)
    }

    /// Whether `did` is a bare account hash rather than a DID.
    pub fn is_bare_hash(&self) -> bool {
        is_account_hash(&self.did)
    }
}

/// The mediator's account identifier for `did`: lowercase hex SHA-256 of the
/// DID string. A value that already is one is returned as it is (lowercased).
pub fn account_hash(did: &str) -> String {
    let did = did.trim();
    if is_account_hash(did) {
        did.to_ascii_lowercase()
    } else {
        sha256::digest(did)
    }
}

/// Whether `s` has the shape of an account hash: 64 hex digits.
pub fn is_account_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Names for account hashes. See the [module docs](self).
#[derive(Clone, Debug, Default)]
pub struct AddressBook {
    /// What the user saved, in order.
    entries: Vec<AddressEntry>,
    /// Names supplied by the application (the console's own account, the
    /// mediator, an embedding app's identities). Consulted after `entries`
    /// and never saved.
    known: HashMap<String, AddressEntry>,
    /// hash → index into `entries`.
    index: HashMap<String, usize>,
}

impl AddressBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a book from `path`. A missing file is an empty book.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let entries: Vec<AddressEntry> = serde_json::from_str(&text)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let mut book = Self::new();
                for entry in entries {
                    book.insert(&entry.did, &entry.name);
                }
                Ok(book)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(e),
        }
    }

    /// Write the saved entries to `path`, creating its directory if needed.
    /// Application-supplied names are not written.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(&self.entries)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, text + "\n")
    }

    /// Name `did` (or a bare account hash). Naming an account again renames
    /// it; a DID replaces a bare hash for the same account.
    pub fn insert(&mut self, did: &str, name: &str) {
        let entry = AddressEntry {
            name: name.trim().to_string(),
            did: did.trim().to_string(),
        };
        let hash = entry.hash();
        match self.index.get(&hash) {
            Some(&i) => {
                let keep_did = !entry.is_bare_hash() || self.entries[i].is_bare_hash();
                self.entries[i].name = entry.name;
                if keep_did {
                    self.entries[i].did = entry.did;
                }
            }
            None => {
                self.index.insert(hash, self.entries.len());
                self.entries.push(entry);
            }
        }
    }

    /// Forget the account `hash` names. Returns whether it was there.
    pub fn remove(&mut self, hash: &str) -> bool {
        let hash = hash.to_ascii_lowercase();
        let Some(i) = self.index.remove(&hash) else {
            return false;
        };
        self.entries.remove(i);
        self.index = self
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| (e.hash(), i))
            .collect();
        true
    }

    /// Supply a name the application knows (its own account, the mediator)
    /// without saving it. A saved entry for the same account wins.
    pub fn know(&mut self, did: &str, name: &str) {
        let entry = AddressEntry {
            name: name.to_string(),
            did: did.to_string(),
        };
        self.known.insert(entry.hash(), entry);
    }

    /// The entry naming `hash`, saved first, then application-supplied.
    pub fn lookup(&self, hash: &str) -> Option<&AddressEntry> {
        let hash = hash.to_ascii_lowercase();
        self.index
            .get(&hash)
            .map(|&i| &self.entries[i])
            .or_else(|| self.known.get(&hash))
    }

    /// The nickname for `hash`, if it has one.
    pub fn name_of(&self, hash: &str) -> Option<&str> {
        self.lookup(hash).map(|e| e.name.as_str())
    }

    /// The DID behind `hash`, if the book knows it.
    pub fn did_of(&self, hash: &str) -> Option<&str> {
        self.lookup(hash)
            .filter(|e| !e.is_bare_hash())
            .map(|e| e.did.as_str())
    }

    /// The saved entries, in the order they were added.
    pub fn entries(&self) -> &[AddressEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:example:alice";

    #[test]
    fn a_did_is_named_by_its_sha256_hash() {
        let mut book = AddressBook::new();
        book.insert(DID, "alice");
        let hash = sha256::digest(DID);
        assert_eq!(book.name_of(&hash), Some("alice"));
        assert_eq!(book.name_of(&hash.to_uppercase()), Some("alice"));
        assert_eq!(book.did_of(&hash), Some(DID));
        assert_eq!(book.name_of(&sha256::digest("did:example:bob")), None);
    }

    #[test]
    fn a_bare_hash_names_an_account_whose_did_is_unknown() {
        let hash = sha256::digest(DID);
        let mut book = AddressBook::new();
        book.insert(&hash, "someone");
        assert_eq!(book.name_of(&hash), Some("someone"));
        assert_eq!(book.did_of(&hash), None);
        // Learning the DID later fills it in and renames.
        book.insert(DID, "alice");
        assert_eq!(book.entries().len(), 1);
        assert_eq!(book.did_of(&hash), Some(DID));
        // A bare hash does not overwrite a known DID.
        book.insert(&hash, "alice again");
        assert_eq!(book.did_of(&hash), Some(DID));
        assert_eq!(book.name_of(&hash), Some("alice again"));
    }

    #[test]
    fn a_saved_name_wins_over_an_application_supplied_one_and_only_saved_are_written() {
        let dir = std::env::temp_dir().join(format!("ab-{}", std::process::id()));
        let path = dir.join("book.json");
        let mut book = AddressBook::new();
        book.know(DID, "you");
        assert_eq!(book.name_of(&sha256::digest(DID)), Some("you"));
        book.insert(DID, "alice");
        book.know("did:example:mediator", "mediator");
        assert_eq!(book.name_of(&sha256::digest(DID)), Some("alice"));
        book.save(&path).unwrap();

        let loaded = AddressBook::load(&path).unwrap();
        assert_eq!(loaded.entries().len(), 1);
        assert_eq!(loaded.name_of(&sha256::digest(DID)), Some("alice"));
        assert_eq!(
            loaded.name_of(&sha256::digest("did:example:mediator")),
            None
        );

        assert!(
            AddressBook::load(&dir.join("absent.json"))
                .unwrap()
                .entries()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn removing_reindexes_what_is_left() {
        let mut book = AddressBook::new();
        book.insert("did:example:a", "a");
        book.insert("did:example:b", "b");
        assert!(book.remove(&sha256::digest("did:example:a")));
        assert!(!book.remove(&sha256::digest("did:example:a")));
        assert_eq!(book.name_of(&sha256::digest("did:example:b")), Some("b"));
    }
}
