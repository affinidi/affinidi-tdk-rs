//! The two files a `did:webs` identifier publishes.
//!
//! Creation returns bytes, not URLs: this crate does not publish. A hosting
//! service writes them at the paths [`DidWebs::artifact_url`] derives, and
//! resolution reads them back.
//!
//! [`DidWebs::artifact_url`]: crate::DidWebs::artifact_url

use crate::identifier::{DID_JSON, KERI_CESR};

/// The published form of a `did:webs` identifier.
///
/// Only `keri_cesr` carries authority. `did_json` is a cache of what the key
/// event log implies, and a resolver checks it against its own derivation
/// rather than trusting it — so the two must not be produced independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifacts {
    /// The CESR stream: key events, and the signed replies that authorise
    /// service endpoints.
    pub keri_cesr: Vec<u8>,
    /// The DID document, derived from the verified key state.
    pub did_json: Vec<u8>,
}

impl Artifacts {
    /// The two artifacts paired with the file names they are published under.
    ///
    /// Convenience for a hosting service writing them out.
    pub fn files(&self) -> [(&'static str, &[u8]); 2] {
        [
            (KERI_CESR, self.keri_cesr.as_slice()),
            (DID_JSON, self.did_json.as_slice()),
        ]
    }
}
