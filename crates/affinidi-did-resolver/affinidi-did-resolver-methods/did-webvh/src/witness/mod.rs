/*!
*   Handling of witnessing changes to the log entries
*/

use crate::DIDWebVHError;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

pub mod proofs;
pub mod validate;

/// Witness nodes
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Witnesses {
    /// Number of witnesses required to witness a change
    /// Must be 1 or greater
    pub threshold: u32,

    /// Set of witness nodes
    pub witnesses: Vec<Witness>,
}

impl Witnesses {
    /// Are any witnesses configured?
    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }

    /// Checks Witnesses parameters for errors
    pub fn validate(&self) -> Result<(), DIDWebVHError> {
        if self.is_empty() {
            Err(DIDWebVHError::ValidationError(
                "Witnesses are enabled, but no witness nodes are specified! Can not be empty!"
                    .to_string(),
            ))
        } else if self.threshold < 1 {
            Err(DIDWebVHError::ValidationError(
                "Witness threshold must be 1 or more".to_string(),
            ))
        } else if self.witnesses.len() < self.threshold as usize {
            Err(DIDWebVHError::ValidationError(format!(
                "Number of Witnesses ({}) is less than the threshold ({})",
                self.witnesses.len(),
                self.threshold
            )))
        } else {
            Ok(())
        }
    }
}

/// Single Witness Node
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Witness {
    pub id: String,
}

impl Display for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl Witness {
    /// Returns the witness ID as a did:key
    /// use [as_did_key] if you wan the DID#Key value
    pub fn as_did(&self) -> String {
        ["did:key:", &self.id].concat()
    }

    /// Returns the witness ID as a did:key:z6...#z6...
    /// Use [as_did] if you want just the base DID
    pub fn as_did_key(&self) -> String {
        [&self.as_did(), "#", &self.id].concat()
    }
}
