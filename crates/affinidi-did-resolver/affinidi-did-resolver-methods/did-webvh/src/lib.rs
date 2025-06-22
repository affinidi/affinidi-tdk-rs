/*!
*   DID method for Web with Verifiable History
*   See [WebVH Spec](https://identity.foundation/didwebvh/v1.0)
*/

use crate::{log_entry::LogEntryState, witness::proofs::WitnessProofCollection};
use thiserror::Error;

pub mod log_entry;
pub mod parameters;
pub mod resolve;
pub mod url;
pub mod validate;
pub mod witness;

pub const SCID_HOLDER: &str = "{SCID}";

/// Error types for WebVH method
#[derive(Error, Debug)]
pub enum DIDWebVHError {
    #[error("DeactivatedError: {0}")]
    DeactivatedError(String),
    #[error("DIDError: {0}")]
    DIDError(String),
    #[error("Invalid method identifier: {0}")]
    InvalidMethodIdentifier(String),
    #[error("LogEntryError: {0}")]
    LogEntryError(String),
    #[error("DID Query NotFound")]
    NotFound,
    #[error("NotImplemented: {0}")]
    NotImplemented(String),
    #[error("ParametersError: {0}")]
    ParametersError(String),
    #[error("SCIDError: {0}")]
    SCIDError(String),
    #[error("ServerError: {0}")]
    ServerError(String),
    #[error("UnsupportedMethod: Must be did:webvh")]
    UnsupportedMethod,
    /// There was an error in validating the DID
    #[error("ValidationError: {0}")]
    ValidationError(String),
    /// An error occurred while working with Witness Proofs
    #[error("WitnessProofError: {0}")]
    WitnessProofError(String),
}

/// Information relating to a webvh DID
#[derive(Debug, Default)]
pub struct DIDWebVHState {
    pub log_entries: Vec<LogEntryState>,
    pub witness_proofs: WitnessProofCollection,
}

impl DIDWebVHState {}

#[cfg(test)]
mod tests {
    use crate::parameters::Parameters;

    #[test]
    fn check_serialization_field_action() {
        let watchers = vec!["did:webvh:watcher1".to_string()];
        let params = Parameters {
            pre_rotation_active: false,
            method: None,
            scid: None,
            update_keys: None,
            active_update_keys: Vec::new(),
            portable: None,
            next_key_hashes: None,
            witness: Some(None),
            active_witness: Some(None),
            watchers: Some(Some(watchers)),
            deactivated: false,
            ttl: None,
        };

        let parsed = serde_json::to_value(&params).expect("Couldn't parse parameters");
        let pretty = serde_json::to_string_pretty(&params).expect("Couldn't parse parameters");

        println!("Parsed: {}", pretty);

        assert_eq!(parsed.get("next_key_hashes"), None);
        assert!(parsed.get("witness").is_some_and(|s| s.is_null()));
        assert!(parsed.get("watchers").is_some_and(|s| s.is_array()));
    }
}
