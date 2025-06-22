/*!
*   DID method for Web with Verifiable History
*   See [WebVH Spec](https://identity.foundation/didwebvh/v1.0)
*/

use crate::{
    log_entry::{LogEntry, LogEntryState, MetaData},
    parameters::Parameters,
    witness::proofs::WitnessProofCollection,
};
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

impl DIDWebVHState {
    /// Convenience method to load LogEntries from a file, will ensure default state is set
    /// NOTE: NO WEBVH VALIDATION IS DONE HERE
    pub fn load_log_entries_from_file(&mut self, file_path: &str) -> Result<(), DIDWebVHError> {
        for log_entry in LogEntry::load_from_file(file_path)? {
            self.log_entries.push(LogEntryState {
                log_entry: log_entry.clone(),
                metadata: MetaData::default(),
                version_number: log_entry.get_version_id_fields()?.0,
                validation_status: log_entry::LogEntryValidationStatus::NotValidated,
                validated_parameters: Parameters::default(),
            });
        }
        Ok(())
    }

    /// Convenience method to load WitnessProofs from a file, will ensure default state is set
    /// NOTE: NO WEBVH VALIDATION IS DONE HERE
    /// NOTE: Not all DIDs will have witness proofs, so this is optional
    pub fn load_witness_proofs_from_file(&mut self, file_path: &str) {
        if let Ok(proofs) = WitnessProofCollection::read_from_file(file_path) {
            self.witness_proofs = proofs;
        }
    }
}

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
