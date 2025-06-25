/*!
*   DID method for Web with Verifiable History
*   See [WebVH Spec](https://identity.foundation/didwebvh/v1.0)
*/

use crate::{
    log_entry::{LogEntry, MetaData},
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
    parameters::Parameters,
    witness::proofs::WitnessProofCollection,
};
use affinidi_data_integrity::{DataIntegrityProof, SigningDocument};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::Utc;
use serde_json::Value;
use thiserror::Error;

pub mod log_entry;
pub mod log_entry_state;
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
                validation_status: LogEntryValidationStatus::NotValidated,
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

    /// Creates a new LogEntry
    /// version_time is optional, if not provided, current time will be used
    /// document is the DID Document as a JSON Value
    /// parameters are the Parameters for the Log Entry (Full set of parameters)
    /// signing_key is the Secret used to sign the Log Entry
    /// witness if set to true will trigger the witnessing of this log entry
    ///   if witness is false, then an additional witnessing step may be required
    ///   NOTE: A diff comparison to previous parameters is automatically done
    /// signing_key is the Secret used to sign the Log Entry
    pub fn create_log_entry(
        &mut self,
        version_time: Option<String>,
        document: &Value,
        parameters: &Parameters,
        signing_key: &Secret,
        witness: bool,
    ) -> Result<Option<&LogEntryState>, DIDWebVHError> {
        let now = Utc::now();

        // Create a VerificationMethod ID from the first updatekey
        let vm_id = if let Some(Some(value)) = &parameters.update_keys {
            if let Some(key) = value.iter().next() {
                // Create a VerificationMethod ID from the first update key
                ["did:key:", key, "#", key].concat()
            } else {
                return Err(DIDWebVHError::SCIDError(
                    "No update keys provided in parameters".to_string(),
                ));
            }
        } else {
            return Err(DIDWebVHError::SCIDError(
                "No update keys provided in parameters".to_string(),
            ));
        };
        // Check that the vm_id matches the secret key id
        if signing_key.id != vm_id {
            return Err(DIDWebVHError::SCIDError(format!(
                "Secret key ID {} does not match VerificationMethod ID {}",
                signing_key.id, vm_id
            )));
        }

        let last_log_entry = self.log_entries.last();

        let mut log_entry = if let Some(last_log_entry) = last_log_entry {
            // Utilizes the previous LogEntry for some info

            LogEntry {
                version_id: last_log_entry.log_entry.version_id.clone(),
                version_time: version_time.unwrap_or_else(|| {
                    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                }),
                // Only use the difference of the parameters
                parameters: last_log_entry.validated_parameters.diff(parameters)?,
                state: document.clone(),
                proof: None,
            }
        } else {
            // First LogEntry so we need to set up a few things first
            // Ensure SCID field is set correctly

            let mut log_entry = LogEntry {
                version_id: SCID_HOLDER.to_string(),
                version_time: version_time
                    .unwrap_or_else(|| now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
                parameters: parameters.clone(),
                state: document.clone(),
                proof: None,
            };
            log_entry.parameters.scid = Some(SCID_HOLDER.to_string());

            // Create the SCID from the first log entry
            let scid = log_entry.generate_scid()?;
            //
            // Replace all instances of {SCID} with the actual SCID
            let le_str = serde_json::to_string(&log_entry).map_err(|e| {
                DIDWebVHError::SCIDError(format!(
                    "Couldn't serialize LogEntry to JSON. Reason: {}",
                    e
                ))
            })?;

            serde_json::from_str(&le_str.replace(SCID_HOLDER, &scid)).map_err(|e| {
                DIDWebVHError::SCIDError(format!(
                    "Couldn't deserialize LogEntry from SCID conversion. Reason: {}",
                    e
                ))
            })?
        };

        // Create the entry hash for this Log Entry
        let entry_hash = log_entry.generate_log_entry_hash().map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate entryHash for first LogEntry. Reason: {}",
                e
            ))
        })?;

        let (created, scid, portable, validated_parameters) =
            if let Some(last_entry) = last_log_entry {
                // Increment the version-id if NOT first LogEntry
                let (current_id, _) = log_entry.get_version_id_fields()?;
                log_entry.version_id = [&(current_id + 1).to_string(), "-", &entry_hash].concat();
                if let Some(first_entry) = self.log_entries.first() {
                    let Some(scid) = first_entry.log_entry.parameters.scid.clone() else {
                        return Err(DIDWebVHError::LogEntryError(
                            "First LogEntry does not have a SCID!".to_string(),
                        ));
                    };
                    (
                        first_entry.log_entry.version_time.clone(),
                        scid,
                        first_entry
                            .log_entry
                            .parameters
                            .portable
                            .unwrap_or_default(),
                        log_entry
                            .parameters
                            .validate(Some(&last_entry.validated_parameters))?,
                    )
                } else {
                    return Err(DIDWebVHError::LogEntryError(
                        "Expected a First LogEntry, but none exist!".to_string(),
                    ));
                }
            } else {
                log_entry.version_id = ["1-", &entry_hash].concat();
                let Some(scid) = log_entry.parameters.scid.clone() else {
                    return Err(DIDWebVHError::LogEntryError(
                        "First LogEntry does not have a SCID!".to_string(),
                    ));
                };
                (
                    log_entry.version_time.clone(),
                    scid,
                    log_entry.parameters.portable.unwrap_or_default(),
                    log_entry.parameters.clone(),
                )
            };

        // Generate the proof for the log entry
        let mut log_entry_unsigned: SigningDocument = (&log_entry).try_into()?;

        DataIntegrityProof::sign_jcs_data(&mut log_entry_unsigned, signing_key).map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate Data Integrity Proof for LogEntry. Reason: {}",
                e
            ))
        })?;

        log_entry.proof = log_entry_unsigned.proof;

        // Generate metadata for this LogEntry
        let metadata = MetaData {
            version_id: log_entry.version_id.clone(),
            version_time: log_entry.version_time.clone(),
            created,
            updated: log_entry.version_time.clone(),
            deactivated: parameters.deactivated,
            portable,
            scid,
            watchers: if let Some(Some(watchers)) = &parameters.watchers {
                Some(watchers.clone())
            } else {
                None
            },
            witness: if let Some(Some(witnesses)) = &parameters.active_witness {
                Some(witnesses.clone())
            } else {
                None
            },
        };

        let id_number = log_entry.get_version_id_fields()?.0;
        self.log_entries.push(LogEntryState {
            log_entry,
            metadata,
            version_number: id_number,
            validation_status: LogEntryValidationStatus::Ok,
            validated_parameters,
        });

        Ok(self.log_entries.last())
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
