/*!
*  Reads a JSON Log file, all functions related to reading and verifying Log Entries are here
*/

use super::LogEntry;
use crate::{DIDWebVHError, SCID_HOLDER, log_entry::MetaData, parameters::Parameters};
use affinidi_data_integrity::verification_proof::verify_data;
use chrono::Utc;
use std::{
    fs::File,
    io::{self, BufRead},
};
use tracing::{debug, warn};

impl LogEntry {
    /// Load all LogEntries from a file and return them as a vector
    /// Returns an error if the file cannot be read or if the entries are invalid.
    pub(crate) fn load_from_file(file_path: &str) -> Result<Vec<LogEntry>, DIDWebVHError> {
        let file = File::open(file_path)
            .map_err(|e| DIDWebVHError::LogEntryError(format!("Failed to open log file: {e}")))?;
        let buf_reader = io::BufReader::new(file);

        let mut entries = Vec::new();
        for line in buf_reader.lines() {
            match line {
                Ok(line) => {
                    let log_entry: LogEntry = serde_json::from_str(&line).map_err(|e| {
                        DIDWebVHError::LogEntryError(format!(
                            "Failed to deserialize log entry: {e}",
                        ))
                    })?;
                    entries.push(log_entry);
                }
                Err(e) => {
                    return Err(DIDWebVHError::LogEntryError(format!(
                        "Failed to read line from log file: {e}",
                    )));
                }
            }
        }

        Ok(entries)
    }

    /// Verify a LogEntry against a previous entry if it exists
    /// NOTE: THIS DOES NOT VERIFY WITNESS PROOFS!
    /// NOTE: You must validate witness proofs separately
    /// Returns validated current-state Parameters and MetaData
    pub fn verify_log_entry(
        &self,
        previous_log_entry: Option<&LogEntry>,
        previous_parameters: Option<&Parameters>,
        previous_meta_data: Option<&MetaData>,
    ) -> Result<(Parameters, MetaData), DIDWebVHError> {
        debug!("Verifiying LogEntry: {}", self.version_id);

        // Ensure we are dealing with a signed LogEntry
        let Some(proof) = &self.proof.first() else {
            return Err(DIDWebVHError::ValidationError(
                "Missing proof in the signed LogEntry!".to_string(),
            ));
        };

        // Ensure the Parameters are correctly setup
        let parameters = match self.parameters.validate(previous_parameters) {
            Ok(params) => params,
            Err(e) => {
                return Err(DIDWebVHError::LogEntryError(format!(
                    "Failed to validate parameters: {e}",
                )));
            }
        };
        debug!("Validated parameters: {parameters:#?}");

        // Ensure that the signed proof key is part of the authorized keys
        if !LogEntry::check_signing_key_authorized(
            &parameters.active_update_keys,
            &proof.verification_method,
        ) {
            warn!(
                "Signing key {} is not authorized",
                &proof.verification_method
            );
            return Err(DIDWebVHError::ValidationError(format!(
                "Signing key ({}) is not authorized",
                &proof.verification_method
            )));
        }

        // Verify Signature
        let verify_doc = LogEntry {
            proof: Vec::new(),
            ..self.clone()
        };

        let verified = verify_data(&verify_doc, None, proof).map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Signature verification failed: {e}"))
        })?;
        if !verified.verified {
            return Err(DIDWebVHError::LogEntryError(
                "Signature verification failed".to_string(),
            ));
        }

        // As a version of this LogEntry gets modified to recalculate hashes,
        // we create a clone once and reuse it for verification
        let mut working_entry = self.clone();
        working_entry.proof.clear();

        // Verify the version ID
        working_entry.verify_version_id(previous_log_entry)?;

        // Validate the version timestamp
        self.verify_version_time(previous_log_entry)?;

        // Do we need to calculate the SCID for the first logEntry?
        if previous_log_entry.is_none() {
            // First LogEntry and we must validate the SCID
            working_entry.verify_scid()?;
        }

        let (created, portable, scid) = if let Some(metadata) = previous_meta_data {
            (
                metadata.created.clone(),
                metadata.portable,
                metadata.scid.clone(),
            )
        } else {
            (
                self.version_time.to_string(),
                parameters.portable.unwrap_or(false),
                parameters.scid.clone().unwrap(),
            )
        };

        debug!("LogEntry {} successfully verified", self.version_id);

        Ok((
            parameters.clone(),
            MetaData {
                version_id: self.version_id.clone(),
                version_time: self.version_time.to_string(),
                created,
                updated: self.version_time.to_string(),
                deactivated: parameters.deactivated,
                portable,
                scid,
                watchers: parameters.watchers,
                witness: parameters.active_witness,
            },
        ))
    }

    /// Ensures that the signing key exists in the currently aothorized keys
    /// Format of authorized keys will be a multikey E.g. z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15
    /// Format of proof_key will be a DID (only supports DID:key)
    /// Returns true if key is authorized or false if not
    fn check_signing_key_authorized(authorized_keys: &[String], proof_key: &str) -> bool {
        if let Some((_, key)) = proof_key.split_once('#') {
            authorized_keys.iter().any(|f| f.as_str() == key)
        } else {
            false
        }
    }

    /// Checks the version ID of a LogEntry against the previous LogEntry
    fn verify_version_id(&mut self, previous: Option<&LogEntry>) -> Result<(), DIDWebVHError> {
        let (current_id, current_hash) = self.get_version_id_fields()?;

        // Check if the version number is incremented correctly
        if let Some(previous) = previous {
            let Some((id, _)) = previous.version_id.split_once('-') else {
                return Err(DIDWebVHError::ValidationError(format!(
                    "versionID ({}) doesn't match format <int>-<hash>",
                    previous.version_id
                )));
            };
            let id = id.parse::<u32>().map_err(|e| {
                DIDWebVHError::ValidationError(format!(
                    "Failed to parse version ID ({id}) as u32: {e}",
                ))
            })?;
            if current_id != id + 1 {
                return Err(DIDWebVHError::ValidationError(format!(
                    "Current LogEntry version ID ({current_id}) must be one greater than previous version ID ({id})",
                )));
            }
            // Set the versionId to the previous versionId to calculate the hash
            self.version_id = previous.version_id.clone();
        } else if current_id != 1 {
            return Err(DIDWebVHError::ValidationError(format!(
                "First LogEntry must have version ID 1, got {current_id}",
            )));
        } else {
            self.version_id = if let Some(scid) = &self.parameters.scid {
                scid.to_string()
            } else {
                return Err(DIDWebVHError::ValidationError(
                    "First LogEntry must have a valid SCID".to_string(),
                ));
            }
        };

        // Validate the entryHash
        let entry_hash = self.generate_log_entry_hash()?;
        if entry_hash != current_hash {
            return Err(DIDWebVHError::ValidationError(format!(
                "Current LogEntry version ID ({current_id}) hash ({current_hash}) does not match calculated hash ({entry_hash})",
            )));
        }

        Ok(())
    }

    /// Verifies everything is ok with the versionTime LogEntry field
    fn verify_version_time(&self, previous: Option<&LogEntry>) -> Result<(), DIDWebVHError> {
        if self.version_time > Utc::now() {
            return Err(DIDWebVHError::ValidationError(format!(
                "versionTime ({}) cannot be in the future",
                self.version_time
            )));
        }

        if let Some(previous) = previous {
            // Current time must be greater than the previous time
            if self.version_time < previous.version_time {
                return Err(DIDWebVHError::ValidationError(format!(
                    "Current versionTime ({}) must be greater than previous versionTime ({})",
                    self.version_time, previous.version_time
                )));
            }
        }

        Ok(())
    }

    /// Verifies that the SCID is correct for the first log entry
    fn verify_scid(&mut self) -> Result<(), DIDWebVHError> {
        self.version_id = SCID_HOLDER.to_string();

        let Some(scid) = self.parameters.scid.clone() else {
            return Err(DIDWebVHError::ValidationError(
                "First LogEntry must have a valid SCID".to_string(),
            ));
        };

        // Convert the SCID value to holder
        let temp = serde_json::to_string(&self).map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Failed to serialize log entry: {e}"))
        })?;

        let scid_entry: LogEntry = serde_json::from_str(&temp.replace(&scid, SCID_HOLDER))
            .map_err(|e| {
                DIDWebVHError::LogEntryError(format!("Failed to deserialize log entry: {e}"))
            })?;

        let verify_scid = scid_entry.generate_scid()?;
        if scid != verify_scid {
            return Err(DIDWebVHError::ValidationError(format!(
                "SCID ({scid}) does not match calculated SCID ({verify_scid})",
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::log_entry::LogEntry;

    #[test]
    fn test_authorized_keys_fail() {
        let authorized_keys: Vec<String> = Vec::new();
        assert!(!LogEntry::check_signing_key_authorized(
            &authorized_keys,
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15#z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }

    #[test]
    fn test_authorized_keys_missing_key_id_fail() {
        let authorized_keys: Vec<String> = Vec::new();
        assert!(!LogEntry::check_signing_key_authorized(
            &authorized_keys,
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }

    #[test]
    fn test_authorized_keys_ok() {
        let authorized_keys: Vec<String> =
            vec!["z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15".to_string()];

        assert!(LogEntry::check_signing_key_authorized(
            &authorized_keys,
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15#z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }
}
