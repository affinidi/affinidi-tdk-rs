/*!
*  Reads a JSON Log file, all functions related to reading and verifying Log Entries are here
*/

use affinidi_data_integrity::verification_proof::verify_data;
use ahash::HashSet;
use chrono::{DateTime, Utc};

use super::LogEntry;
use crate::{DIDWebVHError, SCID_HOLDER, parameters::Parameters};
use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
};

impl LogEntry {
    /// Reads a JSON Log file and returns an iterator over the lines in the file.
    fn read_from_json_file<P>(file_path: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where
        P: AsRef<Path>,
    {
        let file = File::open(file_path)?;
        Ok(io::BufReader::new(file).lines())
    }

    /// Get either latest LogEntry or the specific version if specified.
    pub fn get_log_entry_from_file<P>(
        file_path: P,
        version: Option<u32>,
    ) -> Result<LogEntry, DIDWebVHError>
    where
        P: AsRef<Path>,
    {
        if let Ok(lines) = LogEntry::read_from_json_file(file_path) {
            let mut previous: Option<LogEntry> = None;
            for line in lines.map_while(Result::ok) {
                let log_entry: LogEntry = serde_json::from_str(&line).map_err(|e| {
                    DIDWebVHError::LogEntryError(format!("Failed to deserialize log entry: {}", e))
                })?;
                log_entry.verify_log_entry(previous.as_ref())?;

                previous = Some(log_entry);
            }
        }

        Err(DIDWebVHError::LogEntryError(
            "Failed to read log entry from file".to_string(),
        ))
    }

    pub fn verify_log_entry(
        &self,
        previous: Option<&LogEntry>,
    ) -> Result<Parameters, DIDWebVHError> {
        // Ensure we are dealing with a signed LogEntry
        let Some(proof) = &self.proof else {
            return Err(DIDWebVHError::ValidationError(
                "Missing proof in the signed LogEntry!".to_string(),
            ));
        };

        // Ensure the Parameters are correctly setup
        let parameters = match self.parameters.validate(previous.map(|p| &p.parameters)) {
            Ok(params) => params,
            Err(e) => {
                return Err(DIDWebVHError::LogEntryError(format!(
                    "Failed to validate parameters: {}",
                    e
                )));
            }
        };

        // Ensure that the signed proof key is part of the authorized keys
        if !LogEntry::check_signing_key_authorized(
            &parameters.active_update_keys,
            &proof.verification_method,
        ) {
            return Err(DIDWebVHError::ValidationError(format!(
                "Signing key ({}) is not authorized",
                &proof.verification_method
            )));
        }

        // Verify Signature
        let values = serde_json::to_value(self).map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Failed to serialize log entry: {}", e))
        })?;

        let verified = verify_data(&serde_json::from_value(values).map_err(|e| {
            DIDWebVHError::LogEntryError(format!(
                "Failed to convert log entry to GenericDocument: {}",
                e
            ))
        })?)
        .map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Signature verification failed: {}", e))
        })?;
        if !verified.verified {
            return Err(DIDWebVHError::LogEntryError(
                "Signature verification failed".to_string(),
            ));
        }

        // As a version of this LogEntry gets modified to reclaculate hashes,
        // we create a clone once and reuse it for verification
        let mut working_entry = self.clone();
        working_entry.proof = None; // Remove proof for hash calculation

        // Handle Witness verification
        // This could be done async?
        // TODO: Implement Witness verification

        // Verify the version ID
        working_entry.verify_version_id(previous)?;

        // Validate the version timestamp
        self.verify_version_time(previous)?;

        // Do we need to calculate the SCID for the first logEntry?
        if previous.is_none() {
            // First LogEntry and we must validate the SCID
            working_entry.verify_scid()?;
        }

        Ok(parameters)
    }

    /// Ensures that the signing key exists in the currently aothorized keys
    /// Format of authorized keys will be a multikey E.g. z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15
    /// Format of proof_key will be a DID (only supports DID:key)
    /// Returns true if key is authorized or false if not
    fn check_signing_key_authorized(authorized_keys: &HashSet<String>, proof_key: &str) -> bool {
        if let Some((_, key)) = proof_key.split_once('#') {
            authorized_keys.contains(key)
        } else {
            false
        }
    }

    /// Checks the version ID of a LogEntry against the previous LogEntry
    fn verify_version_id(&mut self, previous: Option<&LogEntry>) -> Result<(), DIDWebVHError> {
        let (current_id, current_hash) = LogEntry::get_version_id_fields(&self.version_id)?;

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
                    "Failed to parse version ID ({}) as u32: {}",
                    id, e
                ))
            })?;
            if current_id != id + 1 {
                return Err(DIDWebVHError::ValidationError(format!(
                    "Current LogEntry version ID ({}) must be one greater than previous version ID ({})",
                    current_id, id
                )));
            }
            // Set the versionId to the previous versionId to calculate the hash
            self.version_id = previous.version_id.clone();
        } else if current_id != 1 {
            return Err(DIDWebVHError::ValidationError(format!(
                "First LogEntry must have version ID 1, got {}",
                current_id
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
                "Current LogEntry version ID ({}) hash ({}) does not match calculated hash ({})",
                current_id, current_hash, entry_hash
            )));
        }

        Ok(())
    }

    /// Splits the version number and the version hash for a DID versionId
    fn get_version_id_fields(version_id: &str) -> Result<(u32, String), DIDWebVHError> {
        let Some((id, hash)) = version_id.split_once('-') else {
            return Err(DIDWebVHError::ValidationError(format!(
                "versionID ({}) doesn't match format <int>-<hash>",
                version_id
            )));
        };
        let id = id.parse::<u32>().map_err(|e| {
            DIDWebVHError::ValidationError(format!(
                "Failed to parse version ID ({}) as u32: {}",
                id, e
            ))
        })?;
        Ok((id, hash.to_string()))
    }

    /// Verifies everything is ok with the versionTime LogEntry field
    fn verify_version_time(&self, previous: Option<&LogEntry>) -> Result<(), DIDWebVHError> {
        let current_time = self.version_time.parse::<DateTime<Utc>>().map_err(|e| {
            DIDWebVHError::ValidationError(format!(
                "Failed to parse versionTime ({}) as DateTime<Utc>: {}",
                self.version_time, e
            ))
        })?;

        if current_time > Utc::now() {
            return Err(DIDWebVHError::ValidationError(format!(
                "versionTime ({}) cannot be in the future",
                self.version_time
            )));
        }

        if let Some(previous) = previous {
            // Current time must be greater than the previous time
            let previous_time = previous
                .version_time
                .parse::<DateTime<Utc>>()
                .map_err(|e| {
                    DIDWebVHError::ValidationError(format!(
                        "Failed to parse previous versionTime ({}) as DateTime<Utc>: {}",
                        self.version_time, e
                    ))
                })?;

            if current_time < previous_time {
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
            DIDWebVHError::LogEntryError(format!("Failed to serialize log entry: {}", e))
        })?;

        let scid_entry: LogEntry = serde_json::from_str(&temp.replace(&scid, SCID_HOLDER))
            .map_err(|e| {
                DIDWebVHError::LogEntryError(format!("Failed to deserialize log entry: {}", e))
            })?;

        println!("{}", serde_json::to_string_pretty(&scid_entry).unwrap());
        let verify_scid = scid_entry.generate_scid()?;
        if scid != verify_scid {
            return Err(DIDWebVHError::ValidationError(format!(
                "SCID ({}) does not match calculated SCID ({})",
                scid, verify_scid
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ahash::{HashSet, HashSetExt};

    use crate::log_entry::LogEntry;

    #[test]
    fn test_authorized_keys_fail() {
        let authorized_keys: HashSet<String> = HashSet::new();
        assert!(!LogEntry::check_signing_key_authorized(
            &authorized_keys,
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15#z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }

    #[test]
    fn test_authorized_keys_missing_key_id_fail() {
        let authorized_keys: HashSet<String> = HashSet::new();
        assert!(!LogEntry::check_signing_key_authorized(
            &authorized_keys,
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }

    #[test]
    fn test_authorized_keys_ok() {
        let mut authorized_keys: HashSet<String> = HashSet::new();
        authorized_keys.insert("z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15".to_string());

        assert!(LogEntry::check_signing_key_authorized(
            &authorized_keys,
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15#z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }
}
