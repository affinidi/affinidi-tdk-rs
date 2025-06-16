/*!
*  Reads a JSON Log file, all functions related to reading and verifying Log Entries are here
*/

use super::LogEntry;
use crate::{DIDWebVHError, MetaData, SCID_HOLDER, parameters::Parameters};
use affinidi_data_integrity::verification_proof::verify_data;
use chrono::{DateTime, Utc};
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
    /// version_id: Must match the full versionId (1-z6M....)
    /// version_ number: Will only match on the leading integer of versionId
    /// version_time: Will match on a Version where the query_time is when that LogEntry was active
    pub fn get_log_entry_from_file<P>(
        file_path: P,
        version_id: Option<&str>,
        version_number: Option<u32>,
        version_time: Option<&DateTime<Utc>>,
    ) -> Result<(LogEntry, MetaData), DIDWebVHError>
    where
        P: AsRef<Path>,
    {
        if let Ok(lines) = LogEntry::read_from_json_file(file_path) {
            let mut previous_log_entry: Option<LogEntry> = None;
            let mut previous_metadata: Option<MetaData> = None;
            for line in lines.map_while(Result::ok) {
                let mut log_entry: LogEntry = serde_json::from_str(&line).map_err(|e| {
                    DIDWebVHError::LogEntryError(format!("Failed to deserialize log entry: {}", e))
                })?;
                let (validated_parameters, current_metadata) = match log_entry
                    .verify_log_entry(previous_log_entry.as_ref(), previous_metadata.as_ref())
                {
                    Ok((parameters, metadata)) => (parameters, metadata),
                    Err(e) => {
                        if let Some(log_entry) = previous_log_entry {
                            if let Some(metadata) = previous_metadata {
                                // Return last known good LogEntry
                                return Ok((log_entry, metadata));
                            }
                        }
                        return Err(DIDWebVHError::ValidationError(format!(
                            "No valid LogEntry found! Reason: {}",
                            e
                        )));
                    }
                };
                log_entry.parameters = validated_parameters;

                // Check if this valid LogEntry has been deactivated, if so then ignore any other
                // Entries
                if current_metadata.deactivated {
                    // Deactivated, return the current LogEntry and MetaData
                    return Ok((log_entry, current_metadata));
                }

                // Check if we are looking for this version-id
                if let Some(version_id) = version_id {
                    if current_metadata.version_id == version_id {
                        // Found the query version versionID
                        return Ok((log_entry, current_metadata));
                    }
                }

                // Check Version number
                if let Some(version_number) = version_number {
                    // Check if the version_id starts with the version_number
                    if let Some((id, _)) = current_metadata.version_id.split_once('-') {
                        if let Ok(id) = id.parse::<u32>() {
                            if id == version_number {
                                // Found the query version number
                                return Ok((log_entry, current_metadata));
                            }
                        }
                    }
                }

                // Check if this log_entry is older than the version_time
                // if so, then return the previous info
                if let Some(version_time) = version_time {
                    let current_time: DateTime<Utc> =
                        current_metadata.version_time.parse().unwrap();
                    let create_time: DateTime<Utc> = current_metadata.created.parse().unwrap();

                    // Is the query versionTime in the range of this LogEntry?
                    if (&create_time < version_time) && (&current_time > version_time) {
                        return Ok((log_entry, current_metadata));
                    }
                }

                // Set the next previous records
                previous_log_entry = Some(log_entry);
                previous_metadata = Some(current_metadata);
            }

            // End of file
            if let Some(log_entry) = previous_log_entry {
                if let Some(metadata) = previous_metadata {
                    // If a specific version was requested, then return NotFound
                    if version_id.is_some() || version_number.is_some() {
                        return Err(DIDWebVHError::NotFound);
                    }

                    // Return last known good LogEntry
                    return Ok((log_entry, metadata));
                }
            }
            Err(DIDWebVHError::ValidationError(
                "Empty LogEntry returned for DID".to_string(),
            ))
        } else {
            Err(DIDWebVHError::LogEntryError(
                "Failed to read log entry from file".to_string(),
            ))
        }
    }

    /// Verify a LogEntry against a previous entry if it exists
    /// Returns validated current-state Parameters and MetaData
    pub fn verify_log_entry(
        &self,
        previous_log_entry: Option<&LogEntry>,
        previous_meta_data: Option<&MetaData>,
    ) -> Result<(Parameters, MetaData), DIDWebVHError> {
        // Ensure we are dealing with a signed LogEntry
        let Some(proof) = &self.proof else {
            return Err(DIDWebVHError::ValidationError(
                "Missing proof in the signed LogEntry!".to_string(),
            ));
        };

        // Ensure the Parameters are correctly setup
        let parameters = match self
            .parameters
            .validate(previous_log_entry.map(|p| &p.parameters))
        {
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
                self.version_time.clone(),
                parameters.portable.unwrap_or(false),
                parameters.scid.clone().unwrap(),
            )
        };

        Ok((
            parameters.clone(),
            MetaData {
                version_id: self.version_id.clone(),
                version_time: self.version_time.clone(),
                created,
                updated: self.version_time.clone(),
                deactivated: parameters.deactivated,
                portable,
                scid,
                watchers: if let Some(Some(watchers)) = parameters.watchers {
                    Some(watchers)
                } else {
                    None
                },
                witness: if let Some(Some(witnesses)) = parameters.active_witness {
                    Some(witnesses)
                } else {
                    None
                },
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
    pub(crate) fn get_version_id_fields(version_id: &str) -> Result<(u32, String), DIDWebVHError> {
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
