/*!
*   Webvh utilizes Log Entries for each version change of the DID Document.
*/
use crate::{DIDWebVHError, parameters::Parameters, witness::Witnesses};
use affinidi_data_integrity::{DataIntegrityProof, verification_proof::verify_data};
use base58::ToBase58;
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use serde_json_canonicalizer::to_string;
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, io::Write};
use tracing::debug;

pub mod read;

/// Resolved Document MetaData
/// Returned as reolved Document MetaData on a successful resolve
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaData {
    pub version_id: String,
    pub version_time: String,
    pub created: String,
    pub updated: String,
    pub scid: String,
    pub portable: bool,
    pub deactivated: bool,
    pub witness: Option<Witnesses>,
    pub watchers: Option<Vec<String>>,
}

/// Each version of the DID gets a new log entry
/// [Log Entries](https://identity.foundation/didwebvh/v1.0/#the-did-log-file)
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// format integer-prev_hash
    pub version_id: String,

    /// ISO 8601 date format
    pub version_time: String,

    /// configuration options from the controller
    pub parameters: Parameters,

    /// DID document
    pub state: Value,

    /// Data Integrity Proof
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof: Vec<DataIntegrityProof>,
}

impl LogEntry {
    /// Append a valid LogEntry to a file
    pub fn save_to_file(&self, file_path: &str) -> Result<(), DIDWebVHError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
            .map_err(|e| {
                DIDWebVHError::LogEntryError(format!("Couldn't open file {file_path}: {e}"))
            })?;

        file.write_all(
            serde_json::to_string(self)
                .map_err(|e| {
                    DIDWebVHError::LogEntryError(format!(
                        "Couldn't serialize LogEntry to JSON. Reason: {e}",
                    ))
                })?
                .as_bytes(),
        )
        .map_err(|e| {
            DIDWebVHError::LogEntryError(format!(
                "Couldn't append LogEntry to file({file_path}). Reason: {e}",
            ))
        })?;
        file.write_all("\n".as_bytes()).map_err(|e| {
            DIDWebVHError::LogEntryError(format!(
                "Couldn't append LogEntry to file({file_path}). Reason: {e}",
            ))
        })?;

        Ok(())
    }

    /// Generates a SCID from a preliminary LogEntry
    /// This only needs to be called once when the DID is first created.
    pub(crate) fn generate_scid(&self) -> Result<String, DIDWebVHError> {
        self.generate_log_entry_hash().map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate SCID from preliminary LogEntry. Reason: {e}",
            ))
        })
    }

    /// Calculates a Log Entry hash
    pub fn generate_log_entry_hash(&self) -> Result<String, DIDWebVHError> {
        let jcs = to_string(self).map_err(|e| {
            DIDWebVHError::SCIDError(format!("Couldn't generate JCS from LogEntry. Reason: {e}",))
        })?;
        debug!("JCS for LogEntry hash: {}", jcs);

        // SHA_256 code = 0x12, length of SHA256 is 32 bytes
        let hash_encoded = Multihash::<32>::wrap(0x12, Sha256::digest(jcs.as_bytes()).as_slice())
            .map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't create multihash encoding for LogEntry. Reason: {e}",
            ))
        })?;
        Ok(hash_encoded.to_bytes().to_base58())
    }

    pub fn validate_witness_proof(
        &self,
        witness_proof: &DataIntegrityProof,
    ) -> Result<bool, DIDWebVHError> {
        // Verify the Data Integrity Proof against the Signing Document
        verify_data(&json!({"versionId": &self.version_id}), None, witness_proof).map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Data Integrity Proof verification failed: {e}"))
        })?;

        Ok(true)
    }

    /// Splits the version number and the version hash for a DID versionId
    pub fn get_version_id_fields(&self) -> Result<(u32, String), DIDWebVHError> {
        LogEntry::parse_version_id_fields(&self.version_id)
    }

    /// Splits the version number and the version hash for a DID versionId
    pub fn parse_version_id_fields(version_id: &str) -> Result<(u32, String), DIDWebVHError> {
        let Some((id, hash)) = version_id.split_once('-') else {
            return Err(DIDWebVHError::ValidationError(format!(
                "versionID ({version_id}) doesn't match format <int>-<hash>",
            )));
        };
        let id = id.parse::<u32>().map_err(|e| {
            DIDWebVHError::ValidationError(
                format!("Failed to parse version ID ({id}) as u32: {e}",),
            )
        })?;
        Ok((id, hash.to_string()))
    }
}
