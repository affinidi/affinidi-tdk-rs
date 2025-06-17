/*!
*   Webvh utilizes Log Entries for each version change of the DID Document.
*/
use crate::{DIDWebVHError, parameters::Parameters};
use affinidi_data_integrity::{DataIntegrityProof, GenericDocument};
use multibase::Base;
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer::to_string;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs::OpenOptions, io::Write};
use tracing::debug;

pub mod create;
pub mod read;

/// Each version of the DID gets a new log entry
/// [Log Entries](https://identity.foundation/didwebvh/v1.0/#the-did-log-file)
#[derive(Clone, Debug, Deserialize, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
}

impl LogEntry {
    /// Append a valid LogEntry to a file
    pub fn save_to_file(&self, file_path: &str) -> Result<(), DIDWebVHError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
            .map_err(|e| {
                DIDWebVHError::LogEntryError(format!("Couldn't open file {}: {}", file_path, e))
            })?;

        file.write_all(
            serde_json::to_string(self)
                .map_err(|e| {
                    DIDWebVHError::LogEntryError(format!(
                        "Couldn't serialize LogEntry to JSON. Reason: {}",
                        e
                    ))
                })?
                .as_bytes(),
        )
        .map_err(|e| {
            DIDWebVHError::LogEntryError(format!(
                "Couldn't append LogEntry to file({}). Reason: {}",
                file_path, e
            ))
        })?;
        file.write_all("\n".as_bytes()).map_err(|e| {
            DIDWebVHError::LogEntryError(format!(
                "Couldn't append LogEntry to file({}). Reason: {}",
                file_path, e
            ))
        })?;

        Ok(())
    }

    /// Generates a SCID from a preliminary LogEntry
    /// This only needs to be called once when the DID is first created.
    fn generate_scid(&self) -> Result<String, DIDWebVHError> {
        self.generate_log_entry_hash().map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate SCID from preliminary LogEntry. Reason: {}",
                e
            ))
        })
    }

    /// Calculates a Log Entry hash
    pub fn generate_log_entry_hash(&self) -> Result<String, DIDWebVHError> {
        let jcs = to_string(self).map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate JCS from LogEntry. Reason: {}",
                e
            ))
        })?;
        debug!("JCS for LogEntry hash: {}", jcs);

        // SHA_256 code = 0x12, length of SHA256 is 32 bytes
        let hash_encoded = Multihash::<32>::wrap(0x12, Sha256::digest(jcs.as_bytes()).as_slice())
            .map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't create multihash encoding for LogEntry. Reason: {}",
                e
            ))
        })?;

        Ok(multibase::encode(Base::Base58Btc, hash_encoded.to_bytes()))
    }
}

/// Converts a log entry to the Signing Document format.
impl TryFrom<&LogEntry> for GenericDocument {
    type Error = DIDWebVHError;

    fn try_from(log_entry: &LogEntry) -> Result<Self, Self::Error> {
        let mut generic = GenericDocument {
            extra: HashMap::new(),
            proof: log_entry.proof.clone(),
        };

        generic.extra.insert(
            "versionId".to_string(),
            log_entry.version_id.to_owned().into(),
        );

        generic.extra.insert(
            "versionTime".to_string(),
            log_entry.version_time.to_owned().into(),
        );

        generic.extra.insert(
            "parameters".to_string(),
            serde_json::to_value(&log_entry.parameters).map_err(|e| {
                DIDWebVHError::ParametersError(format!(
                    "Couldn't serialize Paramaters to JSON Value: {}",
                    e
                ))
            })?,
        );

        generic
            .extra
            .insert("state".to_string(), log_entry.state.clone());

        // If proof already exists in the document, then add it to extra as a signature will be
        // created from it
        if let Some(proof) = &log_entry.proof {
            generic.extra.insert(
                "proof".to_string(),
                serde_json::to_value(proof).map_err(|e| {
                    DIDWebVHError::LogEntryError(format!(
                        "Couldn't serialize Data Integrity Proof to JSON Value: {}",
                        e
                    ))
                })?,
            );
        }

        Ok(generic)
    }
}
