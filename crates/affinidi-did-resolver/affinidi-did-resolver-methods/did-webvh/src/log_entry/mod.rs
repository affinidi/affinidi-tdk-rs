/*!
*   Webvh utilizes Log Entries for each version change of the DID Document.
*/
use crate::{DIDWebVHError, parameters::Parameters, witness::Witnesses};
use affinidi_data_integrity::{
    DataIntegrityProof, SignedDocument, SigningDocument, verification_proof::verify_data,
};
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

/// Tracks validation status of a LogEntry
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum LogEntryValidationStatus {
    /// LogEntry failed validation
    Invalid(String),
    /// Validation process has NOT started yet
    #[default]
    NotValidated,
    /// LogEntry has been validated (step 1 of 2)
    LogEntryOnly,
    /// Witness Proof for this LogEntry has been validated (step 2 of 2)
    WitnessProof,
    /// LogEntry has been fully Validated
    Ok,
}

/// Manages state relating to a LogEntry during validation
#[derive(Debug)]
pub struct LogEntryState {
    /// webvh LogEntry record
    pub log_entry: LogEntry,

    /// MetaData for this LogEntry record
    pub meta_data: MetaData,

    /// Integer representing versionId for this LogEntry
    pub version_number: usize,

    /// After validation, parameters that were active at that time are stored here
    pub validated_parameters: Parameters,

    /// Validation status of this record
    pub validation_status: LogEntryValidationStatus,
}

impl LogEntryState {
    pub fn verify_log_entry(
        &self,
        previous_log_entry: Option<&LogEntryState>,
        previous_meta_data: Option<&MetaData>,
    ) -> Result<(Parameters, MetaData), DIDWebVHError> {
        self.log_entry
            .verify_log_entry(previous_log_entry.map(|e| &e.log_entry), previous_meta_data)
    }

    pub fn get_version_number(&self) -> usize {
        self.version_number
    }
}

/// Resolved Document MetaData
/// Returned as reolved Document MetaData on a successful resolve
#[derive(Clone, Debug, Serialize, Deserialize)]
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

    pub fn validate_witness_proof(
        &self,
        witness_proof: &DataIntegrityProof,
    ) -> Result<bool, DIDWebVHError> {
        // Create a SigningDocument from the LogEntry
        let mut signing_doc: SignedDocument = self.try_into()?;
        signing_doc.proof = Some(witness_proof.clone());
        signing_doc.extra.insert(
            "proof".to_string(),
            serde_json::to_value(&self.proof).map_err(|e| {
                DIDWebVHError::ParametersError(format!(
                    "Couldn't serialize LogEntry Proof to JSON Value: {}",
                    e
                ))
            })?,
        );

        // Verify the Data Integrity Proof against the Signing Document
        verify_data(&signing_doc).map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Data Integrity Proof verification failed: {}", e))
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
}

/// Converts a log entry to the Signing Document format.
/// Allowing a LogEntry to be signed
impl TryFrom<&LogEntry> for SigningDocument {
    type Error = DIDWebVHError;

    fn try_from(log_entry: &LogEntry) -> Result<Self, Self::Error> {
        let mut signing = SigningDocument {
            extra: HashMap::new(),
            proof: None,
        };

        signing.extra.insert(
            "versionId".to_string(),
            log_entry.version_id.to_owned().into(),
        );

        signing.extra.insert(
            "versionTime".to_string(),
            log_entry.version_time.to_owned().into(),
        );

        signing.extra.insert(
            "parameters".to_string(),
            serde_json::to_value(&log_entry.parameters).map_err(|e| {
                DIDWebVHError::ParametersError(format!(
                    "Couldn't serialize Paramaters to JSON Value: {}",
                    e
                ))
            })?,
        );

        signing
            .extra
            .insert("state".to_string(), log_entry.state.clone());

        // If proof already exists in the document, then add it to extra as a signature will be
        // created from it
        if let Some(proof) = &log_entry.proof {
            signing.extra.insert(
                "proof".to_string(),
                serde_json::to_value(proof).map_err(|e| {
                    DIDWebVHError::LogEntryError(format!(
                        "Couldn't serialize Data Integrity Proof to JSON Value: {}",
                        e
                    ))
                })?,
            );
        }

        Ok(signing)
    }
}

/// Converts a signed log entry to the Signed Document format.
/// Allowing a LogEntry to be verified
impl TryFrom<&LogEntry> for SignedDocument {
    type Error = DIDWebVHError;

    fn try_from(log_entry: &LogEntry) -> Result<Self, Self::Error> {
        let mut signing = SignedDocument {
            extra: HashMap::new(),
            proof: log_entry.proof.clone(),
        };

        signing.extra.insert(
            "versionId".to_string(),
            log_entry.version_id.to_owned().into(),
        );

        signing.extra.insert(
            "versionTime".to_string(),
            log_entry.version_time.to_owned().into(),
        );

        signing.extra.insert(
            "parameters".to_string(),
            serde_json::to_value(&log_entry.parameters).map_err(|e| {
                DIDWebVHError::ParametersError(format!(
                    "Couldn't serialize Paramaters to JSON Value: {}",
                    e
                ))
            })?,
        );

        signing
            .extra
            .insert("state".to_string(), log_entry.state.clone());

        Ok(signing)
    }
}
