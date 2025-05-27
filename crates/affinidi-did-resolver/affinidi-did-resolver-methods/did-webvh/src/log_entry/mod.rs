/*!
*   Webvh utilizes Log Entries for each version change of the DID Document.
*/
use affinidi_data_integrity::DataIntegrityProof;
use chrono::Utc;
use multibase::Base;
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer::to_string;
use sha2::{Digest, Sha256};

use crate::{DIDWebVHError, SCID_HOLDER, parameters::Parameters};

/// Each version of the DID gets a new log entry
/// [Log Entries](https://identity.foundation/didwebvh/v1.0/#the-did-log-file)
#[derive(Debug, Deserialize, Serialize)]
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
    /// Creates and resturns the first webvh log Entry.
    /// Generates the SCID and Data Integrity proof
    ///
    /// Inputs:
    /// - version_time: Optional ISO 8601 date string, If not given, defaults to now.
    ///
    /// Returns:
    /// - A valid Log Entry
    pub fn create_first_entry(
        version_time: Option<String>,
        document: &Value,
        parameters: &Parameters,
    ) -> Result<LogEntry, DIDWebVHError> {
        let now = Utc::now();

        // Ensure SCID field is set correctly
        let mut parameters = parameters.clone();
        parameters.scid = Some(SCID_HOLDER.to_string());

        let log_entry = LogEntry {
            version_id: SCID_HOLDER.to_string(),
            version_time: version_time
                .unwrap_or_else(|| now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            parameters,
            state: document.clone(),
            proof: None,
        };

        // Create the SCID from the first log entry
        let scid = log_entry.generate_scid()?;

        // Replace all instances of {SCID} with the actual SCID
        let le_str = serde_json::to_string(&log_entry).map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't serialize LogEntry to JSON. Reason: {}",
                e
            ))
        })?;

        println!("{}", &le_str);
        println!();
        println!(" ******************* ");
        println!();
        println!("{}", &le_str.replace(SCID_HOLDER, &scid));
        let mut log_entry: LogEntry = serde_json::from_str(&le_str.replace(SCID_HOLDER, &scid))
            .map_err(|e| {
                DIDWebVHError::SCIDError(format!(
                    "Couldn't deserialize LogEntry from SCID conversion. Reason: {}",
                    e
                ))
            })?;

        // Create the entry hash for this Log Entry
        let entry_hash = log_entry.generate_scid().map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate SCID for first LogEntry. Reason: {}",
                e
            ))
        })?;

        log_entry.version_id = ["1-", &entry_hash].concat();

        Ok(log_entry)
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
