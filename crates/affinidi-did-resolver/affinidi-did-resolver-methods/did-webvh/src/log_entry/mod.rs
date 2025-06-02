/*!
*   Webvh utilizes Log Entries for each version change of the DID Document.
*/
use crate::{DIDWebVHError, SCID_HOLDER, parameters::Parameters};
use affinidi_data_integrity::DataIntegrityProof;
use affinidi_secrets_resolver::secrets::Secret;
use chrono::Utc;
use multibase::Base;
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer::to_string;
use sha2::{Digest, Sha256};

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
    /// Creates and resturns the first webvh log Entry.
    /// Generates the SCID and Data Integrity proof
    ///
    /// Inputs:
    /// - version_time: Optional ISO 8601 date string, If not given, defaults to now.
    /// - document: The DID Document as a JSON Value.
    /// - parameters: The Parameters for the Log Entry.
    /// - secret: The Secret used to sign the Log Entry.
    ///
    /// Returns:
    /// - A valid Log Entry
    pub async fn create_first_entry(
        version_time: Option<String>,
        document: &Value,
        parameters: &Parameters,
        secret: &Secret,
    ) -> Result<LogEntry, DIDWebVHError> {
        let now = Utc::now();

        // Ensure SCID field is set correctly
        let mut parameters = parameters.clone();
        parameters.scid = Some(SCID_HOLDER.to_string());

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
        if secret.id != vm_id {
            return Err(DIDWebVHError::SCIDError(format!(
                "Secret key ID {} does not match VerificationMethod ID {}",
                secret.id, vm_id
            )));
        }

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

        let mut log_entry: LogEntry = serde_json::from_str(&le_str.replace(SCID_HOLDER, &scid))
            .map_err(|e| {
                DIDWebVHError::SCIDError(format!(
                    "Couldn't deserialize LogEntry from SCID conversion. Reason: {}",
                    e
                ))
            })?;

        // Create the entry hash for this Log Entry
        let entry_hash = log_entry.generate_log_entry_hash().map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate entryHash for first LogEntry. Reason: {}",
                e
            ))
        })?;

        log_entry.version_id = ["1-", &entry_hash].concat();

        // Generate the proof for the log entry
        let log_entry_values = serde_json::to_value(&log_entry).map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't convert LogEntry to JSON Values for Signing. Reason: {}",
                e
            ))
        })?;

        let log_entry = serde_json::from_value(
            DataIntegrityProof::sign_data_jcs(
                &serde_json::from_value(log_entry_values).map_err(|e| {
                    DIDWebVHError::SCIDError(format!(
                        "Couldn't convert LogEntry to JSON Values for Signing. Reason: {}",
                        e
                    ))
                })?,
                &vm_id,
                secret,
            )
            .map_err(|e| {
                DIDWebVHError::SCIDError(format!(
                    "Couldn't generate Data Integrity Proof for LogEntry. Reason: {}",
                    e
                ))
            })?,
        )
        .map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't deserialize signed LogEntry. Reason: {}",
                e
            ))
        })?;
        Ok(log_entry)
    }

    /// Generates a SCID from a preliminary LogEntry
    /// This only needs to be called once when the DID is first created.
    fn generate_scid(&self) -> Result<String, DIDWebVHError> {
        println!("TIMTAM:\n{}", serde_json::to_string_pretty(self).unwrap());
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

    /// Takes a LogEntry and creates a new set of LogEntries to revoke the webvh DID
    /// Returns one or more Log Entries
    /// NOTE: May return more than a single log entry if updateKeys need to be revoked first.
    pub fn revoke(&self) -> Result<Vec<LogEntry>, DIDWebVHError> {
        let mut revoked_entry: LogEntry = self.clone();
        revoked_entry.proof = None;
        revoked_entry.parameters.deactivated = true;
        revoked_entry.parameters.update_keys = Some(None);
        Ok(Vec::new())
    }
}
