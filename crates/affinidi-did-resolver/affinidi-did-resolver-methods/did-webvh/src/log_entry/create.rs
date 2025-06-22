/*!
*   Methods relatings to creating a new LogEntry
*/
use crate::{DIDWebVHError, SCID_HOLDER, log_entry::LogEntry, parameters::Parameters};
use affinidi_data_integrity::{DataIntegrityProof, SigningDocument};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::Utc;
use serde_json::Value;

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

        let mut log_entry_unsigned: SigningDocument = (&log_entry).try_into()?;

        DataIntegrityProof::sign_jcs_data(&mut log_entry_unsigned, secret).map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate Data Integrity Proof for LogEntry. Reason: {}",
                e
            ))
        })?;

        log_entry.proof = log_entry_unsigned.proof;

        Ok(log_entry)
    }

    /// Takes an existing LogEntry and creates a new LogEntry from it
    pub async fn create_new_log_entry(
        previous_log_entry: &LogEntry,
        version_time: Option<String>,
        document: &Value,
        parameters: &Parameters,
        secret: &Secret,
    ) -> Result<LogEntry, DIDWebVHError> {
        let mut new_entry = LogEntry {
            version_id: previous_log_entry.version_id.clone(),
            version_time: version_time
                .unwrap_or_else(|| Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            parameters: parameters.clone(),
            state: document.clone(),
            proof: None,
        };

        // Create the entry hash for this Log Entry
        let entry_hash = new_entry.generate_log_entry_hash().map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate entryHash for LogEntry. Reason: {}",
                e
            ))
        })?;

        // Increment the version-id
        let (current_id, _) = new_entry.get_version_id_fields()?;
        new_entry.version_id = [&(current_id + 1).to_string(), "-", &entry_hash].concat();

        // Generate the proof for the log entry
        let mut log_entry_unsigned: SigningDocument = (&new_entry).try_into()?;

        DataIntegrityProof::sign_jcs_data(&mut log_entry_unsigned, secret).map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate Data Integrity Proof for LogEntry. Reason: {}",
                e
            ))
        })?;

        new_entry.proof = log_entry_unsigned.proof;

        Ok(new_entry)
    }
}
