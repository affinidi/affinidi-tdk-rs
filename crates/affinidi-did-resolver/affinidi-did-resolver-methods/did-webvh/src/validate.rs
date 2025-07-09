/*!
*   Highest level validation logic for a webvh entry
*
*   Step 1: Load LogEntries and validate each LogEntry
*   Step 2: Get the highest LogEntry versionId
*   Step 3: Load the Witness proofs and generate Witness State
*   Step 4: Validate LogEntry Witness Proofs against each other
*   Step 5: Fully validated WebVH DID result
*/

use tracing::{debug, warn};

use crate::{
    DIDWebVHError, DIDWebVHState,
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
};

impl DIDWebVHState {
    /// Validate WebVH Data
    /// Validation will stop at the last known good version
    pub fn validate(&mut self) -> Result<(), DIDWebVHError> {
        // Validate each LogEntry
        let mut previous_entry: Option<&LogEntryState> = None;

        let mut deactivated_flag = false;
        for entry in self.log_entries.iter_mut() {
            match entry.verify_log_entry(previous_entry) {
                Ok(()) => (),
                Err(e) => {
                    warn!(
                        "There was an issue with LogEntry: {}! Reason: {e}",
                        entry.log_entry.version_id
                    );
                    warn!("Falling back to last known good LogEntry!");
                    if previous_entry.is_some() {
                        // Return last known good LogEntry
                        break;
                    }
                    return Err(DIDWebVHError::ValidationError(format!(
                        "No valid LogEntry found! Reason: {e}",
                    )));
                }
            }
            // Check if this valid LogEntry has been deactivated, if so then ignore any other
            // Entries
            if entry.metadata.deactivated {
                // Deactivated, return the current LogEntry and MetaData
                deactivated_flag = true;
            }

            // Set the next previous records
            previous_entry = Some(entry);

            if deactivated_flag {
                // If we have a deactivated entry, we stop processing further entries
                break;
            }
        }

        // Cleanup any LogEntries that are after deactivated or invalid after last ok LogEntry
        self.log_entries
            .retain(|entry| entry.validation_status == LogEntryValidationStatus::LogEntryOnly);
        if self.log_entries.is_empty() {
            return Err(DIDWebVHError::ValidationError(
                "No validated LogEntries exist".to_string(),
            ));
        }

        // Step 1: COMPLETED. LogEntries are verified and only contains good Entries

        // Step 2: Get the highest validated version number
        let highest_version_number = self.log_entries.last().unwrap().get_version_number();
        debug!("Latest LogEntry ID = ({})", highest_version_number);

        // Step 3: Recalculate witness proofs based on the highest LogEntry version
        self.witness_proofs
            .generate_proof_state(highest_version_number)?;

        // Step 4: Validate the witness proofs
        for log_entry in self.log_entries.iter_mut() {
            debug!(
                "Witness Proof Validating: {}",
                log_entry.log_entry.version_id
            );
            self.witness_proofs
                .validate_log_entry(log_entry, highest_version_number)?;
            log_entry.validation_status = LogEntryValidationStatus::Ok;
        }

        Ok(())
    }
}
