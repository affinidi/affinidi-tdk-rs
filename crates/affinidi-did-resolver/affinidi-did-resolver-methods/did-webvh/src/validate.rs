/*!
*   Highest level validation logic for a webvh entry
*
*   Step 1: Load LogEntries and validate each LogEntry
*   Step 2: Get the highest LogEntry versionId
*   Step 3: Load the Witness proofs and generate Witness State
*   Step 4: Validate LogEntry Witness Proofs against each other
*   Step 5: Fully validated WebVH DID result
*/

use tracing::debug;

use crate::{
    DIDWebVHError, DIDWebVHState,
    log_entry::{LogEntryState, LogEntryValidationStatus, MetaData},
};

impl DIDWebVHState {
    /// Validate WebVH Data
    /// Validation will stop at the last known good version
    pub fn validate(&mut self) -> Result<(), DIDWebVHError> {
        // Validate each LogEntry
        let mut previous_entry: Option<&LogEntryState> = None;
        let mut previous_metadata: Option<MetaData> = None;

        let mut deactivated_flag = false;
        for entry in self.log_entries.iter_mut() {
            let (validated_parameters, current_metadata) =
                match entry.verify_log_entry(previous_entry, previous_metadata.as_ref()) {
                    Ok((parameters, metadata)) => (parameters, metadata),
                    Err(e) => {
                        if previous_entry.is_some() && previous_metadata.is_some() {
                            // Return last known good LogEntry
                            break;
                        }
                        return Err(DIDWebVHError::ValidationError(format!(
                            "No valid LogEntry found! Reason: {}",
                            e
                        )));
                    }
                };
            entry.validated_parameters = validated_parameters;
            entry.validation_status = LogEntryValidationStatus::LogEntryOnly;

            // Check if this valid LogEntry has been deactivated, if so then ignore any other
            // Entries
            if current_metadata.deactivated {
                // Deactivated, return the current LogEntry and MetaData
                deactivated_flag = true;
            }

            // Set the next previous records
            previous_entry = Some(entry);
            previous_metadata = Some(current_metadata);

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

        Ok(())
    }
}
