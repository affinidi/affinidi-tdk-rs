use serde::{Deserialize, Serialize};

use crate::{
    DIDWebVHError,
    log_entry::{LogEntry, MetaData},
    parameters::Parameters,
};

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
    pub metadata: MetaData,

    /// Integer representing versionId for this LogEntry
    pub version_number: u32,

    /// After validation, parameters that were active at that time are stored here
    pub validated_parameters: Parameters,

    /// Validation status of this record
    pub validation_status: LogEntryValidationStatus,
}

impl LogEntryState {
    /// Validates a LogEntry
    /// NOTE: Does NOT validate witness proofs!
    pub fn verify_log_entry(
        &mut self,
        previous_log_entry: Option<&LogEntryState>,
    ) -> Result<(), DIDWebVHError> {
        if self.validation_status == LogEntryValidationStatus::Ok {
            // already validated
            return Ok(());
        }

        let (parameters, metadata) = self.log_entry.verify_log_entry(
            previous_log_entry.map(|e| &e.log_entry),
            previous_log_entry.map(|e| &e.metadata),
        )?;

        self.validated_parameters = parameters;
        self.metadata = metadata;
        self.validation_status = LogEntryValidationStatus::LogEntryOnly;

        Ok(())
    }

    /// Get the version Number of this LogEntry
    pub fn get_version_number(&self) -> u32 {
        self.version_number
    }
}
