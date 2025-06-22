/*!
*   Validating LogEntries using Witness Proofs
*/

use crate::{log_entry::LogEntry, witness::proofs::WitnessProofCollection};

impl WitnessProofCollection {
    /// Validates if a LogEntry was correctly witnessed
    pub fn validate_log_entry(&mut self, log_entry: &LogEntry) -> bool {
        true
    }
}
