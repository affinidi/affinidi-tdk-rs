/*!
*   Validating LogEntries using Witness Proofs
*/

use tracing::{debug, warn};

use crate::{DIDWebVHError, log_entry::LogEntry, witness::proofs::WitnessProofCollection};

impl WitnessProofCollection {
    /// Validates if a LogEntry was correctly witnessed
    pub fn validate_log_entry(&mut self, log_entry: &LogEntry) -> Result<bool, DIDWebVHError> {
        // Determine witnesses for this LogEntry
        let Some(Some(witnesses)) = &log_entry.parameters.active_witness else {
            // There are no active witnesses for this LogEntry
            return Ok(true);
        };

        // For each witness, check if there is a proof available
        let mut valid_proofs = 0;
        for w in &witnesses.witnesses {
            let Some((version_id, oldest_id, proof)) = self.witness_version.get(&w.id) else {
                // No proof available for this witness, threshold will catch if too few proofs
                continue;
            };

            let Some((id, _)) = version_id.split_once('-') else {
                return Err(DIDWebVHError::WitnessProofError(format!(
                    "Invalid versionID ({}) in witness proofs! Expected n-hash, but missing n",
                    version_id
                )));
            };
            let Ok(id): Result<usize, _> = str::parse(id) else {
                return Err(DIDWebVHError::WitnessProofError(format!(
                    "Invalid versionID ({}) in witness proofs! expected n-hash, where n is a number!",
                    version_id
                )));
            };

            if oldest_id > &id {
                // This proof is older than the current LogEntry, skip it
                debug!(
                    "LogEntry ({}): Skipping witness proof from {} (oldest: {})",
                    log_entry.version_id, w.id, oldest_id
                );
                continue;
            } else {
                // witness proof is for this verion of the LogEntry
                // Validate the LogEntry against the proof
                log_entry.validate_witness_proof(proof).map_err(|e| {
                    DIDWebVHError::WitnessProofError(format!(
                        "LogEntry ({}): Witness proof validation failed: {}",
                        log_entry.version_id, e
                    ))
                })?;
                valid_proofs += 1;
                debug!(
                    "LogEntry ({}): Witness proof ({}) verified ok",
                    log_entry.version_id, w.id
                );
            }
        }

        if valid_proofs < witnesses.threshold {
            // Not enough valid proofs to consider this LogEntry as witnessed
            warn!(
                "LogEntry ({}): Witness threshold ({}) not met. Only ({} valid proofs!",
                log_entry.version_id, witnesses.threshold, valid_proofs
            );
            Ok(false)
        } else {
            debug!(
                "LogEntry ({}): Witness proofs fully passed",
                log_entry.version_id
            );
            Ok(true)
        }
    }
}
