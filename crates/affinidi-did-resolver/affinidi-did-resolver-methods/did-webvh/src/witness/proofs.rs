/*!
*   A webvh that has witnessing enabled requires a proof file containing each witness proof
*/
use affinidi_data_integrity::DataIntegrityProof;
use serde::{Deserialize, Serialize};

use crate::DIDWebVHError;

// *********************************************************
// Witness Proof File
// *********************************************************

/// Array of WitnessProofs for each Witness Proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessProofCollection(pub Vec<WitnessProof>);

/// Record of each LogEntry that requires witnessing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessProof {
    /// versionId of the DID Log Entry to which witness proofs apply.
    pub version_id: String,
    /// Array of DataIntegrity Proofs from each Witness
    pub proof: Vec<DataIntegrityProof>,
}

impl WitnessProofCollection {
    /// Insert a witness proof for a given versionId
    pub fn add_proof(
        &mut self,
        version_id: &str,
        proof: &DataIntegrityProof,
    ) -> Result<(), DIDWebVHError> {
        if let Some(record) = self.0.iter_mut().find(|p| p.version_id == version_id) {
            // versionId already exists
            record.proof.push(proof.to_owned());
        } else {
            // Need to create a new WitnessProof record
            self.0.push(WitnessProof {
                version_id: version_id.to_string(),
                proof: vec![proof.to_owned()],
            });
        }

        Ok(())
    }

    /// Completely remove all proofs relating to a versionId
    pub fn remove_version_id(&mut self, version_id: &str) {
        self.0.retain(|p| p.version_id != version_id);
    }

    /// How many Witness proofs exist for a given versionId
    /// Returns 0 if no proofs exist for that versionId (or not found)
    /// This is a safe fail for how witness proofs are handled
    pub fn get_proof_count(&self, version_id: &str) -> usize {
        self.0
            .iter()
            .find(|p| p.version_id == version_id)
            .map_or(0, |p| p.proof.len())
    }

    pub fn save_to_file(&self, file_path: &str) -> Result<(), DIDWebVHError> {
        let json_data = serde_json::to_string(self).map_err(|e| {
            DIDWebVHError::WitnessProofError(format!(
                "Couldn't serialize Witness Proofs Data: {}",
                e
            ))
        })?;
        std::fs::write(file_path, json_data).map_err(|e| {
            DIDWebVHError::WitnessProofError(format!(
                "Couldn't write to Witness Proofs file ({}): {}",
                file_path, e
            ))
        })?;
        Ok(())
    }
}
