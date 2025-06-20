/*!
*   A webvh that has witnessing enabled requires a proof file containing each witness proof
*
*   When saving or serializing the Witness Proofs, you should run `optimise_records` first
*   THis will ensure that previous witness proof records have been removed
*/
use std::fs::File;

use crate::DIDWebVHError;
use affinidi_data_integrity::DataIntegrityProof;
use ahash::{HashMap, HashMapExt};
use serde::{Deserialize, Serialize};
use tracing::warn;

// *********************************************************
// Witness Proof File
// *********************************************************

/// Array of WitnessProofs for each Witness Proof
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WitnessProofCollection(Vec<WitnessProof>);

/// Record of each LogEntry that requires witnessing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

    /// Load existing proofs from a file
    pub fn read_from_file(file_path: &str) -> Result<Self, DIDWebVHError> {
        let file = File::open(file_path).map_err(|e| {
            DIDWebVHError::WitnessProofError(format!(
                "Couldn't open Witness Proofs file ({}): {}",
                file_path, e
            ))
        })?;
        let proofs: WitnessProofCollection = serde_json::from_reader(file).map_err(|e| {
            DIDWebVHError::WitnessProofError(format!(
                "Couldn't deserialize Witness Proofs Data from file ({}): {}",
                file_path, e
            ))
        })?;
        Ok(proofs)
    }

    /// Save proofs to a file
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

    /// Get WitnessProof record for a given version_id
    pub fn get_proofs(&self, version_id: &str) -> Option<&WitnessProof> {
        self.0.iter().find(|p| p.version_id == version_id)
    }

    /// Runs through and removes wtiness proofs from earlier LogEntries that are not required
    pub fn optimise_records(&mut self) -> Result<(), DIDWebVHError> {
        let mut witness_versions: HashMap<String, usize> = HashMap::new();

        // Map out which versions each witness is visible in
        for v in &self.0 {
            let Some((id, _)) = v.version_id.split_once('-') else {
                return Err(DIDWebVHError::WitnessProofError(format!(
                    "Invalid versionID ({}) in witness proofs! Expected n-hash, but missing n",
                    v.version_id
                )));
            };
            let Ok(id): Result<usize, _> = str::parse(id) else {
                return Err(DIDWebVHError::WitnessProofError(format!(
                    "Invalid versionID ({}) in witness proofs! expected n-hash, where n is a number!",
                    v.version_id
                )));
            };

            // Walk through each proof for this versionID
            for p in &v.proof {
                if let Some(record) = witness_versions.get_mut(&p.verification_method) {
                    if &id > record {
                        *record = id;
                    }
                } else {
                    // Create new witness record
                    witness_versions.insert(p.verification_method.clone(), id);
                }
            }
        }

        // Strip out older proofs as needed
        self.0.retain_mut(|v| {
            let Some((id, _)) = v.version_id.split_once('-') else {
                warn!(
                    "Invalid versionID ({}) in witness proofs! Expected n-hash, but missing n", v.version_id);
                return false;
            };
            let Ok(id): Result<usize, _> = str::parse(id) else {
                warn!(
                    "Invalid versionID ({}) in witness proofs! expected n-hash, where n is a number!", v.version_id);
            return false;
            };

            // Remove older proofs
            v.proof
                .retain(|p| &id >= witness_versions.get(&p.verification_method).unwrap_or(&0));
            
            // If version has no proofs, then remove it
             !v.proof.is_empty()
        });

        Ok(())
    }
}
