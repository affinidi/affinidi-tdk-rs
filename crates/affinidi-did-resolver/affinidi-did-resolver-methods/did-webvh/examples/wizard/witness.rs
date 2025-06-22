use crate::ConfigInfo;
use affinidi_data_integrity::{DataIntegrityProof, SigningDocument};
use anyhow::{Result, bail};
use console::style;
use did_webvh::{
    DIDWebVHError,
    log_entry::LogEntry,
    witness::{Witnesses, proofs::WitnessProofCollection},
};

/// Witnesses a LogEntry with the active LogEntries
pub fn witness_log_entry(
    witness_proofs: &mut WitnessProofCollection,
    log_entry: &LogEntry,
    witnesses: &Option<Option<Witnesses>>,
    secrets: &ConfigInfo,
) -> Result<Option<()>> {
    let Some(Some(witnesses)) = witnesses else {
        println!(
            "{}",
            style("Witnesses are not being used for this LogEntry. No witnessing is required")
                .color256(69)
        );
        return Ok(None);
    };

    println!(
        "{}{}{}",
        style("Witnessing enabled. Requires at least (").color256(69),
        style(witnesses.threshold).color256(45),
        style(") proofs from witnesses").color256(69)
    );

    let mut doc_to_sign: SigningDocument = log_entry.try_into()?;
    for witness in &witnesses.witnesses {
        // Get secret for Witness
        let Some(secret) = secrets.witnesses.get(&witness.id) else {
            bail!("Couldn't find secret for witness ({})!", witness.id)
        };

        // Generate Signature
        DataIntegrityProof::sign_jcs_data(&mut doc_to_sign, secret).map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate Data Integrity Proof for LogEntry. Reason: {}",
                e
            ))
        })?;

        // Save proof to collection
        if let Some(proof) = &doc_to_sign.proof {
            witness_proofs
                .add_proof(&log_entry.version_id, proof, false)
                .map_err(|e| {
                    DIDWebVHError::WitnessProofError(format!("Error adding proof: {}", e))
                })?;

            doc_to_sign.proof = None; // Reset proof for next witness

            println!(
                "{}{}{}{}{}",
                style("Witness (").color256(69),
                style(&witness.id).color256(45),
                style("): Successfully witnessed LogEntry (").color256(69),
                style(&log_entry.version_id).color256(45),
                style(")").color256(69),
            );
        } else {
            bail!("No proof generated from witness ({})!", witness.id);
        }
    }
    // Strip out any duplicate records where we can
    witness_proofs.write_optimise_records()?;

    println!(
        "{}{}{}{}",
        style("Witnessing completed: ").color256(69),
        style(witness_proofs.get_proof_count(&log_entry.version_id)).color256(45),
        style("/").color256(69),
        style(witnesses.threshold).color256(45),
    );

    Ok(Some(()))
}
