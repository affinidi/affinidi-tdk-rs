use crate::ConfigInfo;
use affinidi_data_integrity::GenericDocument;
use anyhow::Result;
use console::style;
use did_webvh::{log_entry::LogEntry, witness::proofs::WitnessProofCollection};

pub fn witness_log_entry(
    log_entry: &LogEntry,
    secrets: &ConfigInfo,
) -> Result<Option<WitnessProofCollection>> {
    let Some(Some(witnesses)) = &log_entry.parameters.witness else {
        println!(
            "{}",
            style("Witnesses are not being used for this DID. No witnessing is required")
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

    let doc_to_sign: GenericDocument = log_entry.try_into()?;
    for witness in &witnesses.witnesses {
        // Get secret for Witness
        let secret = secrets.find_secret_by_public_key(&witness.id);
        println!("Witness: {} :: {:#?}", witness.id, secret)

        // Generate Signature

        // Save proof to collection
    }

    Ok(None)
}
