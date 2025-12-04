/*
use affinidi_data_integrity::DataIntegrityProof;
use affinidi_tdk::{TDK, common::config::TDKConfigBuilder};
use clap::Parser;
use serde_json::json;
use std::fs;

/// Affinidi Data Integrity Verification Tool
#[derive(Parser)]
#[command(name = "verify")]
#[command(bin_name = "verify")]
struct Cli {
    /// File name to verify
    #[arg(short, long)]
    file_name: String,
}

fn load_file(file: &str) -> String {
    fs::read_to_string(file).unwrap_or_else(|_| panic!("Failed to read file: {file}"))
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let input = load_file(&args.file_name);

    let mut signed_doc = json!(&input);

    let proof = if let Some(proof) = signed_doc.get("proof") {
        serde_json::from_value::<DataIntegrityProof>(proof.clone())
            .expect("Failed to deserialize proof")
    } else {
        panic!("No proof found in Signed Document");
    };
    signed_doc.as_object_mut().unwrap().remove("proof");

    let context = signed_doc.get("@context").map(|context| {
        context
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_string())
            .collect::<Vec<String>>()
    });

    println!("Document to be verified:\n{signed_doc:#?}");
    println!();
    println!("Proof:\n{proof:#?}");
    println!();
    println!("Context:\n{context:#?}");

    let tdk = TDK::new(TDKConfigBuilder::new().build().unwrap(), None)
        .await
        .unwrap();
    tdk.verify_data(&signed_doc, context, &proof)
        .await
        .expect("Failed to verify data integrity proof");
}
*/
