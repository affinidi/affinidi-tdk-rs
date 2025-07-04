use affinidi_data_integrity::verification_proof::verify_data;
use clap::Parser;
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

fn main() {
    let args = Cli::parse();

    let input = load_file(&args.file_name);

    let signed_doc = serde_json::from_str(&input).expect("Couldn't deserialize input");

    verify_data(&signed_doc).expect("Failed to verify data integrity proof");
}
