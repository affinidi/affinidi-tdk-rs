//! Generate a large WebVH DID
//!
//! Model an business DID with the following characteristics
//! 1. Must be used for 10 years
//! 2. They rotate webVH keys every month (two keys per update)
//! 3. They swap a witness node once every 12 months (maintaining 3 threashold, 4 witnesses)
//! 4. They swap a watcher node once every 12 months (maintaining 3 watchers)
//! 5. DID VM Key is rotated every 3 months

use affinidi_data_integrity::DataIntegrityProof;
use affinidi_secrets_resolver::{SecretsResolver, SimpleSecretsResolver, secrets::Secret};
use affinidi_tdk::dids::{DID, KeyType};
use anyhow::{Result, anyhow, bail};
use clap::Parser;
use console::style;
use did_webvh::{
    DIDWebVHState, SCID_HOLDER,
    parameters::Parameters,
    witness::{Witness, Witnesses},
};
use rand::{Rng, distr::Alphabetic};
use serde_json::json;
use std::{
    fs::OpenOptions,
    io::Write,
    thread::sleep,
    time::{Duration, SystemTime},
};
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of LogEntries to generate (default: 120)
    #[arg(short, long, default_value_t = 120)]
    count: u32,

    /// Enables Witnesses with a given threshold (set to 0 to disable)
    #[arg(short, long, default_value_t = 3)]
    witnesses: u32,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let args: Args = Args::parse();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let mut didwebvh = DIDWebVHState::default();
    let mut secrets = SimpleSecretsResolver::new(&[]).await;

    println!("System resting before starting...");
    sleep(Duration::from_secs(3));
    let start = SystemTime::now();

    // Generate initial DID
    let mut next = generate_did(&mut didwebvh, &mut secrets, &args).await?;

    // Loop for count months (first entry represents the first month)
    for i in 2..(args.count + 1) {
        next = create_log_entry(&mut didwebvh, &mut secrets, &next, i, &args).await?;
    }

    let end = SystemTime::now();

    println!(
        "Generation Duration: {}ms",
        end.duration_since(start).unwrap().as_millis()
    );

    println!("Writing to disk");
    // Write records to disk
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("did.jsonl")?;

    for entry in didwebvh.log_entries.iter() {
        // Convert LogEntry to JSON and write to file
        let json_entry = serde_json::to_string(&entry.log_entry)?;
        file.write_all(json_entry.as_bytes())?;
        file.write_all("\n".as_bytes())?;
    }

    if args.witnesses > 0 {
        println!("Witnesses enabled with threshold: {}", args.witnesses);
        // Witness proofs
        didwebvh.witness_proofs.write_optimise_records()?;
        didwebvh.witness_proofs.save_to_file("did-witness.json")?;
    }

    println!("Resetting.. ready for validation");

    let mut verify_state = DIDWebVHState::default();
    sleep(Duration::from_secs(3));
    let start = SystemTime::now();
    verify_state.load_log_entries_from_file("did.jsonl")?;
    let end = SystemTime::now();

    println!(
        "Reading LogEntries Duration: {}ms",
        end.duration_since(start).unwrap().as_millis()
    );
    let mut total_validation = end.duration_since(start).unwrap().as_millis();

    sleep(Duration::from_secs(3));
    let start2 = SystemTime::now();
    verify_state.load_witness_proofs_from_file("did-witness.json");
    let end = SystemTime::now();

    println!(
        "Reading Witness Proofs Duration: {}ms",
        end.duration_since(start2).unwrap().as_millis()
    );

    total_validation += end.duration_since(start2).unwrap().as_millis();

    sleep(Duration::from_secs(3));
    let start3 = SystemTime::now();
    verify_state.validate()?;
    let end = SystemTime::now();

    println!(
        "Validation Duration: {}ms",
        end.duration_since(start3).unwrap().as_millis()
    );
    total_validation += end.duration_since(start3).unwrap().as_millis();

    println!("Total validation: {total_validation}ms",);

    Ok(())
}

async fn generate_did(
    didwebvh: &mut DIDWebVHState,
    secrets: &mut SimpleSecretsResolver,
    args: &Args,
) -> Result<Vec<Secret>> {
    let raw_did = r#"{
    "@context": [
        "https://www.w3.org/ns/did/v1"
    ],
    "assertionMethod": [
        "did:webvh:{SCID}:test.affinidi.com#key-0"
    ],
    "authentication": [
        "did:webvh:{SCID}:test.affinidi.com#key-0"
    ],
    "id": "did:webvh:{SCID}:test.affinidi.com",
    "service": [
        {
        "id": "did:webvh:{SCID}:test.affinidi.com#service-0",
        "serviceEndpoint": [
            {
            "accept": [
                "didcomm/v2"
            ],
            "routingKeys": [],
            "uri": "http://mediator.affinidi.com:/api"
            }
        ],
        "type": "DIDCommMessaging"
        }
    ],
    "verificationMethod": [
        {
        "controller": "did:webvh:{SCID}:test.affinidi.com",
        "id": "did:webvh:{SCID}:test.affinidi.com#key-0",
        "publicKeyMultibase": "test1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "type": "Multikey"
        }
    ]
    }"#;

    let did_document = serde_json::from_str::<serde_json::Value>(raw_did).unwrap();

    // ***** Generate Parameters *****

    // Generate updateKey for first log entry
    let signing_did1_secret = DID::generate_did_key(affinidi_tdk::dids::KeyType::Ed25519)?.1;
    secrets.insert(signing_did1_secret.clone()).await;

    // Generate next_key_hashes
    let next_key1 = DID::generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key1.clone()).await;
    let next_key2 = DID::generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key2.clone()).await;

    // Generate witnesses
    let witness = if args.witnesses > 0 {
        let mut witness = Witnesses {
            threshold: args.witnesses,
            witnesses: Vec::new(),
        };
        for _ in 0..args.witnesses {
            let (w_did, w_secret) = DID::generate_did_key(KeyType::Ed25519)?;
            secrets.insert(w_secret.clone()).await;
            witness.witnesses.push(Witness { id: w_did });
        }
        Some(Some(witness))
    } else {
        None
    };

    let params = Parameters {
        portable: Some(true),
        scid: Some(SCID_HOLDER.to_string()),
        update_keys: Some(Some(vec![signing_did1_secret.get_public_keymultibase()?])),
        next_key_hashes: Some(Some(vec![
            next_key1.get_public_keymultibase_hash()?,
            next_key2.get_public_keymultibase_hash()?,
        ])),
        witness,
        watchers: Some(Some(vec![
            "https://watcher-1.affinidi.com/v1/webvh".to_string(),
            "https://watcher-2.affinidi.com/v1/webvh".to_string(),
            "https://watcher-3.affinidi.com/v1/webvh".to_string(),
        ])),
        ttl: Some(Some(300)),
        ..Default::default()
    };

    let _ = didwebvh.create_log_entry(
        None,
        &did_document,
        &params,
        &secrets.get_secret(&signing_did1_secret.id).await.unwrap(),
    )?;

    // Witness LogEntry
    witness_log_entry(didwebvh, secrets).await?;

    let log_entry = didwebvh.log_entries.last().unwrap();
    println!(
        "DID First LogEntry created: {}",
        log_entry.log_entry.version_id
    );

    Ok(vec![next_key1, next_key2])
}

async fn witness_log_entry(
    didwebvh: &mut DIDWebVHState,
    secrets: &SimpleSecretsResolver,
) -> Result<()> {
    let log_entry = didwebvh
        .log_entries
        .last()
        .ok_or_else(|| anyhow!("Couldn't find a LogEntry to witness"))?;

    let Some(Some(witnesses)) = &log_entry.validated_parameters.active_witness else {
        println!(
            "{}",
            style("Witnesses are not being used for this LogEntry. No witnessing is required")
                .color256(69)
        );
        return Ok(());
    };

    for witness in &witnesses.witnesses {
        let key = witness.id.split_at(8);
        // Get secret for Witness
        let Some(secret) = secrets
            .get_secret(&[&witness.id, "#", key.1].concat())
            .await
        else {
            bail!("Couldn't find secret for witness ({})!", witness.id)
        };

        // Generate Signature
        let proof = DataIntegrityProof::sign_jcs_data(
            &json!({"versionId": &log_entry.log_entry.version_id}),
            None,
            &secret,
            None,
        )
        .map_err(|e| {
            anyhow!("Couldn't generate Data Integrity Proof for LogEntry. Reason: {e}",)
        })?;

        // Save proof to collection
        didwebvh
            .witness_proofs
            .add_proof(&log_entry.log_entry.version_id, &proof, false)
            .map_err(|e| anyhow!("Error adding proof: {e}"))?;
    }

    Ok(())
}

async fn create_log_entry(
    didwebvh: &mut DIDWebVHState,
    secrets: &mut SimpleSecretsResolver,
    previous_keys: &[Secret],
    count: u32,
    args: &Args,
) -> Result<Vec<Secret>> {
    let old_log_entry = didwebvh
        .log_entries
        .last()
        .ok_or_else(|| anyhow!("No previous log entry found. Please generate a DID first."))?;
    let new_state = old_log_entry.log_entry.state.clone();

    let mut new_params = old_log_entry.validated_parameters.clone();

    // Generate next_key_hashes
    let next_key1 = DID::generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key1.clone()).await;
    let next_key2 = DID::generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key2.clone()).await;

    new_params.next_key_hashes = Some(Some(vec![
        next_key1.get_public_keymultibase_hash()?,
        next_key2.get_public_keymultibase_hash()?,
    ]));

    // Modify update_key for this entry
    let update_keys = previous_keys
        .iter()
        .map(|s| s.get_public_keymultibase().unwrap())
        .collect();
    new_params.update_keys = Some(Some(update_keys));

    // Swap a witness node?
    if args.witnesses > 0 && count % 12 == 6 {
        swap_witness(&mut new_params, secrets).await?;
    }

    // Swap a watcher node?
    if count % 12 == 0 {
        swap_watcher(&mut new_params)?;
    }

    let _ = didwebvh.create_log_entry(
        None,
        &new_state,
        &new_params,
        previous_keys
            .first()
            .ok_or_else(|| anyhow!("No next key provided for log entry creation"))?,
    )?;

    // Witness LogEntry
    witness_log_entry(didwebvh, secrets).await?;

    // let log_entry = didwebvh.log_entries.last().unwrap();
    // println!(
    //     "{:03}: DID LogEntry created: {}",
    //     count, log_entry.log_entry.version_id
    // );

    Ok(vec![next_key1, next_key2])
}

async fn swap_witness(params: &mut Parameters, secrets: &mut SimpleSecretsResolver) -> Result<()> {
    // Pick a random witness and remove it
    let mut rng = rand::rng();

    let Some(Some(witnesses)) = &params.witness else {
        bail!("Witnesses incorrectly configured for this test!");
    };
    let mut new_witnesses = witnesses.clone();

    let rn = rng.random_range(0..new_witnesses.witnesses.len());

    // remove random witness
    new_witnesses.witnesses.remove(rn);

    let (new_witness_did, secret) = DID::generate_did_key(KeyType::Ed25519)?;
    secrets.insert(secret.clone()).await;

    new_witnesses.witnesses.push(Witness {
        id: new_witness_did,
    });

    params.witness = Some(Some(new_witnesses));

    Ok(())
}

fn swap_watcher(params: &mut Parameters) -> Result<()> {
    // Pick a random witness and remove it
    let mut rng = rand::rng();

    let Some(Some(watchers)) = &params.watchers else {
        bail!("Watchers incorrectly configured for this test!");
    };
    let mut new_watchers = watchers.clone();
    let rn = rng.random_range(0..new_watchers.len());

    let new_watcher_id: String = rng
        .sample_iter(&Alphabetic)
        .take(4)
        .map(char::from)
        .collect();

    new_watchers.remove(rn);
    new_watchers.push(
        [
            "https://watcher-",
            &new_watcher_id,
            ".affinidi.com/v1/webvh",
        ]
        .concat(),
    );

    params.watchers = Some(Some(new_watchers));

    Ok(())
}
