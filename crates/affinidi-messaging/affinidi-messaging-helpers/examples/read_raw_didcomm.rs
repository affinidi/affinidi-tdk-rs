/*!
 * This is a test app that can read raw DIDComm messages to help in troubleshooting what is happening.
 *
 * To read the DIDComm messages, you will need access to the Secrets for the DID Recipients
 */

use affinidi_messaging_didcomm::jwe::envelope::Jwe;
use affinidi_messaging_sdk::{ATM, config::ATMConfig, errors::ATMError, profiles::ATMProfile};
use affinidi_tdk::{
    common::TDKSharedState,
    secrets_resolver::{SecretsResolver, secrets::Secret},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use clap::Parser;
use console::style;
use std::{
    fs::File,
    io::{self, BufRead, Read},
    sync::Arc,
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Raw DIDComm message
    #[arg(short, long)]
    raw_message: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    // Create a new ATM Client
    let config = ATMConfig::builder();
    let tdk = Arc::new(TDKSharedState::default().await);
    let atm = ATM::new(config.build()?, tdk).await?;

    // Load the DIDComm message
    println!("{}", style("Raw DIDComm Message troubleshooting").green(),);

    let args: Args = Args::parse();
    let raw_message = match args.raw_message {
        Some(raw_message) => raw_message,
        None => {
            println!("{}", style("No DIDComm message provided").red());
            return Ok(());
        }
    };

    let mut file = File::open(&raw_message).map_err(|e| {
        ATMError::ConfigError(format!("Can't open file ({}). Reason: {}", raw_message, e))
    })?;
    let mut didcomm_raw_message = String::new();
    file.read_to_string(&mut didcomm_raw_message).map_err(|e| {
        ATMError::ConfigError(format!(
            "Couldn't read file ({}) contents. Reason: {}",
            raw_message, e
        ))
    })?;

    println!();
    println!(
        "{}",
        style("Reading the DIDComm message envelope...").blue()
    );

    // Parse the JWE envelope to extract recipient information
    let jwe: Jwe = serde_json::from_str(&didcomm_raw_message).map_err(|e| {
        ATMError::DidcommError(
            "NA".to_string(),
            format!("Couldn't parse JWE envelope: {}", e),
        )
    })?;

    // Extract recipient DID from the first recipient's kid
    let to_did = if let Some(recipient) = jwe.recipients.first() {
        // kid format is typically "did:...#key-id", extract the DID part
        let kid = &recipient.header.kid;
        if let Some(hash_pos) = kid.find('#') {
            kid[..hash_pos].to_string()
        } else {
            kid.clone()
        }
    } else {
        println!(
            "{}",
            style("Couldn't find the recipient DID. Exiting...").red()
        );
        return Ok(());
    };

    println!(
        "{}",
        style(format!("\t  To DID: {}", to_did)).cyan()
    );
    println!(
        "{}",
        style(format!("\tMSG Hash: {}", sha256::digest(&didcomm_raw_message))).cyan()
    );

    // Grab the secrets
    let stdin = io::stdin();
    let lines = stdin.lock().lines();
    let mut raw_secrets = String::new();

    println!();
    println!(
        "{}",
        style(format!(
            "Copy and Paste the JSON Secrets for {}. Press <ENTER> to terminate input",
            to_did
        ))
        .green(),
    );
    for line in lines {
        match line {
            Ok(line) => {
                if line.is_empty() {
                    break;
                }
                raw_secrets.push_str(&line);
            }
            Err(e) => {
                println!("Error reading input: {:?}", e);
                break;
            }
        }
    }

    let secrets: Vec<Secret> = match serde_json::from_str(&raw_secrets) {
        Ok(secrets) => secrets,
        Err(e) => {
            println!(
                "{}",
                style(format!("Error converting secrets: {}", e)).red()
            );
            return Ok(());
        }
    };
    atm.get_tdk().secrets_resolver.insert_vec(&secrets).await;

    let profile = ATMProfile::new(&atm, None, to_did.clone(), None).await?;
    atm.profile_add(&profile, false).await?;
    println!("{}", style("DIDComm Profile created...").green());

    let (inner_message, meta) = atm.unpack(&didcomm_raw_message).await?;

    println!("{}", style("DIDComm Message").green());
    println!();

    println!("{}", style(format!("{:#?}", meta)).yellow());
    println!();
    println!("{}", style(format!("{:#?}", inner_message)).green());

    // >>>>> Additional processing of the message can be done here <<<<<

    if inner_message.typ == "https://didcomm.org/routing/2.0/forward" {
        println!();
        println!("{}", style("Forwarded Message").green());
        if let Some(attachments) = inner_message.attachments {
            let attachment = attachments.first().unwrap();
            let data = if let Some(ref b64) = attachment.data.base64 {
                    String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(b64).unwrap())
                        .unwrap()
                } else if let Some(ref json_val) = attachment.data.json {
                    if attachment.data.jws.is_some() {
                        println!("{}", style("JWS is not supported").red());
                        return Ok(());
                    } else {
                        match serde_json::to_string(json_val) {
                            Ok(data) => data,
                            Err(e) => {
                                println!(
                                    "{}",
                                    style(format!("Error converting JSON: {}", e)).red()
                                );
                                return Ok(());
                            }
                        }
                    }
                } else {
                    println!("{}", style("Unsupported attachment type").red());
                    return Ok(());
                };
            println!("{}", style("Forwarded message found").green());
            println!();
            println!("{}", style(data).green());
        }
    }

    Ok(())
}
