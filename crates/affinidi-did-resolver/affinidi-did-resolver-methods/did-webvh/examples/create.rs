/*!
*   creates a new webvh DID
*/

use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk::dids::{DID, KeyType};
use anyhow::Result;
use console::style;
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use did_webvh::url::WebVHURL;
use tracing_subscriber::filter;
use url::Url;

/// Display a fun banner
fn show_banner() {
    println!();
    println!(
        "{}",
        style("██████╗ ██╗██████╗    ██╗    ██╗███████╗██████╗ ██╗   ██╗██╗  ██╗").color256(196)
    );
    println!(
        "{}",
        style("██╔══██╗██║██╔══██╗██╗██║    ██║██╔════╝██╔══██╗██║   ██║██║  ██║").color256(202)
    );
    println!(
        "{}",
        style("██║  ██║██║██║  ██║╚═╝██║ █╗ ██║█████╗  ██████╔╝██║   ██║███████║").color256(220)
    );
    println!(
        "{}",
        style("██║  ██║██║██║  ██║██╗██║███╗██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══██║").color256(34)
    );
    println!(
        "{}",
        style("██████╔╝██║██████╔╝╚═╝╚███╔███╔╝███████╗██████╔╝ ╚████╔╝ ██║  ██║").color256(21)
    );
    println!(
        "{}",
        style("╚═════╝ ╚═╝╚═════╝     ╚══╝╚══╝ ╚══════╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝").color256(92)
    );
    println!();

    println!(
        "{}",
        style("This wizard will walk you through all the steps in creating a webvh DID")
            .color256(69)
    );
    println!(
        "{} {} {} {} ❤️ ❤️ ❤️",
        style("Built by").color256(69),
        style("Affinidi").color256(255),
        style("- for").color256(69),
        style("- for everyone").color256(255)
    );
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    show_banner();

    // Step 1: Get the URLs for this DID
    let (http_url, webvh_did) = loop {
        match get_address() {
            Ok((url, did)) => break (url, did),
            Err(_) => {
                println!("{}", style("Invalid input, please try again").color256(196));
                continue;
            }
        }
    };

    println!();
    println!(
        "{} {}",
        style("webvh DID:").color256(69),
        style(&webvh_did).color256(141)
    );
    println!();

    // Step 2: Create authorization keys to manage this DID
    let authorizing_keys = loop {
        match get_authorization_keys(&webvh_did) {
            Ok(keys) => break keys,
            Err(_) => {
                println!("{}", style("Invalid input, please try again").color256(196));
                continue;
            }
        }
    };

    println!();
    println!(
        "{} {}",
        style("webvh DID:").color256(69),
        style(&webvh_did).color256(141)
    );
    println!("{}", style("Authorizing Keys:").color256(69),);
    for k in &authorizing_keys {
        println!("\t{}", style(&k.0).color256(141));
    }
    println!();
    Ok(())
}

/// Step 1: Get the URL and the DID Identifier
/// Returns: URL and DID Identifier
fn get_address() -> Result<(String, String)> {
    println!(
        "{} {} {}",
        style("What is the address where the").color256(69),
        style("webvh").color256(141),
        style("files can be found?").color256(69)
    );
    println!(
        "{} {} {} {}",
        style("Default Location:").color256(69),
        style("https://example.com/.well-known/did.jsonl").color256(45),
        style("would refer to").color256(69),
        style("did:webvh:{SCID}:example.com").color256(141),
    );
    println!(
        "{} {} {} {}",
        style("Example:").color256(69),
        style("https://affinidi.com:8000/path/dids/did.jsonl").color256(45),
        style("converts to").color256(69),
        style(" did:webvh:{SCID}:affinidi.com%3A8000:path:dids").color256(141)
    );

    let mut initial_text = String::new();
    let theme = ColorfulTheme::default();
    loop {
        println!(
            "{} {} {} {} {}",
            style("Enter the address (can be").color256(69),
            style("URL").color256(45),
            style("or").color256(69),
            style("DID").color256(141),
            style(")").color256(69),
        );

        let mut input = Input::with_theme(&theme).with_prompt("Address");

        if initial_text.is_empty() {
            input = input.default("http://localhost:8000/".to_string());
        } else {
            input = input.with_initial_text(&initial_text);
        }
        let input: String = input.interact_text()?;

        // Check address
        let did_url = if input.starts_with("did:") {
            match WebVHURL::parse_did_url(&input) {
                Ok(did_url) => did_url,
                Err(e) => {
                    println!(
                        "{}  {}",
                        style("Invalid DID URL, please try again:").color256(196),
                        style(e.to_string()).color256(9),
                    );
                    initial_text = input;
                    continue;
                }
            }
        } else {
            // User entered a URL
            let url = match Url::parse(&input) {
                Ok(url) => url,
                Err(e) => {
                    println!(
                        "{}  {}",
                        style("Invalid URL, please try again:").color256(196),
                        style(e.to_string()).color256(9),
                    );
                    initial_text = input;
                    continue;
                }
            };

            match WebVHURL::parse_url(&url) {
                Ok(did_url) => did_url,
                Err(e) => {
                    println!(
                        "{}  {}",
                        style("Invalid URL, please try again:").color256(196),
                        style(e.to_string()).color256(9),
                    );
                    initial_text = input;
                    continue;
                }
            }
        };

        let http_url = match did_url.get_http_url() {
            Ok(http_url) => http_url,
            Err(e) => {
                println!(
                    "{}  {}",
                    style("Invalid DID URL, please try again:").color256(196),
                    style(e.to_string()).color256(9),
                );
                initial_text = input;
                continue;
            }
        };

        println!(
            "{} {}",
            style("DID:").color256(69),
            style(&did_url).color256(141)
        );
        println!(
            "{} {}",
            style("URL:").color256(69),
            style(&http_url).color256(45)
        );
        if Confirm::with_theme(&theme)
            .with_prompt("are you sure?")
            .default(true)
            .interact()?
        {
            break Ok((http_url.to_string(), did_url.to_string()));
        }
    }
}

// Create authorization keys for the DID
fn get_authorization_keys(webvh_did: &str) -> Result<Vec<(String, Secret)>> {
    println!(
        "{} {} {}",
        style("A set of keys are required to manage").color256(69),
        style("webvh").color256(141),
        style("dids.").color256(69)
    );
    println!(
        "{}",
        style("At least one key is required, though you can have more than one!").color256(69),
    );
    println!(
        "{} {} {}{}{}",
        style("These will become the published").color256(69),
        style("updateKeys").color256(141),
        style("for this DID (").color256(69),
        style(webvh_did).color256(141),
        style(")").color256(69)
    );

    let mut keys: Vec<(String, Secret)> = Vec::new();

    loop {
        if !keys.is_empty() {
            println!("{}", style("Authorizing Keys:").color256(69),);
            for k in &keys {
                println!("\t{}", style(&k.0).color256(141));
            }
            if !Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Do you want to add another key?")
                .default(false)
                .interact()?
            {
                break;
            }
        }

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you already have a key to use?")
            .default(false)
            .interact()?
        {
        } else {
            // Generate a new key
            let key = DID::generate_did_key(KeyType::Ed25519).unwrap();
            println!(
                "{} {}",
                style("DID:").color256(69),
                style(&key.0).color256(141)
            );
            println!(
                "{} {} {} {}",
                style("publicKeyMultibase:").color256(69),
                style(&key.1.get_public_keymultibase()?).color256(34),
                style("privateKeyMultibase:").color256(69),
                style(&key.1.get_private_keymultibase()?).color256(214)
            );
            keys.push((key.0, key.1));
        }
    }

    Ok(keys)
}
