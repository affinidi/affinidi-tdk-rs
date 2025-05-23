/*!
*   creates a new webvh DID
*/

use anyhow::Result;
use console::style;
use dialoguer::{Input, theme::ColorfulTheme};
use did_webvh::url::WebVHURL;
use tracing_subscriber::filter;

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
        "{} {} {}",
        style("Built by").color256(69),
        style("Affinidi").color256(255),
        style("- for everyone ❤️").color256(69)
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

    // Step 1: Get the URLfor the DID
    loop {
        match get_address() {
            Ok((url, did)) => break,
            Err(_) => {
                println!("{}", style("Invalid input, please try again").color256(196));
                continue;
            }
        }
    }
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
        style("did:webvh:{scid}:example.com").color256(141),
    );
    println!(
        "{} {} {} {}",
        style("Example:").color256(69),
        style("https://affinidi.com:8000/path/dids/did.jsonl").color256(45),
        style("converts to").color256(69),
        style(" did:webvh:{scid}:affinidi.com%3A8000:path:dids").color256(141)
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
        let (http_url, did_url): (String, String) = if input.starts_with("did:") {
            let did_url = match WebVHURL::parse_did_url(&input) {
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
            break Ok((http_url.to_string(), did_url.to_string()));
        } else {
            break Ok(("url".to_string(), "did".to_string()));
        };
    }
}
