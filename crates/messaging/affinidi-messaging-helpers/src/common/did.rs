//! Methods relating to working with DIDs

use console::style;
use dialoguer::{Input, theme::ColorfulTheme};
use sha256::digest;

pub fn manually_enter_did_or_hash(theme: &ColorfulTheme) -> Option<String> {
    println!();
    println!(
        "{}",
        style("Limited checks are done on the DID or Hash - be careful!").yellow()
    );
    println!("DID or SHA256 Hash of a DID (type exit to quit this dialog)");

    let input: String = Input::with_theme(theme)
        .with_prompt("DID or SHA256 Hash")
        .interact_text()
        .unwrap();

    if input == "exit" {
        return None;
    }

    if input.starts_with("did:") {
        Some(digest(input))
    } else if input.len() != 64 {
        println!(
            "{}",
            style(format!(
                "Invalid SHA256 Hash length. length({}) when expected(64)",
                input.len()
            ))
            .red()
        );
        None
    } else {
        Some(input.to_ascii_lowercase())
    }
}
