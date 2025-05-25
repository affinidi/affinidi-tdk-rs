/*!
*   creates a new webvh DID
*/

use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk::{
    dids::{DID, KeyType},
    meeting_place::find_api_service_endpoint,
};
use anyhow::Result;
use console::style;
use dialoguer::{Confirm, Editor, Input, MultiSelect, Select, theme::ColorfulTheme};
use did_webvh::url::WebVHURL;
use serde_json::{Value, json};
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

    // ************************************************************************
    // Step 1: Get the URLs for this DID
    // ************************************************************************
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

    // ************************************************************************
    // Step 2: Create authorization keys to manage this DID
    // ************************************************************************
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
        println!("\t{}", style(&k.get_public_keymultibase()?).color256(141));
    }
    println!();

    // ************************************************************************
    // Step 3: Create the DID Document
    // ************************************************************************
    let did_document = loop {
        match create_did_document(&webvh_did) {
            Ok(keys) => break keys,
            Err(_) => {
                println!(
                    "{}",
                    style("Invalid did document, please try again").color256(196)
                );
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
        println!("\t{}", style(&k.get_public_keymultibase()?).color256(141));
    }
    println!(
        "{}\n{}",
        style("DID Document:").color256(69),
        style(&serde_json::to_string_pretty(&did_document).unwrap()).color256(141)
    );

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
fn get_authorization_keys(webvh_did: &str) -> Result<Vec<Secret>> {
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

    let mut keys: Vec<Secret> = Vec::new();

    loop {
        if !keys.is_empty() {
            println!("{}", style("Authorizing Keys:").color256(69),);
            for k in &keys {
                println!("\t{}", style(&k.get_public_keymultibase()?).color256(141));
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
            let public: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("publicKeyMultibase")
                .interact()
                .unwrap();

            let private: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("privateKeyMultibase")
                .interact()
                .unwrap();

            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(format!(
                    "Use public({}) and private({}) as an authorized key?",
                    &public, &private
                ))
                .interact()
                .unwrap()
            {
                keys.push(Secret::from_multibase(
                    "", // No controller for this key
                    &public, &private,
                )?);
            }
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
            keys.push(key.1);
        }
    }

    Ok(keys)
}

// Create DID Document
fn create_did_document(webvh_did: &str) -> Result<Value> {
    println!(
        "{} {}",
        style("Create a DID Document for:").color256(69),
        style(webvh_did).color256(141),
    );

    let mut did_document = json!({
      "id": webvh_did,
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://www.w3.org/ns/cid/v1",
      ],
      "verificationMethod": [],
      "authentication": [],
      "assertionMethod": [],
      "keyAgreement": [],
      "capabilityInvocation": [],
      "capabilityDelegation": [],
    });

    // Controller
    if let Some(controller) = controller() {
        did_document["controller"] = json!(controller);
    }

    // AlsoKnownAs
    let also_known_as = also_known_as();
    if !also_known_as.is_empty() {
        did_document["alsoKnownAs"] = json!(also_known_as);
    }

    // Add Verification Methods
    get_verification_methods(webvh_did, &mut did_document);

    println!();
    println!(
        "{}\n{}",
        style("DID Document").color256(69),
        style(serde_json::to_string_pretty(&did_document).unwrap()).color256(34)
    );
    println!();

    // Add Services
    add_services(webvh_did, &mut did_document);

    println!();
    println!(
        "{}\n{}",
        style("DID Document").color256(69),
        style(serde_json::to_string_pretty(&did_document).unwrap()).color256(34)
    );
    println!();

    let did_document = if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Would you like to edit this DID Document?")
        .default(false)
        .interact()
        .unwrap()
    {
        if let Some(document) = Editor::new()
            .extension("json")
            .edit(&serde_json::to_string_pretty(&did_document).unwrap())
            .unwrap()
        {
            match serde_json::from_str(&document) {
                Ok(document) => document,
                Err(e) => {
                    println!("{}", style("Invalid DID Document!").color256(196));
                    println!("\t{}", style(e.to_string()).color256(196));
                    did_document
                }
            }
        } else {
            did_document
        }
    } else {
        did_document
    };

    Ok(did_document)
}

// Handle if the did needs a controller
fn controller() -> Option<String> {
    loop {
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Does this DID have a controller?")
            .default(false)
            .interact()
            .unwrap()
        {
            let input = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Controller")
                .interact()
                .unwrap();
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(format!("Use ({}) as controller?", &input))
                .interact()
                .unwrap()
            {
                break Some(input);
            }
        } else {
            break None;
        }
    }
}

// Is this controller also known as another DID?
fn also_known_as() -> Vec<String> {
    let mut others: Vec<String> = Vec::new();
    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Is this DID also known as another DID?")
        .default(false)
        .interact()
        .unwrap()
    {
        loop {
            let input = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Other DID")
                .interact()
                .unwrap();
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(format!("Use ({}) as alias?", &input))
                .interact()
                .unwrap()
            {
                others.push(input);
            }
            if !Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Add another alias?")
                .default(false)
                .interact()
                .unwrap()
            {
                break;
            }
        }
    }
    others
}

// Create Verification Methods
fn get_verification_methods(webvh_did: &str, doc: &mut Value) {
    let mut key_id: u32 = 0;
    let mut success_count: u32 = 0;

    loop {
        let vm_id: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Verification ID")
            .default(format!("{}#key-{}", webvh_did, key_id))
            .interact()
            .unwrap();

        let secret = create_key(&vm_id);
        let vm = json!({
            "id": vm_id.clone(),
            "type": "Multikey",
            "publicKeyMultibase": secret.get_public_keymultibase().unwrap(),
            "controller": webvh_did.to_string()
        });

        let relationships = [
            "authentication",
            "assertionMethod",
            "keyAgreement",
            "capabilityInvocation",
            "capabilityDelegation",
        ];
        let purpose = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("What are the relationships of this Verification Method?")
            .items(&relationships)
            .defaults(&[true, true, true, false, false]) // Default to authentication
            .interact()
            .unwrap();

        println!(
            "{}\n{}",
            style("Verification Method:").color256(69),
            style(serde_json::to_string_pretty(&vm).unwrap()).color256(141)
        );
        print!("{} ", style("Relationships:").color256(69),);
        for r in &purpose {
            print!("{} ", style(relationships[r.to_owned()]).color256(141));
        }
        println!();

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Accept this Verification Method?")
            .default(true)
            .interact()
            .unwrap()
        {
            success_count += 1;
            key_id += 1;

            // Add to document
            doc["verificationMethod"]
                .as_array_mut()
                .unwrap()
                .push(vm.clone());
            for r in purpose {
                match r {
                    0 => doc["authentication"]
                        .as_array_mut()
                        .unwrap()
                        .push(Value::String(vm_id.clone())),
                    1 => doc["assertionMethod"]
                        .as_array_mut()
                        .unwrap()
                        .push(Value::String(vm_id.clone())),
                    2 => doc["keyAgreement"]
                        .as_array_mut()
                        .unwrap()
                        .push(Value::String(vm_id.clone())),
                    3 => doc["capabilityInvocation"]
                        .as_array_mut()
                        .unwrap()
                        .push(Value::String(vm_id.clone())),
                    4 => doc["capabilityDelegation"]
                        .as_array_mut()
                        .unwrap()
                        .push(Value::String(vm_id.clone())),
                    _ => {}
                }
            }
        }
        if success_count > 0
            && !Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Add another Verification Method?")
                .default(false)
                .interact()
                .unwrap()
        {
            break;
        }
    }
}

fn create_key(id: &str) -> Secret {
    let items = vec![
        KeyType::Ed25519.to_string(),
        KeyType::P256.to_string(),
        KeyType::Secp256k1.to_string(),
        KeyType::P384.to_string(),
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("What key type?")
        .items(&items)
        .default(0) // Default to Ed25519
        .interact()
        .unwrap();

    let (_, mut secret) =
        DID::generate_did_key(KeyType::try_from(items[selection].as_str()).unwrap()).unwrap();

    secret.id = id.to_string();
    secret
}

// Add Services
fn add_services(webvh_did: &str, doc: &mut Value) {
    doc["service"] = json!([]);
    let service_choice = ["Simple", "Complex"];
    let mut service_id: u32 = 0;

    let default_service_map = r#"{
  "id": "REPLACE",
  "type": "DIDCommMessaging",
  "serviceEndpoint": [
    {
      "accept": [
        "didcomm/v2"
      ],
      "routingKeys": [],
      "uri": "http://localhost:8000/api"
    }
  ]
}"#;
    loop {
        if !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Add a service for this DID?")
            .default(false)
            .interact()
            .unwrap()
        {
            return;
        }

        let service = match Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Service type?")
            .items(&service_choice)
            .default(0) // Default to Ed25519
            .interact()
            .unwrap()
        {
            0 => {
                // Simple
                let service_id: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Service ID")
                    .default(format!("{}#service-{}", webvh_did, service_id))
                    .interact()
                    .unwrap();

                let service_type: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Service Type")
                    .interact()
                    .unwrap();
                let service_endpoint: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Service Endpoint")
                    .interact()
                    .unwrap();

                let service = json!({
                    "id": service_id,
                    "type": service_type,
                    "serviceEndpoint": service_endpoint
                });
                service
            }
            1 => {
                // Complex
                let template = default_service_map
                    .replace("REPLACE", &format!("{}#service-{}", webvh_did, service_id));
                if let Some(service) = Editor::new().extension("json").edit(&template).unwrap() {
                    match serde_json::from_str(&service) {
                        Ok(service) => service,
                        Err(e) => {
                            println!("{}", style("Invalid service definition").color256(196));
                            println!("\t{}", style(e.to_string()).color256(196));
                            continue;
                        }
                    }
                } else {
                    println!("Service definition wasn't saved!");
                    continue;
                }
            }
            _ => continue,
        };

        println!();
        println!(
            "{}\n{}",
            style("Service:").color256(69),
            style(serde_json::to_string_pretty(&service).unwrap()).color256(141)
        );
        println!();

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Accept this Service?")
            .default(true)
            .interact()
            .unwrap()
        {
            doc["service"].as_array_mut().unwrap().push(service);
            service_id += 1;
        }
    }
}
