//! Interactive CLI wizard for configuring VTA integration with the mediator.
//!
//! Build and run:
//!   cargo run --bin mediator-setup-vta --features setup [-- --config path/to/mediator.toml]

use affinidi_did_common::{
    Document,
    verification_method::{VerificationMethod, VerificationRelationship},
};
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use console::style;
use dialoguer::{Confirm, Input, Password, Select};
use std::{collections::HashMap, env, fs, process};
use vta_sdk::{
    client::{CreateContextRequest, CreateDidWebvhRequest, ImportKeyRequest, UpdateContextRequest, VtaClient},
    credentials::CredentialBundle,
    keys::KeyType,
};

const DEFAULT_CONFIG_PATH: &str = "conf/mediator.toml";

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("\n{} {e}", style("Error:").red().bold());
        process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = parse_config_path();

    println!();
    println!("{}", style("Mediator VTA Setup").bold().cyan());
    println!("{}", style("==================").dim());
    println!();

    // Step 1: Get and validate credential
    let (client, credential_raw) = step_credential().await?;

    // Step 2: Choose credential storage
    let credential_config = step_storage(&credential_raw)?;

    // Step 3: Context setup
    let context_id = step_context(&client).await?;

    // Step 4: DID setup
    step_did(&client, &context_id).await?;

    // Step 5: Save config
    step_save_config(&config_path, &credential_config, &context_id)?;

    println!();
    println!("{}", style("Setup complete!").green().bold());
    println!();
    println!("Start the mediator with:");
    println!("  cargo run --bin mediator");
    println!();

    Ok(())
}

fn parse_config_path() -> String {
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" && i + 1 < args.len() {
            return args[i + 1].clone();
        }
        i += 1;
    }
    DEFAULT_CONFIG_PATH.to_string()
}

// ─── Step 1: Credential ─────────────────────────────────────────────────────

async fn step_credential() -> Result<(VtaClient, String), Box<dyn std::error::Error>> {
    println!("{}", style("Step 1: VTA Credential").bold());
    println!("  Paste the credential bundle from your VTA admin.");
    println!(
        "  (Generated via: {})",
        style("cnm-cli auth credentials generate").dim()
    );
    println!();

    let credential_raw: String = Password::new()
        .with_prompt("  Credential bundle (base64url)")
        .interact()?;

    let credential_raw = credential_raw.trim().to_string();
    if credential_raw.is_empty() {
        return Err("Credential cannot be empty".into());
    }

    // Validate the credential structure
    let credential = CredentialBundle::decode(&credential_raw).map_err(|e| {
        format!("Invalid credential bundle: {e}. Make sure you pasted the full base64url string.")
    })?;

    let vta_url = credential
        .vta_url
        .as_deref()
        .ok_or("Credential does not contain a VTA URL. You may need a newer credential.")?;

    println!(
        "  {} Credential valid. VTA: {}",
        style("*").green(),
        style(vta_url).cyan()
    );

    // Authenticate
    print!("  Authenticating...");
    let client = VtaClient::from_credential(&credential_raw, None)
        .await
        .map_err(|e| {
            if e.is_network() {
                format!(
                    "Cannot reach VTA at {vta_url}: {e}\n  \
                     Ensure the VTA is running and the REST endpoint is accessible."
                )
            } else {
                format!("Authentication failed: {e}")
            }
        })?;

    println!(
        "\r  {} Authenticated to VTA at {}",
        style("*").green(),
        style(client.base_url()).cyan()
    );
    println!();

    Ok((client, credential_raw))
}

// ─── Step 2: Credential Storage ──────────────────────────────────────────────

/// Returns the credential config string for mediator.toml (e.g., "string://eyJ...")
fn step_storage(credential_raw: &str) -> Result<String, Box<dyn std::error::Error>> {
    println!("{}", style("Step 2: Credential Storage").bold());
    println!("  How should the mediator load this credential at runtime?");
    println!();

    let options = vec![
        "Embed in config file (string://) - simple, suitable for dev/CI",
        "AWS Secrets Manager (aws_secrets://) - production",
        "OS Keyring (keyring://) - local dev with OS keychain",
    ];

    let selection = Select::new()
        .with_prompt("  Storage backend")
        .items(&options)
        .default(0)
        .interact()?;

    let credential_config = match selection {
        0 => {
            // String - embed directly
            let config = format!("string://{credential_raw}");
            println!(
                "  {} Credential will be embedded in config file",
                style("*").green()
            );
            config
        }
        1 => {
            // AWS Secrets Manager
            let secret_name: String = Input::new()
                .with_prompt("  AWS Secret name")
                .with_initial_text("mediator/vta-credential")
                .interact_text()?;

            println!(
                "  {} Store the credential in AWS Secrets Manager as '{}'",
                style("!").yellow(),
                style(&secret_name).cyan()
            );
            println!("  Run:");
            println!(
                "    aws secretsmanager create-secret --name '{}' --secret-string '{}'",
                secret_name, credential_raw
            );
            println!();
            println!(
                "  Build the mediator with: {}",
                style("--features vta-aws-secrets").cyan()
            );

            if !Confirm::new()
                .with_prompt("  Have you stored the credential in AWS?")
                .default(false)
                .interact()?
            {
                println!(
                    "  {} You can store it later. The mediator will fail to start until the secret exists.",
                    style("!").yellow()
                );
            }

            format!("aws_secrets://{secret_name}")
        }
        2 => {
            // OS Keyring
            let service: String = Input::new()
                .with_prompt("  Keyring service name")
                .with_initial_text("affinidi-mediator")
                .interact_text()?;

            let user: String = Input::new()
                .with_prompt("  Keyring user")
                .with_initial_text("vta-credential")
                .interact_text()?;

            // Try to save to keyring
            #[cfg(feature = "vta-keyring")]
            {
                let entry = keyring::Entry::new(&service, &user)?;
                entry.set_password(credential_raw)?;
                println!(
                    "  {} Credential saved to OS keyring ({}/{})",
                    style("*").green(),
                    service,
                    user
                );
            }
            #[cfg(not(feature = "vta-keyring"))]
            {
                println!(
                    "  {} Cannot save to keyring (vta-keyring feature not enabled)",
                    style("!").yellow()
                );
                println!("  Save it manually using your OS keyring tools.");
                println!(
                    "  Build the mediator with: {}",
                    style("--features vta-keyring").cyan()
                );
            }

            format!("keyring://{service}/{user}")
        }
        _ => unreachable!(),
    };

    println!();
    Ok(credential_config)
}

// ─── Step 3: Context ─────────────────────────────────────────────────────────

async fn step_context(client: &VtaClient) -> Result<String, Box<dyn std::error::Error>> {
    println!("{}", style("Step 3: VTA Context").bold());
    println!("  A context groups the mediator's DID and keys in the VTA.");
    println!();

    // List existing contexts
    let contexts = client.list_contexts().await?;
    let mut options: Vec<String> = contexts
        .contexts
        .iter()
        .map(|c| {
            let did_info = c
                .did
                .as_deref()
                .map(|d| format!(" (DID: {})", truncate_did(d)))
                .unwrap_or_else(|| " (no DID)".into());
            format!("{}{}", c.id, did_info)
        })
        .collect();
    options.push(style("[Create new context]").yellow().to_string());

    let selection = Select::new()
        .with_prompt("  Select context")
        .items(&options)
        .default(0)
        .interact()?;

    let context_id = if selection == contexts.contexts.len() {
        // Create new context
        let id: String = Input::new()
            .with_prompt("  Context ID")
            .with_initial_text("mediator")
            .interact_text()?;

        let name: String = Input::new()
            .with_prompt("  Context name")
            .with_initial_text("Messaging Mediator")
            .interact_text()?;

        let req = CreateContextRequest::new(&id, &name);
        client.create_context(req).await?;
        println!(
            "  {} Created context '{}'",
            style("*").green(),
            style(&id).cyan()
        );
        id
    } else {
        let ctx = &contexts.contexts[selection];
        println!(
            "  {} Using context '{}'",
            style("*").green(),
            style(&ctx.id).cyan()
        );
        ctx.id.clone()
    };

    println!();
    Ok(context_id)
}

// ─── Step 4: DID Setup ──────────────────────────────────────────────────────

async fn step_did(
    client: &VtaClient,
    context_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", style("Step 4: Mediator DID").bold());
    println!();

    // Check if context already has a DID
    let ctx = client.get_context(context_id).await?;
    if let Some(existing_did) = &ctx.did {
        println!(
            "  Context '{}' already has DID: {}",
            context_id,
            style(existing_did).cyan()
        );
        if !Confirm::new()
            .with_prompt("  Reconfigure DID?")
            .default(false)
            .interact()?
        {
            println!("  {} Keeping existing DID", style("*").green());
            println!();
            return Ok(());
        }
    }

    let options = vec![
        "Create a new did:webvh via VTA (recommended for new deployments)",
        "Import an existing DID and its private keys into VTA",
    ];

    let selection = Select::new()
        .with_prompt("  DID setup method")
        .items(&options)
        .default(0)
        .interact()?;

    match selection {
        0 => create_new_did(client, context_id).await?,
        1 => import_existing_did(client, context_id).await?,
        _ => unreachable!(),
    }

    println!();
    Ok(())
}

async fn create_new_did(
    client: &VtaClient,
    context_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("  Creating a new did:webvh for the mediator...");
    println!();

    // Check if VTA has webvh servers configured
    let servers_resp = client.list_webvh_servers().await?;
    let servers = &servers_resp.servers;

    if servers.is_empty() {
        return Err(
            "No did:webvh servers configured in VTA. \
             Add one via: cnm-cli webvh server add <url>"
                .into(),
        );
    }

    // Select server if multiple
    let server_id = if servers.len() == 1 {
        let label = servers[0].label.as_deref().unwrap_or(&servers[0].id);
        println!(
            "  Using webvh server: {}",
            style(label).cyan()
        );
        Some(servers[0].id.clone())
    } else {
        let server_options: Vec<String> = servers
            .iter()
            .map(|s| {
                let label = s.label.as_deref().unwrap_or("?");
                format!("{} ({})", s.id, label)
            })
            .collect();

        let sel = Select::new()
            .with_prompt("  Select webvh server")
            .items(&server_options)
            .default(0)
            .interact()?;

        Some(servers[sel].id.clone())
    };

    let req = CreateDidWebvhRequest {
        context_id: context_id.to_string(),
        server_id,
        url: None,
        path: None,
        label: Some("mediator".to_string()),
        portable: false,
        add_mediator_service: false,
        additional_services: None,
        pre_rotation_count: 1,
    };

    println!("  Creating DID (this may take a moment)...");
    let result = client.create_did_webvh(req).await?;

    println!(
        "  {} Created DID: {}",
        style("*").green(),
        style(&result.did).cyan()
    );

    // Update context with the new DID
    let update_req = UpdateContextRequest {
        name: None,
        did: Some(result.did),
        description: None,
    };
    client.update_context(context_id, update_req).await?;
    println!(
        "  {} Context '{}' updated with new DID",
        style("*").green(),
        context_id
    );

    Ok(())
}

async fn import_existing_did(
    client: &VtaClient,
    context_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    let did: String = Input::new()
        .with_prompt("  Paste the DID")
        .interact_text()?;

    let did = did.trim().to_string();

    // Resolve the DID document
    println!("  Resolving DID document...");
    let resolver = DIDCacheClient::new(
        DIDCacheConfigBuilder::default()
            .with_network_timeout(10)
            .build(),
    )
    .await
    .map_err(|e| format!("Could not start DID resolver: {e}"))?;

    let resolved = resolver
        .resolve(&did)
        .await
        .map_err(|e| format!("Could not resolve DID '{}': {e}", did))?;

    let doc = &resolved.doc;

    // Collect all verification methods and their roles
    let vm_roles = collect_vm_roles(doc);
    let vms = &doc.verification_method;

    if vms.is_empty() {
        return Err(format!("DID document for '{}' has no verification methods", did).into());
    }

    println!(
        "  Found {} verification method{}:",
        vms.len(),
        if vms.len() == 1 { "" } else { "s" }
    );

    for vm in vms {
        let vm_id = vm.id.to_string();
        let fragment = vm_id.rsplit_once('#').map(|(_, f)| f).unwrap_or(&vm_id);
        let key_type = detect_key_type(vm);
        let roles = vm_roles
            .get(&vm_id)
            .map(|r| r.join(", "))
            .unwrap_or_else(|| "none".into());

        println!(
            "    {} {} ({}) - {}",
            style("*").dim(),
            style(fragment).cyan(),
            style(format!("{key_type:?}")).yellow(),
            roles
        );
    }

    println!();
    println!("  For each key, provide the private key in multibase format.");
    println!(
        "  These will be securely imported into the VTA context '{}'.",
        style(context_id).cyan()
    );
    println!();

    for vm in vms {
        let vm_id = vm.id.to_string();
        let fragment = vm_id.rsplit_once('#').map(|(_, f)| f).unwrap_or(&vm_id);
        let key_type = detect_key_type(vm);

        let private_key: String = Password::new()
            .with_prompt(format!("  Private key for {fragment} ({key_type:?})"))
            .interact()?;

        let private_key = private_key.trim().to_string();
        if private_key.is_empty() {
            println!(
                "  {} Skipping {} (no key provided)",
                style("!").yellow(),
                fragment
            );
            continue;
        }

        let req = ImportKeyRequest {
            key_type: key_type.clone(),
            private_key_jwe: None,
            private_key_multibase: Some(private_key),
            label: Some(format!("mediator-{fragment}")),
            context_id: Some(context_id.to_string()),
        };

        client
            .import_key(req)
            .await
            .map_err(|e| format!("Failed to import key '{fragment}': {e}"))?;

        println!(
            "  {} Imported {} into VTA",
            style("*").green(),
            style(fragment).cyan()
        );
    }

    // Update context with the DID
    let update_req = UpdateContextRequest {
        name: None,
        did: Some(did.clone()),
        description: None,
    };
    client.update_context(context_id, update_req).await?;
    println!(
        "  {} Context '{}' updated with DID: {}",
        style("*").green(),
        context_id,
        style(&did).cyan()
    );

    Ok(())
}

/// Collect verification method IDs and their roles from the DID document.
fn collect_vm_roles(doc: &Document) -> HashMap<String, Vec<&'static str>> {
    let mut roles: HashMap<String, Vec<&'static str>> = HashMap::new();

    for vr in &doc.authentication {
        if let Some(id) = vr_id(vr) {
            roles.entry(id).or_default().push("authentication");
        }
    }
    for vr in &doc.assertion_method {
        if let Some(id) = vr_id(vr) {
            roles.entry(id).or_default().push("assertionMethod");
        }
    }
    for vr in &doc.key_agreement {
        if let Some(id) = vr_id(vr) {
            roles.entry(id).or_default().push("keyAgreement");
        }
    }
    for vr in &doc.capability_invocation {
        if let Some(id) = vr_id(vr) {
            roles.entry(id).or_default().push("capabilityInvocation");
        }
    }
    for vr in &doc.capability_delegation {
        if let Some(id) = vr_id(vr) {
            roles.entry(id).or_default().push("capabilityDelegation");
        }
    }

    roles
}

/// Extract the ID string from a VerificationRelationship.
fn vr_id(vr: &VerificationRelationship) -> Option<String> {
    match vr {
        VerificationRelationship::Reference(url) => Some(url.to_string()),
        VerificationRelationship::VerificationMethod(vm) => Some(vm.id.to_string()),
    }
}

/// Detect the key type from a verification method using its type string and multibase prefix.
fn detect_key_type(vm: &VerificationMethod) -> KeyType {
    let type_str = vm.type_.as_str();

    // Check type string first
    if type_str.contains("X25519") {
        return KeyType::X25519;
    }
    if type_str.contains("Ed25519") {
        return KeyType::Ed25519;
    }
    if type_str.contains("P256") || type_str.contains("P-256") || type_str.contains("secp256r1") {
        return KeyType::P256;
    }

    // For Multikey or JsonWebKey2020, inspect the key material
    if let Some(serde_json::Value::String(mb)) = vm.property_set.get("publicKeyMultibase") {
        // Multibase-multicodec prefixes:
        // z6Mk... = Ed25519 public key (0xed01)
        // z6LS... = X25519 public key (0xec01)
        if mb.starts_with("z6Mk") {
            return KeyType::Ed25519;
        }
        if mb.starts_with("z6LS") {
            return KeyType::X25519;
        }
    }

    if let Some(jwk) = vm.property_set.get("publicKeyJwk") {
        if let Some(crv) = jwk.get("crv").and_then(|v| v.as_str()) {
            return match crv {
                "Ed25519" => KeyType::Ed25519,
                "X25519" => KeyType::X25519,
                "P-256" => KeyType::P256,
                _ => KeyType::Ed25519, // fallback
            };
        }
    }

    // Default to Ed25519 for unknown types
    KeyType::Ed25519
}

// ─── Step 5: Save Config ─────────────────────────────────────────────────────

fn step_save_config(
    config_path: &str,
    credential_config: &str,
    context_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", style("Step 5: Update Configuration").bold());
    println!();

    if !std::path::Path::new(config_path).exists() {
        println!(
            "  {} Config file '{}' not found.",
            style("!").yellow(),
            config_path
        );
        println!("  Add the following to your mediator config:");
        println!();
        print_config_snippet(credential_config, context_id);
        return Ok(());
    }

    let content = fs::read_to_string(config_path)?;

    // Update mediator_did
    let content = replace_config_value(&content, "mediator_did", &format!("vta://{context_id}"));

    // Update mediator_secrets
    let content =
        replace_config_value(&content, "mediator_secrets", &format!("vta://{context_id}"));

    // Add or update [vta] section
    let content = upsert_vta_section(&content, credential_config, context_id);

    fs::write(config_path, &content)?;

    println!(
        "  {} Updated {}",
        style("*").green(),
        style(config_path).cyan()
    );
    println!(
        "    mediator_did = \"vta://{}\"",
        style(context_id).cyan()
    );
    println!(
        "    mediator_secrets = \"vta://{}\"",
        style(context_id).cyan()
    );
    println!(
        "    [vta] credential = \"{}...\"",
        style(&credential_config[..credential_config.len().min(30)]).dim()
    );

    Ok(())
}

/// Replace a top-level or section-level config value, handling commented-out lines.
fn replace_config_value(content: &str, key: &str, new_value: &str) -> String {
    let mut result = Vec::new();
    let mut replaced = false;

    for line in content.lines() {
        let trimmed = line.trim();
        // Match: key = "..." (not commented out)
        let is_match = trimmed.starts_with(key) && trimmed.contains('=');

        if is_match && !replaced {
            // Preserve leading whitespace
            let indent = &line[..line.len() - line.trim_start().len()];
            result.push(format!("{indent}{key} = \"{new_value}\""));
            replaced = true;
        } else {
            result.push(line.to_string());
        }
    }

    result.join("\n")
}

/// Add or replace the [vta] section in the config file.
fn upsert_vta_section(content: &str, credential_config: &str, context_id: &str) -> String {
    let vta_section = format!(
        "\n[vta]\ncredential = \"{credential_config}\"\ncontext = \"{context_id}\"\n"
    );

    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::new();
    let mut in_vta_section = false;
    let mut vta_section_replaced = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Detect start of [vta] section (commented or not)
        let is_vta_header = {
            let uncommented = trimmed.trim_start_matches('#').trim();
            uncommented == "[vta]"
        };

        if is_vta_header && !vta_section_replaced {
            // Replace the entire [vta] section
            in_vta_section = true;
            vta_section_replaced = true;
            result.push("[vta]".to_string());
            result.push(format!("credential = \"{credential_config}\""));
            result.push(format!("context = \"{context_id}\""));
            continue;
        }

        if in_vta_section {
            // Skip lines until we hit the next section or a separator
            let is_next_section = trimmed.starts_with('[') && !trimmed.starts_with("# [");
            let is_separator =
                trimmed.starts_with("### ***") && i + 1 < lines.len();

            if is_next_section || is_separator {
                in_vta_section = false;
                result.push(line.to_string());
            }
            // Skip old VTA section lines
            continue;
        }

        result.push(line.to_string());
    }

    let mut final_content = result.join("\n");

    // If no [vta] section existed, insert it before [server]
    if !vta_section_replaced {
        if let Some(pos) = final_content.find("\n[server]") {
            final_content.insert_str(pos, &vta_section);
        } else {
            // Fallback: append at end
            final_content.push_str(&vta_section);
        }
    }

    final_content
}

fn print_config_snippet(credential_config: &str, context_id: &str) {
    println!("  mediator_did = \"vta://{context_id}\"");
    println!();
    println!("  [security]");
    println!("  mediator_secrets = \"vta://{context_id}\"");
    println!();
    println!("  [vta]");
    println!("  credential = \"{credential_config}\"");
    println!("  context = \"{context_id}\"");
}

fn truncate_did(did: &str) -> String {
    if did.len() > 50 {
        format!("{}...{}", &did[..30], &did[did.len() - 15..])
    } else {
        did.to_string()
    }
}
