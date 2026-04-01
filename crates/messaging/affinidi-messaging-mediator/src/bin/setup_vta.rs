//! Interactive CLI wizard for configuring VTA integration with the mediator.
//!
//! Accepts a **Context Provision Bundle** from `pnm contexts provision` (recommended)
//! or a raw **Credential Bundle** from `cnm-cli auth credentials generate`.
//!
//! Build and run:
//!   cargo run --bin mediator-setup-vta --features setup [-- --config path/to/mediator.toml]
//!
//! Use `--rest` to resolve the VTA DID document and discover a `VTARest` service
//! endpoint for REST communication (instead of relying on the URL in the credential):
//!   cargo run --bin mediator-setup-vta --features setup -- --rest

use affinidi_did_common::{
    Document,
    verification_method::{VerificationMethod, VerificationRelationship},
};
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use aws_config;
use aws_sdk_secretsmanager;
use console::{Key, Term, style};
use dialoguer::{Confirm, Input, Select};
use std::{collections::HashMap, env, fs, process, sync::Mutex};
use vta_sdk::{
    client::{CreateContextRequest, CreateDidWebvhRequest, ImportKeyRequest, VtaClient},
    context_provision::ContextProvisionBundle,
    credentials::CredentialBundle,
    keys::KeyType,
    session::{SessionBackend, SessionStore},
};

const DEFAULT_CONFIG_PATH: &str = "conf/mediator.toml";

/// Parsed CLI arguments.
struct CliArgs {
    config: String,
    /// When true, resolve the VTA DID document and look for a VTARest service
    /// endpoint to use as the REST URL override (instead of DIDComm transport).
    rest: bool,
}

/// What the user pasted — either a full provision bundle or a plain credential.
enum BundleInput {
    /// Full provision bundle from `pnm contexts provision` — includes context, DID, secrets.
    Provision {
        bundle: ContextProvisionBundle,
        credential_raw: String,
    },
    /// Plain credential from `cnm-cli auth credentials generate` — manual setup required.
    Credential { credential_raw: String },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("\n{} {e}", style("Error:").red().bold());
        process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    println!();
    println!("{}", style("Mediator VTA Setup").bold().cyan());
    println!("{}", style("==================").dim());
    println!();

    // Step 1: Get and validate bundle/credential
    let (client, input, vta_rest_url) = step_credential(args.rest).await?;

    // Step 2: Choose credential storage
    let credential_raw = match &input {
        BundleInput::Provision { credential_raw, .. } => credential_raw,
        BundleInput::Credential { credential_raw } => credential_raw,
    };
    let credential_config = step_storage(credential_raw).await?;

    // Step 3: Context setup
    let context_id = step_context(&client, &input).await?;

    // Step 4: DID setup
    let did_doc_path = step_did(&client, &context_id, &input).await?;

    // Step 5: Save config
    step_save_config(
        &args.config,
        &credential_config,
        &context_id,
        did_doc_path.as_deref(),
        vta_rest_url.as_deref(),
    )?;

    println!();
    println!("{}", style("Setup complete!").green().bold());
    println!();
    println!("Start the mediator with:");
    println!("  cargo run --bin mediator");
    println!();

    Ok(())
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = env::args().collect();
    let mut config = DEFAULT_CONFIG_PATH.to_string();
    let mut rest = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" if i + 1 < args.len() => {
                config = args[i + 1].clone();
                i += 2;
            }
            "--rest" => {
                rest = true;
                i += 1;
            }
            _ => i += 1,
        }
    }
    CliArgs { config, rest }
}

// ─── Masked input helper ─────────────────────────────────────────────────────

/// Read a line of input, displaying `*` for each character typed/pasted.
fn read_masked(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let term = Term::stderr();
    term.write_str(prompt)?;

    let mut input = String::new();
    loop {
        match term.read_key()? {
            Key::Enter => {
                term.write_line("")?;
                break;
            }
            Key::Backspace => {
                if input.pop().is_some() {
                    term.clear_chars(1)?;
                }
            }
            Key::Char(c) if !c.is_control() => {
                input.push(c);
                term.write_str("*")?;
            }
            _ => {}
        }
    }
    Ok(input)
}

/// Try to extract the nested `credential` field from a base64url-encoded JSON bundle.
/// This handles the case where ContextProvisionBundle::decode() fails due to version
/// mismatch or unknown fields, but the nested credential is still valid.
fn try_extract_credential_from_json(raw_b64: &str) -> Option<String> {
    use base64::prelude::*;
    let json_bytes = BASE64_URL_SAFE_NO_PAD.decode(raw_b64).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&json_bytes).ok()?;
    json.get("credential")?.as_str().map(String::from)
}

/// Try to extract context_id and context_name from a base64url-encoded JSON bundle.
fn try_extract_context_from_json(raw_b64: &str) -> Option<(String, String)> {
    use base64::prelude::*;
    let json_bytes = BASE64_URL_SAFE_NO_PAD.decode(raw_b64).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&json_bytes).ok()?;
    let id = json.get("context_id")?.as_str()?.to_string();
    let name = json
        .get("context_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    Some((id, name))
}

/// Try to decode the raw input as a plain CredentialBundle.
/// Validates that the credential's DID is a did:key (required for authentication).
fn try_as_credential_bundle(
    raw: &str,
    provision_err: &impl std::fmt::Display,
) -> Result<BundleInput, Box<dyn std::error::Error>> {
    match CredentialBundle::decode(raw) {
        Ok(cred) if cred.did.starts_with("did:key:") => {
            println!(
                "  {} Decoded credential bundle (manual context/DID setup required)",
                style("*").green(),
            );
            Ok(BundleInput::Credential {
                credential_raw: raw.to_string(),
            })
        }
        Ok(cred) => {
            // Decoded but DID is not a did:key — likely a provision bundle that was
            // incorrectly decoded as a credential
            Err(format!(
                "The input appears to be a Context Provision Bundle, but could not be decoded:\n  \
                 {provision_err}\n\n  \
                 (The credential DID '{}' is not a did:key, which confirms this is not a \
                 plain Credential Bundle.)\n\n  \
                 This may be a version mismatch between the VTA and this tool. Try upgrading \
                 the mediator or re-provisioning the context with a compatible VTA version.",
                cred.did
            )
            .into())
        }
        Err(_) => Err(format!(
            "Could not decode input as a Context Provision Bundle or Credential Bundle.\n\n  \
             Provision bundle error: {provision_err}\n\n  \
             Make sure you pasted the full base64url string from either:\n  \
             - pnm contexts provision\n  \
             - cnm-cli auth credentials generate"
        )
        .into()),
    }
}

/// In-memory session backend for the ephemeral setup session.
///
/// The DIDComm session is only needed for the duration of the setup wizard
/// (to create DIDs via the VTA). No persistence to disk.
struct InMemoryBackend {
    data: Mutex<HashMap<String, String>>,
}

impl SessionBackend for InMemoryBackend {
    fn load(&self, key: &str) -> Option<String> {
        self.data.lock().unwrap().get(key).cloned()
    }
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn clear(&self, key: &str) {
        self.data.lock().unwrap().remove(key);
    }
}

/// Resolve the VTA DID document and look for a service with type "VTARest".
/// Returns the REST endpoint URL if found.
async fn resolve_vta_rest_url(vta_did: &str) -> Result<String, Box<dyn std::error::Error>> {
    let resolver = DIDCacheClient::new(
        DIDCacheConfigBuilder::default()
            .with_network_timeout(10)
            .build(),
    )
    .await
    .map_err(|e| format!("Could not start DID resolver: {e}"))?;

    let resolved = resolver
        .resolve(vta_did)
        .await
        .map_err(|e| format!("Could not resolve VTA DID '{}': {e}", vta_did))?;

    for svc in &resolved.doc.service {
        if svc.type_.iter().any(|t| t == "VTARest") {
            if let Some(url) = svc.service_endpoint.get_uri() {
                // get_uri() may return a quoted string from JSON, strip quotes
                let url = url.trim_matches('"').to_string();
                return Ok(url);
            }
        }
    }

    Err(format!(
        "VTA DID '{}' has no service with type \"VTARest\".\n  \
         The DID document must include a VTARest service endpoint for --rest to work.",
        vta_did
    )
    .into())
}

// ─── Step 1: Credential ─────────────────────────────────────────────────────

/// Returns (client, input, optional VTA REST URL discovered via --rest).
async fn step_credential(
    force_rest: bool,
) -> Result<(VtaClient, BundleInput, Option<String>), Box<dyn std::error::Error>> {
    println!("{}", style("Step 1: VTA Bundle").bold());
    println!("  Paste the bundle from your VTA provisioning:");
    println!(
        "  - Context Provision Bundle (from {})",
        style("pnm contexts provision").dim()
    );
    println!(
        "  - Or a Credential Bundle (from {})",
        style("cnm-cli auth credentials generate").dim()
    );
    println!();

    let raw = read_masked("  Bundle (base64url): ")?;
    let raw = raw.trim().to_string();

    if raw.is_empty() {
        return Err("Bundle cannot be empty".into());
    }

    // Try to decode as ContextProvisionBundle first, fall back to CredentialBundle.
    //
    // Important: if the input is a provision bundle but decode fails (version mismatch,
    // new fields, etc.), we try to extract the nested credential field from the raw JSON.
    // We do NOT blindly try CredentialBundle::decode on the original input, because a
    // provision bundle can partially deserialize as a credential with wrong field mappings
    // (e.g., the `did` field gets a non-did:key value, causing "not a did:key" errors).
    let input = match ContextProvisionBundle::decode(&raw) {
        Ok(bundle) => {
            println!("  {} Decoded context provision bundle", style("*").green(),);
            println!(
                "    Context: {} ({})",
                style(&bundle.context_id).cyan(),
                &bundle.context_name
            );
            if let Some(did) = &bundle.did {
                println!("    DID: {}", style(&did.id).cyan());
                println!(
                    "    Keys: {} secret{}",
                    did.secrets.len(),
                    if did.secrets.len() == 1 { "" } else { "s" }
                );
            }

            let credential_raw = bundle.credential.clone();
            BundleInput::Provision {
                bundle,
                credential_raw,
            }
        }
        Err(provision_err) => {
            // Provision bundle decode failed. Try to extract the nested credential
            // from the raw JSON in case it's a provision bundle with unknown fields.
            if let Some(credential_raw) = try_extract_credential_from_json(&raw) {
                // Validate the extracted credential
                match CredentialBundle::decode(&credential_raw) {
                    Ok(cred) if cred.did.starts_with("did:key:") => {
                        println!(
                            "  {} Decoded provision bundle (extracted credential)",
                            style("*").green(),
                        );
                        // Try to extract context info from the raw JSON
                        if let Some((ctx_id, ctx_name)) = try_extract_context_from_json(&raw) {
                            println!("    Context: {} ({})", style(&ctx_id).cyan(), ctx_name);
                        }
                        BundleInput::Credential { credential_raw }
                    }
                    _ => {
                        // Extracted credential is also invalid, try the raw input as a plain credential
                        try_as_credential_bundle(&raw, &provision_err)?
                    }
                }
            } else {
                // No nested credential found, try the raw input as a plain credential
                try_as_credential_bundle(&raw, &provision_err)?
            }
        }
    };

    // Authenticate
    let credential_raw = match &input {
        BundleInput::Provision { credential_raw, .. } => credential_raw,
        BundleInput::Credential { credential_raw } => credential_raw,
    };

    // If --rest is set, resolve the VTA DID and look for a VTARest service endpoint
    // to use as the REST URL override. This avoids routing through DIDComm transport.
    let mut vta_rest_url: Option<String> = None;

    if force_rest {
        print!("  Resolving VTA DID for REST endpoint...");
        let credential = CredentialBundle::decode(credential_raw)
            .map_err(|e| format!("Invalid credential: {e}"))?;

        match resolve_vta_rest_url(&credential.vta_did).await {
            Ok(url) => {
                println!(
                    "\r  {} Found VTARest service: {}         ",
                    style("*").green(),
                    style(&url).cyan()
                );
                vta_rest_url = Some(url);
            }
            Err(e) => {
                println!("\r  {} {}         ", style("!").yellow(), e);
            }
        }
    }

    print!("  Authenticating to VTA via DIDComm...");

    // The setup wizard needs a full DIDComm session (not just REST) because
    // operations like create_did_webvh require the VTA to send DIDComm messages
    // to the webvh server through its mediator. We use an ephemeral in-memory
    // session backend — it's only needed for the duration of this wizard.
    let credential = CredentialBundle::decode(credential_raw)
        .map_err(|e| format!("Invalid credential: {e}"))?;

    let vta_url = vta_rest_url
        .as_deref()
        .or(credential.vta_url.as_deref())
        .ok_or("VTA URL not found in credential or --rest. Set [vta].url in config.")?;

    let backend = InMemoryBackend {
        data: Mutex::new(HashMap::new()),
    };
    let store = SessionStore::with_backend(Box::new(backend));
    let session_key = "mediator-setup";

    store
        .login(credential_raw, vta_url, session_key)
        .await
        .map_err(|e| format!("VTA authentication failed: {e}"))?;

    // Pass None for url_override so connect() resolves the VTA DID document
    // and uses DIDComm transport through the VTA's mediator (not REST).
    let client = store
        .connect(session_key, None)
        .await
        .map_err(|e| format!("Could not establish DIDComm session with VTA: {e}"))?;

    println!(
        "\r  {} Authenticated to VTA at {}         ",
        style("*").green(),
        style(client.base_url()).cyan()
    );
    println!();

    Ok((client, input, vta_rest_url))
}

// ─── Step 2: Credential Storage ──────────────────────────────────────────────

/// Returns the credential config string for mediator.toml (e.g., "string://eyJ...")
async fn step_storage(credential_raw: &str) -> Result<String, Box<dyn std::error::Error>> {
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
            let config = format!("string://{credential_raw}");
            println!(
                "  {} Credential will be embedded in config file",
                style("*").green()
            );
            config
        }
        1 => {
            let secret_name: String = Input::new()
                .with_prompt("  AWS Secret name")
                .with_initial_text("mediator/vta-credential")
                .interact_text()?;

            println!("  Saving credential to AWS Secrets Manager...");

            let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .load()
                .await;
            let asm = aws_sdk_secretsmanager::Client::new(&aws_config);

            // Try to create the secret; if it already exists, update it
            match asm
                .create_secret()
                .name(&secret_name)
                .secret_string(credential_raw)
                .send()
                .await
            {
                Ok(_) => {
                    println!(
                        "  {} Created secret '{}'",
                        style("*").green(),
                        style(&secret_name).cyan()
                    );
                }
                Err(e) => {
                    // Use Debug format for full error chain; Display only says "service error"
                    let err_detail = format!("{e:?}");
                    if err_detail.contains("ResourceExistsException")
                        || err_detail.contains("already exists")
                    {
                        // Secret exists — update it
                        asm.put_secret_value()
                            .secret_id(&secret_name)
                            .secret_string(credential_raw)
                            .send()
                            .await
                            .map_err(|e| {
                                format!("Could not update existing secret '{secret_name}': {e:?}")
                            })?;
                        println!(
                            "  {} Updated existing secret '{}'",
                            style("*").green(),
                            style(&secret_name).cyan()
                        );
                    } else {
                        return Err(format!(
                            "Could not create secret '{secret_name}' in AWS Secrets Manager:\n  {err_detail}"
                        ).into());
                    }
                }
            }

            println!(
                "  Build the mediator with: {}",
                style("--features vta-aws-secrets").cyan()
            );

            format!("aws_secrets://{secret_name}")
        }
        2 => {
            let service: String = Input::new()
                .with_prompt("  Keyring service name")
                .with_initial_text("affinidi-mediator")
                .interact_text()?;

            let user: String = Input::new()
                .with_prompt("  Keyring user")
                .with_initial_text("vta-credential")
                .interact_text()?;

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

async fn step_context(
    client: &VtaClient,
    input: &BundleInput,
) -> Result<String, Box<dyn std::error::Error>> {
    println!("{}", style("Step 3: VTA Context").bold());

    // If from provision bundle, context is already known
    if let BundleInput::Provision { bundle, .. } = input {
        println!(
            "  Context from bundle: {} ({})",
            style(&bundle.context_id).cyan(),
            &bundle.context_name
        );

        if Confirm::new()
            .with_prompt(format!("  Use context '{}'?", bundle.context_id))
            .default(true)
            .interact()?
        {
            println!(
                "  {} Using context '{}'",
                style("*").green(),
                style(&bundle.context_id).cyan()
            );
            println!();
            return Ok(bundle.context_id.clone());
        }
        println!("  Falling back to manual context selection...");
        println!();
    } else {
        println!("  A context groups the mediator's DID and keys in the VTA.");
        println!();
    }

    // Manual context selection
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

/// Returns an optional path to a saved DID document file (for did_web_self_hosted).
async fn step_did(
    client: &VtaClient,
    context_id: &str,
    input: &BundleInput,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    println!("{}", style("Step 4: Mediator DID").bold());
    println!();

    // If provision bundle has a DID, use it directly — keys are already in VTA
    if let BundleInput::Provision { bundle, .. } = input {
        if let Some(provisioned_did) = &bundle.did {
            println!("  DID from bundle: {}", style(&provisioned_did.id).cyan());
            println!(
                "  {} key{} already provisioned in VTA",
                provisioned_did.secrets.len(),
                if provisioned_did.secrets.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );

            // Update context with the DID (may already be set, but ensure it's correct)
            client
                .update_context_did(context_id, &provisioned_did.id)
                .await?;
            println!(
                "  {} Context '{}' configured with DID",
                style("*").green(),
                context_id
            );

            // If there's a log entry, offer to save it for did:web self-hosting
            let doc_path =
                if provisioned_did.log_entry.is_some() || provisioned_did.did_document.is_some() {
                    if Confirm::new()
                        .with_prompt("  Save DID document for self-hosting (did:web)?")
                        .default(true)
                        .interact()?
                    {
                        let path: String = Input::new()
                            .with_prompt("  DID document path")
                            .with_initial_text("conf/mediator_did.json")
                            .interact_text()?;

                        let content = if let Some(log_entry) = &provisioned_did.log_entry {
                            log_entry.clone()
                        } else if let Some(doc) = &provisioned_did.did_document {
                            serde_json::to_string_pretty(doc)?
                        } else {
                            unreachable!()
                        };

                        fs::write(&path, &content)?;
                        println!(
                            "  {} Saved DID document to {}",
                            style("*").green(),
                            style(&path).cyan()
                        );
                        Some(path)
                    } else {
                        None
                    }
                } else {
                    None
                };

            println!();
            return Ok(doc_path);
        }
    }

    // No DID from bundle — check if context already has one
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
            return Ok(None);
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
    Ok(None)
}

async fn create_new_did(
    client: &VtaClient,
    context_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("  Creating a new did:webvh for the mediator...");
    println!();

    let servers_resp = client.list_webvh_servers().await?;
    let servers = &servers_resp.servers;

    if servers.is_empty() {
        return Err("No did:webvh servers configured in VTA. \
             Add one via: cnm-cli webvh server add <url>"
            .into());
    }

    let server_id = if servers.len() == 1 {
        let label = servers[0].label.as_deref().unwrap_or(&servers[0].id);
        println!("  Using webvh server: {}", style(label).cyan());
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

    client.update_context_did(context_id, &result.did).await?;
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
        "  These will be imported into the VTA context '{}'.",
        style(context_id).cyan()
    );
    println!();

    for vm in vms {
        let vm_id = vm.id.to_string();
        let fragment = vm_id.rsplit_once('#').map(|(_, f)| f).unwrap_or(&vm_id);
        let key_type = detect_key_type(vm);

        let private_key = read_masked(&format!("  Private key for {fragment} ({key_type:?}): "))?;
        let private_key = private_key.trim().to_string();

        if private_key.is_empty() {
            println!(
                "  {} Skipping {} (no key provided)",
                style("!").yellow(),
                fragment
            );
            continue;
        }

        // Decode multibase-multicodec format and validate key type matches the DID document.
        // The VTA expects raw key bytes in multibase (no multicodec prefix).
        let private_key = decode_and_validate_private_key(&private_key, &key_type, fragment)?;

        // Use the full verification method ID as the label so that the mediator's
        // secrets resolver can match keys to DID document verification methods.
        let req = ImportKeyRequest {
            key_type: key_type.clone(),
            private_key_jwe: None,
            private_key_multibase: Some(private_key),
            label: Some(vm_id.clone()),
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

    client.update_context_did(context_id, &did).await?;
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

fn vr_id(vr: &VerificationRelationship) -> Option<String> {
    match vr {
        VerificationRelationship::Reference(url) => Some(url.to_string()),
        VerificationRelationship::VerificationMethod(vm) => Some(vm.id.to_string()),
    }
}

/// Decode a multibase-multicodec encoded private key, validate the key type matches
/// what the DID document expects, and return the raw key bytes as a plain multibase string
/// (without multicodec prefix) for the VTA import API.
///
/// If the input is NOT multicodec-encoded (just raw bytes in multibase), returns it as-is.
fn decode_and_validate_private_key(
    multibase_key: &str,
    expected_type: &KeyType,
    fragment: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use affinidi_encoding::{
        Codec, ED25519_PRIV, P256_PRIV, X25519_PRIV, decode_multikey_with_codec, encode_base58btc,
    };

    // Try to decode as multibase-multicodec
    match decode_multikey_with_codec(multibase_key) {
        Ok((codec_value, raw_bytes)) => {
            // Validate the codec matches the expected key type
            let decoded_codec = Codec::from_u64(codec_value);
            let (expected_codec, expected_name) = match expected_type {
                KeyType::Ed25519 => (ED25519_PRIV, "Ed25519"),
                KeyType::X25519 => (X25519_PRIV, "X25519"),
                KeyType::P256 => (P256_PRIV, "P-256"),
            };

            match decoded_codec {
                Codec::Unknown(_) => {
                    // Unknown codec — might be raw bytes that happened to parse.
                    // Return the raw bytes as multibase, let VTA validate.
                }
                _ if codec_value == expected_codec => {
                    // Codec matches expected type
                }
                _ => {
                    return Err(format!(
                        "Key type mismatch for '{fragment}': DID document expects {expected_name} \
                         but the private key is encoded as {decoded_codec:?}"
                    )
                    .into());
                }
            }

            // Re-encode raw bytes as plain multibase base58btc (no multicodec prefix)
            Ok(encode_base58btc(&raw_bytes))
        }
        Err(_) => {
            // Not valid multicodec — might already be raw bytes in multibase.
            // Return as-is, let the VTA validate.
            Ok(multibase_key.to_string())
        }
    }
}

/// Detect the key type from a verification method using its type string and multibase prefix.
fn detect_key_type(vm: &VerificationMethod) -> KeyType {
    let type_str = vm.type_.as_str();

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
                _ => KeyType::Ed25519,
            };
        }
    }

    KeyType::Ed25519
}

// ─── Step 5: Save Config ─────────────────────────────────────────────────────

fn step_save_config(
    config_path: &str,
    credential_config: &str,
    context_id: &str,
    did_doc_path: Option<&str>,
    vta_rest_url: Option<&str>,
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
        print_config_snippet(credential_config, context_id, did_doc_path, vta_rest_url);
        return Ok(());
    }

    let content = fs::read_to_string(config_path)?;

    // Update mediator_did
    let content = replace_config_value(&content, "mediator_did", &format!("vta://{context_id}"));

    // Update mediator_secrets
    let content =
        replace_config_value(&content, "mediator_secrets", &format!("vta://{context_id}"));

    // Update did_web_self_hosted if we saved a DID document
    let content = if let Some(path) = did_doc_path {
        replace_config_value(&content, "did_web_self_hosted", &format!("file://{path}"))
    } else {
        content
    };

    // Add or update [vta] section
    let content = upsert_vta_section(&content, credential_config, context_id, vta_rest_url);

    fs::write(config_path, &content)?;

    println!(
        "  {} Updated {}",
        style("*").green(),
        style(config_path).cyan()
    );
    println!("    mediator_did = \"vta://{}\"", style(context_id).cyan());
    println!(
        "    mediator_secrets = \"vta://{}\"",
        style(context_id).cyan()
    );
    if let Some(path) = did_doc_path {
        println!(
            "    did_web_self_hosted = \"file://{}\"",
            style(path).cyan()
        );
    }
    if let Some(url) = vta_rest_url {
        println!("    [vta] url = \"{}\"", style(url).cyan());
    }
    println!(
        "    [vta] credential = \"{}...\"",
        style(&credential_config[..credential_config.len().min(30)]).dim()
    );

    Ok(())
}

/// Replace a config value in the TOML content (only un-commented lines).
fn replace_config_value(content: &str, key: &str, new_value: &str) -> String {
    let mut result = Vec::new();
    let mut replaced = false;

    for line in content.lines() {
        let trimmed = line.trim();
        let is_match = trimmed.starts_with(key) && trimmed.contains('=');

        if is_match && !replaced {
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
fn upsert_vta_section(
    content: &str,
    credential_config: &str,
    context_id: &str,
    vta_rest_url: Option<&str>,
) -> String {
    let url_line = vta_rest_url
        .map(|u| format!("\nurl = \"{u}\""))
        .unwrap_or_default();
    let vta_section = format!(
        "\n[vta]\ncredential = \"{credential_config}\"\ncontext = \"{context_id}\"{url_line}\n"
    );

    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::new();
    let mut in_vta_section = false;
    let mut vta_section_replaced = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        let is_vta_header = {
            let uncommented = trimmed.trim_start_matches('#').trim();
            uncommented == "[vta]"
        };

        if is_vta_header && !vta_section_replaced {
            in_vta_section = true;
            vta_section_replaced = true;
            result.push("[vta]".to_string());
            result.push(format!("credential = \"{credential_config}\""));
            result.push(format!("context = \"{context_id}\""));
            if let Some(url) = vta_rest_url {
                result.push(format!("url = \"{url}\""));
            }
            continue;
        }

        if in_vta_section {
            let is_next_section = trimmed.starts_with('[') && !trimmed.starts_with("# [");
            let is_separator = trimmed.starts_with("### ***") && i + 1 < lines.len();

            if is_next_section || is_separator {
                in_vta_section = false;
                result.push(line.to_string());
            }
            continue;
        }

        result.push(line.to_string());
    }

    let mut final_content = result.join("\n");

    if !vta_section_replaced {
        if let Some(pos) = final_content.find("\n[server]") {
            final_content.insert_str(pos, &vta_section);
        } else {
            final_content.push_str(&vta_section);
        }
    }

    final_content
}

fn print_config_snippet(
    credential_config: &str,
    context_id: &str,
    did_doc_path: Option<&str>,
    vta_rest_url: Option<&str>,
) {
    println!("  mediator_did = \"vta://{context_id}\"");
    println!();
    println!("  [server]");
    if let Some(path) = did_doc_path {
        println!("  did_web_self_hosted = \"file://{path}\"");
    }
    println!();
    println!("  [security]");
    println!("  mediator_secrets = \"vta://{context_id}\"");
    println!();
    println!("  [vta]");
    println!("  credential = \"{credential_config}\"");
    println!("  context = \"{context_id}\"");
    if let Some(url) = vta_rest_url {
        println!("  url = \"{url}\"");
    }
}

fn truncate_did(did: &str) -> String {
    if did.len() > 50 {
        format!("{}...{}", &did[..30], &did[did.len() - 15..])
    } else {
        did.to_string()
    }
}
