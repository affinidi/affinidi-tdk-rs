mod app;
mod cli;
mod config_writer;
mod consts;
mod docker;
mod generators;
mod recipe;
mod reprovision;
mod sealed_handoff;
mod secrets;
mod ui;
mod vta_connect;

use std::{
    io::{self, Stdout, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use crossterm::event::EventStream;
use ratatui::{
    crossterm::{
        event::{
            DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, Event, KeyCode,
            KeyEventKind, KeyModifiers,
        },
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    },
    prelude::*,
};
use tokio_stream::StreamExt;
use tui_input::InputRequest;

use app::{InputMode, WizardApp, WizardConfig};
use cli::Args;
use consts::*;

const RENDERING_TICK_RATE: Duration = Duration::from_millis(250);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // `--uninstall` is mutually exclusive with every other mode. Run it
    // up-front so flag combinations like `--uninstall --from recipe.toml`
    // can't accidentally re-provision after teardown.
    if args.uninstall {
        return reprovision::run_uninstall(&args.config).await;
    }

    // Online-VTA connection phases take precedence over every other entry
    // point: they are self-contained and exit without touching the wizard
    // config pipeline.
    if let Some(path) = args.setup_key_out.as_ref() {
        return vta_connect::cli::run_phase1_init(
            path,
            args.vta_did.as_deref(),
            args.vta_context.as_deref(),
        )
        .await;
    }
    if let Some(path) = args.setup_key_file.as_ref() {
        let vta_did = vta_connect::cli::validate_phase2_args(&args.vta_did)?;
        let mediator_url = args.mediator_url.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "--mediator-url is required for --setup-key-file (Phase 2). The VTA's \
                 didcomm-mediator template renders the mediator DID using this URL."
            )
        })?;
        return vta_connect::cli::run_phase2_connect(
            path,
            vta_did,
            args.vta_context.as_deref(),
            mediator_url,
            args.wait_for_acl,
        )
        .await;
    }

    if let Some(ref recipe_path) = args.from {
        return run_from_recipe(recipe_path, args.force_reprovision).await;
    }

    if args.non_interactive {
        return run_non_interactive(args).await;
    }

    // Check for existing config — refuse to silently rotate live keys
    // unless the operator explicitly opts in with `--force-reprovision`.
    // The unified backend stores the JWT signing key, the admin
    // credential, and the operating keys; rotating any of them while a
    // mediator is running invalidates active sessions.
    let config_path = args.config.clone();
    let config_path_obj = std::path::Path::new(&config_path);
    if let Some(setup) = reprovision::inspect_existing(config_path_obj).await? {
        if setup.is_provisioned() && !args.force_reprovision {
            reprovision::refuse_overwrite(config_path_obj, &setup);
        }
        if config_path_obj.exists() {
            // Operator opted in (or there were no provisioned keys —
            // e.g. backend was wiped manually). Back up the existing
            // mediator.toml before generating the new one so the
            // previous configuration is recoverable.
            std::fs::copy(&config_path, format!("{config_path}.bak"))?;
            eprintln!(
                "Existing {config_path} backed up to {config_path}.bak before re-provisioning."
            );
        }
    }

    let mut app = WizardApp::new(config_path);

    // Apply CLI-provided options to pre-fill wizard
    apply_cli_args(&args, &mut app.config);
    app.vta_did_prefill = args.vta_did.clone();
    app.vta_context_prefill = args.vta_context.clone();

    let mut terminal = setup_terminal()?;

    let result = run_event_loop(&mut terminal, &mut app).await;

    restore_terminal(&mut terminal)?;

    match result {
        Ok(()) => {
            if app.write_config {
                print_banner();

                // Config file location was collected inside the TUI
                // (WizardStep::Output) — no stdin prompt here.

                println!("  Generating cryptographic material...\n");
                match generate_and_write(&app.config, app.vta_session.as_ref(), true).await {
                    Ok(()) => {
                        offer_build_and_guidance(&app.config);
                    }
                    Err(e) => {
                        eprintln!("\n\x1b[31mError: {e}\x1b[0m");
                        std::process::exit(1);
                    }
                }
            } else {
                println!("\n\x1b[33mSetup cancelled.\x1b[0m");
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Apply CLI arguments to the wizard config as pre-filled defaults.
fn apply_cli_args(args: &Args, config: &mut WizardConfig) {
    if let Some(ref deployment) = args.deployment {
        config.deployment_type = deployment.to_string();
    }
    if let Some(ref protocol) = args.protocol {
        match protocol {
            cli::Protocol::Didcomm => {
                config.didcomm_enabled = true;
            }
            cli::Protocol::Tsp => {
                config.tsp_enabled = true;
            }
        }
    }
    if let Some(ref did_method) = args.did_method {
        config.did_method = did_method.to_string();
    }
    if let Some(ref public_url) = args.public_url {
        config.public_url = public_url.clone();
    }
    if let Some(ref secret_storage) = args.secret_storage {
        config.secret_storage = secret_storage.to_string();
    }
    if let Some(ref ssl) = args.ssl {
        config.ssl_mode = ssl.to_string();
    }
    if let Some(ref database_url) = args.database_url {
        config.database_url = database_url.clone();
    }
    if let Some(ref admin) = args.admin {
        config.admin_did_mode = admin.to_string();
    }
    if let Some(ref listen_address) = args.listen_address {
        config.listen_address = listen_address.clone();
    }
}

/// Non-interactive mode: build config from CLI args + deployment defaults, then generate.
async fn run_non_interactive(args: Args) -> anyhow::Result<()> {
    // Same re-run safety story as the interactive flow — refuse to
    // overwrite an existing setup unless `--force-reprovision` is set.
    let existing_path = std::path::Path::new(&args.config);
    if let Some(setup) = reprovision::inspect_existing(existing_path).await? {
        if setup.is_provisioned() && !args.force_reprovision {
            reprovision::refuse_overwrite(existing_path, &setup);
        }
    }

    let deployment = args.deployment.unwrap_or(cli::DeploymentType::Local);

    let mut config = WizardConfig::default();
    config.config_path = args.config.clone();

    // Apply deployment defaults (identical across all deployment types)
    config.deployment_type = deployment.to_string();
    config.use_vta = true;
    config.vta_mode = VTA_MODE_ONLINE.into();
    config.didcomm_enabled = true;
    config.did_method = DID_VTA.into();
    config.secret_storage = STORAGE_KEYRING.into();
    config.ssl_mode = SSL_NONE.into();
    config.database_url = DEFAULT_REDIS_URL.into();
    config.admin_did_mode = ADMIN_GENERATE.into();

    // Override with any explicit CLI args
    apply_cli_args(&args, &mut config);

    // Validate required fields for did:webvh
    if config.did_method == DID_WEBVH && config.public_url.is_empty() {
        anyhow::bail!("--public-url is required when using did:webvh in non-interactive mode");
    }

    println!("Mediator Setup (non-interactive)");
    println!("  Deployment:   {}", config.deployment_type);
    println!(
        "  VTA:          {}",
        if config.use_vta {
            format!("Enabled ({})", config.vta_mode)
        } else {
            "Disabled".into()
        }
    );
    println!("  Protocol:     {}", config.protocol_display());
    println!("  DID method:   {}", config.did_method);
    println!("  Key storage:  {}", config.secret_storage);
    println!("  SSL/TLS:      {}", config.ssl_mode);
    println!("  Database:     {}", config.database_url);
    println!("  Admin:        {}", config.admin_did_mode);
    println!();
    println!("Generating cryptographic material...");

    // Non-interactive / recipe paths don't run the online-VTA sub-flow, so
    // there's no captured session — VTA-managed DID creation isn't
    // supported from `--from` / `--non-interactive` yet.
    generate_and_write(&config, None, true).await?;
    offer_build_and_guidance(&config);

    Ok(())
}

/// Run from a declarative build recipe TOML file (fully non-interactive).
async fn run_from_recipe(recipe_path: &str, force_reprovision: bool) -> anyhow::Result<()> {
    let recipe = recipe::load(recipe_path)?;
    let mut config = recipe::to_wizard_config(&recipe)?;

    // Re-run safety: refuse to overwrite an existing provisioned setup
    // unless the operator opts in. This matches the interactive flow so
    // recipe-driven CI can't silently rotate live keys.
    let target = std::path::Path::new(&config.config_path);
    if let Some(setup) = reprovision::inspect_existing(target).await? {
        if setup.is_provisioned() && !force_reprovision {
            reprovision::refuse_overwrite(target, &setup);
        }
    }

    // Check if database URL needs credentials — allow env var override
    if let Ok(env_url) = std::env::var("DATABASE_URL") {
        config.database_url = env_url;
    } else if recipe::needs_database_credentials(&config.database_url) {
        eprintln!("The database URL in the recipe needs credentials.");
        eprintln!("Set DATABASE_URL environment variable or update the recipe.");
        anyhow::bail!("Database credentials required but not provided");
    }

    print_banner();
    println!("  \x1b[2mFrom recipe: {recipe_path}\x1b[0m\n");
    println!("  Deployment:   {}", config.deployment_type);
    println!(
        "  VTA:          {}",
        if config.use_vta {
            format!("Enabled ({})", config.vta_mode)
        } else {
            "Disabled".into()
        }
    );
    println!("  Protocol:     {}", config.protocol_display());
    println!("  DID method:   {}", config.did_method);
    println!("  Key storage:  {}", config.secret_storage);
    println!("  SSL/TLS:      {}", config.ssl_mode);
    println!("  Database:     {}", config.database_url);
    println!("  Admin:        {}", config.admin_did_mode);
    println!("  Config file:  {}", config.config_path);
    println!("  Listen:       {}", config.listen_address);
    println!();
    println!("  Generating cryptographic material...\n");

    generate_and_write(&config, None, false).await?;

    let features = build_features(&config);

    // Auto-install if recipe says so
    if recipe.install.enabled {
        let install_root = recipe.install.path.as_deref();
        let install_args = build_install_args(&features, install_root);
        let install_cmd = format!("cargo {}", install_args.join(" "));

        let workspace_root = find_workspace_root();
        let build_dir = workspace_root
            .ok_or_else(|| anyhow::anyhow!("Cannot find workspace root for cargo install"))?;

        let install_location = install_root.map(|r| format!("{r}/bin")).unwrap_or_else(|| {
            let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| "~/.cargo".into());
            format!("{cargo_home}/bin")
        });

        println!("  \x1b[1mInstall command:\x1b[0m\n    \x1b[36m{install_cmd}\x1b[0m\n");
        println!(
            "  \x1b[38;5;69mInstalling mediator to {install_location} \
             (this may take a few minutes)...\x1b[0m\n"
        );

        let status = Command::new("cargo")
            .args(&install_args)
            .current_dir(&build_dir)
            .status();

        match status {
            Ok(exit) if exit.success() => {
                println!("\n  \x1b[32m\u{2714} Installation successful!\x1b[0m\n");
                print_run_command(&config.config_path, &install_location);
            }
            Ok(exit) => {
                anyhow::bail!("cargo install failed with exit code: {}", exit);
            }
            Err(e) => {
                anyhow::bail!("Failed to run cargo: {}", e);
            }
        }
    } else {
        let install_cmd = format!("cargo {}", build_install_args(&features, None).join(" "));
        let build_cmd = format!("cargo {}", build_cargo_args(&features).join(" "));
        println!("  \x1b[1mTo install:\x1b[0m\n    \x1b[36m{install_cmd}\x1b[0m\n");
        println!("  \x1b[1mTo build from source:\x1b[0m\n    \x1b[36m{build_cmd}\x1b[0m\n");
    }

    print_final_summary(&config);

    Ok(())
}

async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut WizardApp,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(RENDERING_TICK_RATE);
    let mut crossterm_events = EventStream::new();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Pick up any events from the online-VTA runner task so
                // the diagnostic checklist updates without waiting on a
                // keypress.
                app.drain_vta_events();
            }
            maybe_event = crossterm_events.next() => match maybe_event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    handle_key_event(app, key.code, key.modifiers);
                },
                Some(Ok(Event::Paste(text))) => {
                    app.paste_text(&text);
                },
                None => break,
                _ => (),
            },
        }

        if app.should_quit {
            break;
        }

        terminal
            .draw(|frame| ui::render(frame, app))
            .context("could not render to the terminal")?;
    }

    Ok(())
}

fn handle_key_event(app: &mut WizardApp, code: KeyCode, modifiers: KeyModifiers) {
    // F10 or Ctrl+C quits immediately
    if code == KeyCode::F(10)
        || (code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL))
    {
        app.should_quit = true;
        return;
    }

    // Bare `c` / `v` / `p` on the sealed-handoff RequestGenerated screen
    // copy one of: the bootstrap request JSON, the `vta bootstrap seal`
    // command, or the `pnm-cli bootstrap seal` command to the system
    // clipboard. Placed ahead of the mode-based dispatch so it fires in
    // both Selecting and TextInput modes — the RequestGenerated phase
    // uses Selecting mode today, but keeping the hotkey mode-agnostic
    // is cheap and future-proofs against UI shuffling.
    if !modifiers.contains(KeyModifiers::CONTROL)
        && matches!(
            code,
            KeyCode::Char('c')
                | KeyCode::Char('C')
                | KeyCode::Char('v')
                | KeyCode::Char('V')
                | KeyCode::Char('p')
                | KeyCode::Char('P')
                | KeyCode::Char('f')
                | KeyCode::Char('F')
        )
        && app.in_sealed_handoff_subflow()
    {
        if let Some(state) = app.sealed_handoff.as_mut() {
            if state.phase == crate::sealed_handoff::SealedPhase::RequestGenerated {
                // Primary command hotkey: `p` for AdminOnly
                // (pnm contexts bootstrap), `v` for FullSetup
                // (vta bootstrap provision-integration). `f` copies
                // the fallback command when one exists (AdminOnly's
                // raw `vta bootstrap seal` invocation).
                match code {
                    KeyCode::Char('c') | KeyCode::Char('C') => {
                        state.copy_request_to_clipboard();
                    }
                    KeyCode::Char('p')
                    | KeyCode::Char('P')
                    | KeyCode::Char('v')
                    | KeyCode::Char('V') => {
                        state.copy_primary_command_to_clipboard();
                    }
                    KeyCode::Char('f') | KeyCode::Char('F') => {
                        state.copy_fallback_command_to_clipboard();
                    }
                    _ => unreachable!("outer matches! guards the code space"),
                }
                return;
            }
        }
    }

    // Bare `c` / `C` on the online-VTA AwaitingAcl screen copies the
    // rendered `pnm acl create` command to the system clipboard. Same
    // early-return placement as the sealed-handoff hotkey so it fires
    // regardless of InputMode.
    if !modifiers.contains(KeyModifiers::CONTROL)
        && matches!(code, KeyCode::Char('c') | KeyCode::Char('C'))
    {
        if let Some(state) = app.vta_connect.as_mut() {
            if state.phase == crate::vta_connect::ConnectPhase::AwaitingAcl {
                state.copy_acl_command_to_clipboard();
                return;
            }
        }
    }

    match app.mode {
        InputMode::TextInput => match code {
            KeyCode::Enter => app.confirm_text_input(),
            KeyCode::Esc => app.go_back(),
            KeyCode::Char(c) => {
                app.handle_text_input(InputRequest::InsertChar(c));
            }
            KeyCode::Backspace => {
                app.handle_text_input(InputRequest::DeletePrevChar);
            }
            KeyCode::Delete => {
                app.handle_text_input(InputRequest::DeleteNextChar);
            }
            KeyCode::Left => {
                app.handle_text_input(InputRequest::GoToPrevChar);
            }
            KeyCode::Right => {
                app.handle_text_input(InputRequest::GoToNextChar);
            }
            KeyCode::Home => {
                app.handle_text_input(InputRequest::GoToStart);
            }
            KeyCode::End => {
                app.handle_text_input(InputRequest::GoToEnd);
            }
            _ => {}
        },
        InputMode::Selecting => match app.focus {
            app::FocusPanel::Content => match code {
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Char(' ') if app.current_step.is_multi_select() => {
                    app.toggle_current_multi_select();
                }
                KeyCode::Enter => app.select_current(),
                KeyCode::Esc => app.go_back(),
                KeyCode::Left => app.focus_progress(),
                _ => {}
            },
            app::FocusPanel::Progress => match code {
                KeyCode::Up | KeyCode::Char('k') => app.progress_up(),
                KeyCode::Down | KeyCode::Char('j') => app.progress_down(),
                KeyCode::Enter => app.jump_to_progress_step(),
                KeyCode::Right | KeyCode::Esc => app.focus_content(),
                _ => {}
            },
        },
        InputMode::Confirming => match code {
            KeyCode::Enter => app.select_current(),
            KeyCode::Esc => app.go_back(),
            _ => {}
        },
    }
}

/// Normalise an operator-typed URL to the base webvh host. webvh
/// resolves `did:webvh:<scid>:example.com` to
/// `https://example.com/.well-known/did.jsonl`, so the VTA's `url`
/// field wants the base `<scheme>://<host>[:port]` — any path the
/// operator typed (often the mediator's API prefix like
/// `/mediator/v1`) would land the DID document somewhere the webvh
/// resolver won't look. Strip it.
///
/// Malformed / relative URLs fall back to the caller's input verbatim
/// so the VTA's validation surfaces a useful error rather than the
/// wizard masking it.
fn strip_path_from_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            u.set_path("");
            // `Url::to_string` trailing slash is harmless for webvh,
            // but trim it so self-host display matches the typical
            // `https://mediator.example.com` shape.
            u.to_string().trim_end_matches('/').to_string()
        }
        Err(_) => raw.to_string(),
    }
}

#[cfg(test)]
mod strip_path_tests {
    use super::strip_path_from_url;

    #[test]
    fn strips_path_from_mediator_url() {
        assert_eq!(
            strip_path_from_url("https://mediator.example.com/mediator/v1"),
            "https://mediator.example.com"
        );
    }

    #[test]
    fn preserves_port() {
        assert_eq!(
            strip_path_from_url("https://mediator.example.com:8443/mediator/v1"),
            "https://mediator.example.com:8443"
        );
    }

    #[test]
    fn no_trailing_slash_on_host_only_url() {
        assert_eq!(
            strip_path_from_url("https://mediator.example.com/"),
            "https://mediator.example.com"
        );
    }

    #[test]
    fn unparseable_url_returns_input_unchanged() {
        // Not a URL — the VTA will reject it with its own validation
        // error, which is more actionable than the wizard's best
        // guess.
        assert_eq!(strip_path_from_url("not a url"), "not a url");
    }
}

/// Project a [`vta_sdk::provision_integration::payload::DidKeyMaterial`]
/// onto the `Secret` shape the mediator-common secrets store expects.
///
/// Emits two entries — the signing key and the key-agreement key —
/// keyed by their full DID-URL verification-method ids. The private
/// bytes move through `Secret::from_multibase`, which decodes the
/// multibase string and populates the secret's internal zeroized
/// buffers.
fn did_key_material_to_secrets(
    material: &vta_sdk::provision_integration::payload::DidKeyMaterial,
) -> anyhow::Result<Vec<affinidi_secrets_resolver::secrets::Secret>> {
    use affinidi_secrets_resolver::secrets::Secret;

    let signing = Secret::from_multibase(
        &material.signing_key.private_key_multibase,
        Some(&material.signing_key.key_id),
    )
    .map_err(|e| anyhow::anyhow!("decode signing private key: {e}"))?;
    let ka = Secret::from_multibase(
        &material.ka_key.private_key_multibase,
        Some(&material.ka_key.key_id),
    )
    .map_err(|e| anyhow::anyhow!("decode key-agreement private key: {e}"))?;
    Ok(vec![signing, ka])
}

/// Run all generators and write configuration files.
/// When `save_recipe` is true, a `mediator-build.toml` recipe is saved alongside
/// the config for reproducibility. Set to false when running from `--from` to
/// avoid overwriting the input recipe.
async fn generate_and_write(
    config: &app::WizardConfig,
    vta_session: Option<&vta_connect::VtaSession>,
    save_recipe: bool,
) -> anyhow::Result<()> {
    // Generate mediator DID + secrets
    let (mediator_did, mediator_secrets, did_doc) = match config.did_method.as_str() {
        DID_PEER => {
            let service_uri = if config.public_url.is_empty() {
                None
            } else {
                Some(config.public_url.clone())
            };
            let (did, secrets) = generators::did_peer::generate_did_peer(service_uri)?;
            (did, secrets, None)
        }
        DID_WEBVH => {
            let host = if config.public_url.is_empty() {
                "localhost:7037/mediator/v1"
            } else {
                &config.public_url
            };
            let result = generators::did_webvh::generate_did_webvh(host).await?;
            (result.did, result.secrets, Some(result.did_doc))
        }
        DID_VTA => {
            // VTA-managed DID: the mediator DID + keys were minted by
            // the VTA at Vta-step provisioning time and shipped inside
            // the `TemplateBootstrap` sealed bundle. Pull them out of
            // the session's `ProvisionResult` — no further round-trip.
            match vta_session.and_then(|s| s.as_full_provision()) {
                Some(provision) => {
                    let integration_did = provision.integration_did().to_string();
                    println!("  VTA-minted mediator DID: {integration_did}");

                    // Persist the integration DID's private keys as
                    // `Secret` values — the mediator's runtime secrets
                    // loader reads these at startup.
                    let secrets = provision
                        .integration_key()
                        .map(did_key_material_to_secrets)
                        .transpose()?
                        .unwrap_or_default();

                    // Write the VTA-provided did.jsonl alongside the
                    // config so the mediator (or a downstream operator)
                    // can publish / inspect the log content locally.
                    if let Some(log) = provision.webvh_log() {
                        let did_jsonl_path = std::path::Path::new(&config.config_path)
                            .parent()
                            .unwrap_or(std::path::Path::new("."))
                            .join("did.jsonl");
                        match std::fs::write(&did_jsonl_path, log) {
                            Ok(()) => println!(
                                "  \x1b[32m\u{2714}\x1b[0m Saved DID log: \x1b[36m{}\x1b[0m",
                                did_jsonl_path.display()
                            ),
                            Err(e) => eprintln!(
                                "  \x1b[33mWarning:\x1b[0m could not write {}: {e}",
                                did_jsonl_path.display()
                            ),
                        }
                    }

                    // Archive the VTA-issued authorization VC next to
                    // the config. Short-lived (~1h validity) but useful
                    // for operator audit trails.
                    let vc_path = std::path::Path::new(&config.config_path)
                        .parent()
                        .unwrap_or(std::path::Path::new("."))
                        .join("authorization.jsonld");
                    if let Ok(serialized) =
                        serde_json::to_string_pretty(provision.authorization_vc())
                    {
                        match std::fs::write(&vc_path, serialized) {
                            Ok(()) => println!(
                                "  \x1b[32m\u{2714}\x1b[0m Archived authorization VC: \x1b[36m{}\x1b[0m",
                                vc_path.display()
                            ),
                            Err(e) => eprintln!(
                                "  \x1b[33mWarning:\x1b[0m could not write {}: {e}",
                                vc_path.display()
                            ),
                        }
                    }

                    let doc_string =
                        serde_json::to_string(&provision.payload.config.did_document).ok();
                    (integration_did, secrets, doc_string)
                }
                None => {
                    eprintln!(
                        "  Note: VTA-managed DID selected but no provisioned session \
                         was captured. Falling back to placeholder — edit mediator.toml \
                         manually before starting the mediator."
                    );
                    ("vta://mediator".into(), vec![], None)
                }
            }
        }
        _ => {
            // Import existing — user will need to provide details
            eprintln!(
                "  Note: {} requires manual DID configuration.",
                config.did_method
            );
            ("PLACEHOLDER_DID".into(), vec![], None)
        }
    };

    // Generate JWT secret only if the operator chose `generate`. With
    // `provide` we leave the well-known key absent — the mediator's
    // boot-time loader picks it up from MEDIATOR_JWT_SECRET or the
    // `--jwt-secret-file` flag and surfaces a clear error if neither is
    // set, so the operator can't accidentally start without one.
    let jwt_secret: Option<Vec<u8>> = if config.jwt_mode == JWT_MODE_PROVIDE {
        println!(
            "  JWT secret: provide mode — wizard will NOT generate or store a key. \
             Set MEDIATOR_JWT_SECRET or pass --jwt-secret-file <path> when starting \
             the mediator."
        );
        None
    } else {
        Some(generators::jwt::generate_jwt_secret()?)
    };

    // Generate admin DID. If the operator went through the online-VTA
    // sub-flow, the setup did:key they pasted into the ACL has already
    // been rotated to a fresh admin identity by the SDK — prefer that
    // over a freshly-minted local did:key so the mediator has a single
    // canonical admin DID that also exists in the VTA's ACL.
    let (admin_did, admin_secret) = match (vta_session, config.admin_did_mode.as_str()) {
        (Some(session), _) => {
            println!(
                "  Using rotated admin DID from VTA session: {}",
                session.admin_did()
            );
            (Some(session.admin_did().to_string()), None)
        }
        (None, ADMIN_GENERATE) => {
            let (did, secret) = generators::did_key::generate_admin_did_key()?;
            (Some(did), Some(secret))
        }
        (None, ADMIN_SKIP) => (None, None),
        (None, _) => (None, None),
    };

    // Generate self-signed SSL if requested
    let (ssl_cert_path, ssl_key_path) = if config.ssl_mode == SSL_SELF_SIGNED {
        let (cert, key) = generators::ssl::generate_self_signed_cert("conf/keys")?;
        (Some(cert), Some(key))
    } else {
        (None, None)
    };

    // ── Provision the unified secret backend ────────────────────────────
    //
    // Open the same backend the mediator will read at startup, probe it
    // (catches typos / missing AWS creds / dead Vault tokens *now*, not
    // at boot), and push every well-known entry the mediator expects.
    //
    // Self-hosted (did:peer / did:webvh): operating keys + JWT.
    // VTA-managed: admin credential (so the mediator can authenticate
    //   to the VTA at boot) + JWT. Operating keys come from the VTA.
    let backend_url = config_writer::build_backend_url(config);
    println!("  Provisioning unified secret backend: {backend_url}");
    let mediator_secrets_store =
        affinidi_messaging_mediator_common::MediatorSecrets::from_url(&backend_url)
            .map_err(|e| anyhow::anyhow!("Failed to open secret backend '{backend_url}': {e}"))?;
    mediator_secrets_store
        .probe()
        .await
        .map_err(|e| anyhow::anyhow!("Secret backend '{backend_url}' failed probe: {e}"))?;

    // JWT signing key — only when generated. Provide-mode skips this
    // and relies on the boot-time env-var/flag path.
    if let Some(ref bytes) = jwt_secret {
        mediator_secrets_store
            .store_jwt_secret(bytes)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to store JWT secret: {e}"))?;
        println!(
            "    \x1b[32m\u{2714}\x1b[0m {}",
            affinidi_messaging_mediator_common::JWT_SECRET
        );
    } else {
        println!(
            "    \x1b[33m\u{26A0}\x1b[0m {} (deferred to boot — provide mode)",
            affinidi_messaging_mediator_common::JWT_SECRET
        );
    }

    // Operating keys — only when the wizard generated them locally
    // (peer/webvh). VTA-managed deployments fetch them at startup.
    if !mediator_secrets.is_empty() {
        mediator_secrets_store
            .store_entry(
                affinidi_messaging_mediator_common::OPERATING_SECRETS,
                "operating-secrets",
                &mediator_secrets,
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to store operating secrets: {e}"))?;
        println!(
            "    \x1b[32m\u{2714}\x1b[0m {} ({} key{})",
            affinidi_messaging_mediator_common::OPERATING_SECRETS,
            mediator_secrets.len(),
            if mediator_secrets.len() == 1 { "" } else { "s" }
        );
    }

    // Admin credential — only when the operator went through the
    // online-VTA sub-flow. The session captures the rotated admin
    // did:key + the VTA DID/URL that minted it.
    if let Some(session) = vta_session {
        let cred = affinidi_messaging_mediator_common::AdminCredential {
            did: session.admin_did().to_string(),
            private_key_multibase: session.admin_private_key_mb().to_string(),
            vta_did: session.vta_did.clone(),
            vta_url: session.rest_url.clone(),
            context: session.context_id.clone(),
        };
        mediator_secrets_store
            .store_admin_credential(&cred)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to store admin credential: {e}"))?;
        println!(
            "    \x1b[32m\u{2714}\x1b[0m {}",
            affinidi_messaging_mediator_common::ADMIN_CREDENTIAL
        );
    }

    // Legacy backend-specific provisioning (file://: secrets.json,
    // keyring:// debug helpers, etc.) — only meaningful for backends the
    // unified store can't fully express yet. Most paths are now no-ops.
    secrets::provision_secrets(&config.secret_storage, &mediator_secrets, &mediator_did)?;

    let generated = config_writer::GeneratedValues {
        mediator_did,
        mediator_secrets,
        jwt_secret,
        admin_did: admin_did.clone(),
        admin_secret: admin_secret.clone(),
        ssl_cert_path,
        ssl_key_path,
    };

    config_writer::write_config(config, &generated)?;

    // Write DID document file for did:webvh
    if let Some(ref doc) = did_doc {
        let doc_path = std::path::Path::new(&config.config_path)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("mediator_did.json");
        std::fs::write(&doc_path, doc)?;
        println!("  DID document: {}", doc_path.display());
    }

    let conf_dir = std::path::Path::new(&config.config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    println!(
        "  \x1b[32m\u{2714}\x1b[0m Configuration: \x1b[1m{}\x1b[0m",
        config.config_path
    );
    println!(
        "  \x1b[32m\u{2714}\x1b[0m Lua functions: \x1b[1m{}\x1b[0m",
        conf_dir.join("atm-functions.lua").display()
    );

    // Display admin DID info to user
    if let Some(ref did) = admin_did {
        println!("  \x1b[32m\u{2714}\x1b[0m Admin DID: \x1b[36m{did}\x1b[0m");
        if let Some(ref secret) = admin_secret {
            if let Ok(privkey) = secret.get_private_keymultibase() {
                println!();
                println!(
                    "  \x1b[33m\u{26A0}  IMPORTANT: Save this admin private key securely!\x1b[0m"
                );
                println!("  \x1b[2mPrivate key (multibase): {privkey}\x1b[0m");
            }
        } else if let Some(session) = vta_session {
            // VTA-session rotation case: we don't have a `Secret` object,
            // just the multibase private key. Surface it plainly so the
            // operator can stash it until full secret-backend persistence
            // lands (followup to task 15).
            println!();
            println!(
                "  \x1b[33m\u{26A0}  IMPORTANT: Save this rotated admin private key — the mediator will need it to authenticate to the VTA.\x1b[0m"
            );
            println!(
                "  \x1b[2mPrivate key (multibase): {}\x1b[0m",
                session.admin_private_key_mb()
            );
            println!(
                "  \x1b[2mVTA DID: {}   Context: {}\x1b[0m",
                session.vta_did, session.context_id
            );
            println!(
                "  \x1b[2m(Auto-provisioning into the selected secret backend is \
                 tracked as a follow-up — for now, store the key pair yourself and \
                 configure `[vta].credential` in mediator.toml accordingly.)\x1b[0m"
            );
        }
    }

    if config.secret_storage == STORAGE_FILE {
        println!("  \x1b[32m\u{2714}\x1b[0m Secrets: conf/secrets.json");
    }

    if config.ssl_mode == SSL_SELF_SIGNED {
        println!("  \x1b[32m\u{2714}\x1b[0m SSL certificates: conf/keys/");
    }

    // Save build recipe for reproducibility (skip when running from --from)
    if save_recipe {
        let recipe_path = std::path::Path::new(&config.config_path)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("mediator-build.toml");
        let recipe_content = recipe::from_wizard_config(config);
        std::fs::write(&recipe_path, &recipe_content)?;
        println!(
            "  \x1b[32m\u{2714}\x1b[0m Build recipe:  \x1b[1m{}\x1b[0m",
            recipe_path.display()
        );
    }

    // Generate Docker files for container deployments
    if config.deployment_type == DEPLOYMENT_CONTAINER {
        docker::generate_dockerfile(config, ".")?;
    }

    Ok(())
}

fn print_banner() {
    // Gradient from purple (141) → blue (69) → cyan (43) across rows
    let r = "\x1b[0m";

    println!();
    println!("  \x1b[38;5;141m    ___    _________       _     ___ {r}");
    println!("  \x1b[38;5;135m   /   |  / __/ __(_)___  (_)___/ (_){r}");
    println!("  \x1b[38;5;105m  / /| | / /_/ /_/ / __ \\/ / __  / / {r}");
    println!("  \x1b[38;5;69m / ___ |/ __/ __/ / / / / / /_/ / /  {r}");
    println!("  \x1b[38;5;33m/_/  |_/_/ /_/ /_/_/ /_/_/\\__,_/_/   {r}");
    println!();
    println!(
        "  \x1b[38;5;43m\u{2501}\u{2501}\u{2501}\x1b[0m \x1b[1;38;5;255mMediator Setup\x1b[0m"
    );
    println!("  \x1b[2mSecure, scalable DIDComm & TSP messaging infrastructure\x1b[0m");
    println!();
}

fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<Stdout>>> {
    let mut stdout = io::stdout();
    enable_raw_mode()?;
    // Bracketed paste lets the terminal deliver a multi-char paste as a
    // single `Event::Paste(String)` instead of a flood of individual Key
    // events. Without it, pasting a 30-char DID triggers 30 redraws and
    // feels sluggish.
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableBracketedPaste,
        DisableMouseCapture
    )?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    Ok(terminal.show_cursor()?)
}

/// Build the feature flags list based on wizard config choices.
fn build_features(config: &app::WizardConfig) -> Vec<&'static str> {
    let mut features = Vec::new();

    if config.didcomm_enabled {
        features.push("didcomm");
    }
    if config.tsp_enabled {
        features.push("tsp");
    }

    match config.secret_storage.as_str() {
        STORAGE_KEYRING => features.push("secrets-keyring"),
        STORAGE_AWS => features.push("secrets-aws"),
        STORAGE_GCP => features.push("secrets-gcp"),
        STORAGE_AZURE => features.push("secrets-azure"),
        STORAGE_VAULT => features.push("secrets-vault"),
        _ => {}
    }

    features
}

/// Build the cargo build arguments for the mediator.
fn build_cargo_args(features: &[&str]) -> Vec<String> {
    let mut args = vec![
        "build".to_string(),
        "--release".to_string(),
        "-p".to_string(),
        "affinidi-messaging-mediator".to_string(),
    ];

    if features.len() > 1 || (features.len() == 1 && features[0] != "didcomm") {
        args.push("--no-default-features".to_string());
        args.push("--features".to_string());
        args.push(features.join(","));
    }

    args
}

/// Find the workspace root by walking up from the current directory
/// looking for a Cargo.toml that contains [workspace].
fn find_workspace_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;

    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(contents) = std::fs::read_to_string(&cargo_toml) {
                if contents.contains("[workspace]") {
                    return Some(dir);
                }
            }
        }

        if !dir.pop() {
            break;
        }
    }
    None
}

/// Resolve the absolute config path for the run command.
fn resolve_config_path(config_path: &str) -> String {
    if Path::new(config_path).is_absolute() {
        return config_path.to_string();
    }
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(abs) = cwd.join(config_path).canonicalize() {
            return abs.to_string_lossy().into_owned();
        }
    }
    config_path.to_string()
}

/// Inline selector: renders options with arrow-key navigation in the terminal.
/// Returns the index of the selected option, or `None` if the user pressed Esc/Ctrl+C.
fn inline_select(prompt: &str, options: &[&str], default: usize) -> Option<usize> {
    use ratatui::crossterm::event as ct;

    let mut selected = default;

    // Print the prompt
    println!("  {prompt}\n");

    // Enter raw mode for key capture
    if enable_raw_mode().is_err() {
        return Some(default);
    }

    loop {
        // Render options (overwrite previous lines)
        for (i, option) in options.iter().enumerate() {
            if i == selected {
                // Turquoise bold with › indicator
                print!("\r  \x1b[38;5;80m\x1b[1m› {option}\x1b[0m\x1b[K");
            } else {
                print!("\r  \x1b[2m  {option}\x1b[0m\x1b[K");
            }
            if i < options.len() - 1 {
                println!();
            }
        }
        let _ = io::stdout().flush();

        // Wait for key
        if let Ok(ct::Event::Key(key)) = ct::read() {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    if selected > 0 {
                        selected -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if selected < options.len() - 1 {
                        selected += 1;
                    }
                }
                KeyCode::Enter => {
                    let _ = disable_raw_mode();
                    println!();
                    return Some(selected);
                }
                KeyCode::Esc => {
                    let _ = disable_raw_mode();
                    println!();
                    return None;
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    let _ = disable_raw_mode();
                    println!();
                    return None;
                }
                _ => {}
            }
        }

        // Move cursor back up to re-render
        if options.len() > 1 {
            print!("\x1b[{}A", options.len() - 1);
        }
    }
}

/// Build the `cargo install` arguments for the mediator.
fn build_install_args(features: &[&str], install_root: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "install".to_string(),
        "--path".to_string(),
        "crates/messaging/affinidi-messaging-mediator".to_string(),
    ];

    if features.len() > 1 || (features.len() == 1 && features[0] != "didcomm") {
        args.push("--no-default-features".to_string());
        args.push("--features".to_string());
        args.push(features.join(","));
    }

    if let Some(root) = install_root {
        args.push("--root".to_string());
        args.push(root.to_string());
    }

    args
}

/// Print the run command for the mediator binary.
fn print_run_command(config_path: &str, install_location: &str) {
    let abs_config = resolve_config_path(config_path);
    println!("  \x1b[1mTo start the mediator:\x1b[0m");
    if abs_config == "conf/mediator.toml" || abs_config.ends_with("/conf/mediator.toml") {
        println!("    \x1b[36mmediator\x1b[0m");
    } else {
        println!("    \x1b[36mmediator -c {abs_config}\x1b[0m");
    }
    println!();
    println!("  \x1b[2mThe mediator binary is installed at {install_location}/mediator\x1b[0m");
}

/// Offer to install the mediator after configuration.
fn offer_build_and_guidance(config: &app::WizardConfig) {
    let features = build_features(config);
    let build_args = build_cargo_args(&features);
    let build_cmd = format!("cargo {}", build_args.join(" "));

    // Try to find workspace root
    let workspace_root = find_workspace_root();

    println!(
        "\n  \x1b[38;5;69m\u{2501}\u{2501}\u{2501} Next Steps \u{2501}\u{2501}\u{2501}\x1b[0m\n"
    );

    // Determine build directory first — we need it for both install and manual instructions
    let build_dir = if let Some(root) = workspace_root {
        root
    } else {
        let install_cmd = format!("cargo {}", build_install_args(&features, None).join(" "));
        println!("  \x1b[33mCannot find workspace root.\x1b[0m");
        print_manual_instructions(&install_cmd, &build_cmd, config);
        print_final_summary(config);
        return;
    };

    let choice = inline_select(
        "The mediator can be installed as a binary so you can run it from anywhere.",
        &[
            "Install now (may take a few minutes)",
            "Show manual instructions",
            "Skip",
        ],
        0,
    );

    match choice {
        Some(1) => {
            let install_cmd = format!("cargo {}", build_install_args(&features, None).join(" "));
            print_manual_instructions(&install_cmd, &build_cmd, config);
            print_final_summary(config);
            return;
        }
        Some(2) | None => {
            print_final_summary(config);
            return;
        }
        _ => {} // Install now (0)
    }

    // Ask for custom install path
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| "~/.cargo".to_string());
    let default_bin = format!("{cargo_home}/bin");

    println!();
    print!("  \x1b[1mInstall location\x1b[0m [{}]: ", default_bin);
    let _ = io::stdout().flush();

    let mut path_input = String::new();
    let install_root = if io::stdin().read_line(&mut path_input).is_ok() {
        let trimmed = path_input.trim();
        if trimmed.is_empty() || trimmed == default_bin {
            None
        } else {
            println!(
                "\n  \x1b[33mNote: installing to a custom path may require elevated \
                 permissions (sudo).\x1b[0m"
            );
            Some(trimmed.to_string())
        }
    } else {
        None
    };

    let install_args = build_install_args(&features, install_root.as_deref());
    let install_cmd = format!("cargo {}", install_args.join(" "));

    let install_location = install_root
        .as_ref()
        .map(|r| format!("{r}/bin"))
        .unwrap_or_else(|| default_bin.clone());

    println!(
        "\n  \x1b[38;5;69mInstalling mediator to {install_location} \
         (this may take a few minutes)...\x1b[0m\n"
    );

    let status = Command::new("cargo")
        .args(&install_args)
        .current_dir(&build_dir)
        .status();

    match status {
        Ok(exit) if exit.success() => {
            println!("\n  \x1b[32m\u{2714} Installation successful!\x1b[0m\n");
            print_run_command(&config.config_path, &install_location);
        }
        Ok(exit) => {
            eprintln!(
                "\n  \x1b[31m\u{2718} Install failed (exit code: {})\x1b[0m",
                exit
            );
            eprintln!("  Check the output above for errors. You can retry with:");
            eprintln!("    cd {} && {}", build_dir.display(), install_cmd);
        }
        Err(e) => {
            eprintln!("\n  \x1b[31mFailed to run cargo: {e}\x1b[0m");
            eprintln!("  Is cargo installed and in your PATH?");
            print_manual_instructions(&install_cmd, &build_cmd, config);
        }
    }

    print_final_summary(config);
}

/// Print manual build/run instructions when auto-install is skipped or fails.
fn print_manual_instructions(install_cmd: &str, build_cmd: &str, config: &app::WizardConfig) {
    let abs_config = resolve_config_path(&config.config_path);

    println!("  \x1b[1mOption 1 — Install (recommended):\x1b[0m");
    println!("    \x1b[36m{install_cmd}\x1b[0m");
    println!("    \x1b[36mmediator -c {abs_config}\x1b[0m");
    println!();
    println!("  \x1b[1mOption 2 — Build and run from source:\x1b[0m");
    println!("    \x1b[36m{build_cmd}\x1b[0m");
    println!(
        "    \x1b[36mcargo run --release -p affinidi-messaging-mediator -- -c {abs_config}\x1b[0m"
    );
}

/// Print a final summary of everything that was created and what to do next.
fn print_final_summary(config: &app::WizardConfig) {
    let abs_config = resolve_config_path(&config.config_path);
    let config_dir = std::path::Path::new(&config.config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."));

    println!("\n  \x1b[38;5;69m\u{2501}\u{2501}\u{2501} Summary \u{2501}\u{2501}\u{2501}\x1b[0m\n");

    // Files created
    println!("  \x1b[1mFiles created:\x1b[0m");
    println!("    \x1b[36m{abs_config}\x1b[0m  — mediator configuration");
    println!(
        "    \x1b[36m{}\x1b[0m  — Redis Lua functions",
        config_dir.join("atm-functions.lua").display()
    );

    let recipe_path = config_dir.join("mediator-build.toml");
    println!(
        "    \x1b[36m{}\x1b[0m  — build recipe (reproducible setup)",
        recipe_path.display()
    );

    if config.secret_storage == STORAGE_FILE {
        let secrets_path = config_dir.join("secrets.json");
        println!(
            "    \x1b[36m{}\x1b[0m  — \x1b[33mprivate keys (keep secure!)\x1b[0m",
            secrets_path.display()
        );
    }

    if config.ssl_mode == SSL_SELF_SIGNED {
        println!("    \x1b[36mconf/keys/end.cert\x1b[0m  — SSL certificate");
        println!("    \x1b[36mconf/keys/end.key\x1b[0m   — SSL private key");
    }

    if config.did_method == DID_WEBVH {
        let did_doc_path = config_dir.join("mediator_did.json");
        println!(
            "    \x1b[36m{}\x1b[0m  — DID document",
            did_doc_path.display()
        );
    }

    if config.deployment_type == DEPLOYMENT_CONTAINER {
        println!("    \x1b[36mDockerfile\x1b[0m  — container build file");
    }

    // Key information
    if config.secret_storage != STORAGE_FILE {
        println!();
        println!("  \x1b[1mSecrets:\x1b[0m");
        println!("    Stored in: \x1b[36m{}\x1b[0m", config.secret_storage);
    }

    // Reproduce
    println!();
    println!("  \x1b[1mReproduce this setup:\x1b[0m");
    println!(
        "    \x1b[36mmediator-setup --from {}\x1b[0m",
        recipe_path.display()
    );

    println!();
}
