mod admin_monitor_profile;
mod app;
mod bootstrap_headless;
mod cli;
mod clipboard;
mod config_writer;
mod consts;
mod discovery;
mod docker;
mod exit_recap;
mod generators;
mod publish;
mod recipe;
mod reprovision;
mod sealed_handoff;
mod secret_backend;
mod secure_fs;
mod ui;
mod vta;

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
        return vta::cli::run_phase1_init(
            path,
            args.vta_did.as_deref(),
            args.vta_context.as_deref(),
        )
        .await;
    }
    if let Some(path) = args.setup_key_file.as_ref() {
        let vta_did = vta::cli::validate_phase2_args(&args.vta_did)?;
        let mediator_url = args.mediator_url.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "--mediator-url is required for --setup-key-file (Phase 2). The VTA's \
                 didcomm-mediator template renders the mediator DID using this URL."
            )
        })?;
        // Phase 2's headless flow returns a structured failure
        // shape (transport-by-transport reasons + a kind) so we
        // can map cleanly to documented exit codes:
        //   0 → success
        //   2 → no transport worked (NoTransport)
        //   3 → VTA accepted the auth handshake but rejected the
        //        request body (PostAuthFailed)
        match vta::cli::run_phase2_connect(
            path,
            vta_did,
            args.vta_context.as_deref(),
            mediator_url,
            args.wait_for_acl,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(err) => {
                eprintln!("\n{err}");
                let code = match err.kind {
                    vta::cli::HeadlessFailureKind::NoTransport => 2,
                    vta::cli::HeadlessFailureKind::PostAuthFailed => 3,
                };
                std::process::exit(code);
            }
        }
    }

    if let Some(ref recipe_path) = args.from {
        return run_from_recipe(
            recipe_path,
            args.force_reprovision,
            args.bundle.as_deref(),
            args.digest.as_deref(),
        )
        .await;
    } else if args.bundle.is_some() {
        anyhow::bail!(
            "--bundle requires --from <recipe.toml>. The recipe tells the wizard \
             the deployment type, secret backend, and VTA mode the bundle belongs to."
        );
    }

    if args.non_interactive {
        return run_non_interactive(args).await;
    }

    // Check for existing config — refuse to silently rotate live keys
    // unless the operator explicitly opts in with `--force-reprovision`.
    // The unified backend stores the JWT signing key, the admin
    // credential, and the operating keys; rotating any of them while a
    // mediator is running invalidates active sessions.
    //
    // `inspect_existing()` scans every well-known key on the backend —
    // on keyring that's N reads, each of which can trigger a macOS
    // Keychain unlock prompt when the binary's ACL identity differs
    // from the last write (common across `cargo build` rebuilds).
    // When the operator has already opted in via `--force-reprovision`
    // the scan result is only used for the listing in
    // `refuse_overwrite`, which we skip — so skip the scan too. The
    // file-level backup below still runs from `mediator.toml` alone.
    let config_path = args.config.clone();
    let config_path_obj = std::path::Path::new(&config_path);
    guard_existing_setup(config_path_obj, args.force_reprovision).await?;
    if config_path_obj.exists() {
        // Operator opted in (or there were no provisioned keys —
        // e.g. backend was wiped manually). Back up the existing
        // mediator.toml before generating the new one so the
        // previous configuration is recoverable.
        std::fs::copy(&config_path, format!("{config_path}.bak"))?;
        eprintln!("Existing {config_path} backed up to {config_path}.bak before re-provisioning.");
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
                match generate_and_write(
                    &app.config,
                    app.vta_session.as_ref(),
                    true,
                    secret_backend::ProvisionProbe::ReadWrite,
                )
                .await
                {
                    Ok(()) => {
                        // Clean up the sealed-handoff request / seed
                        // files if the setup went through that flow.
                        // Same contract as the non-interactive path:
                        // only material the mediator needs to start
                        // survives. No-op when the interactive flow
                        // didn't hit sealed-handoff (e.g. online VTA
                        // or non-VTA deployments).
                        if let Some(ref artefacts) = app.tui_bootstrap_artifacts {
                            bootstrap_headless::cleanup_artifacts(artefacts);
                        }
                        offer_build_and_guidance(&app.config);
                        // Print the structured recap to normal stdout
                        // (alt-screen has been left by `restore_terminal`
                        // above) so the operator can scroll back and
                        // mouse-select DIDs / paths / commands. Suppressed
                        // for `--non-interactive` / `--from <recipe>` runs
                        // — those have their own structured stdout that
                        // CI scripts parse, and a recap would corrupt
                        // the format.
                        exit_recap::print_exit_recap(&app.config, app.vta_session.as_ref());
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
    if args.save_did_web {
        config.save_did_web = true;
    }
    if !args.key_suite.is_empty() {
        config.key_suite = args.key_suite.clone();
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

/// Refuse to overwrite an existing *provisioned* setup unless
/// `--force-reprovision` is set — shared by the interactive, non-interactive,
/// and recipe flows so none can silently rotate live keys (the unified backend
/// holds the JWT key, admin credential, and operating keys). When the operator
/// has opted in, the keyring scan is skipped (it can trigger one macOS Keychain
/// prompt per well-known key). Diverges (process exit) when it refuses.
async fn guard_existing_setup(
    config_path: &std::path::Path,
    force_reprovision: bool,
) -> anyhow::Result<()> {
    if !force_reprovision
        && let Some(setup) = reprovision::inspect_existing(config_path).await?
        && setup.is_provisioned()
    {
        reprovision::refuse_overwrite(config_path, &setup);
    }
    Ok(())
}

/// Build a [`WizardConfig`] from CLI args layered over deployment defaults — the
/// non-interactive (`--non-interactive`) path's config source. Extracted so the
/// CLI-args path is unit-testable and can be checked for equivalence against the
/// recipe path's [`recipe::to_wizard_config`].
pub(crate) fn build_config_from_args(args: &Args) -> anyhow::Result<WizardConfig> {
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
    apply_cli_args(args, &mut config);

    // Validate required fields for did:webvh
    if config.did_method == DID_WEBVH && config.public_url.is_empty() {
        anyhow::bail!("--public-url is required when using did:webvh in non-interactive mode");
    }

    Ok(config)
}

/// Print the shared "what we're about to generate" summary used by both
/// non-interactive entry points (`--non-interactive` and `--from <recipe>`),
/// so the two stay consistent.
fn print_config_summary(config: &WizardConfig) {
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
}

/// Non-interactive mode: build config from CLI args + deployment defaults, then generate.
async fn run_non_interactive(args: Args) -> anyhow::Result<()> {
    // Same re-run safety story as the interactive flow — refuse to
    // overwrite an existing setup unless `--force-reprovision` is set.
    guard_existing_setup(std::path::Path::new(&args.config), args.force_reprovision).await?;

    let config = build_config_from_args(&args)?;

    println!("Mediator Setup (non-interactive)");
    print_config_summary(&config);
    println!();
    println!("Generating cryptographic material...");

    // Non-interactive / recipe paths don't run the online-VTA sub-flow, so
    // there's no captured session — VTA-managed DID creation isn't
    // supported from `--from` / `--non-interactive` yet. Headless flows use a
    // read-only backend probe: the well-known secrets are pre-created
    // out-of-band (e.g. by CDK), so setup only overwrites them and never needs
    // create/delete rights — matching the runtime, which also probes read-only.
    generate_and_write(&config, None, true, secret_backend::ProvisionProbe::ReadOnly).await?;
    offer_build_and_guidance(&config);

    Ok(())
}

/// Run from a declarative build recipe TOML file (fully non-interactive).
async fn run_from_recipe(
    recipe_path: &str,
    force_reprovision: bool,
    bundle_path: Option<&std::path::Path>,
    digest: Option<&str>,
) -> anyhow::Result<()> {
    let recipe = recipe::load(recipe_path)?;
    let mut config = recipe::to_wizard_config(&recipe)?;

    // Re-run safety: refuse to overwrite an existing provisioned setup
    // unless the operator opts in. This matches the interactive flow so
    // recipe-driven CI can't silently rotate live keys.
    guard_existing_setup(std::path::Path::new(&config.config_path), force_reprovision).await?;

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
    print_config_summary(&config);
    println!();

    // Sealed-handoff dispatch:
    //   use_vta + vta_mode sealed-* → phase 1 (no --bundle) or phase 2
    //     (with --bundle). Phase 1 emits request and exits early;
    //     phase 2 produces a `VtaSession` that feeds `generate_and_write`.
    //   use_vta + vta_mode online    → rejected (see intent_for_mode)
    //   use_vta = false OR no vta_mode → legacy no-VTA generation path.
    let vta_session = if config.use_vta
        && matches!(
            config.vta_mode.as_str(),
            consts::VTA_MODE_SEALED_MINT | consts::VTA_MODE_SEALED_EXPORT | consts::VTA_MODE_ONLINE
        ) {
        use bootstrap_headless::HeadlessOutcome;
        let outcome = bootstrap_headless::dispatch(&config, bundle_path, digest).await?;
        match outcome {
            HeadlessOutcome::RequestEmitted {
                request_path,
                bundle_id_hex,
                producer_command,
                pnm_command,
            } => {
                print_phase1_next_steps(
                    recipe_path,
                    &request_path,
                    &bundle_id_hex,
                    &producer_command,
                    &pnm_command,
                );
                return Ok(());
            }
            HeadlessOutcome::Applied { session, artifacts } => {
                println!("  Generating cryptographic material...\n");
                generate_and_write(
                    &config,
                    Some(&session),
                    false,
                    secret_backend::ProvisionProbe::ReadOnly,
                )
                .await?;
                bootstrap_headless::cleanup_artifacts(&artifacts);
                println!(
                    "  \x1b[32m\u{2714}\x1b[0m Setup artefacts removed — \
                     the mediator has everything it needs in the \
                     configured secret backend.\n"
                );
                Some(session)
            }
        }
    } else {
        println!("  Generating cryptographic material...\n");
        generate_and_write(&config, None, false, secret_backend::ProvisionProbe::ReadOnly).await?;
        None
    };

    // `vta_session` is intentionally dropped here — it already fed
    // `generate_and_write` above, and the install step below doesn't
    // need it. Consuming it keeps the variable live for the compiler
    // without leaving a dangling binding.
    drop(vta_session);

    let features = config.cargo_features();
    let needs_explicit = config.needs_explicit_features();

    // Auto-install if recipe says so
    if recipe.install.enabled {
        let install_root = recipe.install.path.as_deref();
        let install_args = build_install_args(&features, needs_explicit, install_root);
        let install_cmd = format!("cargo {}", install_args.join(" "));

        let workspace_root = find_workspace_root();
        let build_dir = workspace_root
            .ok_or_else(|| anyhow::anyhow!("Cannot find workspace root for cargo install"))?;

        let install_location = install_root.map(|r| format!("{r}/bin")).unwrap_or_else(|| {
            let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| "~/.cargo".into());
            format!("{cargo_home}/bin")
        });

        println!("  \x1b[1mInstall command:\x1b[0m");
        println!(
            "    \x1b[2mcd\x1b[0m \x1b[36m{}\x1b[0m",
            build_dir.display()
        );
        println!("    \x1b[36m{install_cmd}\x1b[0m\n");
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
                anyhow::bail!("cargo install failed with exit code: {exit}");
            }
            Err(e) => {
                anyhow::bail!("Failed to run cargo: {e}");
            }
        }
    } else {
        let install_cmd = format!(
            "cargo {}",
            build_install_args(&features, needs_explicit, None).join(" ")
        );
        let build_cmd = format!(
            "cargo {}",
            build_cargo_args(&features, needs_explicit).join(" ")
        );
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
                // Same idea for the F5-triggered cloud-backend
                // discovery: result lands on a tokio mpsc and the
                // wizard transitions Loading → Loaded / Failed.
                app.drain_discovery_events();
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

    // Discovery overlay (cloud-backend secrets list via F5) takes
    // every key while it's on screen — Loading swallows everything
    // except Esc, Loaded scrolls / picks (Enter) / cancels (Esc),
    // Failed dismisses on any key. Placed before mode dispatch so
    // normal text-input keys don't leak into the input widget while
    // the overlay is active.
    if app.in_discovery_overlay() {
        app.handle_discovery_key(code);
        return;
    }

    // F5 on a discoverable key-storage phase kicks off the async
    // `list_namespace` call. Discoverable phases are AwsNamespace /
    // GcpNamespace / AzureVault / VaultMount; F5 anywhere else is a
    // no-op so the keystroke isn't actively misleading. The hint
    // footer on each prompt advertises the requirement (e.g. AWS
    // creds in the environment).
    if code == KeyCode::F(5) {
        app.kick_off_discovery();
        return;
    }

    // F2 on the sealed-handoff DigestVerify phase copies the
    // wizard-computed digest to the clipboard. F2 (not a bare
    // letter) because the panel has an active text input for the
    // operator's OOB-shared digest — letters would land in the
    // field. Routes through the SSH-aware copy helper.
    if code == KeyCode::F(2)
        && let Some(state) = app.sealed_handoff.as_mut()
        && state.phase == crate::sealed_handoff::SealedPhase::DigestVerify
    {
        state.copy_digest_to_clipboard();
        return;
    }

    // Bare `c` / `v` / `p` on the sealed-handoff RequestGenerated screen
    // copy one of: the bootstrap request JSON, the `vta bootstrap seal`
    // command, or the `pnm-cli bootstrap seal` command to the system
    // clipboard. Arrow / Page / Home keys scroll the panel — the
    // rendered content (VP JSON + commands + hotkey cheatsheet) exceeds
    // the viewport on smaller terminals. Placed ahead of the mode-based
    // dispatch so it fires in both Selecting and TextInput modes — the
    // RequestGenerated phase uses Selecting mode today, but keeping the
    // hotkey mode-agnostic is cheap and future-proofs against UI
    // shuffling.
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
                | KeyCode::Up
                | KeyCode::Down
                | KeyCode::PageUp
                | KeyCode::PageDown
                | KeyCode::Home
        )
        && app.in_sealed_handoff_subflow()
        && let Some(state) = app.sealed_handoff.as_mut()
        && state.phase == crate::sealed_handoff::SealedPhase::RequestGenerated
    {
        // Command-copy hotkeys: `v` always copies the `vta …`
        // flavour (the offline producer the wizard recommends for
        // FullSetup / OfflineExport), `p` always copies the
        // `pnm …` flavour (what an operator with an authenticated
        // pnm session against a live VTA runs). For AdminOnly the
        // two collapse — primary is already `pnm contexts bootstrap`.
        // `f` copies the fallback command when one exists.
        //
        // Scroll keys: one line (arrows) or 10 lines (Page).
        // 10 is a compromise between "obvious jump" and "don't
        // shoot past useful content in one keystroke"; the
        // panel is about 40–60 rendered lines typically.
        const PAGE: u16 = 10;
        match code {
            KeyCode::Char('c') | KeyCode::Char('C') => {
                state.copy_request_to_clipboard();
            }
            KeyCode::Char('v') | KeyCode::Char('V') => {
                state.copy_primary_command_to_clipboard();
            }
            KeyCode::Char('p') | KeyCode::Char('P') => {
                state.copy_pnm_command_to_clipboard();
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                state.copy_fallback_command_to_clipboard();
            }
            KeyCode::Up => state.scroll_request_up(1),
            KeyCode::Down => state.scroll_request_down(1),
            KeyCode::PageUp => state.scroll_request_up(PAGE),
            KeyCode::PageDown => state.scroll_request_down(PAGE),
            KeyCode::Home => state.scroll_request_home(),
            _ => unreachable!("outer matches! guards the code space"),
        }
        return;
    }

    // Bare `m` / `a` / `v` on the sealed-handoff Complete screen copy
    // the mediator / admin / VTA DIDs to the clipboard. Phase-scoped
    // to Complete so the same letters don't conflict with `[v]` /
    // `[p]` on the RequestGenerated screen above.
    if !modifiers.contains(KeyModifiers::CONTROL)
        && matches!(
            code,
            KeyCode::Char('m')
                | KeyCode::Char('M')
                | KeyCode::Char('a')
                | KeyCode::Char('A')
                | KeyCode::Char('v')
                | KeyCode::Char('V')
        )
        && app.in_sealed_handoff_subflow()
        && let Some(state) = app.sealed_handoff.as_mut()
        && state.phase == crate::sealed_handoff::SealedPhase::Complete
    {
        match code {
            KeyCode::Char('m') | KeyCode::Char('M') => {
                state.copy_mediator_did_to_clipboard();
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                state.copy_admin_did_to_clipboard();
            }
            KeyCode::Char('v') | KeyCode::Char('V') => {
                state.copy_vta_did_to_clipboard();
            }
            _ => unreachable!("outer matches! guards the code space"),
        }
        return;
    }

    // Bare `c` / `C` on the online-VTA AwaitingAcl screen copies the
    // rendered `pnm acl create` command to the system clipboard. Same
    // early-return placement as the sealed-handoff hotkey so it fires
    // regardless of InputMode.
    if !modifiers.contains(KeyModifiers::CONTROL)
        && matches!(code, KeyCode::Char('c') | KeyCode::Char('C'))
        && let Some(state) = app.vta_connect.as_mut()
        && state.phase == crate::vta::ConnectPhase::AwaitingAcl
    {
        state.copy_acl_command_to_clipboard();
        return;
    }

    // Bare `c` / `b` on the wizard's final Summary screen copy the
    // config-file path and the resolved backend URL respectively.
    // Step-scoped so they don't interfere with the same letters
    // used elsewhere (e.g. `c` on AwaitingAcl).
    if !modifiers.contains(KeyModifiers::CONTROL)
        && app.current_step == app::WizardStep::Summary
        && matches!(
            code,
            KeyCode::Char('c') | KeyCode::Char('C') | KeyCode::Char('b') | KeyCode::Char('B')
        )
    {
        match code {
            KeyCode::Char('c') | KeyCode::Char('C') => {
                app.copy_config_path_to_clipboard();
            }
            KeyCode::Char('b') | KeyCode::Char('B') => {
                app.copy_backend_url_to_clipboard();
            }
            _ => unreachable!("outer matches! guards the code space"),
        }
        return;
    }

    // Bare `v` / `m` / `a` on the online-VTA Connected screen copy
    // the VTA / mediator / admin DIDs to the clipboard. Phase-scoped
    // to Connected so the same letter keys can be used for unrelated
    // actions on other phases without ambiguity.
    if !modifiers.contains(KeyModifiers::CONTROL)
        && matches!(
            code,
            KeyCode::Char('v')
                | KeyCode::Char('V')
                | KeyCode::Char('m')
                | KeyCode::Char('M')
                | KeyCode::Char('a')
                | KeyCode::Char('A')
        )
        && let Some(state) = app.vta_connect.as_mut()
        && state.phase == crate::vta::ConnectPhase::Connected
    {
        match code {
            KeyCode::Char('v') | KeyCode::Char('V') => {
                state.copy_vta_did_to_clipboard();
            }
            KeyCode::Char('m') | KeyCode::Char('M') => {
                state.copy_mediator_did_to_clipboard();
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                state.copy_admin_did_to_clipboard();
            }
            _ => unreachable!("outer matches! guards the code space"),
        }
        return;
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

/// Convert a flat `Vec<SecretEntry>` (the `ContextProvisionBundle`
/// shape used by the OfflineExport path) into `Secret` values the
/// mediator's runtime loader consumes.
///
/// Sibling to [`did_key_material_to_secrets`] — that one walks a
/// typed (signing, ka) pair grouped by DID; this one iterates a flat
/// list keyed by `key_id` and trusts the multibase prefix on each
/// entry to disambiguate Ed25519 / X25519 / P-256. The loader's
/// `Secret::from_multibase` does the actual key-type detection.
///
/// Both helpers feed into the same downstream sink (`provision_secrets`
/// in `secrets/mod.rs`); the duplication is in *iteration shape*
/// only, not in per-key handling.
fn secret_entries_to_secrets(
    entries: &[vta_sdk::did_secrets::SecretEntry],
) -> anyhow::Result<Vec<affinidi_secrets_resolver::secrets::Secret>> {
    use affinidi_secrets_resolver::secrets::Secret;

    entries
        .iter()
        .map(|entry| {
            Secret::from_multibase(&entry.private_key_multibase, Some(&entry.key_id))
                .map_err(|e| anyhow::anyhow!("decode key {}: {e}", entry.key_id))
        })
        .collect()
}

/// Project a completed [`vta::VtaSession`] onto the
/// [`vta_sdk::did_secrets::DidSecretsBundle`] shape the mediator's
/// runtime expects in its VTA fallback cache.
///
/// The mediator boots, tries to reach its VTA, and on any failure
/// (network, timeout, or VTA-side validation — `integration::startup`
/// in vta-sdk doesn't distinguish) loads this bundle to keep serving
/// DIDComm traffic with its existing keys. Pre-populating it at
/// wizard time means first-boot survives VTA unavailability.
///
/// Returns `None` for [`VtaReply::AdminOnly`] sessions — those don't
/// carry a VTA-provisioned integration DID (the mediator brought its
/// own via the Did step), so there's nothing for the VTA cache to
/// seed. `TemplateBootstrap` and `ContextProvision` replies both map
/// to a bundle; their shapes differ but the target is unified.
fn build_did_secrets_bundle(
    session: &vta::VtaSession,
) -> Option<vta_sdk::did_secrets::DidSecretsBundle> {
    use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
    use vta_sdk::keys::KeyType;

    if let Some(provision) = session.as_full_provision() {
        // TemplateBootstrap path — `DidKeyMaterial` is a typed
        // (signing, ka) pair keyed by DID. Pin the discriminants to
        // match the `didcomm-mediator` template's renderer contract:
        // signing_key is always Ed25519, ka_key is always X25519.
        let material = provision.integration_key()?;
        let secrets = vec![
            SecretEntry {
                key_id: material.signing_key.key_id.clone(),
                key_type: KeyType::Ed25519,
                private_key_multibase: material.signing_key.private_key_multibase.clone(),
            },
            SecretEntry {
                key_id: material.ka_key.key_id.clone(),
                key_type: KeyType::X25519,
                private_key_multibase: material.ka_key.private_key_multibase.clone(),
            },
        ];
        return Some(DidSecretsBundle {
            did: provision.integration_did()?.to_string(),
            secrets,
        });
    }

    if let Some(bundle) = session.as_context_export() {
        // OfflineExport path — ContextProvisionBundle already carries
        // a flat `Vec<SecretEntry>` typed by the VTA, so we pass it
        // through verbatim (including any future key types the VTA
        // adds).
        let did = bundle.did.as_ref()?;
        return Some(DidSecretsBundle {
            did: did.id.clone(),
            secrets: did.secrets.clone(),
        });
    }

    // AdminOnly — no VTA-provisioned integration DID to cache.
    None
}

/// Write a `did.jsonl` log entry next to the mediator's config file
/// and print a green tick / yellow warning in the same style as the
/// rest of `generate_and_write`. Centralises the CWD-versus-config-dir
/// logic that was duplicated between the FullSetup and OfflineExport
/// branches.
fn write_did_jsonl(config_path: &str, log_content: &str) {
    let did_jsonl_path = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("did.jsonl");
    // Strict JSON-Lines requires each record to end with `\n`. Some upstream
    // sources (the VTA's `provision.webvh_log()`, the local generator) include
    // a trailing newline already, others don't — normalise to exactly one so
    // `cat`-ing the file or appending future log entries always works.
    let normalised = format!("{}\n", log_content.trim_end_matches('\n'));
    // did.jsonl is the DID's log of public state, but it also pins
    // the mediator's identity. Owner-only on Unix is defence in
    // depth — a public-readable log isn't a confidentiality break,
    // but a co-tenant who can't read the file can't subtly mutate
    // it either if they ever get write access.
    match crate::secure_fs::write_sensitive(&did_jsonl_path, normalised) {
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

/// Convert the mediator's did:webvh log entry to a did:web DID document
/// and write it next to the config as `did-web.json`. Purely an operator
/// artefact for hosting the DID under did:web — the mediator runtime
/// serves its own document from the webvh log, never this file, so the
/// filename deliberately differs from the runtime-served `did.json`.
/// Failures are surfaced but non-fatal: a bad conversion shouldn't roll
/// back an otherwise-good setup.
fn write_did_web_json(config_path: &str, log_content: &str, webvh_did: &str) {
    let (web_did, doc) = match generators::did_webvh::webvh_log_to_did_web(log_content, webvh_did) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("  \x1b[33mWarning:\x1b[0m could not derive did:web document: {e}");
            return;
        }
    };
    let did_web_path = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("did-web.json");
    // did:web documents are public by definition (the operator hosts
    // them at `/.well-known/did.json`), but mirror the owner-only posture
    // of did.jsonl for defence in depth until the operator copies it out.
    let body = format!("{}\n", doc.trim_end_matches('\n'));
    match crate::secure_fs::write_sensitive(&did_web_path, body) {
        Ok(()) => println!(
            "  \x1b[32m\u{2714}\x1b[0m Saved did:web document (\x1b[36m{web_did}\x1b[0m): \
             \x1b[36m{}\x1b[0m",
            did_web_path.display()
        ),
        Err(e) => eprintln!(
            "  \x1b[33mWarning:\x1b[0m could not write {}: {e}",
            did_web_path.display()
        ),
    }
}

/// Drop any HTTP path from a URL, returning `<scheme>://<host>[:<port>]`.
/// Used to derive the did:webvh DID identifier from the operator's full
/// public URL (the trailing `/mediator/v1` would otherwise get baked into
/// the DID and route the resolver away from `/.well-known/did.jsonl`).
fn strip_url_path_owned(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            u.set_path("");
            u.to_string().trim_end_matches('/').to_string()
        }
        Err(_) => raw.to_string(),
    }
}

/// Glue a base URL and an HTTP path prefix together with exactly one
/// `/` between them and no trailing slash. Used to feed the did:webvh
/// template's `URL` variable so service-endpoint URIs match what the
/// mediator actually serves at runtime.
///
/// `combine_url_prefix("https://m.example.com", "/mediator/v1/")`
/// → `"https://m.example.com/mediator/v1"`. An empty or `/` prefix
/// returns the base URL unchanged.
fn combine_url_prefix(base: &str, prefix: &str) -> String {
    let base = base.trim_end_matches('/');
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{prefix}")
    }
}

/// Build the DIDComm base URL advertised inside a generated did:peer.
///
/// `public_url` may be either the host root (`https://m.example.com`) or
/// an already-prefixed URL (`https://m.example.com/mediator/v1`). To stay
/// backward compatible with existing operator habits, append `api_prefix`
/// only when the URL path does not already end with it.
fn did_peer_service_url(public_url: &str, api_prefix: &str) -> Option<String> {
    let public_url = public_url.trim().trim_end_matches('/');
    if public_url.is_empty() {
        return None;
    }

    let prefix = api_prefix.trim_matches('/');
    if prefix.is_empty() {
        return Some(public_url.to_string());
    }

    let already_prefixed = url::Url::parse(public_url)
        .ok()
        .map(|url| {
            let path = url.path().trim_matches('/');
            path == prefix || path.ends_with(&format!("/{prefix}"))
        })
        .unwrap_or(false);

    Some(if already_prefixed {
        public_url.to_string()
    } else {
        combine_url_prefix(public_url, api_prefix)
    })
}

#[cfg(test)]
mod did_peer_service_url_tests {
    use super::did_peer_service_url;

    #[test]
    fn appends_default_api_prefix_for_host_root_public_url() {
        assert_eq!(
            did_peer_service_url("https://mediator.example.com", "/mediator/v1/"),
            Some("https://mediator.example.com/mediator/v1".into())
        );
    }

    #[test]
    fn does_not_double_append_existing_api_prefix() {
        assert_eq!(
            did_peer_service_url("https://mediator.example.com/mediator/v1/", "/mediator/v1/"),
            Some("https://mediator.example.com/mediator/v1".into())
        );
    }
}

/// Bag of artefacts the mint phase produces and the later phases
/// consume. Keeps the four `generate_and_write` phases coupled by an
/// explicit value type rather than the prior soup of mutable locals.
///
/// Pure-ish: every field is a value, not a handle to a backend or
/// open file. Side effects (file writes, network calls, stdout) live
/// in `provision_secret_backend`, `write_config_artefacts`, and
/// `print_completion_summary` which take a borrowed `&MintedArtefacts`.
struct MintedArtefacts {
    /// The mediator's DID — `did:peer:…`, `did:webvh:…`, or a
    /// VTA-managed DID forwarded from the Vta sub-flow.
    mediator_did: String,
    /// Operating-key secrets the mediator's runtime loader expects
    /// at `mediator/operating/secrets`. Empty when the VTA hosts
    /// the keys (the runtime fetches them at startup).
    mediator_secrets: Vec<affinidi_secrets_resolver::secrets::Secret>,
    /// Serialised did:webvh log entry (or VTA-returned log) that
    /// `write_config_artefacts` writes to `did.jsonl`. `None` when
    /// the deployment uses no self-hosted DID log.
    did_doc: Option<String>,
    /// Authorization credential JSON the VTA returned with the
    /// minted DID. Archived alongside the config in
    /// `write_config_artefacts`. `None` for non-VTA / OfflineExport
    /// deployments.
    authorization_vc: Option<String>,
    /// Raw PKCS8 bytes of the JWT signing key. `None` under
    /// `jwt_mode = provide` — the runtime expects
    /// `MEDIATOR_JWT_SECRET` / `--jwt-secret-file` at boot.
    jwt_secret: Option<Vec<u8>>,
    /// Operator's admin DID. `None` under `ADMIN_SKIP`.
    admin_did: Option<String>,
    /// Admin DID's secret material. `None` when the admin DID came
    /// from a VTA session (the rotated credential is in the session
    /// already) or under `ADMIN_SKIP`.
    admin_secret: Option<affinidi_secrets_resolver::secrets::Secret>,
}

/// Run all generators and write configuration files.
/// When `save_recipe` is true, a `mediator-build.toml` recipe is saved alongside
/// the config for reproducibility. Set to false when running from `--from` to
/// avoid overwriting the input recipe.
///
/// Orchestrator — delegates to four phase functions in order. Each
/// phase has a distinct concern:
///
/// 1. [`mint_artefacts`] — pure-ish value computation (DID + JWT +
///    admin DID). No file IO; no network; the only side effect is
///    progress `println!` calls that report which branch ran.
/// 2. [`provision_secret_backend`] — opens the unified
///    `MediatorSecrets` store, probes it (catches typos / missing
///    AWS creds / dead Vault tokens here, not at first mediator
///    boot), and pushes every well-known entry the runtime expects.
/// 3. [`write_config_artefacts`] — file IO: SSL gen, `mediator.toml`
///    plus Lua, `did.jsonl`, authorization VC archive, recipe,
///    Dockerfile.
/// 4. [`print_completion_summary`] — operator-facing terminal output:
///    paths written plus admin-key echo with the UNSAFE banner.
///
/// The split exists so `mint_artefacts` is unit-testable (no IO),
/// the IO phases can be tested with a tempdir + file:// backend, and
/// each branch of the (`did_method` × `vta_session` ×
/// `admin_did_mode`) matrix lives in its own arm of one phase rather
/// than being interleaved with side effects. Integration coverage in
/// `generate_and_write_tests` locks the end-to-end behaviour against
/// regressions across the split.
async fn generate_and_write(
    config: &app::WizardConfig,
    vta_session: Option<&vta::VtaSession>,
    save_recipe: bool,
    probe: secret_backend::ProvisionProbe,
) -> anyhow::Result<()> {
    let artefacts = mint_artefacts(config, vta_session).await?;
    provision_secret_backend(config, &artefacts, vta_session, probe).await?;
    write_config_artefacts(config, &artefacts, save_recipe)?;
    // Optional: publish the minted DID + its did:webvh log to the recipe's
    // `[output].did_target` / `[output].did_log_target`. No-op unless a target
    // is configured.
    publish::publish_did_artefacts(&artefacts.mediator_did, config.did_target.as_deref()).await?;
    publish::publish_did_log_artefacts(artefacts.did_doc.as_deref(), config.did_log_target.as_deref())
        .await?;
    print_completion_summary(config, &artefacts, vta_session);
    Ok(())
}

/// Phase 1 — pure-ish value computation. Branches on `did_method`,
/// `jwt_mode`, and `admin_did_mode` to determine what the wizard will
/// stamp into the config; produces no file or network side effects.
/// `println!` progress messages stay inline so the operator sees the
/// streaming UX they're used to (which-branch-ran), but no writes
/// happen here.
///
/// The `authorization_vc` field used to be written mid-mint inside
/// the `DID_VTA` branch — that file write is now deferred to
/// [`write_config_artefacts`] so this phase is genuinely pure for
/// IO purposes.
async fn mint_artefacts(
    config: &app::WizardConfig,
    vta_session: Option<&vta::VtaSession>,
) -> anyhow::Result<MintedArtefacts> {
    // ── DID + operating secrets + (optional) DID log + (optional) VC ──
    let (mediator_did, mediator_secrets, did_doc, authorization_vc) =
        mint_did_material(config, vta_session).await?;

    // ── JWT secret ────────────────────────────────────────────────────
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

    // ── Admin DID ─────────────────────────────────────────────────────
    // If the operator went through the online-VTA sub-flow, the setup
    // did:key they pasted into the ACL has already been rotated to a
    // fresh admin identity by the SDK — prefer that over a freshly-minted
    // local did:key so the mediator has a single canonical admin DID
    // that also exists in the VTA's ACL.
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

    Ok(MintedArtefacts {
        mediator_did,
        mediator_secrets,
        did_doc,
        authorization_vc,
        jwt_secret,
        admin_did,
        admin_secret,
    })
}

/// Mint the mediator's DID + operating secrets per `did_method`.
/// Returns `(did, secrets, did_log, authorization_vc)` — the last two
/// are `None` for non-webvh / non-VTA deployments.
///
/// Used to live as a `match` block inside `mint_artefacts`; extracted
/// because the four-tuple was getting dense and the VTA arm in
/// particular was 50 lines that benefit from sitting alone.
async fn mint_did_material(
    config: &app::WizardConfig,
    vta_session: Option<&vta::VtaSession>,
) -> anyhow::Result<(
    String,
    Vec<affinidi_secrets_resolver::secrets::Secret>,
    Option<String>,
    Option<String>,
)> {
    let (did, secrets, did_log, authorization_vc) = match config.did_method.as_str() {
        DID_PEER => {
            let service_uri = did_peer_service_url(&config.public_url, &config.api_prefix);
            let (did, secrets) = generators::did_peer::generate_did_peer(
                service_uri,
                &config.key_suite,
                config.tsp_enabled,
            )?;
            (did, secrets, None, None)
        }
        DID_WEBVH => {
            // The DID identifier should encode the host only (`example.com`)
            // so the resolver fetches `<host>/.well-known/did.jsonl`. The
            // template's URL variable, by contrast, needs the *full* URL
            // including the operator's `api_prefix` so the rendered service
            // endpoints (`#didcomm`, `#auth`, `#whois`) point at the routes
            // the mediator actually serves.
            let raw_url = if config.public_url.is_empty() {
                "https://localhost:7037".to_string()
            } else {
                config.public_url.clone()
            };
            let address = strip_url_path_owned(&raw_url);
            let service_url = combine_url_prefix(&address, &config.api_prefix);
            let result = generators::did_webvh::generate_did_webvh(
                &address,
                &service_url,
                &config.key_suite,
                config.tsp_enabled,
            )
            .await?;
            (result.did, result.secrets, Some(result.did_doc), None)
        }
        DID_VTA => {
            // VTA-managed DID: two reply shapes carry it.
            // - `Full(ProvisionResult)` — fresh template render
            //   (online / offline-mint paths, FullSetup intent).
            // - `ContextExport(ContextProvisionBundle)` — re-export
            //   of already-provisioned material (offline-export path,
            //   OfflineExport intent).
            let from_full = vta_session.and_then(|s| s.as_full_provision());
            let from_export = vta_session.and_then(|s| s.as_context_export());
            if let Some(provision) = from_full {
                let integration_did = provision
                    .integration_did()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "VTA Full reply has no integration DID — the AdminRotation \
                             flow can't drive a mediator (`did_method = vta`); \
                             re-run with a FullSetup intent or pick a different did_method."
                        )
                    })?
                    .to_string();
                println!("  VTA-minted mediator DID: {integration_did}");

                // Persist the integration DID's private keys as `Secret`
                // values — the mediator's runtime secrets loader reads
                // these at startup.
                let secrets = provision
                    .integration_key()
                    .map(did_key_material_to_secrets)
                    .transpose()?
                    .unwrap_or_default();

                // Authorization VC content — actual file write happens
                // in `write_config_artefacts`. Pre-serialise here so the
                // mint phase produces a value-only `Option<String>` and
                // the IO phase has nothing to compute.
                let vc = serde_json::to_string_pretty(provision.authorization_vc()).ok();

                // The VTA also exposes the inner DID document separately
                // on `provision.payload.config.did_document`, but the
                // wizard only needs the log entry — the mediator's
                // loader extracts the DID document from the log envelope
                // for `/.well-known/did.json`.
                let log_entry = provision.webvh_log().map(str::to_string);
                (integration_did, secrets, log_entry, vc)
            } else if let Some(bundle) = from_export {
                // OfflineExport path. Bundle carries the existing
                // mediator DID + operational keys (Vec<SecretEntry>)
                // + did.jsonl entry. No authorization VC — the admin
                // identity is the `bundle.credential` itself.
                let did_view = bundle.did.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "OfflineExport bundle has no DID slot — admin-only contexts \
                         can't drive a mediator (`did_method = vta`); \
                         re-run with `did_method = peer` (admin-only) or \
                         re-export with a DID-bearing context."
                    )
                })?;
                let integration_did = did_view.id.clone();
                println!("  VTA-exported mediator DID: {integration_did}");

                let secrets = secret_entries_to_secrets(&did_view.secrets)?;
                let log_entry = did_view.log_entry.clone();
                (integration_did, secrets, log_entry, None)
            } else {
                eprintln!(
                    "  Note: VTA-managed DID selected but no provisioned session \
                     was captured. Falling back to placeholder — edit mediator.toml \
                     manually before starting the mediator."
                );
                ("vta://mediator".into(), vec![], None, None)
            }
        }
        _ => {
            // Import existing — user will need to provide details
            eprintln!(
                "  Note: {} requires manual DID configuration.",
                config.did_method
            );
            ("PLACEHOLDER_DID".into(), vec![], None, None)
        }
    };

    // Provision-time guard — reject any keyset that the mediator could not use
    // to decrypt its own inbound traffic before it ever reaches disk / the VTA.
    let admin_did = vta_session.map(|s| s.admin_did().to_string());
    validate_operating_secrets(&did, &secrets, admin_did.as_deref())?;

    Ok((did, secrets, did_log, authorization_vc))
}

/// Provision-time invariant: every operating secret must be a verification
/// method of the mediator's own DID (`{did}#…`), and the admin credential key
/// must never be provisioned as an operating secret.
///
/// The runtime registers each operating secret under its id, and a peer
/// encrypts inbound DIDComm to the keyAgreement verification-method id
/// published in the mediator's DID document. If the ids diverge the mediator
/// boots cleanly but fails to decrypt *every* inbound message ("No local secret
/// matches any JWE recipient"). The classic cause is a VTA context whose key
/// *labels* are `did:key:…`/free-text instead of the DID document's `#key-N`
/// ids — `fetch_did_secrets_bundle` uses the label as the kid — so catch it
/// here rather than as a silent per-request runtime outage.
fn validate_operating_secrets(
    did: &str,
    secrets: &[affinidi_secrets_resolver::secrets::Secret],
    admin_did: Option<&str>,
) -> anyhow::Result<()> {
    let vm_prefix = format!("{did}#");
    for secret in secrets {
        if let Some(admin) = admin_did
            && secret.id.starts_with(admin)
        {
            anyhow::bail!(
                "The admin DID key `{admin}` was returned as an operating secret. The admin \
                 credential must not double as a mediator operating key — re-provision the VTA \
                 context so operating secrets contain only the mediator DID's keys."
            );
        }
        if !secret.id.starts_with(&vm_prefix) {
            anyhow::bail!(
                "Operating secret id `{}` is not a verification method of the mediator DID \
                 `{did}` (expected `{did}#…`). The mediator would publish its keyAgreement key \
                 under `{did}#…` but hold the secret under a different id, so every inbound \
                 message would fail to decrypt. If this DID is VTA-managed, set the VTA \
                 context's key labels to the DID document verification-method ids and \
                 re-provision.",
                secret.id
            );
        }
    }
    Ok(())
}

/// Phase 2 — open the unified secret backend, probe it, push every
/// well-known entry the mediator runtime expects at startup. Async
/// because every backend (keyring, AWS, GCP, Azure, Vault, file) is
/// async at the trait level.
///
/// Self-hosted (did:peer / did:webvh): operating keys + JWT.
/// VTA-managed: admin credential (so the mediator can authenticate to
/// the VTA at boot) + JWT. Operating keys come from the VTA.
async fn provision_secret_backend(
    config: &app::WizardConfig,
    artefacts: &MintedArtefacts,
    vta_session: Option<&vta::VtaSession>,
    probe: secret_backend::ProvisionProbe,
) -> anyhow::Result<()> {
    let backend_url = config_writer::build_backend_url(config);
    println!("  Provisioning unified secret backend: {backend_url}");
    // macOS Keychain prompts once per keychain item the first time a
    // given binary (code-signature ACL) accesses it. Each `cargo
    // build` produces a new binary — so operators rebuilding the
    // wizard during development see fresh prompts on every run. Tell
    // them up-front so they know to click "Always Allow" once per
    // item, and that subsequent re-runs from the same binary won't
    // re-prompt.
    if backend_url.starts_with("keyring://") {
        println!(
            "    \x1b[2mNote: macOS may prompt the Keychain once per item on first \
             access. Click \"Always Allow\" to grant this binary permanent access; \
             subsequent re-runs of the same binary won't re-prompt.\x1b[0m"
        );
    }
    let mediator_secrets_store =
        secret_backend::open_and_probe_secret_backend(&backend_url, probe).await?;

    // JWT signing key — only when generated. Provide-mode skips this
    // and relies on the boot-time env-var/flag path.
    if let Some(ref bytes) = artefacts.jwt_secret {
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
    if !artefacts.mediator_secrets.is_empty() {
        mediator_secrets_store
            .store_entry(
                affinidi_messaging_mediator_common::OPERATING_SECRETS,
                "operating-secrets",
                &artefacts.mediator_secrets,
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to store operating secrets: {e}"))?;
        let count = artefacts.mediator_secrets.len();
        println!(
            "    \x1b[32m\u{2714}\x1b[0m {} ({} key{})",
            affinidi_messaging_mediator_common::OPERATING_SECRETS,
            count,
            if count == 1 { "" } else { "s" }
        );
    }

    // Admin credential — VTA-linked path. The session captures the
    // rotated admin did:key + the VTA DID/URL that minted it.
    if let Some(session) = vta_session {
        let cred = affinidi_messaging_mediator_common::AdminCredential {
            did: session.admin_did().to_string(),
            private_key_multibase: session.admin_private_key_mb().to_string(),
            vta_did: Some(session.vta_did.clone()),
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

        // Seed the VTA fallback cache with the bundle we just
        // provisioned. The mediator's runtime boot calls
        // `vta_sdk::integration::startup()`, which tries a live fetch
        // and falls back to this cache on *any* failure — network
        // timeout, auth rejection, or VTA-side validation error
        // (see `integration/mod.rs::startup` match arms). Pre-populating
        // here means first-boot survives VTA unavailability and, as
        // a side effect, unblocks the "context has no DID assigned"
        // validation failure until the VTA service auto-binds the
        // provisioned DID to the context row. TTL `0` = no expiry:
        // the runtime overwrites this with a fresh snapshot on every
        // successful VTA contact, so staleness is self-healing.
        // AdminOnly sessions return `None` — the mediator brought its
        // own DID and there's nothing to cache.
        if let Some(bundle) = build_did_secrets_bundle(session) {
            let json = serde_json::to_value(&bundle)
                .map_err(|e| anyhow::anyhow!("Failed to serialize cached VTA bundle: {e}"))?;
            mediator_secrets_store
                .store_vta_cached_bundle(json, 0)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to seed VTA cache: {e}"))?;
            println!(
                "    \x1b[32m\u{2714}\x1b[0m mediator/vta/last_known_bundle ({} key{})",
                bundle.secrets.len(),
                if bundle.secrets.len() == 1 { "" } else { "s" }
            );
        }
    } else if let (Some(did), Some(secret)) = (
        artefacts.admin_did.as_ref(),
        artefacts.admin_secret.as_ref(),
    ) {
        // Self-hosted ADMIN_GENERATE: the wizard minted the admin DID
        // locally (no VTA session), so the only place the private key
        // exists outside this process is the operator's terminal
        // buffer. Persist it into the configured backend under the
        // same well-known key VTA-linked runs use, with vta_did /
        // vta_url left `None` so the mediator's config loader skips
        // the VTA integration branch for this deployment.
        if let Ok(privkey) = secret.get_private_keymultibase() {
            let cred = affinidi_messaging_mediator_common::AdminCredential {
                did: did.clone(),
                private_key_multibase: privkey,
                vta_did: None,
                vta_url: None,
                context: "mediator".into(),
            };
            mediator_secrets_store
                .store_admin_credential(&cred)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to store admin credential: {e}"))?;
            println!(
                "    \x1b[32m\u{2714}\x1b[0m {} (self-hosted)",
                affinidi_messaging_mediator_common::ADMIN_CREDENTIAL
            );
        }
    }

    Ok(())
}

/// Phase 3 — file IO. Generates self-signed SSL (when requested),
/// writes `mediator.toml` + `atm-functions.lua` (via
/// `config_writer::write_config`), the did.jsonl log envelope, the
/// authorization VC archive, the build recipe (when requested), and
/// the Docker artefacts (when requested).
///
/// SSL generation lives here rather than in `mint_artefacts` because
/// it's a side effect — `generators::ssl::generate_self_signed_cert`
/// writes the `.cert` / `.key` pair to disk before returning the
/// paths. Keeping the call here matches the "no IO in mint" rule.
fn write_config_artefacts(
    config: &app::WizardConfig,
    artefacts: &MintedArtefacts,
    save_recipe: bool,
) -> anyhow::Result<()> {
    // Self-signed SSL (when requested). Writes `conf/keys/end.cert`
    // and `conf/keys/end.key` (the latter at 0o600 via
    // `secure_fs`); paths feed into `mediator.toml`.
    let (ssl_cert_path, ssl_key_path) = if config.ssl_mode == SSL_SELF_SIGNED {
        let (cert, key) = generators::ssl::generate_self_signed_cert("conf/keys")?;
        (Some(cert), Some(key))
    } else {
        (None, None)
    };

    let generated = config_writer::GeneratedValues {
        mediator_did: artefacts.mediator_did.clone(),
        jwt_secret: artefacts.jwt_secret.clone(),
        admin_did: artefacts.admin_did.clone(),
        admin_secret: artefacts.admin_secret.clone(),
        ssl_cert_path,
        ssl_key_path,
        // The post-match write below mirrors this flag — they're set
        // off the same `did_doc` Option so `did_web_self_hosted` is
        // wired into `mediator.toml` exactly when there's a `did.jsonl`
        // on disk for the loader to read.
        did_log_jsonl_written: artefacts.did_doc.is_some(),
    };

    config_writer::write_config(config, &generated)?;

    // Write the did:webvh log entry to `did.jsonl` so the mediator's
    // `/.well-known/did.jsonl` route can serve it. Source is either the
    // self-host generator (DID_WEBVH branch) or the VTA's
    // `provision.webvh_log()` / `did_view.log_entry` (DID_VTA branches);
    // both return the canonical log-entry JSON envelope.
    // `write_did_jsonl` adds the trailing newline strict JSONL requires.
    if let Some(ref doc) = artefacts.did_doc {
        write_did_jsonl(&config.config_path, doc);

        // Optional did:web export. When the operator asked for it and the
        // minted DID is a did:webvh (local generator or VTA-managed webvh
        // log), rewrite the resolved DID document to its did:web form and
        // drop it next to the config as `did-web.json` for hosting under
        // did:web. Non-webvh DIDs (did:peer, VTA-managed did:web/did:key)
        // have no scid to drop, so we skip with a note rather than emit a
        // misleading file.
        if config.save_did_web {
            if artefacts.mediator_did.starts_with("did:webvh:") {
                write_did_web_json(&config.config_path, doc, &artefacts.mediator_did);
            } else {
                eprintln!(
                    "  \x1b[33mNote:\x1b[0m --save-did-web requested but the mediator DID \
                     is not a did:webvh ({}); skipping did:web export.",
                    artefacts.mediator_did
                );
            }
        }
    }

    // Authorization VC archive (DID_VTA Full path only). Pre-serialised
    // in `mint_did_material` so this phase is pure file IO. Short-lived
    // (~1h validity) but useful for operator audit trails. Owner-only
    // on Unix — VC is a signed authorization credential and a co-tenant
    // shouldn't be able to read the operator's audit trail.
    if let Some(ref vc_text) = artefacts.authorization_vc {
        let vc_path = std::path::Path::new(&config.config_path)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("authorization.jsonld");
        match crate::secure_fs::write_sensitive(&vc_path, vc_text) {
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

    // Admin monitor profile (`admin-monitor.json`). Emitted only when the
    // wizard has the admin DID's secret material in memory — i.e., the
    // `ADMIN_GENERATE` path. This is the file `mediator-monitor
    // --admin-profile <path>` consumes. For VTA-managed admins the
    // secret material lives in the configured secret backend; we don't
    // re-derive a flat-file profile here (often the backend is cloud-
    // hosted specifically to keep secrets off disk).
    //
    // Only `(Some, Some)` triggers the write: `mint_artefacts` sets
    // `admin_secret = None` for the VTA path (credential is in the
    // session) and for `ADMIN_SKIP` (no admin at all).
    if let (Some(admin_did), Some(admin_secret)) = (&artefacts.admin_did, &artefacts.admin_secret) {
        match admin_monitor_profile::write(
            &config.config_path,
            &artefacts.mediator_did,
            admin_did,
            admin_secret,
        ) {
            Ok(path) => println!(
                "  \x1b[32m\u{2714}\x1b[0m Admin monitor profile: \x1b[1m{}\x1b[0m\n    \
                 \x1b[2mUse with: \x1b[36mmediator-monitor --admin-profile {}\x1b[0m",
                path.display(),
                path.display(),
            ),
            // Non-fatal — the wizard's primary job is the mediator
            // config; a failed monitor profile shouldn't roll back
            // an otherwise good setup. Surface it loudly so the
            // operator knows to construct it manually if they
            // wanted monitor.
            Err(e) => eprintln!(
                "  \x1b[33mWarning:\x1b[0m could not write admin monitor profile: {e}\n    \
                 mediator-monitor --admin-profile won't have a ready-made file; \
                 reconstruct manually if needed."
            ),
        }
    }

    // Save build recipe for reproducibility (skip when running from --from).
    if save_recipe {
        let recipe_path = std::path::Path::new(&config.config_path)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("mediator-build.toml");
        let recipe_content = recipe::from_wizard_config(config);
        // Recipe is "designed to not contain secrets" (URLs are
        // redacted by `redact_url`), but it does carry the resolved
        // secret-backend URL — vault endpoint, AWS region/namespace,
        // azure vault id, etc. — which is enough to mount a targeted
        // attack on the mediator's secret store. Owner-only on Unix.
        crate::secure_fs::write_sensitive(&recipe_path, &recipe_content)?;
        println!(
            "  \x1b[32m\u{2714}\x1b[0m Build recipe:  \x1b[1m{}\x1b[0m",
            recipe_path.display()
        );
    }

    // Generate Docker files for container deployments.
    if config.deployment_type == DEPLOYMENT_CONTAINER {
        docker::generate_dockerfile(config, ".")?;
    }

    Ok(())
}

/// Phase 4 — operator-facing terminal output. No file or network IO;
/// just the streaming progress messages + admin-key echo with the
/// UNSAFE banner. Kept separate from `write_config_artefacts` so the
/// IO phase doesn't have to share its termination point with the
/// final summary banner — easier to keep both readable.
fn print_completion_summary(
    config: &app::WizardConfig,
    artefacts: &MintedArtefacts,
    vta_session: Option<&vta::VtaSession>,
) {
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

    if let Some(ref did) = artefacts.admin_did {
        println!("  \x1b[32m\u{2714}\x1b[0m Admin DID: \x1b[36m{did}\x1b[0m");
        if let Some(ref secret) = artefacts.admin_secret {
            if let Ok(privkey) = secret.get_private_keymultibase() {
                print_admin_key_echo(&privkey, None);
            }
        } else if let Some(session) = vta_session {
            // VTA-session rotation case: the credential is already in
            // the backend (stored by `provision_secret_backend`). The
            // stdout echo is a convenience so operators can copy the
            // key for offline storage — same UNSAFE warning applies.
            print_admin_key_echo(
                session.admin_private_key_mb(),
                Some((session.vta_did.as_str(), session.context_id.as_str())),
            );
        }
    }

    if config.secret_storage == STORAGE_FILE {
        // Report the operator's actual backend path, not a hard-coded
        // `conf/secrets.json` — the unified backend writes wherever
        // `[secrets].storage` points.
        println!(
            "  \x1b[32m\u{2714}\x1b[0m Secrets: \x1b[1m{}\x1b[0m",
            config.secret_file_path
        );
    }

    if config.ssl_mode == SSL_SELF_SIGNED {
        println!("  \x1b[32m\u{2714}\x1b[0m SSL certificates: conf/keys/");
    }
}

/// Print the admin private key to stdout alongside an UNSAFE banner.
/// Used for both the self-hosted ADMIN_GENERATE path and the VTA
/// rotation path — in both cases the key is ALREADY safely stored in
/// the configured secret backend, so the stdout echo is a courtesy
/// that the operator can copy to offline storage. The banner makes
/// the trust posture explicit: anything that tails this output
/// (systemd-journal, CI logs, shoulder-surfers) gets the key.
///
/// `vta_context`, when supplied, prints the VTA DID + context the
/// credential was minted against. It doesn't change the warning.
fn print_admin_key_echo(privkey_multibase: &str, vta_context: Option<(&str, &str)>) {
    println!();
    // Red-background bold ` UNSAFE ` badge, then a white-bold
    // explanation. Copying exact escape sequences from the spec.
    println!(
        "  \x1b[41;97m UNSAFE \x1b[0m \x1b[1mAdmin private key printed below for operator \
         bookkeeping.\x1b[0m"
    );
    println!(
        "  \x1b[2mThis key is already stored in the configured secret backend — copy it to \
         an offline store now and clear your terminal scrollback if you care about \
         confidentiality.\x1b[0m"
    );
    println!("  \x1b[2mPrivate key (multibase): {privkey_multibase}\x1b[0m");
    if let Some((vta_did, context)) = vta_context {
        println!("  \x1b[2mVTA DID: {vta_did}   Context: {context}\x1b[0m");
    }
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
/// Build the cargo build arguments for the mediator. `needs_explicit`
/// must come from [`app::WizardConfig::needs_explicit_features`] so
/// `--no-default-features` is set if and only if the wizard's choices
/// differ from the mediator crate's defaults.
fn build_cargo_args(features: &[&str], needs_explicit: bool) -> Vec<String> {
    let mut args = vec![
        "build".to_string(),
        "--release".to_string(),
        "-p".to_string(),
        "affinidi-messaging-mediator".to_string(),
    ];

    if needs_explicit {
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
        if cargo_toml.exists()
            && let Ok(contents) = std::fs::read_to_string(&cargo_toml)
            && contents.contains("[workspace]")
        {
            return Some(dir);
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
    if let Ok(cwd) = std::env::current_dir()
        && let Ok(abs) = cwd.join(config_path).canonicalize()
    {
        return abs.to_string_lossy().into_owned();
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
                    selected = selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') if selected < options.len() - 1 => {
                    selected += 1;
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

/// Build the `cargo install` arguments for the mediator. `needs_explicit`
/// must come from [`app::WizardConfig::needs_explicit_features`] so
/// `--no-default-features` is set if and only if the wizard's choices
/// differ from the mediator crate's defaults.
fn build_install_args(
    features: &[&str],
    needs_explicit: bool,
    install_root: Option<&str>,
) -> Vec<String> {
    let mut args = vec![
        "install".to_string(),
        "--path".to_string(),
        "crates/messaging/affinidi-messaging-mediator".to_string(),
    ];

    if needs_explicit {
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
/// Emit the "phase 1 complete — now do this on the VTA host, then
/// re-run with --bundle" guidance after the headless dispatcher
/// writes the request file. Mirrors the interactive TUI's
/// `primary_command` screen but addressed to an operator looking at
/// a shell prompt rather than a ratatui panel.
fn print_phase1_next_steps(
    recipe_path: &str,
    request_path: &std::path::Path,
    bundle_id_hex: &str,
    producer_command: &str,
    pnm_command: &str,
) {
    println!("  \x1b[32m\u{2714}\x1b[0m Phase 1 complete — bootstrap request written.");
    println!();
    println!(
        "  \x1b[1mRequest file:\x1b[0m  \x1b[36m{}\x1b[0m",
        request_path.display()
    );
    println!("  \x1b[1mBundle ID:\x1b[0m     \x1b[36m{bundle_id_hex}\x1b[0m");
    println!();
    // `AdminOnly` intent has the same `pnm contexts bootstrap …` shape
    // for both the offline and live-API flavours, so an "unseal first"
    // note doesn't apply — show the single command and move on.
    //
    // `FullSetup` and `OfflineExport` *do* gate the offline `vta …`
    // form on an unsealed VTA. After install or after `vta bootstrap-
    // admin`, the VTA is sealed by default, and the offline command
    // errors with "VTA is sealed (… Offline CLI commands are
    // disabled)" — exactly the coldstart trap a first-time operator
    // hits. The unseal note is the canonical fix; the pnm alternative
    // is shown as an escape hatch for operators who already have a
    // pnm session against an operational VTA.
    if producer_command == pnm_command {
        println!("  \x1b[1mNext — on the VTA host, run:\x1b[0m");
        println!("    \x1b[36m{producer_command}\x1b[0m");
    } else {
        println!("  \x1b[1mNext — on the VTA host, run:\x1b[0m");
        println!("    \x1b[36m{producer_command}\x1b[0m");
        println!();
        println!(
            "  \x1b[2mIf the VTA is sealed (default state after install or after\n  \
             `vta bootstrap-admin`), the command above errors with\n  \
             \"VTA is sealed (… Offline CLI commands are disabled)\".\n  \
             Unseal first (challenge-response with your super-admin key),\n  \
             then re-run the command above:\x1b[0m"
        );
        println!("    \x1b[36mvta unseal\x1b[0m");
        println!();
        println!(
            "  \x1b[2mAlternatively, if you have a `pnm` session authenticated\n  \
             against this VTA, the live-API form skips the unseal step:\x1b[0m"
        );
        println!("    \x1b[36m{pnm_command}\x1b[0m");
    }
    println!();
    println!("  \x1b[1mThen — back on this host, run:\x1b[0m");
    println!(
        "    \x1b[36mmediator-setup --from {recipe_path} --bundle bundle.armor \\\n     [--digest <sha256>]\x1b[0m"
    );
    println!();
    println!(
        "  \x1b[2mThe --digest is optional but recommended — paste the SHA-256\n  \
         the VTA admin prints out-of-band.\x1b[0m"
    );
}

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
    let features = config.cargo_features();
    let needs_explicit = config.needs_explicit_features();
    let build_args = build_cargo_args(&features, needs_explicit);
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
        let install_cmd = format!(
            "cargo {}",
            build_install_args(&features, needs_explicit, None).join(" ")
        );
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
            let install_cmd = format!(
                "cargo {}",
                build_install_args(&features, needs_explicit, None).join(" ")
            );
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
    print!("  \x1b[1mInstall location\x1b[0m [{default_bin}]: ");
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

    let install_args = build_install_args(&features, needs_explicit, install_root.as_deref());
    let install_cmd = format!("cargo {}", install_args.join(" "));

    let install_location = install_root
        .as_ref()
        .map(|r| format!("{r}/bin"))
        .unwrap_or_else(|| default_bin.clone());

    // Print the full command + working directory *before* running it.
    // Mirrors `run_from_recipe`'s existing behaviour — the command
    // lives in the operator's scroll history regardless of whether
    // the build succeeds, so a "retry with different flags" or
    // "inspect why this rebuilt everything" follow-up doesn't need
    // them to chase the recipe or memo the feature set.
    println!("\n  \x1b[1mInstall command:\x1b[0m");
    println!(
        "    \x1b[2mcd\x1b[0m \x1b[36m{}\x1b[0m",
        build_dir.display()
    );
    println!("    \x1b[36m{install_cmd}\x1b[0m\n");

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
            eprintln!("\n  \x1b[31m\u{2718} Install failed (exit code: {exit})\x1b[0m");
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
    let run_features_flag = if config.needs_explicit_features() {
        format!(
            " --no-default-features --features {}",
            config.cargo_features().join(",")
        )
    } else {
        String::new()
    };

    println!("  \x1b[1mOption 1 — Install (recommended):\x1b[0m");
    println!("    \x1b[36m{install_cmd}\x1b[0m");
    println!("    \x1b[36mmediator -c {abs_config}\x1b[0m");
    println!();
    println!("  \x1b[1mOption 2 — Build and run from source:\x1b[0m");
    println!("    \x1b[36m{build_cmd}\x1b[0m");
    println!(
        "    \x1b[36mcargo run --release -p affinidi-messaging-mediator{run_features_flag} -- -c {abs_config}\x1b[0m"
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
        // The unified backend writes to the operator's configured
        // `[secrets].storage` path — show that, not a hard-coded
        // `<config_dir>/secrets.json`.
        println!(
            "    \x1b[36m{}\x1b[0m  — \x1b[33mprivate keys (keep secure!)\x1b[0m",
            config.secret_file_path
        );
    }

    if config.ssl_mode == SSL_SELF_SIGNED {
        println!("    \x1b[36mconf/keys/end.cert\x1b[0m  — SSL certificate");
        println!("    \x1b[36mconf/keys/end.key\x1b[0m   — SSL private key");
    }

    if config.did_method == DID_WEBVH {
        let did_log_path = config_dir.join("did.jsonl");
        println!(
            "    \x1b[36m{}\x1b[0m  — did:webvh log entry",
            did_log_path.display()
        );
    }

    if config.deployment_type == DEPLOYMENT_CONTAINER {
        println!("    \x1b[36mDockerfile\x1b[0m  — container build file");
        println!("    \x1b[36mdocker-compose.yml\x1b[0m  — mediator + Redis self-contained stack");
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

#[cfg(test)]
mod operating_secrets_guard_tests {
    use super::validate_operating_secrets;
    use affinidi_secrets_resolver::secrets::Secret;

    const MED: &str =
        "did:webvh:QmQjq4GHRH9fwSXCg4884kxpCMT5EUqHB9XY2U7aXisP8R:webvh.storm.ws:mediator-2";

    fn secret_with_id(id: &str) -> Secret {
        let mut s = Secret::generate_ed25519(None, None);
        s.id = id.to_string();
        s
    }

    #[test]
    fn accepts_secrets_keyed_by_mediator_vm_ids() {
        let secrets = vec![
            secret_with_id(&format!("{MED}#key-0")),
            secret_with_id(&format!("{MED}#key-1")),
        ];
        assert!(validate_operating_secrets(MED, &secrets, None).is_ok());
    }

    #[test]
    fn empty_secrets_is_ok() {
        assert!(validate_operating_secrets(MED, &[], None).is_ok());
    }

    #[test]
    fn rejects_did_key_labelled_secret() {
        // The exact shape that broke a live mediator: a VTA context whose key
        // labels are `did:key:` + free text instead of the DID document's
        // `#key-N` verification-method ids.
        let secrets = vec![secret_with_id(
            "did:key:z6Mkr4JCdsEVcQvYKxcyjf39tPmVriDfg3gALvqv4GQHc5BH key-agreement key",
        )];
        let err = validate_operating_secrets(MED, &secrets, None).unwrap_err();
        assert!(
            err.to_string().contains("not a verification method"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_admin_key_as_operating_secret() {
        let admin = "did:key:z6Mkt6eNM38RhFfjSdmXBtT1SRL7sPgPZD1MkXZbwjYBhTLf";
        let secrets = vec![secret_with_id(&format!(
            "{admin}#{}",
            &admin["did:key:".len()..]
        ))];
        let err = validate_operating_secrets(MED, &secrets, Some(admin)).unwrap_err();
        assert!(err.to_string().contains("admin"), "unexpected error: {err}");
    }
}

#[cfg(test)]
mod cache_bundle_tests {
    use super::build_did_secrets_bundle;
    use crate::vta::VtaSession;
    use vta_sdk::context_provision::{ContextProvisionBundle, ProvisionedDid};
    use vta_sdk::credentials::CredentialBundle;
    use vta_sdk::did_secrets::SecretEntry;
    use vta_sdk::keys::KeyType;

    #[test]
    fn full_provision_projects_to_signing_plus_ka_bundle() {
        // TemplateBootstrap path: mediator DID + typed signing/ka key
        // pair. Must land as two SecretEntries with the correct
        // discriminants (Ed25519 for signing, X25519 for key-agreement)
        // and the raw multibase passthrough.
        let provision = vta_sdk::provision_client::test_helpers::sample_provision_result(
            /*rolled_over=*/ true,
        );
        let session = VtaSession::full(
            "prod-mediator".into(),
            "did:webvh:vta.example.com".into(),
            Some("https://vta.example.com".into()),
            None,
            provision,
        );

        let bundle = build_did_secrets_bundle(&session).expect("bundle projected");
        assert_eq!(bundle.did, "did:webvh:integration.example.com");
        assert_eq!(bundle.secrets.len(), 2);
        assert!(matches!(bundle.secrets[0].key_type, KeyType::Ed25519));
        assert!(matches!(bundle.secrets[1].key_type, KeyType::X25519));
        // Multibase passthrough — the runtime's `Secret::from_multibase`
        // is the one doing the actual key decode, so we round-trip the
        // string verbatim.
        assert_eq!(bundle.secrets[0].private_key_multibase, "zPrivateSample");
        assert_eq!(bundle.secrets[1].private_key_multibase, "zKaPrivate");
    }

    #[test]
    fn admin_only_yields_no_bundle() {
        // AdminOnly session doesn't carry a VTA-provisioned integration
        // DID — the mediator brought its own. Nothing to cache; the
        // helper must signal that explicitly so the caller doesn't
        // write a malformed bundle keyed to the admin DID.
        let session = VtaSession::admin_only(
            "prod-mediator".into(),
            "did:webvh:vta.example.com".into(),
            None,
            None,
            "did:key:z6MkAdmin".into(),
            "zAdminPrivate".into(),
        );
        assert!(build_did_secrets_bundle(&session).is_none());
    }

    #[test]
    fn context_export_passes_through_secret_entries() {
        // OfflineExport path: ContextProvisionBundle already has a
        // flat Vec<SecretEntry> (including whatever key types the VTA
        // chose), so the projection is a direct copy.
        let did_view = ProvisionedDid {
            id: "did:webvh:mediator.example.com".into(),
            did_document: None,
            log_entry: None,
            secrets: vec![
                SecretEntry {
                    key_id: "did:webvh:mediator.example.com#key-0".into(),
                    key_type: KeyType::Ed25519,
                    private_key_multibase: "zSigning".into(),
                },
                SecretEntry {
                    key_id: "did:webvh:mediator.example.com#key-1".into(),
                    key_type: KeyType::X25519,
                    private_key_multibase: "zKa".into(),
                },
            ],
        };
        let ctx_bundle = ContextProvisionBundle {
            context_id: "prod-mediator".into(),
            context_name: "Prod mediator".into(),
            vta_url: None,
            vta_did: Some("did:webvh:vta.example.com".into()),
            credential: CredentialBundle::new(
                "did:key:z6MkAdmin",
                "zAdminPrivate",
                "did:webvh:vta.example.com",
            ),
            admin_did: "did:key:z6MkAdmin".into(),
            did: Some(did_view),
        };
        let session = VtaSession::context_export("prod-mediator".into(), ctx_bundle);

        let bundle = build_did_secrets_bundle(&session).expect("bundle projected");
        assert_eq!(bundle.did, "did:webvh:mediator.example.com");
        assert_eq!(bundle.secrets.len(), 2);
        assert_eq!(
            bundle.secrets[0].key_id,
            "did:webvh:mediator.example.com#key-0"
        );
        assert_eq!(bundle.secrets[1].private_key_multibase, "zKa");
    }
}

/// Integration tests against `generate_and_write` end-to-end.
///
/// Locks down the recipe → wizard config → on-disk artefact contract
/// before refactoring the function into smaller phases. The test
/// shouldn't change behaviour pre- and post-refactor; if the same
/// inputs produce a different `mediator.toml` / `secrets.json` /
/// recipe, the refactor regressed something.
///
/// All tests use a tempdir and `#[serial_test::serial]` because
/// `generate_and_write` writes some artefacts (SSL keys, Dockerfile)
/// to paths relative to CWD via the `conf/` prefix; CWD-mutating
/// tests must not race with each other.
#[cfg(test)]
mod generate_and_write_tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    fn decode_service_segments(did: &str) -> Vec<serde_json::Value> {
        did.split('.')
            .filter_map(|segment| segment.strip_prefix('S'))
            .map(|segment| {
                let bytes = URL_SAFE_NO_PAD.decode(segment).unwrap();
                serde_json::from_slice(&bytes).unwrap()
            })
            .collect()
    }

    /// Tempdir + CWD swap, restored on drop. Mirrors the
    /// `bootstrap_headless::tests::CwdGuard` pattern (kept private to
    /// that module). Two-line duplication is cheaper than restructuring
    /// for re-use across binary-private mod tests.
    struct CwdGuard {
        _tmp: tempfile::TempDir,
        path: std::path::PathBuf,
        prev: std::path::PathBuf,
    }

    impl CwdGuard {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let prev = std::env::current_dir().unwrap();
            let path = tmp.path().to_path_buf();
            std::env::set_current_dir(&path).unwrap();
            Self {
                _tmp: tmp,
                path,
                prev,
            }
        }
        fn dir(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev);
        }
    }

    /// Build a minimal `did:peer` config that exercises every
    /// non-VTA generate_and_write phase: DID generation, JWT mint,
    /// admin did:key generation, file:// backend probe + writes,
    /// mediator.toml write, atm-functions.lua write, recipe write.
    /// Skips SSL (writes to relative `conf/keys/` and is exercised
    /// elsewhere) and Docker (deployment_type-gated).
    fn did_peer_config(dir: &std::path::Path) -> app::WizardConfig {
        let conf_dir = dir.join("conf");
        let secrets_path = dir.join("unified-secrets.json");
        app::WizardConfig {
            config_path: conf_dir
                .join("mediator.toml")
                .to_string_lossy()
                .into_owned(),
            deployment_type: DEPLOYMENT_LOCAL.into(),
            didcomm_enabled: true,
            tsp_enabled: false,
            did_method: DID_PEER.into(),
            secret_storage: crate::consts::STORAGE_FILE.into(),
            secret_file_path: secrets_path.to_string_lossy().into_owned(),
            secret_file_encrypted: false,
            ssl_mode: SSL_NONE.into(),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: ADMIN_GENERATE.into(),
            public_url: "http://localhost:7037".into(),
            ..app::WizardConfig::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn generate_and_write_did_peer_emits_full_artefact_set() {
        // End-to-end: did:peer + file:// + JWT generate + admin
        // generate. Every phase except SSL and Docker runs. The
        // assertions cover what the upcoming refactor must preserve:
        // every file lands in the right place with the right shape.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let config = did_peer_config(&dir);

        generate_and_write(
            &config,
            None,
            /*save_recipe=*/ true,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .expect("generate_and_write must succeed for did:peer");

        // Phase: write_config — mediator.toml + atm-functions.lua.
        let toml_path = dir.join("conf").join("mediator.toml");
        let lua_path = dir.join("conf").join("atm-functions.lua");
        assert!(toml_path.exists(), "mediator.toml must be written");
        assert!(lua_path.exists(), "atm-functions.lua must be written");

        // mediator.toml must parse and carry every field the wizard
        // sets: mediator DID (did:peer:…), admin DID (did:key:…),
        // backend URL (file://…), api_prefix, listen_address.
        let toml_text = std::fs::read_to_string(&toml_path).unwrap();
        let parsed: toml::Value =
            toml::from_str(&toml_text).expect("mediator.toml must be valid TOML");
        let mediator_did = parsed
            .get("mediator_did")
            .and_then(|v| v.as_str())
            .expect("mediator_did must be present");
        assert!(
            mediator_did.starts_with("did://did:peer:"),
            "mediator_did must be a did:peer (got: {mediator_did})"
        );
        let mediator_did = mediator_did.trim_start_matches("did://");
        assert_eq!(
            mediator_did.matches(".S").count(),
            2,
            "did:peer should advertise DIDComm + #auth services"
        );
        let services = decode_service_segments(mediator_did);
        assert_eq!(services.len(), 2);
        assert_eq!(
            services[0]["s"][0]["uri"],
            "http://localhost:7037/mediator/v1"
        );
        assert_eq!(
            services[0]["s"][1]["uri"],
            "ws://localhost:7037/mediator/v1/ws"
        );
        assert!(services[1]["id"].as_str().unwrap().ends_with("#auth"));
        assert_eq!(
            services[1]["s"],
            "http://localhost:7037/mediator/v1/authenticate"
        );
        let server = parsed.get("server").expect("[server] section");
        let admin_did = server
            .get("admin_did")
            .and_then(|v| v.as_str())
            .expect("admin_did must be present");
        assert!(
            admin_did.starts_with("did://did:key:"),
            "admin_did must be a did:key (got: {admin_did})"
        );
        let secrets = parsed.get("secrets").expect("[secrets] section");
        let backend = secrets
            .get("backend")
            .and_then(|v| v.as_str())
            .expect("[secrets].backend");
        assert!(
            backend.starts_with("file://"),
            "backend must be the file:// URL (got: {backend})"
        );

        // Phase: provision_secret_backend — unified store contains
        // the JWT secret + operating secrets + admin credential.
        // Verify the file backend was populated rather than asserting
        // exact bytes (the JWT key is randomly generated).
        let unified_path = dir.join("unified-secrets.json");
        assert!(
            unified_path.exists(),
            "unified secret backend file must exist after probe + writes"
        );
        let unified_text = std::fs::read_to_string(&unified_path).unwrap();
        // Parse to verify well-formed JSON; assert on the well-known
        // keys mediator-common defines.
        let unified_json: serde_json::Value =
            serde_json::from_str(&unified_text).expect("unified secrets file must be valid JSON");
        let _ = unified_json; // structural-validity check only
        for well_known in [
            affinidi_messaging_mediator_common::JWT_SECRET,
            affinidi_messaging_mediator_common::OPERATING_SECRETS,
            affinidi_messaging_mediator_common::ADMIN_CREDENTIAL,
        ] {
            assert!(
                unified_text.contains(well_known),
                "unified secret backend missing well-known key '{well_known}': {unified_text}"
            );
        }

        // No legacy `<config_dir>/secrets.json` array is written anymore:
        // the unified backend is the sole owner of secret persistence
        // (#354). The wizard used to emit an `affinidi_secrets_resolver`
        // array here that clobbered the unified file on the default path.
        let legacy_secrets = dir.join("conf").join("secrets.json");
        assert!(
            !legacy_secrets.exists(),
            "wizard must not write a legacy secrets.json array (#354)"
        );

        // Phase: admin-monitor.json — TDKProfile-shaped JSON for
        // `mediator-monitor --admin-profile`. Emitted by
        // `write_config_artefacts` whenever the wizard has the admin
        // DID's secret material in memory (i.e., ADMIN_GENERATE).
        let monitor_profile = dir.join("conf").join("admin-monitor.json");
        assert!(
            monitor_profile.exists(),
            "admin-monitor.json must be written when admin DID is generated locally"
        );
        let monitor_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&monitor_profile).unwrap())
                .expect("admin-monitor.json must be valid JSON");
        let monitor_obj = monitor_json
            .as_object()
            .expect("admin-monitor.json top-level must be an object");
        // Mediator DID in the monitor profile must match what the
        // wizard wrote into mediator.toml — same identity used as the
        // JWT audience.
        let monitor_mediator = monitor_obj
            .get("mediator")
            .and_then(serde_json::Value::as_str)
            .expect("admin-monitor.json `mediator` field");
        // mediator.toml stores the DID with a `did://` URI prefix; the
        // monitor profile is the bare DID since TDKProfile.mediator
        // expects a DID, not a URI. Compare by stripping that prefix.
        let toml_did_bare = mediator_did.trim_start_matches("did://");
        assert_eq!(
            monitor_mediator, toml_did_bare,
            "admin-monitor.json mediator DID must match mediator.toml's mediator_did",
        );
        let monitor_admin = monitor_obj
            .get("did")
            .and_then(serde_json::Value::as_str)
            .expect("admin-monitor.json `did` field");
        let toml_admin_bare = admin_did.trim_start_matches("did://");
        assert_eq!(
            monitor_admin, toml_admin_bare,
            "admin-monitor.json admin DID must match mediator.toml's admin_did",
        );
        let monitor_secrets = monitor_obj
            .get("secrets")
            .and_then(serde_json::Value::as_array)
            .expect("admin-monitor.json `secrets` array");
        assert_eq!(
            monitor_secrets.len(),
            1,
            "ADMIN_GENERATE produces exactly one Ed25519 admin secret",
        );

        // Phase: recipe write (save_recipe=true).
        let recipe_path = dir.join("conf").join("mediator-build.toml");
        assert!(
            recipe_path.exists(),
            "build recipe must be saved when save_recipe=true"
        );
        let recipe_text = std::fs::read_to_string(&recipe_path).unwrap();
        let recipe_parsed: toml::Value =
            toml::from_str(&recipe_text).expect("recipe must be valid TOML");
        // Round-trip check: parsing back as a BuildRecipe must
        // succeed, otherwise the auto-write produced something the
        // recipe loader can't consume.
        let _: recipe::BuildRecipe = toml::from_str(&recipe_text)
            .expect("auto-written recipe must round-trip through BuildRecipe deserialize");
        assert_eq!(recipe_parsed["deployment"]["type"].as_str(), Some("local"));
        assert_eq!(
            recipe_parsed["identity"]["did_method"].as_str(),
            Some("did:peer")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn generate_and_write_skips_recipe_when_save_recipe_false() {
        // Recipe write is gated by save_recipe — passing `false`
        // (the recipe-driven `--from <recipe>` re-run path) must not
        // overwrite the input recipe with a re-rendered copy.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let config = did_peer_config(&dir);

        generate_and_write(
            &config,
            None,
            /*save_recipe=*/ false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .expect("generate_and_write must succeed");

        let recipe_path = dir.join("conf").join("mediator-build.toml");
        assert!(
            !recipe_path.exists(),
            "recipe must NOT be written when save_recipe=false"
        );
        // Mediator.toml still lands — the recipe-skip is independent
        // of the main config write.
        assert!(dir.join("conf").join("mediator.toml").exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn generate_and_write_file_backend_on_default_path_survives(/* #354 */) {
        // Regression for #354. The default `[secrets].storage` path is
        // `<config_dir>/secrets.json` — the very path the now-removed
        // legacy writer hard-coded. Point the file:// backend there and
        // assert the unified `{"entries": …}` envelope survives instead
        // of being clobbered by a legacy `[{…}]` array.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let conf_dir = dir.join("conf");
        let secrets_path = conf_dir.join("secrets.json");
        let config = app::WizardConfig {
            config_path: conf_dir
                .join("mediator.toml")
                .to_string_lossy()
                .into_owned(),
            deployment_type: DEPLOYMENT_LOCAL.into(),
            didcomm_enabled: true,
            did_method: DID_PEER.into(),
            secret_storage: crate::consts::STORAGE_FILE.into(),
            // Collides with the legacy writer's hard-coded target.
            secret_file_path: secrets_path.to_string_lossy().into_owned(),
            secret_file_encrypted: false,
            ssl_mode: SSL_NONE.into(),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: ADMIN_GENERATE.into(),
            ..app::WizardConfig::default()
        };

        generate_and_write(
            &config,
            None,
            /*save_recipe=*/ false,
            secret_backend::ProvisionProbe::ReadWrite,
        )
        .await
        .expect("generate_and_write must succeed for did:peer file:// backend");

        assert!(
            secrets_path.exists(),
            "the unified backend file must exist at the operator's path"
        );
        let text = std::fs::read_to_string(&secrets_path).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&text).expect("secrets file must be valid JSON");

        // The unified envelope is a JSON object keyed by `entries`; the
        // clobbered legacy form was a top-level array. Asserting the
        // object shape is what would have caught #354.
        assert!(
            json.get("entries").and_then(|e| e.as_object()).is_some(),
            "secrets file must be the unified {{\"entries\": …}} envelope, not a legacy array: {text}"
        );
        for well_known in [
            affinidi_messaging_mediator_common::JWT_SECRET,
            affinidi_messaging_mediator_common::OPERATING_SECRETS,
            affinidi_messaging_mediator_common::ADMIN_CREDENTIAL,
        ] {
            assert!(
                text.contains(well_known),
                "unified backend missing well-known key '{well_known}' after write: {text}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn generate_and_write_admin_skip_omits_admin_did_field() {
        // ADMIN_SKIP path: no admin DID generated, no admin
        // credential in the unified backend, and `[server].admin_did`
        // is absent from mediator.toml. Lock down so a refactor
        // doesn't accidentally always-mint an admin DID.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let mut config = did_peer_config(&dir);
        config.admin_did_mode = ADMIN_SKIP.into();

        generate_and_write(&config, None, false, secret_backend::ProvisionProbe::ReadWrite)
            .await
            .expect("generate_and_write with ADMIN_SKIP");

        let toml_text = std::fs::read_to_string(dir.join("conf").join("mediator.toml")).unwrap();
        let parsed: toml::Value = toml::from_str(&toml_text).unwrap();
        let server = parsed.get("server").expect("[server] section");
        assert!(
            server.get("admin_did").is_none(),
            "admin_did must be absent under ADMIN_SKIP — got: {server:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn mint_artefacts_did_peer_returns_value_only_bag_no_io() {
        // The `mint_artefacts` phase is the value-only / IO-free
        // counterpart to `provision_secret_backend` /
        // `write_config_artefacts`. This test runs it inside a
        // CWD-isolated tempdir so a regression that sneaks a file
        // write back in (the prior structure had one in the DID_VTA
        // arm — now deferred to write_config_artefacts) shows up as
        // a stray artefact in the tempdir.
        let cwd = CwdGuard::new();
        let cwd_before: std::collections::BTreeSet<_> = std::fs::read_dir(cwd.dir())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();

        let config = app::WizardConfig {
            did_method: DID_PEER.into(),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: ADMIN_GENERATE.into(),
            ..app::WizardConfig::default()
        };
        let artefacts = mint_artefacts(&config, None)
            .await
            .expect("did:peer mint must succeed");

        // Value contract: did:peer DID, two operating secrets, JWT
        // present, admin DID present, no VC, no DID log.
        assert!(
            artefacts.mediator_did.starts_with("did:peer:"),
            "got: {}",
            artefacts.mediator_did
        );
        assert_eq!(
            artefacts.mediator_secrets.len(),
            2,
            "did:peer mints signing + KA"
        );
        assert!(artefacts.jwt_secret.is_some());
        assert!(
            artefacts
                .admin_did
                .as_deref()
                .map(|d| d.starts_with("did:key:"))
                .unwrap_or(false)
        );
        assert!(artefacts.admin_secret.is_some());
        assert!(artefacts.did_doc.is_none());
        assert!(artefacts.authorization_vc.is_none());

        // IO contract: nothing new in CWD. If a future regression
        // re-introduces a file write inside mint, this catches it.
        let cwd_after: std::collections::BTreeSet<_> = std::fs::read_dir(cwd.dir())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        assert_eq!(
            cwd_before, cwd_after,
            "mint_artefacts must not write any files — phase 1 is value-only"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn mint_artefacts_admin_skip_returns_no_admin_did() {
        // Lock down the ADMIN_SKIP branch at the unit level — the
        // integration test covers the same path end-to-end, but
        // this one runs in microseconds and surfaces the precise
        // value contract.
        let config = app::WizardConfig {
            did_method: DID_PEER.into(),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: ADMIN_SKIP.into(),
            ..app::WizardConfig::default()
        };
        let artefacts = mint_artefacts(&config, None).await.unwrap();
        assert!(artefacts.admin_did.is_none());
        assert!(artefacts.admin_secret.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn mint_artefacts_jwt_provide_returns_none_jwt_secret() {
        let config = app::WizardConfig {
            did_method: DID_PEER.into(),
            jwt_mode: JWT_MODE_PROVIDE.into(),
            admin_did_mode: ADMIN_GENERATE.into(),
            ..app::WizardConfig::default()
        };
        let artefacts = mint_artefacts(&config, None).await.unwrap();
        assert!(
            artefacts.jwt_secret.is_none(),
            "jwt_mode = provide must not mint a key"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn generate_and_write_jwt_provide_skips_jwt_secret_in_backend() {
        // jwt_mode = provide: the wizard records the choice and DOES
        // NOT mint or store a JWT secret. The mediator's runtime
        // boot picks it up from MEDIATOR_JWT_SECRET / --jwt-secret-file.
        // Refactor must preserve this — silently always-minting would
        // be a security regression.
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let mut config = did_peer_config(&dir);
        config.jwt_mode = JWT_MODE_PROVIDE.into();

        generate_and_write(&config, None, false, secret_backend::ProvisionProbe::ReadWrite)
            .await
            .unwrap();

        let unified_text = std::fs::read_to_string(dir.join("unified-secrets.json")).unwrap();
        assert!(
            !unified_text.contains(affinidi_messaging_mediator_common::JWT_SECRET),
            "JWT_SECRET key must be absent under jwt_mode = provide"
        );
        // Operating secrets + admin credential still land — they're
        // independent of jwt_mode.
        assert!(unified_text.contains(affinidi_messaging_mediator_common::OPERATING_SECRETS));
        assert!(unified_text.contains(affinidi_messaging_mediator_common::ADMIN_CREDENTIAL));
    }
}
