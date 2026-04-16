mod app;
mod cli;
mod config_writer;
mod docker;
mod generators;
mod secrets;
mod ui;

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
        event::{DisableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    },
    prelude::*,
};
use tokio_stream::StreamExt;
use tui_input::InputRequest;

use app::{InputMode, WizardApp, WizardConfig};
use cli::Args;

const RENDERING_TICK_RATE: Duration = Duration::from_millis(250);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.non_interactive {
        return run_non_interactive(args).await;
    }

    // Check for existing config — offer reconfiguration
    let config_path = args.config.clone();
    if std::path::Path::new(&config_path).exists() {
        eprintln!("Existing configuration found at: {config_path}");
        eprintln!("The wizard will generate a new configuration.");
        eprintln!("The existing file will be backed up to {config_path}.bak");
        eprintln!();
        std::fs::copy(&config_path, format!("{config_path}.bak"))?;
    }

    let mut app = WizardApp::new(config_path);

    // Apply CLI-provided options to pre-fill wizard
    apply_cli_args(&args, &mut app.config);

    let mut terminal = setup_terminal()?;

    let result = run_event_loop(&mut terminal, &mut app).await;

    restore_terminal(&mut terminal)?;

    match result {
        Ok(()) => {
            if app.write_config {
                print_banner();
                println!("  Generating cryptographic material...\n");
                match generate_and_write(&app.config).await {
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
    let deployment = args.deployment.unwrap_or(cli::DeploymentType::Local);

    let mut config = WizardConfig::default();
    config.config_path = args.config.clone();

    // Apply deployment defaults first
    config.deployment_type = deployment.to_string();
    match deployment {
        cli::DeploymentType::Local => {
            config.didcomm_enabled = true;
            config.did_method = "VTA managed".into();
            config.secret_storage = "vta://".into();
            config.ssl_mode = "No SSL (TLS proxy)".into();
            config.database_url = "redis://127.0.0.1/".into();
            config.admin_did_mode = "Generate did:key".into();
        }
        cli::DeploymentType::Server | cli::DeploymentType::Container => {
            config.didcomm_enabled = true;
            config.did_method = "VTA managed".into();
            config.secret_storage = "vta://".into();
            config.ssl_mode = "No SSL (TLS proxy)".into();
            config.database_url = "redis://127.0.0.1/".into();
            config.admin_did_mode = "Generate did:key".into();
        }
    }

    // Override with any explicit CLI args
    apply_cli_args(&args, &mut config);

    // Validate required fields for did:webvh
    if config.did_method == "did:webvh" && config.public_url.is_empty() {
        anyhow::bail!("--public-url is required when using did:webvh in non-interactive mode");
    }

    println!("Mediator Setup (non-interactive)");
    println!("  Deployment:   {}", config.deployment_type);
    println!("  Protocol:     {}", config.protocol_display());
    println!("  DID method:   {}", config.did_method);
    println!("  Key storage:  {}", config.secret_storage);
    println!("  SSL/TLS:      {}", config.ssl_mode);
    println!("  Database:     {}", config.database_url);
    println!("  Admin:        {}", config.admin_did_mode);
    println!();
    println!("Generating cryptographic material...");

    generate_and_write(&config).await?;
    offer_build_and_guidance(&config);

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
            _ = ticker.tick() => (),
            maybe_event = crossterm_events.next() => match maybe_event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    handle_key_event(app, key.code, key.modifiers);
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
    // Ctrl+C or Ctrl+Q always triggers quit confirmation
    if (code == KeyCode::Char('c') || code == KeyCode::Char('q'))
        && modifiers.contains(KeyModifiers::CONTROL)
    {
        app.request_quit();
        return;
    }

    // Quit confirmation overlay
    if app.quit_confirm {
        match code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                app.should_quit = true;
            }
            _ => {
                app.cancel_quit();
            }
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

/// Run all generators and write configuration files.
async fn generate_and_write(config: &app::WizardConfig) -> anyhow::Result<()> {
    // Generate mediator DID + secrets
    let (mediator_did, mediator_secrets, did_doc) = match config.did_method.as_str() {
        "did:peer" => {
            let service_uri = if config.public_url.is_empty() {
                None
            } else {
                Some(config.public_url.clone())
            };
            let (did, secrets) = generators::did_peer::generate_did_peer(service_uri)?;
            (did, secrets, None)
        }
        "did:webvh" => {
            let host = if config.public_url.is_empty() {
                "localhost:7037/mediator/v1"
            } else {
                &config.public_url
            };
            let secure = !host.contains("localhost") && !host.contains("127.0.0.1");
            let result = generators::did_webvh::generate_did_webvh(host, secure).await?;
            (result.did, result.secrets, Some(result.did_doc))
        }
        "VTA managed" => {
            // VTA-managed DIDs are referenced by scheme, no local generation needed
            ("vta://mediator".into(), vec![], None)
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

    // Generate JWT secret
    let jwt_secret = generators::jwt::generate_jwt_secret()?;

    // Generate admin DID
    let (admin_did, admin_secret) = match config.admin_did_mode.as_str() {
        "Generate did:key" => {
            let (did, secret) = generators::did_key::generate_admin_did_key()?;
            (Some(did), Some(secret))
        }
        "Skip" => (None, None),
        _ => (None, None),
    };

    // Generate self-signed SSL if requested
    let (ssl_cert_path, ssl_key_path) = if config.ssl_mode == "Self-signed" {
        let (cert, key) = generators::ssl::generate_self_signed_cert("conf/keys")?;
        (Some(cert), Some(key))
    } else {
        (None, None)
    };

    // Provision secrets to the selected backend
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

    println!(
        "  \x1b[32m\u{2714}\x1b[0m Configuration written to: \x1b[1m{}\x1b[0m",
        config.config_path
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
        }
    }

    if config.secret_storage == "file://" {
        println!("  \x1b[32m\u{2714}\x1b[0m Secrets: conf/secrets.json");
    }

    if config.ssl_mode == "Self-signed" {
        println!("  \x1b[32m\u{2714}\x1b[0m SSL certificates: conf/keys/");
    }

    // Generate Docker files for container deployments
    if config.deployment_type == "Container" {
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
    execute!(stdout, EnterAlternateScreen, DisableMouseCapture)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
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
        "keyring://" => features.push("vta-keyring"),
        "aws_secrets://" => features.push("vta-aws-secrets"),
        "gcp_secrets://" => features.push("vta-gcp-secrets"),
        "azure_keyvault://" => features.push("vta-azure-keyvault"),
        "vault://" => features.push("vta-hashicorp-vault"),
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

/// Build the `cargo install` arguments for the mediator.
fn build_install_args(features: &[&str]) -> Vec<String> {
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

    args
}

/// Print the run command for the mediator binary.
fn print_run_command(config_path: &str) {
    let abs_config = resolve_config_path(config_path);
    println!("  \x1b[1mTo start the mediator:\x1b[0m");
    if abs_config == "conf/mediator.toml" || abs_config.ends_with("/conf/mediator.toml") {
        println!("    \x1b[36mmediator\x1b[0m");
    } else {
        println!("    \x1b[36mmediator -c {abs_config}\x1b[0m");
    }
    println!();
    println!("  \x1b[2mThe mediator binary is installed at ~/.cargo/bin/mediator\x1b[0m");
}

/// Offer to install the mediator after configuration.
fn offer_build_and_guidance(config: &app::WizardConfig) {
    let features = build_features(config);
    let install_args = build_install_args(&features);
    let install_cmd = format!("cargo {}", install_args.join(" "));
    let build_args = build_cargo_args(&features);
    let build_cmd = format!("cargo {}", build_args.join(" "));

    // Try to find workspace root
    let workspace_root = find_workspace_root();
    let cwd = std::env::current_dir().ok();
    let in_workspace = match (&workspace_root, &cwd) {
        (Some(root), Some(current)) => current.starts_with(root),
        _ => false,
    };

    println!(
        "\n  \x1b[38;5;69m\u{2501}\u{2501}\u{2501} Next Steps \u{2501}\u{2501}\u{2501}\x1b[0m\n"
    );

    // Ask if user wants to install now
    print!("  Install the mediator to ~/.cargo/bin? [\x1b[1mY\x1b[0m/n] ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        println!("  Could not read input.");
        print_manual_instructions(&install_cmd, &build_cmd, config);
        return;
    }

    let input = input.trim().to_lowercase();
    if !input.is_empty() && input != "y" && input != "yes" {
        println!();
        print_manual_instructions(&install_cmd, &build_cmd, config);
        return;
    }

    // Determine build directory
    let build_dir = if in_workspace {
        cwd.unwrap()
    } else if let Some(root) = workspace_root {
        println!(
            "  \x1b[2mChanging to workspace root: {}\x1b[0m",
            root.display()
        );
        root
    } else {
        println!("  \x1b[33mCannot find workspace root.\x1b[0m");
        print_manual_instructions(&install_cmd, &build_cmd, config);
        return;
    };

    println!("\n  \x1b[38;5;69mInstalling mediator (this may take a few minutes)...\x1b[0m\n");

    let status = Command::new("cargo")
        .args(&install_args)
        .current_dir(&build_dir)
        .status();

    match status {
        Ok(exit) if exit.success() => {
            println!("\n  \x1b[32m\u{2714} Installation successful!\x1b[0m\n");
            print_run_command(&config.config_path);
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
