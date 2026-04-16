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
            config.did_method = "did:peer".into();
            config.secret_storage = "string://".into();
            config.ssl_mode = "No SSL (TLS proxy)".into();
            config.database_url = "redis://127.0.0.1/".into();
            config.admin_did_mode = "Generate did:key".into();
        }
        cli::DeploymentType::Server | cli::DeploymentType::Container => {
            config.didcomm_enabled = true;
            config.did_method = "did:webvh".into();
            config.secret_storage = "aws_secrets://".into();
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
    // Ctrl+C always quits
    if code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL) {
        app.should_quit = true;
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
                KeyCode::Char('q') => app.request_quit(),
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Enter => app.select_current(),
                KeyCode::Esc => app.go_back(),
                KeyCode::Left => app.focus_progress(),
                _ => {}
            },
            app::FocusPanel::Progress => match code {
                KeyCode::Char('q') => app.request_quit(),
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
            KeyCode::Char('q') => app.request_quit(),
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
    // ANSI color codes: 38;5;69 = cornflower blue, 38;5;43 = teal accent
    let blue = "\x1b[38;5;69m";
    let teal = "\x1b[38;5;43m";
    let white = "\x1b[38;5;255m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    println!();
    println!("  {blue}    _    __  __ _       _     _ _{reset}");
    println!("  {blue}   / \\  / _|/ _(_)_ __ (_) __| (_){reset}");
    println!("  {blue}  / _ \\| |_| |_| | '_ \\| |/ _` | |{reset}");
    println!("  {blue} / ___ \\  _|  _| | | | | | (_| | |{reset}");
    println!("  {blue}/_/   \\_\\_| |_| |_|_| |_|_|\\__,_|_|{reset}");
    println!();
    println!("  {teal}\u{2588}\u{2588}\u{2588}{reset} {white}Messaging Mediator Setup{reset}");
    println!("  {dim}Secure, scalable DIDComm & TSP messaging infrastructure{reset}");
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

/// Offer to build the mediator after configuration.
fn offer_build_and_guidance(config: &app::WizardConfig) {
    let features = build_features(config);
    let cargo_args = build_cargo_args(&features);
    let build_cmd = format!("cargo {}", cargo_args.join(" "));

    println!(
        "\n  \x1b[38;5;69m\u{2501}\u{2501}\u{2501} Next Steps \u{2501}\u{2501}\u{2501}\x1b[0m\n"
    );
    println!("  \x1b[1mBuild:\x1b[0m");
    println!("    \x1b[36m{build_cmd}\x1b[0m");
    println!();
    println!("  \x1b[1mRun:\x1b[0m");
    println!(
        "    \x1b[36mcargo run --release -p affinidi-messaging-mediator -- -c {}\x1b[0m",
        config.config_path
    );

    // Try to find workspace root
    let workspace_root = find_workspace_root();
    let cwd = std::env::current_dir().ok();

    let in_workspace = match (&workspace_root, &cwd) {
        (Some(root), Some(current)) => current.starts_with(root),
        _ => false,
    };

    if !in_workspace {
        if let Some(ref root) = workspace_root {
            println!("\nNote: You are not in the workspace root. The build command needs");
            println!("to be run from: {}", root.display());
        } else {
            println!("\nNote: Could not find the workspace root (Cargo.toml with [workspace]).");
            println!(
                "Make sure you run the build command from the affinidi-tdk-rs root directory."
            );
            return;
        }
    }

    // Ask if user wants to build now
    println!();
    print!("Build the mediator now? [Y/n] ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        println!("Could not read input. Run the build command manually.");
        return;
    }

    let input = input.trim().to_lowercase();
    if !input.is_empty() && input != "y" && input != "yes" {
        println!("Skipping build. Run the commands above when ready.");
        return;
    }

    // Determine build directory
    let build_dir = if in_workspace {
        cwd.unwrap()
    } else if let Some(root) = workspace_root {
        println!("Changing to workspace root: {}", root.display());
        root
    } else {
        println!("Cannot determine build directory. Run the build command manually.");
        return;
    };

    println!("\nBuilding mediator (this may take a few minutes)...\n");

    let status = Command::new("cargo")
        .args(&cargo_args)
        .current_dir(&build_dir)
        .status();

    match status {
        Ok(exit) if exit.success() => {
            println!("\nBuild successful!");
            println!("\nTo start the mediator:");

            // Build the run command relative to the workspace root
            let config_path = if Path::new(&config.config_path).is_absolute() {
                config.config_path.clone()
            } else {
                // If config path is relative, make it relative to where the user ran the wizard
                if let Ok(original_cwd) = std::env::current_dir() {
                    if let Ok(abs) = original_cwd.join(&config.config_path).canonicalize() {
                        abs.to_string_lossy().into_owned()
                    } else {
                        config.config_path.clone()
                    }
                } else {
                    config.config_path.clone()
                }
            };

            let mut run_args = vec![
                "run",
                "--release",
                "-p",
                "affinidi-messaging-mediator",
                "--",
            ];
            if config_path != "conf/mediator.toml" {
                run_args.push("-c");
                // Can't push config_path directly since it's a String, print separately
                println!(
                    "  cd {} && cargo {} -c {}",
                    build_dir.display(),
                    run_args.join(" "),
                    config_path
                );
            } else {
                println!(
                    "  cd {} && cargo {}",
                    build_dir.display(),
                    run_args.join(" ")
                );
            }
        }
        Ok(exit) => {
            eprintln!("\nBuild failed with exit code: {}", exit);
            eprintln!("Check the build output above for errors.");
            eprintln!("You can retry manually with:");
            eprintln!("  cd {} && {}", build_dir.display(), build_cmd);
        }
        Err(e) => {
            eprintln!("\nFailed to run cargo: {e}");
            eprintln!("Is cargo installed and in your PATH?");
            eprintln!("You can build manually with:");
            eprintln!("  cd {} && {}", build_dir.display(), build_cmd);
        }
    }
}
