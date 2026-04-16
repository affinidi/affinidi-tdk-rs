mod app;
mod cli;
mod config_writer;
mod docker;
mod generators;
mod secrets;
mod ui;

use std::{
    io::{self, Stdout},
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

use app::{InputMode, WizardApp};
use cli::Args;

const RENDERING_TICK_RATE: Duration = Duration::from_millis(250);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.non_interactive {
        eprintln!("Non-interactive mode is not yet implemented.");
        std::process::exit(1);
    }

    let mut app = WizardApp::new(args.config);

    // Apply CLI-provided deployment type if given
    if let Some(deployment) = args.deployment {
        app.config.deployment_type = deployment.to_string();
    }

    let mut terminal = setup_terminal()?;

    let result = run_event_loop(&mut terminal, &mut app).await;

    restore_terminal(&mut terminal)?;

    match result {
        Ok(()) => {
            if app.write_config {
                println!("\nGenerating cryptographic material...");
                match generate_and_write(&app.config).await {
                    Ok(()) => {
                        print_build_command(&app.config);
                    }
                    Err(e) => {
                        eprintln!("\nError: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                println!("\nSetup cancelled.");
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
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
        InputMode::Selecting => match code {
            KeyCode::Char('q') => app.request_quit(),
            KeyCode::Up | KeyCode::Char('k') => app.move_up(),
            KeyCode::Down | KeyCode::Char('j') => app.move_down(),
            KeyCode::Enter => app.select_current(),
            KeyCode::Esc => app.go_back(),
            _ => {}
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

    println!("\nConfiguration written to: {}", config.config_path);

    // Display admin DID info to user
    if let Some(ref did) = admin_did {
        println!("\nAdmin DID: {did}");
        if let Some(ref secret) = admin_secret {
            if let Ok(privkey) = secret.get_private_keymultibase() {
                println!("\n  IMPORTANT: Save this admin private key securely!");
                println!("  Private key (multibase): {privkey}");
            }
        }
    }

    if config.secret_storage == "file://" {
        println!("  Secrets: conf/secrets.json");
    }

    if config.ssl_mode == "Self-signed" {
        println!("  SSL certificates: conf/keys/");
    }

    // Generate Docker files for container deployments
    if config.deployment_type == "Container" {
        docker::generate_dockerfile(config, ".")?;
    }

    Ok(())
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

fn print_build_command(config: &app::WizardConfig) {
    let mut features = Vec::new();

    match config.protocol.as_str() {
        "TSP" => features.push("tsp"),
        _ => features.push("didcomm"),
    }

    match config.secret_storage.as_str() {
        "keyring://" => features.push("vta-keyring"),
        "aws_secrets://" => features.push("vta-aws-secrets"),
        "gcp_secrets://" => features.push("vta-gcp-secrets"),
        "azure_keyvault://" => features.push("vta-azure-keyvault"),
        "vault://" => features.push("vta-hashicorp-vault"),
        _ => {}
    }

    println!("\nTo build the mediator:");
    if features.len() == 1 && features[0] == "didcomm" {
        println!("  cargo build --release -p affinidi-messaging-mediator");
    } else {
        println!(
            "  cargo build --release -p affinidi-messaging-mediator --no-default-features --features {}",
            features.join(",")
        );
    }

    println!("\nTo run:");
    println!(
        "  cargo run --release -p affinidi-messaging-mediator -- -c {}",
        config.config_path
    );
}
