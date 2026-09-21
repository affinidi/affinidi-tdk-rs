//! `mediator-console` — operate an Affinidi messaging mediator from a terminal.
//!
//! Connects as the DID in a TDK profile file (the one `mediator-setup` writes
//! for its administrator, or any account's) and opens the console: the whole
//! mediator for an administrator, the account's own queues for anyone else.

use std::path::PathBuf;

use affinidi_messaging_mediator_admin::{IdentitySource, MediatorConsole, Mode, ProfileFileSource};
use affinidi_messaging_mediator_tui::App;
use clap::Parser;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// TDK profile JSON file(s) to connect with: `{ alias, did, mediator, secrets }`.
    #[arg(short, long = "profile", required = true)]
    profiles: Vec<PathBuf>,

    /// Which profile to use, by alias or DID, when more than one is given.
    #[arg(long = "as")]
    choose: Option<String>,

    /// Mediator DID, overriding the profile's (and its DID document's).
    #[arg(long)]
    mediator: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(e) = run(args).await {
        eprintln!("mediator-console: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let source = ProfileFileSource::new(args.profiles);
    let choices = source.list().await?;
    let choice = match &args.choose {
        Some(want) => choices
            .iter()
            .find(|c| c.label == *want || c.did.as_deref() == Some(want.as_str()))
            .ok_or_else(|| format!("no profile named {want}"))?,
        None => choices.first().ok_or("no profiles")?,
    };
    let mut identity = source.load(choice).await?;
    if args.mediator.is_some() {
        identity.mediator_did = args.mediator;
    }

    eprintln!("connecting as {} …", identity.alias);
    let console = MediatorConsole::connect(identity).await?;
    eprintln!(
        "connected: {}",
        match console.mode() {
            Mode::Admin { root: true } => "rootAdmin",
            Mode::Admin { root: false } => "admin",
            Mode::SelfService => "self-service",
        }
    );

    let mut terminal = ratatui::init();
    let result = App::new(console).run(&mut terminal).await;
    ratatui::restore();
    Ok(result?)
}
