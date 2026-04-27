use affinidi_messaging_mediator::{commands, server::start};
use clap::{Parser, Subcommand};

/// Affinidi Messaging Mediator.
///
/// Without a subcommand, runs the mediator HTTP server (the historical
/// behaviour). Subcommands cover one-shot operator tasks that share
/// the server's config + secret-backend code paths but don't need a
/// running mediator.
#[derive(Parser)]
#[command(
    name = "mediator",
    about = "Affinidi Messaging Mediator",
    long_about = "Run the mediator server (default), or invoke an operator subcommand \
                  like `mediator rotate-admin`."
)]
struct Cli {
    /// Path to the mediator config file. Defaults to
    /// `conf/mediator.toml` (relative to CWD) for parity with the
    /// historical hard-coded path; pass `--config <path>` to point at
    /// a config the wizard wrote to a non-default location.
    #[arg(short = 'c', long, default_value = "conf/mediator.toml", global = true)]
    config: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Rotate the mediator's admin credential.
    ///
    /// Reads the existing credential from the unified secret backend,
    /// authenticates to the VTA, registers a fresh did:key with the
    /// same ACL scope, writes the new credential back, and removes
    /// the old ACL entry. Use `--dry-run` to preview without
    /// touching state. The config path comes from the top-level
    /// `--config` flag (default `conf/mediator.toml`).
    RotateAdmin {
        /// Skip the VTA mutation + backend write. The wizard prints
        /// the rotation plan and exits.
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        None => start(&cli.config).await,
        Some(Command::RotateAdmin { dry_run }) => {
            // Subcommands handle their own tracing init lazily
            // (rotate_admin uses the global subscriber if one is
            // already in place; otherwise it falls back to a minimal
            // env-filter setup so info!/warn! land somewhere visible).
            init_subcommand_tracing();
            if let Err(e) = commands::rotate_admin::run(&cli.config, dry_run).await {
                eprintln!("\x1b[31mError:\x1b[0m {e}");
                std::process::exit(1);
            }
        }
    }
}

/// Subcommands run outside of `server::start`, which is where the
/// production tracing subscriber is normally installed. Set up a
/// minimal one here so `tracing::info!` calls inside the rotation
/// flow actually surface to stderr — without this the rotation runs
/// "silent" except for `println!`s.
fn init_subcommand_tracing() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();
}
