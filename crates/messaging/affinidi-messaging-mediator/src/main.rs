use affinidi_messaging_mediator::{commands, server::start};
use clap::{Parser, Subcommand};

// ─── Allocator ──────────────────────────────────────────────────────────────
//
// Set on the binary only. A library that installs a #[global_allocator] forces
// it on every consumer, so this deliberately does not live in lib.rs.
//
// Why not the system allocator: the storage backend churns large, short-lived
// buffers (write buffers, packed message bodies). glibc malloc keeps those
// arenas rather than returning them, so RSS ratchets to the high-water mark and
// never falls back — indistinguishable from a leak on a memory graph.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc tuning, read by jemalloc itself at startup via this well-known symbol.
///
/// `background_thread:true` runs the purger off the request path.
/// `dirty_decay_ms` / `muzzy_decay_ms` are how long freed pages linger before
/// being returned to the OS; jemalloc's defaults (10s / 10s) are tuned for
/// throughput on allocation-heavy workloads, and hold RSS well above the live
/// heap. 5s keeps the memory graph honest at a negligible cost here, because
/// the mediator's hot path is I/O-bound, not allocation-bound.
///
/// Raise these (or drop the `jemalloc` feature) if you are optimising for
/// allocation throughput over resident footprint.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[unsafe(export_name = "malloc_conf")]
pub static MALLOC_CONF: &[u8] = b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000\0";

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
        None => {
            if let Err(e) = start(&cli.config).await {
                eprintln!("\x1b[31mMediator failed:\x1b[0m {e}");
                std::process::exit(1);
            }
        }
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
