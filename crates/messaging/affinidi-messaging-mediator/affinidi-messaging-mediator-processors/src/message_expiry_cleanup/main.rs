//! # Standalone Message Expiry Cleanup — Redis-only
//!
//! Sweeps expired messages from the mediator's Redis store. Designed for
//! horizontal scaling: deploy multiple instances on different hosts to
//! share the work. Coordination is via atomic `SPOP` on the
//! per-timeslot expiry sets, so concurrent processors never delete the
//! same message twice.
//!
//! Only meaningful for Redis-backed mediator deployments. The mediator
//! also runs an in-process expiry sweep (via `MediatorStore::sweep_expired_messages`)
//! that works against any backend — Memory and Fjall don't need this
//! binary because they're single-process by design.

use affinidi_messaging_mediator_common::{database::DatabaseHandler, errors::ProcessorError};
use affinidi_messaging_mediator_processors::message_expiry_cleanup::processor::MessageExpiryCleanupProcessor;
use clap::Parser;
use config::Config;
use tokio::join;
use tracing::{error, info};
use tracing_subscriber::filter;

mod config;

/// Affinidi Messaging Processors
/// Handles the cleaning up of expired messages
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "conf/message_expiry_cleanup.toml")]
    config_file: String,
}

#[tokio::main]
async fn main() -> Result<(), ProcessorError> {
    let args = Args::parse();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let config = _read_config(&args.config_file)?;
    info!("Configuration loaded successfully");

    // Setting up the database durability and handling
    info!("Connecting to database...");
    let database = match DatabaseHandler::new(&config.database).await {
        Ok(db) => db,
        Err(err) => {
            error!("Error opening database: {}", err);
            error!("Exiting...");
            return Err(ProcessorError::MessageExpiryCleanupError(format!(
                "Error opening database. Reason: {err}"
            )));
        }
    };

    // The admin DID hash is used for Lua-level delete permission. When running
    // standalone, use a system-level identity that the Lua script recognizes.
    let admin_did_hash = sha256::digest("SYSTEM_EXPIRY_PROCESSOR");
    let processor = MessageExpiryCleanupProcessor::new(
        config.processors.message_expiry_cleanup,
        database,
        admin_did_hash,
    );

    let handle = {
        tokio::spawn(async move {
            processor
                .start()
                .await
                .expect("Error starting message_expiry_cleanup processor");
        })
    };

    let _ = join!(handle);

    Ok(())
}

// Reads configuration file contents and converts it to a Config struct
fn _read_config(file: &str) -> Result<Config, ProcessorError> {
    let config = std::fs::read_to_string(file).expect("Couldn't read config file");
    let config: Config = toml::from_str(&config).expect("Couldn't parse config file");
    Ok(config)
}
