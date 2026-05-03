//! # Standalone Message Expiry Cleanup — Redis-only
//!
//! Sweeps expired messages from the mediator's Redis store. Designed for
//! horizontal scaling: deploy multiple instances on different hosts to
//! share the work. Coordination is via atomic `SPOP` on the
//! per-timeslot expiry sets, so concurrent processors never delete the
//! same message twice.
//!
//! Only meaningful for Redis-backed mediator deployments. The mediator
//! also runs an in-process expiry sweep
//! (via `MediatorStore::sweep_expired_messages`) that works against any
//! backend — Memory and Fjall don't need this binary because they're
//! single-process by design.
//!
//! Implementation: this binary now reuses the trait-based code path.
//! It constructs the same [`RedisStore`] the mediator uses and drives
//! its [`sweep_expired_messages`] method on a one-second tick. Memory
//! and Fjall backends would refuse to compile here because the binary
//! pulls in `redis-backend` directly.
//!
//! [`RedisStore`]: affinidi_messaging_mediator_common::store::redis::RedisStore
//! [`sweep_expired_messages`]: affinidi_messaging_mediator_common::store::MediatorStore::sweep_expired_messages

use affinidi_messaging_mediator_common::{
    database::DatabaseHandler,
    errors::ProcessorError,
    store::{MediatorStore, redis::RedisStore},
    time::unix_timestamp_secs,
};
use clap::Parser;
use config::Config;
use std::time::Duration;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{error, info, warn};
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

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let config = _read_config(&args.config_file)?;
    info!("Configuration loaded successfully");

    info!("Connecting to database...");
    let handler = DatabaseHandler::new(&config.database)
        .await
        .map_err(|err| {
            error!("Error opening database: {}", err);
            ProcessorError::MessageExpiryCleanupError(format!(
                "Error opening database. Reason: {err}"
            ))
        })?;

    // Build the same RedisStore the mediator uses. Sane defaults for
    // the circuit breaker — the standalone binary doesn't have a
    // /readyz path that needs to surface its state.
    let store = RedisStore::new(
        handler,
        config.database.circuit_breaker_threshold,
        config.database.circuit_breaker_recovery_secs,
        config.database.functions_file.clone(),
    );

    // The admin DID hash is used for Lua-level delete permission. When
    // running standalone, use a system-level identity that the Lua
    // script recognizes.
    let admin_did_hash = sha256::digest("SYSTEM_EXPIRY_PROCESSOR");

    info!("Message expiry cleanup processor started");

    // Same one-second cadence as the mediator's in-process loop. We
    // skip missed ticks if the previous sweep ran long.
    let mut tick = interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tick.tick().await;

        let now_secs = unix_timestamp_secs();
        match store
            .sweep_expired_messages(now_secs, &admin_did_hash)
            .await
        {
            Ok(report) if report.expired > 0 || report.timeslots_swept > 0 => {
                info!(
                    timeslots_swept = report.timeslots_swept,
                    expired = report.expired,
                    already_deleted = report.already_deleted,
                    "expiry sweep drained {} messages across {} timeslots",
                    report.expired,
                    report.timeslots_swept,
                );
            }
            Ok(_) => {} // nothing to sweep
            Err(err) => {
                warn!("Message expiry sweep error: {err}");
            }
        }
    }
}

fn _read_config(file: &str) -> Result<Config, ProcessorError> {
    let config = std::fs::read_to_string(file).expect("Couldn't read config file");
    let config: Config = toml::from_str(&config).expect("Couldn't parse config file");
    Ok(config)
}
