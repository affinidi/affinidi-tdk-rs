//! # Standalone Forwarding Processor — Redis-only
//!
//! Reads messages from the `FORWARD_Q` Redis stream and delivers them to
//! remote mediators. Designed for horizontal scaling: deploy multiple
//! instances on different hosts, all pointed at the same Redis. They
//! coordinate through the consumer group (`XREADGROUP` / `XACK` /
//! `XAUTOCLAIM`) so each message is processed exactly once.
//!
//! Only meaningful for Redis-backed mediator deployments. If the mediator
//! is using `memory-backend` or `fjall-backend`, run the in-process
//! forwarding loop instead — those backends are single-process by design
//! and there is no second host for this binary to coordinate with.
//!
//! Implementation: this binary reuses the trait-based code path. It
//! constructs the same [`RedisStore`] the mediator uses, wraps it in
//! `Arc<dyn MediatorStore>`, and feeds it to
//! [`ForwardingProcessor`] from `mediator-common`. Both this binary
//! and the in-process mediator forwarding loop run identical code.
//!
//! [`RedisStore`]: affinidi_messaging_mediator_common::store::redis::RedisStore
//! [`ForwardingProcessor`]: affinidi_messaging_mediator_common::tasks::forwarding::ForwardingProcessor

use affinidi_messaging_mediator_common::{
    database::DatabaseHandler,
    errors::ProcessorError,
    store::{MediatorStore, redis::RedisStore},
    tasks::forwarding::ForwardingProcessor,
};
use clap::Parser;
use config::Config;
use std::sync::Arc;
use tokio::join;
use tracing::{error, info};
use tracing_subscriber::filter;

mod config;

/// Affinidi Messaging Forwarding Processor
/// Reads messages from FORWARD_Q and delivers them to remote mediators
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "conf/forwarding.toml")]
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
            ProcessorError::ForwardingError(format!("Error opening database. Reason: {err}"))
        })?;

    // Same RedisStore the mediator uses — sane circuit breaker
    // defaults; the standalone binary doesn't surface its state via
    // `/readyz` so the values just need to be sensible.
    let store: Arc<dyn MediatorStore> = Arc::new(RedisStore::new(
        handler,
        config.database.circuit_breaker_threshold,
        config.database.circuit_breaker_recovery_secs,
        config.database.functions_file.clone(),
    ));

    let processor =
        ForwardingProcessor::new(config.processors.forwarding, store).map_err(|err| {
            error!("Error initialising forwarding processor: {err}");
            ProcessorError::ForwardingError(format!(
                "Failed to initialise forwarding processor: {err}"
            ))
        })?;

    let handle = tokio::spawn(async move {
        if let Err(err) = processor.start().await {
            error!("Forwarding processor exited with error: {err}");
        }
    });

    let _ = join!(handle);

    Ok(())
}

fn _read_config(file: &str) -> Result<Config, ProcessorError> {
    let config = std::fs::read_to_string(file).expect("Couldn't read config file");
    let config: Config = toml::from_str(&config).expect("Couldn't parse config file");
    Ok(config)
}
