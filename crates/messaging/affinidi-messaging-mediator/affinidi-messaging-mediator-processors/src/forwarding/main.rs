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

use affinidi_messaging_mediator_common::{database::DatabaseHandler, errors::ProcessorError};
use affinidi_messaging_mediator_processors::forwarding::processor::ForwardingProcessor;
use clap::Parser;
use config::Config;
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
    let database = match DatabaseHandler::new(&config.database).await {
        Ok(db) => db,
        Err(err) => {
            error!("Error opening database: {}", err);
            error!("Exiting...");
            return Err(ProcessorError::ForwardingError(format!(
                "Error opening database. Reason: {err}"
            )));
        }
    };

    let mut processor = ForwardingProcessor::new(config.processors.forwarding, database);

    let handle = tokio::spawn(async move {
        processor
            .start()
            .await
            .expect("Error starting forwarding processor");
    });

    let _ = join!(handle);

    Ok(())
}

fn _read_config(file: &str) -> Result<Config, ProcessorError> {
    let config = std::fs::read_to_string(file).expect("Couldn't read config file");
    let config: Config = toml::from_str(&config).expect("Couldn't parse config file");
    Ok(config)
}
