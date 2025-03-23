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
                "Error opening database. Reason: {}",
                err
            )));
        }
    };

    let processor =
        MessageExpiryCleanupProcessor::new(config.processors.message_expiry_cleanup, database);

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
