use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, config::DIDCacheConfigBuilder, errors::DIDCacheError,
};
use clap::Parser;
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// DID to look up
    #[arg(short, long)]
    did: String,
}

#[tokio::main]
async fn main() -> Result<(), DIDCacheError> {
    // **************************************************************
    // *** Initial setup
    // **************************************************************
    let args = Args::parse();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    println!();
    println!(" ****************************** ");
    println!(" *  Local Resolver Example    * ");
    println!(" ****************************** ");
    println!();

    // Create a new local client configuration, use default values
    let local_config = DIDCacheConfigBuilder::default().build();
    let local_resolver = DIDCacheClient::new(local_config).await?;

    let response = local_resolver.resolve(&args.did).await?;
    println!(
        "Resolved DID Document:\n{}",
        serde_json::to_string_pretty(&response.doc).unwrap()
    );

    Ok(())
}
