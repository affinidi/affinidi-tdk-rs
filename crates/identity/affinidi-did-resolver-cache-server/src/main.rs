use affinidi_did_resolver_cache_sdk::errors::DIDCacheError;
use affinidi_did_resolver_cache_server::{config::DEFAULT_CONFIG_PATH, server::start_with_config};
use clap::Parser;

/// Affinidi DID Resolver Cache Server.
///
/// Run with `--config <path>` (or `-c <path>`) to point the server at a
/// config file outside the current working directory — useful when the
/// binary is installed in `/usr/local/bin` but the config lives in
/// `/etc/affinidi/cache-conf.toml` (or anywhere else).
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to the cache server TOML config file.
    #[arg(short, long, value_name = "FILE", default_value = DEFAULT_CONFIG_PATH)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), DIDCacheError> {
    let cli = Cli::parse();
    start_with_config(&cli.config).await
}
