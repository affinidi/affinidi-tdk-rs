/*!
 * Resolve a DID through the TDK facade and print its DID Document.
 *
 * Facade-first: every Affinidi type is reached through `affinidi_tdk::*`
 * re-exports — this example depends on no sub-crate directly.
 *
 * ```sh
 * cargo run -p affinidi-tdk --example resolve_did -- \
 *   did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv
 * ```
 */

use affinidi_tdk::common::errors::Result;
use affinidi_tdk::did_resolver::{DIDCacheClient, config::DIDCacheConfigBuilder};
use clap::Parser;

#[derive(Parser)]
#[command(name = "resolve_did", bin_name = "resolve_did")]
struct Cli {
    /// DID to resolve (e.g. `did:key:…`, `did:peer:…`).
    did: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();

    // Local-mode resolver: did:key / did:peer resolve with no network.
    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let response = resolver.resolve(&cli.did).await?;

    let json = serde_json::to_string_pretty(&response.doc).expect("DID Document serializes");
    println!("{json}");
    Ok(())
}
