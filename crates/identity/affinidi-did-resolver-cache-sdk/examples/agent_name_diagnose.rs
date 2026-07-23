//! Diagnose the agent-name resolve/verify chain against a live DID, and show
//! what `ResolveResponse::display_name()` returns for each entry point.

use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, config::DIDCacheConfigBuilder, errors::DIDCacheError,
};
use clap::Parser;
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
struct Args {
    /// DID to diagnose
    #[arg(short, long)]
    did: String,
    /// Agent name to resolve, e.g. `example.com/@alice`
    #[arg(short, long)]
    name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), DIDCacheError> {
    let args = Args::parse();

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;

    println!("\n=== resolve(did), shortcuts OFF (default) ===");
    let resp = resolver.resolve(&args.did).await?;
    println!("alsoKnownAs   = {:?}", resp.doc.also_known_as);
    println!("shortcut      = {:?}", resp.shortcut);
    println!("display_name  = {}", resp.display_name());
    println!("  (no name lookup was asked for, so this is the DID)");

    println!("\n=== resolve(did), shortcuts ON ===");
    let with_shortcuts = DIDCacheClient::new(
        DIDCacheConfigBuilder::default()
            .with_resolve_shortcuts(true)
            .build(),
    )
    .await?;
    let resp = with_shortcuts.resolve(&args.did).await?;
    println!("shortcut      = {:?}", resp.shortcut);
    println!("display_name  = {}", resp.display_name());
    if resp.shortcut.is_some() {
        println!("  >>> DID -> verified agent name, from a plain resolve()");
    }

    if let Some(name) = &args.name {
        println!("\n=== resolve_any(name) ===");
        let resp = resolver.resolve_any(name).await?;
        println!("did           = {}", resp.did);
        println!("shortcut      = {:?}", resp.shortcut);
        println!("display_name  = {}", resp.display_name());
        assert_eq!(
            resp.display_name(),
            name.trim_start_matches("https://"),
            "display_name should be the verified agent name"
        );
        println!("  >>> display_name() returned the verified agent name");
    }

    Ok(())
}
