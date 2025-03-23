use affinidi_did_resolver_cache_sdk::errors::DIDCacheError;
use affinidi_did_resolver_cache_server::server::start;

/// Main entry point for the `affinidi-did-resolver-cache-server` binary.
///
/// This binary runs as a DID Cache resolver service with built in caching
#[tokio::main]
async fn main() -> Result<(), DIDCacheError> {
    return start().await;
}
