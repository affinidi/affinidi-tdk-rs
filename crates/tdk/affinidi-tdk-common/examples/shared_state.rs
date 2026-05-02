//! End-to-end `TDKSharedState` lifecycle: build a config, construct the
//! shared state, attach a profile, do a quick lookup, then drain.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example shared_state
//! ```

use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::{
    TDKSharedState, config::TDKConfig, environments::TDKEnvironment, profiles::TDKProfile,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a config that bypasses the on-disk environment file. For most
    // applications you'd skip `with_environment` and let TDK load from
    // `environments.json` instead.
    let mut env = TDKEnvironment::default();
    env.set_default_mediator(Some("did:web:mediator.example".into()));

    let config = TDKConfig::builder()
        .with_load_environment(false)
        .with_environment(env)
        .build()?;

    let state = TDKSharedState::new(config).await?;
    println!(
        "TDKSharedState built; auth-cache limit = {}",
        state.config().authentication_cache_limit()
    );

    // Generate a fresh ed25519 secret and attach it via a TDKProfile.
    let kid = "did:example:alice#key-1";
    let secret = Secret::generate_ed25519(Some(kid), None);
    let profile = TDKProfile::new(
        "alice",
        "did:example:alice",
        None, // mediator falls back to environment.default_mediator
        vec![secret],
    );

    state.add_profile(&profile).await;
    println!(
        "Profile added; resolver finds secret? {}",
        state.secrets_resolver().get_secret(kid).await.is_some()
    );

    println!(
        "Resolved mediator for profile = {:?}",
        state.resolve_mediator(&profile)
    );

    // Graceful drain — stops the background AuthenticationCache task and
    // awaits its JoinHandle.
    state.shutdown().await;
    println!("Shutdown complete.");
    Ok(())
}
