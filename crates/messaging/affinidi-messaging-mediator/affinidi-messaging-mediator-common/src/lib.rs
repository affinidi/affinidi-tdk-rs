//! Shared types and runtime infrastructure for the mediator.
//!
//! ## Feature layout
//!
//! - **types** (always built) — protocol-vocabulary types (ACL bits,
//!   problem-report shape, message envelopes, account records). Lean
//!   deps: `serde`, `thiserror`, `regex`. Suitable for the SDK and
//!   any client-side consumer.
//! - **`server`** (default) — full server-side stack: error wrappers
//!   tied to axum, the `MediatorStore` trait, secrets backends,
//!   circuit breaker, forwarding processor, time helpers. Pulls
//!   axum, redis, reqwest, tokio-tungstenite, aes-gcm/argon2/zeroize,
//!   metrics, etc. Required by the mediator binary and the
//!   mediator-setup wizard.
//! - **`redis-backend`** — implies `server`, plus the RedisStore impl.
//! - **`secrets-{keyring,aws,gcp,azure,vault}`** — each implies `server`
//!   and pulls in the matching cloud SDK.
//!
//! Downstream client crates (the SDK, third-party tooling) should
//! depend on this crate with `default-features = false` to avoid
//! pulling the server stack into their build graph.

pub mod types;

/// `did:webvh` → `did:web` document rewriting. Pure (`serde_json` only),
/// always built: shared by the mediator runtime (serving `did.json`) and
/// the `mediator-setup` wizard (writing the `did-web.json` artefact).
pub mod did_web;

/// `aws_parameter_store://` target parsing. Pure (no AWS SDK), always
/// built: shared by the mediator runtime (reading `mediator_did` from a
/// parameter) and the `mediator-setup` wizard (publishing the minted DID
/// to one), so the string one writes is the string the other reads.
pub mod parameter_store;

/// `s3://` target parsing. Pure (no AWS SDK), always built: shared by the
/// mediator runtime (reading its self-hosted `did.jsonl` log from an S3
/// object) and the `mediator-setup` wizard (publishing the minted log to
/// one), so the string one writes is the string the other reads.
pub mod s3_target;

#[cfg(feature = "server")]
pub mod circuit_breaker;
/// Database wiring: the lean `DatabaseConfig` serde struct is always
/// available under `server` (the mediator's main config parses it
/// regardless of which storage backend is selected). The
/// `DatabaseHandler` and its redis-specific helpers are gated inside
/// the module on `redis-backend`.
#[cfg(feature = "server")]
pub mod database;
#[cfg(feature = "server")]
pub mod errors;
#[cfg(feature = "server")]
pub mod secrets;
#[cfg(feature = "server")]
pub mod store;
#[cfg(feature = "server")]
pub mod tasks;
#[cfg(feature = "server")]
pub mod time;

#[cfg(feature = "server")]
pub use secrets::backends::{PASSPHRASE_ENV, PASSPHRASE_FILE_ENV};
#[cfg(feature = "server")]
pub use secrets::well_known::OPERATING_SECRETS;
#[cfg(feature = "server")]
pub use secrets::{
    ADMIN_CREDENTIAL, AdminCredential, BOOTSTRAP_EPHEMERAL_SEED_PREFIX, BOOTSTRAP_SEED_INDEX,
    BootstrapSeedIndex, BootstrapSeedIndexEntry, JWT_SECRET, MediatorSecrets,
    OPERATING_DID_DOCUMENT, OPERATING_KEY_AGREEMENT, OPERATING_SIGNING, PROBE_SENTINEL_PREFIX,
    VTA_LAST_KNOWN_BUNDLE, VtaCachedBundle,
};
