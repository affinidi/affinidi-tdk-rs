//! Minimal init parameters for the Redis backend.
//!
//! `RedisStore::initialize_redis` and the migration runner only need a
//! handful of fields from the mediator's full `Config`. Pulling those
//! into a tiny dedicated struct lets the migration code live in
//! `mediator-common` without depending on the mediator binary's HTTP
//! / TLS / VTA configuration.

use crate::types::acls::MediatorACLSet;

/// Inputs the Redis backend needs to seed the mediator + root-admin
/// accounts and run schema migrations.
#[derive(Clone, Debug)]
pub struct RedisInitConfig {
    /// SHA-256 hash of the mediator's own DID (the `did:peer:2.*`
    /// identity served from the DIDComm endpoint).
    pub mediator_did_hash: String,
    /// The configured root-admin DID (raw, not hashed).
    pub admin_did: String,
    /// Default ACL applied to the root-admin and to migration-time
    /// account upgrades.
    pub global_acl_default: MediatorACLSet,
}
