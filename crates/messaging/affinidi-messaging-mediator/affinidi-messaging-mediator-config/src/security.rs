//! Raw `[security]` config schema.
//!
//! The resolved `SecurityConfig` (parsed ACL set, JWT keys, CORS layer) and the
//! `SecurityConfigRaw → SecurityConfig` conversion stay in the mediator — they
//! load secrets and build runtime objects this crate intentionally avoids.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfigRaw {
    pub mediator_acl_mode: String,
    pub global_acl_default: String,
    pub local_direct_delivery_allowed: String,
    pub local_direct_delivery_allow_anon: String,
    pub use_ssl: String,
    pub ssl_certificate_file: Option<String>,
    pub ssl_key_file: Option<String>,
    pub jwt_access_expiry: String,
    pub jwt_refresh_expiry: String,
    pub cors_allow_origin: Option<String>,
    pub block_anonymous_outer_envelope: String,
    pub block_remote_admin_msgs: String,
    pub force_session_did_match: String,
    pub admin_messages_expiry: String,
    /// Explicit inter-mediator relay switch. `#[serde(default)]` so configs
    /// that predate the flag deserialize without it (empty → `false`).
    #[serde(default)]
    pub enable_inter_mediator_relay: String,
}
