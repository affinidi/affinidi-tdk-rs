//! Raw TOML configuration schema for the Affinidi Messaging Mediator.
//!
//! This crate holds **only the serde deserialization types** that mirror the
//! mediator's `mediator.toml` — the `*ConfigRaw` structs and their plain-serde
//! sub-structs. Every field is the on-disk shape (mostly `String`, parsed into
//! typed/runtime values later).
//!
//! It is intentionally dependency-light (serde + the lean tier of
//! `affinidi-messaging-mediator-common`, for `DatabaseConfigRaw`). The
//! **resolved** runtime `Config` — opened secret backends, JWT keys, the
//! DID-resolver client, the VTA refresher — and all `ConfigRaw → Config`
//! conversions stay in the mediator binary, which re-exports these types so
//! existing `crate::common::config::*` paths keep resolving.
//!
//! The goal (mediator simplification T18) is one schema, two consumers: the
//! mediator and (later) the `mediator-setup` wizard, which today renders this
//! TOML by hand with no shared types. Env-var override logic and boot-time
//! validation move here in a follow-up (T18b), once they carry a crate-local
//! error type instead of the mediator's server-tier `MediatorError`.

pub mod env;
pub mod error;
mod limits;
mod processors;
mod schema;
mod security;
pub mod validate;

pub use error::ConfigError;
pub use limits::*;
pub use processors::*;
pub use schema::*;
pub use security::*;

#[cfg(test)]
mod golden {
    use super::ConfigRaw;

    /// The shipped `mediator.toml` must still deserialize into `ConfigRaw`
    /// after the schema relocation — a structural guard that the moved types
    /// stay byte-compatible with the real config the mediator parses.
    #[test]
    fn shipped_mediator_toml_parses() {
        let toml = include_str!("../../conf/mediator.toml");
        let raw: ConfigRaw =
            ::toml::from_str(toml).expect("conf/mediator.toml parses as ConfigRaw");

        // Spot-check a field from a few different sections so an accidental
        // rename or moved field is caught, not just "it deserialized".
        assert!(raw.mediator_did.starts_with("did"));
        assert!(!raw.server.listen_address.is_empty());
        assert!(!raw.security.global_acl_default.is_empty());
        assert!(!raw.limits.message_size.is_empty());
        assert!(!raw.processors.forwarding.enabled.is_empty());
        assert!(!raw.secrets.backend.is_empty());
    }
}
