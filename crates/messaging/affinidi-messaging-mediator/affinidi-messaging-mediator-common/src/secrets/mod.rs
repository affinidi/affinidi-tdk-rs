//! Unified secret storage for the Affinidi Messaging Mediator.
//!
//! Two orthogonal layers:
//!
//! - **Backend** — where bytes live. Pluggable via [`SecretStore`]: the
//!   mediator picks one backend (keyring, file, AWS, GCP, Azure, Vault),
//!   identifies it with a URL (`keyring://<service>`, `file:///path`,
//!   `aws_secrets://<region>/<prefix>`, ...), and every secret it cares
//!   about goes through that one interface.
//!
//! - **Well-known keys** — what the mediator reads. A small set of named
//!   entries (`mediator/admin/credential`, `mediator/jwt/secret`,
//!   `mediator/vta/last_known_bundle`, ...) with typed accessors in
//!   [`well_known`]. The mediator never dereferences raw URLs per-field;
//!   it asks [`MediatorSecrets`] for, say, "the admin credential" and the
//!   helper handles lookup, envelope parsing, and shape validation.
//!
//! All stored bytes are wrapped in a schema-versioned [`envelope::Envelope`]
//! (`{version: 1, kind: "...", data: ...}`) so entries can evolve without
//! breaking existing backends.

pub mod backends;
pub mod envelope;
pub mod error;
pub mod retry;
pub mod store;
pub mod url;
pub mod well_known;

pub use envelope::{ENVELOPE_VERSION, Envelope};
pub use error::{Result, SecretStoreError};
pub use store::{DynSecretStore, SecretStore, open_store};
pub use url::{BackendUrl, parse_url};
pub use well_known::{
    ADMIN_CREDENTIAL, AdminCredential, BOOTSTRAP_EPHEMERAL_SEED_PREFIX, BOOTSTRAP_SEED_INDEX,
    BootstrapSeedIndex, BootstrapSeedIndexEntry, JWT_SECRET, MediatorSecrets,
    OPERATING_DID_DOCUMENT, OPERATING_KEY_AGREEMENT, OPERATING_SIGNING, PROBE_SENTINEL_PREFIX,
    VTA_LAST_KNOWN_BUNDLE, VtaCachedBundle,
};
