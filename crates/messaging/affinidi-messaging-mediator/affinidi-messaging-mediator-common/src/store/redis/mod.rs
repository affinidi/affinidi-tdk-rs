//! Redis backend implementation of [`crate::store::MediatorStore`].
//!
//! Lives in `mediator-common` (rather than the parent `mediator`
//! crate) so the standalone binaries in `affinidi-messaging-mediator-processors`
//! can construct a `RedisStore` for horizontal-scaling deployments
//! without depending on the mediator's HTTP machinery.
//!
//! See [`store::RedisStore`] for the type itself; per-topic
//! implementation modules live under `database/`.

pub mod database;
pub mod init;
pub mod store;

pub use init::RedisInitConfig;
pub use store::RedisStore;
