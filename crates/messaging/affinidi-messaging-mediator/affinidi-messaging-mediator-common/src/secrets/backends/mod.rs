//! Backend implementations.

pub(crate) mod aws;
pub(crate) mod azure;
pub(crate) mod file;
pub(crate) mod file_encrypted;
pub(crate) mod gcp;
pub(crate) mod keyring;
pub(crate) mod memory;
pub(crate) mod stubs;

pub use file_encrypted::{PASSPHRASE_ENV, PASSPHRASE_FILE_ENV};

// Re-export stub submodules under their scheme names so `store::open_store`
// has a consistent call shape for every backend.
pub(crate) use stubs::vault;

pub use memory::MemoryStore;
