//! Backend implementations.

pub(crate) mod aws;
pub(crate) mod azure;
pub(crate) mod file;
pub(crate) mod file_encrypted;
pub(crate) mod gcp;
pub(crate) mod keyring;
pub(crate) mod memory;
pub(crate) mod vault;

pub use file_encrypted::{PASSPHRASE_ENV, PASSPHRASE_FILE_ENV};

pub use memory::MemoryStore;
