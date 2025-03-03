/*!
 * Secrets Manager Errors
 */

use thiserror::Error;

/// Affinidi Secrets Resolver Errors
#[derive(Error, Debug)]
pub enum SecretsResolverError {
    #[error("Generic Error: {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, SecretsResolverError>;
