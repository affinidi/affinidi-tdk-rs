/*!
 * Common TDK Errors and handling/conversion
 */

use thiserror::Error;

/// Affinidi Trust Development Kit Errors
#[derive(Error, Debug)]
pub enum TDKError {
    #[error("Authentication failed: {0}")]
    Authentication(String),
}
