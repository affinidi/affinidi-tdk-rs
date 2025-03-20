/*!
 * Rust library for Affinidi [Meeting Place](https://meetingplace.world)
 */

use affinidi_did_authentication::AuthorizationTokens;
use tracing::debug;

/// Affinidi Meeting Place SDK
#[derive(Clone)]
pub struct MeetingPlace {
    /// The Meeting Place DID
    pub(crate) _mp_did: String,

    /// The Authorization Tokens for Meeting Place
    _auth_tokens: Option<AuthorizationTokens>,
}

impl MeetingPlace {
    /// Create a new instance of the Meeting Place SDK
    /// # Arguments
    /// * `mp_did` - The Meeting Place DID
    pub fn new(mp_did: String) -> Self {
        debug!(
            "Creating new Meeting Place SDK instance with DID: {}",
            mp_did
        );
        Self {
            _mp_did: mp_did,
            _auth_tokens: None,
        }
    }

    /// Authenticate with Meeting Place
    pub fn authenticate(&self) {}
}
