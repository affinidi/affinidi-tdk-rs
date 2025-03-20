/*!
 * Rust library for Affinidi [Meeting Place](https://meetingplace.world)
 */

// TODO: uncomment me
// use affinidi_did_authentication::AuthorizationTokens;
use tracing::debug;

/// Affinidi Meeting Place SDK
#[derive(Clone)]
pub struct MeetingPlace {
    // TODO: uncomment me
    // /// The Meeting Place DID
    // pub(crate) mp_did: String,

    // /// The Authorization Tokens for Meeting Place
    // auth_tokens: Option<AuthorizationTokens>,
    // TODO: uncomment me
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
            // TODO: uncomment me
            // mp_did,
            // auth_tokens: None,
            // TODO: uncomment me
        }
    }

    /// Authenticate with Meeting Place
    pub fn authenticate(&self) {}
}
