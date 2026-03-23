//! Authorization Process
//! 1. Client gets a random challenge from the server
//! 2. Client encrypts the random challenge in a message and sends it back to the server POST /authenticate
//! 3. Server decrypts the message and verifies the challenge
//! 4. If the challenge is correct, the server sends two JWT tokens to the client (access and refresh tokens)
//! 5. Client uses the access token to access protected services
//! 6. If the access token expires, the client uses the refresh token to get a new access token
//!
//! NOTE: All errors handled in the handlers are returned as a Problem Report messages

mod challenge;
mod helpers;
mod refresh;
mod response;

pub use challenge::*;
pub use helpers::create_random_string;
pub use refresh::*;
pub use response::*;

use affinidi_messaging_sdk::messages::GenericDataStruct;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthenticationChallenge {
    pub challenge: String,
    pub session_id: String,
}
impl GenericDataStruct for AuthenticationChallenge {}

/// Refresh tokens response from the authentication service.
/// Includes a rotated refresh token (one-time use).
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthRefreshResponse {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}
impl GenericDataStruct for AuthRefreshResponse {}

/// Request body for POST /authenticate/challenge
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ChallengeBody {
    pub did: String,
}
