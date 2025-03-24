/*!
 * Rust library for Affinidi [Meeting Place](https://meetingplace.world)
 */

use affinidi_did_authentication::AuthorizationTokens;
use errors::{MeetingPlaceError, Result};
use reqwest::Client;
use serde::Deserialize;
use tracing::debug;

pub mod errors;

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

async fn _http_post<T>(
    client: &Client,
    url: &str,
    body: &str,
    tokens: &AuthorizationTokens,
) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    debug!("POSTing to {}", url);
    debug!("Body: {}", body);
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| MeetingPlaceError::API(format!("HTTP POST failed ({}): {:?}", url, e)))?;

    let response_status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| MeetingPlaceError::API(format!("Couldn't get HTTP body: {:?}", e)))?;

    if !response_status.is_success() {
        if response_status.as_u16() == 401 {
            return Err(MeetingPlaceError::Authentication(
                "Permission Denied (401: Unauthorized)`".into(),
            ));
        } else {
            return Err(MeetingPlaceError::API(format!(
                "Failed to get authentication response. url: {}, status: {}",
                url, response_status
            )));
        }
    }

    debug!("response body: {}", response_body);
    serde_json::from_str::<T>(&response_body).map_err(|e| {
        MeetingPlaceError::API(format!("Couldn't deserialize API body response: {}", e))
    })
}
