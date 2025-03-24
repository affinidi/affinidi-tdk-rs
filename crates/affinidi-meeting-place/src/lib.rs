/*!
 * Rust library for Affinidi [Meeting Place](https://meetingplace.world)
 */

use affinidi_did_authentication::AuthorizationTokens;
use affinidi_tdk_common::{TDKSharedState, profiles::TDKProfile};
use errors::{MeetingPlaceError, Result};
use reqwest::Client;
use serde::Deserialize;
use tracing::debug;

pub mod errors;

/// Affinidi Meeting Place SDK
#[derive(Clone)]
pub struct MeetingPlace {}

impl MeetingPlace {
    pub async fn check_offer_phrase(
        tdk: &TDKSharedState,
        profile: TDKProfile,
        phrase: &str,
    ) -> Result<bool> {
    }
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
