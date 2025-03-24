/*!
 * Rust library for Affinidi [Meeting Place](https://meetingplace.world)
 */

use affinidi_did_authentication::AuthorizationTokens;
use affinidi_tdk_common::{TDKSharedState, profiles::TDKProfile};
use errors::{MeetingPlaceError, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info};

pub mod errors;

/// Affinidi Meeting Place SDK
#[derive(Clone)]
pub struct MeetingPlace {
    /// DID for MeetingPlace
    mp_did: String,
}

impl MeetingPlace {
    pub fn new(mp_did: String) -> Self {
        Self { mp_did }
    }

    pub async fn check_offer_phrase(
        &self,
        tdk: &TDKSharedState,
        profile: TDKProfile,
        phrase: &str,
    ) -> Result<bool> {
        let tokens = tdk
            .authentication
            .authenticate(profile.did, self.mp_did.clone(), 3, None)
            .await?;

        let response = _http_post::<CheckOfferPhraseResponse>(&tdk.client, "https://ib8w1f44k7.execute-api.ap-southeast-1.amazonaws.com/dev/mpx/v1/check-offer-phrase", &json!({"offerPhrase": phrase}).to_string(), &tokens).await;
        info!("check_offer_phrase response: {:#?}", response);
        Ok(false)
    }
}

// ************************************************************************************************

#[derive(Debug, Deserialize)]
struct CheckOfferPhraseResponse {
    is_in_use: bool,
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
