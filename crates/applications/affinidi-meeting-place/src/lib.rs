/*!
 * Rust library for Affinidi [Meeting Place](https://meetingplace.world)
 */

use affinidi_did_authentication::AuthorizationTokens;
use affinidi_did_common::{Document, service::Endpoint};
use affinidi_tdk_common::{TDKSharedState, profiles::TDKProfile};
use errors::{MeetingPlaceError, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use tracing::debug;

pub mod errors;
pub mod offers;
pub mod vcard;

/// Affinidi Meeting Place SDK
#[derive(Clone)]
pub struct MeetingPlace {
    /// DID for MeetingPlace
    mp_did: String,

    /// Service endpoint for MeetingPlace API
    mp_api: String,
}

impl MeetingPlace {
    pub async fn new(tdk: &TDKSharedState, mp_did: String) -> Result<Self> {
        let did_doc = tdk.did_resolver.resolve(&mp_did).await?;
        Ok(Self {
            mp_did,
            mp_api: find_api_service_endpoint(&did_doc.doc).unwrap_or(
                "https://ib8w1f44k7.execute-api.ap-southeast-1.amazonaws.com/dev/mpx/v1"
                    .to_string(),
            ),
        })
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

        let response = _http_post::<CheckOfferPhraseResponse>(
            &tdk.client,
            &[&self.mp_api, "/check-offer-phrase"].concat(),
            &json!({"offerPhrase": phrase}).to_string(),
            &tokens,
        )
        .await?;

        Ok(response.is_in_use)
    }
}

// ************************************************************************************************

#[derive(Debug, Deserialize)]
struct CheckOfferPhraseResponse {
    #[serde(rename = "isInUse")]
    is_in_use: bool,
}

pub(crate) async fn _http_post<T>(
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
        .map_err(|e| MeetingPlaceError::API(format!("HTTP POST failed ({url}): {e:?}")))?;

    let response_status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| MeetingPlaceError::API(format!("Couldn't get HTTP body: {e:?}")))?;

    debug!(
        "status: {} response_body: {}",
        response_status, response_body
    );
    if !response_status.is_success() {
        if response_status.as_u16() == 401 {
            return Err(MeetingPlaceError::Authentication(
                "Permission Denied (401: Unauthorized)`".into(),
            ));
        } else {
            return Err(MeetingPlaceError::API(format!(
                "Failed to get authentication response. url: {url}, status: {response_status}"
            )));
        }
    }

    serde_json::from_str::<T>(&response_body)
        .map_err(|e| MeetingPlaceError::API(format!("Couldn't deserialize API body response: {e}")))
}

/// Find the [serviceEndpoint](https://www.w3.org/TR/did-1.0/#services) with type `DIDCommMessaging` from a DID Document
/// # Arguments
/// * `doc` - The DID Document to search
///
/// # Returns
/// URI of the service endpoint if it exists
pub(crate) fn find_mediator_service_endpoints(doc: &Document) -> Vec<String> {
    if let Some(service) = doc.find_service("service") {
        let mut uris = Vec::new();
        match &service.service_endpoint {
            Endpoint::Url(e) => {
                uris.push(e.to_string());
            }
            Endpoint::Map(map) => {
                if let Some(array) = map.as_array() {
                    for endpoint in array {
                        if let Some(uri) = endpoint.get("uri") {
                            uris.push(
                                uri.to_string()
                                    .trim_start_matches('"')
                                    .trim_end_matches('"')
                                    .to_string(),
                            );
                        }
                    }
                } else if let Some(uri) = map.get("uri") {
                    uris.push(
                        uri.to_string()
                            .trim_start_matches('"')
                            .trim_end_matches('"')
                            .to_string(),
                    );
                }
            }
        }
        uris
    } else {
        vec![]
    }
}

/// Find the [serviceEndpoint](https://www.w3.org/TR/did-1.0/#services) with id `api` from a DID Document
/// # Arguments
/// * `doc` - The DID Document to search
///
/// # Returns
/// URI of the service endpoint if it exists
pub fn find_api_service_endpoint(doc: &Document) -> Option<String> {
    if let Some(service) = doc.find_service("api") {
        if let Endpoint::Url(e) = &service.service_endpoint {
            debug!("Found service endpoint: {}", e);
            Some(e.to_string())
        } else {
            None
        }
    } else {
        None
    }
}
