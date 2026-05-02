/*!
 * Rust client for Affinidi [Meeting Place](https://meetingplace.world).
 *
 * Construct a [`MeetingPlace`] from a [`TDKSharedState`] and the meeting-place
 * service DID. The service DID is resolved once at construction time to
 * discover the API endpoint via its `api` service entry; further requests
 * reuse the cached endpoint.
 */

#![forbid(unsafe_code)]

use affinidi_did_authentication::AuthorizationTokens;
use affinidi_did_common::{Document, service::Endpoint};
use affinidi_tdk_common::{TDKSharedState, profiles::TDKProfile};
use errors::{MeetingPlaceError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;

pub mod errors;
pub mod offers;
pub mod vcard;

/// Affinidi Meeting Place client.
///
/// Cheap to clone — it holds two `String`s.
#[derive(Clone, Debug)]
pub struct MeetingPlace {
    /// DID of the Meeting Place service. Used as the `target_did` for DID
    /// authentication and surfaces in error contexts.
    pub(crate) mp_did: String,

    /// Resolved API base URL (without trailing slash). Discovered from the
    /// Meeting Place DID document's `api` service entry at construction
    /// time.
    pub(crate) mp_api: String,
}

impl MeetingPlace {
    /// Construct a new client.
    ///
    /// Resolves `mp_did` via the supplied [`TDKSharedState`]'s DID resolver
    /// and extracts the `api` service endpoint. Returns
    /// [`MeetingPlaceError::DIDError`] if the DID cannot be resolved, or
    /// [`MeetingPlaceError::Configuration`] if the DID document does not
    /// expose an `api` endpoint.
    pub async fn new(tdk: &TDKSharedState, mp_did: String) -> Result<Self> {
        let did_doc = tdk.did_resolver().resolve(&mp_did).await?;
        let mp_api = find_api_service_endpoint(&did_doc.doc).ok_or_else(|| {
            MeetingPlaceError::Configuration(format!(
                "Meeting Place DID ({mp_did}) does not expose an `api` service endpoint"
            ))
        })?;
        Ok(Self { mp_did, mp_api })
    }

    /// DID of the Meeting Place service this client talks to.
    pub fn did(&self) -> &str {
        &self.mp_did
    }

    /// Resolved API base URL.
    pub fn api_url(&self) -> &str {
        &self.mp_api
    }

    /// Check whether an offer phrase is currently in use.
    pub async fn check_offer_phrase(
        &self,
        tdk: &TDKSharedState,
        profile: &TDKProfile,
        phrase: &str,
    ) -> Result<bool> {
        let tokens = tdk.authenticate_profile(profile, &self.mp_did).await?;

        let response = http_post::<_, CheckOfferPhraseResponse>(
            tdk.client(),
            &endpoint(&self.mp_api, "/check-offer-phrase"),
            &json!({ "offerPhrase": phrase }),
            &tokens,
        )
        .await?;

        Ok(response.is_in_use)
    }
}

#[derive(Debug, Deserialize)]
struct CheckOfferPhraseResponse {
    #[serde(rename = "isInUse")]
    is_in_use: bool,
}

/// Build a request URL by joining the API base with a path. Both must be
/// supplied; the path should start with `/`.
pub(crate) fn endpoint(base: &str, path: &str) -> String {
    let mut s = String::with_capacity(base.len() + path.len());
    s.push_str(base);
    s.push_str(path);
    s
}

/// POST a JSON body to `url`, deserialise the response into `T`.
///
/// Maps non-2xx HTTP responses to [`MeetingPlaceError`]: 401/403 → `Authentication`,
/// other non-success → `API`. The request body is **not** logged (it may
/// contain offer phrases or other identifiers).
pub(crate) async fn http_post<B, T>(
    client: &Client,
    url: &str,
    body: &B,
    tokens: &AuthorizationTokens,
) -> Result<T>
where
    B: Serialize + ?Sized,
    T: for<'de> Deserialize<'de>,
{
    debug!(url, "POST");
    let response = client
        .post(url)
        .bearer_auth(&tokens.access_token)
        .json(body)
        .send()
        .await
        .map_err(|e| MeetingPlaceError::API(format!("HTTP POST failed ({url}): {e}")))?;

    let status = response.status();
    let body_text = response
        .text()
        .await
        .map_err(|e| MeetingPlaceError::API(format!("Couldn't read HTTP body ({url}): {e}")))?;

    if !status.is_success() {
        return Err(match status.as_u16() {
            401 | 403 => MeetingPlaceError::Authentication(format!(
                "Permission denied ({status}) calling {url}"
            )),
            _ => MeetingPlaceError::API(format!("Request to {url} failed: {status}")),
        });
    }

    serde_json::from_str::<T>(&body_text).map_err(|e| {
        MeetingPlaceError::Serialization(format!("Couldn't deserialise response from {url}: {e}"))
    })
}

/// Find HTTP(S) and WebSocket service endpoints on a DID document's
/// `service` entry.
///
/// Both forms of `serviceEndpoint` are supported: a single
/// [`Endpoint::Url`], or a [`Endpoint::Map`] that holds either an `{uri}`
/// object or an array of them. Non-string `uri` values are skipped.
pub(crate) fn find_mediator_service_endpoints(doc: &Document) -> Vec<String> {
    let Some(service) = doc.find_service("service") else {
        return Vec::new();
    };
    match &service.service_endpoint {
        Endpoint::Url(url) => vec![url.to_string()],
        Endpoint::Map(map) => {
            if let Some(array) = map.as_array() {
                array.iter().filter_map(extract_uri).collect()
            } else {
                extract_uri(map).into_iter().collect()
            }
        }
    }
}

/// Pull the `uri` field out of a service-endpoint map, returning `None` if
/// it is absent or not a JSON string.
fn extract_uri(value: &serde_json::Value) -> Option<String> {
    value.get("uri")?.as_str().map(str::to_owned)
}

/// Find the [serviceEndpoint](https://www.w3.org/TR/did-1.0/#services) with
/// id `api` from a DID Document, returning its URL when present.
pub fn find_api_service_endpoint(doc: &Document) -> Option<String> {
    let service = doc.find_service("api")?;
    if let Endpoint::Url(url) = &service.service_endpoint {
        debug!(endpoint = %url, "found api service endpoint");
        Some(url.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_uri_handles_string() {
        let v = json!({ "uri": "https://example.com" });
        assert_eq!(extract_uri(&v), Some("https://example.com".to_string()));
    }

    #[test]
    fn extract_uri_returns_none_for_missing() {
        let v = json!({ "accept": ["didcomm/v2"] });
        assert_eq!(extract_uri(&v), None);
    }

    #[test]
    fn extract_uri_returns_none_for_non_string() {
        let v = json!({ "uri": 42 });
        assert_eq!(extract_uri(&v), None);
    }

    #[test]
    fn endpoint_joins_base_and_path() {
        assert_eq!(
            endpoint("https://api.example/v1", "/register-offer"),
            "https://api.example/v1/register-offer"
        );
    }
}
