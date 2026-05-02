/*!
 * Offer creation, registration, query, and deregistration.
 */

use crate::{
    MeetingPlace, endpoint,
    errors::{MeetingPlaceError, Result},
    find_mediator_service_endpoints, http_post,
    vcard::Vcard,
};
use affinidi_messaging_didcomm::message::Message;
use affinidi_tdk_common::{TDKSharedState, profiles::TDKProfile};
use base64::prelude::*;
use chrono::{Local, TimeDelta};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{str::FromStr, time::Duration};
use uuid::Uuid;

/// Top-level Meeting Place struct for an Offer.
#[derive(Debug)]
pub struct Offer {
    pub status: String,
    /// DIDComm message (base64 URL-safe, no pad).
    pub message: Option<String>,
    pub offer_link: Option<String>,
    pub valid_until: Option<String>,
    pub registration: Option<RegisterOffer>,
    pub mnemonic: Option<String>,
}

/// Register an offer with Meeting Place.
///
/// Construct via [`RegisterOffer::create`] (returns a builder).
#[derive(Debug, Serialize)]
pub struct RegisterOffer {
    /// Name of the offer that will be displayed to acceptors in their UI.
    #[serde(rename = "offerName")]
    name: String,

    /// Description of the offer that will be displayed to potential acceptors.
    #[serde(rename = "offerDescription")]
    description: String,

    /// Base64 encoded DIDComm plaintext message containing the invitation.
    #[serde(rename = "didcommMessage")]
    didcomm_message: String,

    /// Base64 encoded vCard containing the offerer's contact details.
    vcard: String,

    /// ISO-8601 formatted date/time when the offer expires (e.g.,
    /// `"2024-12-31T23:59:59Z"`). An empty string asks the system to apply
    /// its maximum.
    #[serde(rename = "validUntil")]
    valid_until: String,

    /// Maximum number of times this offer can be accepted (0 = system
    /// default).
    #[serde(rename = "maximumUsage")]
    maximum_usage: usize,

    /// Token from the device's push notification API/SDK.
    #[serde(rename = "deviceToken")]
    device_token: String,

    /// Push notification platform.
    #[serde(rename = "platformType")]
    platform_type: PlatformType,

    /// HTTP(S) endpoint of the DIDComm mediator service for this offer.
    #[serde(rename = "mediatorEndpoint")]
    mediator_endpoint: String,

    /// DID of the DIDComm mediator service for this offer.
    #[serde(rename = "mediatorDid")]
    mediator_did: String,

    /// WebSocket(S) endpoint of the DIDComm mediator service.
    #[serde(rename = "mediatorWSSEndpoint")]
    mediator_websocket_endpoint: String,

    /// Optional custom phrase to identify this offer (must be unique if
    /// provided). If absent, the system generates one.
    #[serde(rename = "customPhrase", skip_serializing_if = "Option::is_none")]
    custom_phrase: Option<String>,

    /// Bitfield describing the contact. Currently the API does not enforce
    /// or validate these bits — the client interprets them. Today's
    /// Meeting Place mobile client uses:
    ///
    /// - `Unknown=0`, `Person=1`, `Adult=2`, `Robot=4`,
    ///   `Service=8`, `Organisation=16`.
    ///
    /// Subject to change.
    #[serde(rename = "contactAttributes")]
    contact_attributes: u32,
}

/// Push notification platform type.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlatformType {
    Apns,
    ApnsSandbox,
    Fcm,
    /// No push notifications supported on this platform.
    #[default]
    None,
}

impl FromStr for PlatformType {
    type Err = MeetingPlaceError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_ascii_uppercase().as_str() {
            "APNS" => PlatformType::Apns,
            "APNS_SANDBOX" => PlatformType::ApnsSandbox,
            "FCM" => PlatformType::Fcm,
            "" | "NONE" => PlatformType::None,
            other => {
                return Err(MeetingPlaceError::Configuration(format!(
                    "Unknown push platform type {other:?} (expected APNS, APNS_SANDBOX, FCM, NONE)"
                )));
            }
        })
    }
}

/// Type of contact represented by the offer. Subject to change.
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub enum ContactAttributeType {
    #[default]
    Unknown,
    Person,
    Adult,
    Robot,
    Service,
    Organisation,
}

impl ContactAttributeType {
    /// Single-bit numeric encoding sent over the wire.
    pub const fn to_u32(self) -> u32 {
        match self {
            ContactAttributeType::Unknown => 0,
            ContactAttributeType::Person => 1,
            ContactAttributeType::Adult => 2,
            ContactAttributeType::Robot => 4,
            ContactAttributeType::Service => 8,
            ContactAttributeType::Organisation => 16,
        }
    }

    /// Inverse of [`to_u32`](Self::to_u32). Unknown bits map to
    /// [`Unknown`](Self::Unknown).
    pub const fn from_u32(bits: u32) -> Self {
        match bits {
            1 => ContactAttributeType::Person,
            2 => ContactAttributeType::Adult,
            4 => ContactAttributeType::Robot,
            8 => ContactAttributeType::Service,
            16 => ContactAttributeType::Organisation,
            _ => ContactAttributeType::Unknown,
        }
    }
}

/// Builder for [`RegisterOffer`].
#[derive(Debug)]
pub struct RegisterOfferBuilder {
    name: String,
    description: String,
    didcomm_message: String,
    vcard: Vcard,
    valid_until: Duration,
    maximum_usage: usize,
    device_token: String,
    platform_type: PlatformType,
    mediator_did: String,
    custom_phrase: Option<String>,
    contact_attributes: u32,
}

impl RegisterOfferBuilder {
    /// Set a Vcard for the offer.
    pub fn vcard(&mut self, vcard: Vcard) -> &mut Self {
        self.vcard = vcard;
        self
    }

    /// Lifetime of the offer from now. Defaults to `Duration::ZERO`, which
    /// asks Meeting Place to apply its maximum.
    pub fn valid_until(&mut self, valid_until: Duration) -> &mut Self {
        self.valid_until = valid_until;
        self
    }

    /// Maximum number of times this offer can be accepted (0 = system
    /// default).
    pub fn maximum_usage(&mut self, maximum_usage: usize) -> &mut Self {
        self.maximum_usage = maximum_usage;
        self
    }

    /// Token received from the device's push notification API/SDK.
    /// Defaults to `"NO_TOKEN"`.
    pub fn device_token(&mut self, device_token: &str) -> &mut Self {
        self.device_token = device_token.to_string();
        self
    }

    /// Push notification platform type. Defaults to
    /// [`PlatformType::None`].
    pub fn platform_type(&mut self, platform_type: PlatformType) -> &mut Self {
        self.platform_type = platform_type;
        self
    }

    /// Optional custom phrase to identify this offer.
    pub fn custom_phrase(&mut self, custom_phrase: &str) -> &mut Self {
        self.custom_phrase = Some(custom_phrase.to_string());
        self
    }

    /// Bitfield representing various contact attributes for the offer.
    pub fn contact_attributes(&mut self, contact_attributes: ContactAttributeType) -> &mut Self {
        self.contact_attributes = contact_attributes.to_u32();
        self
    }

    /// Build the [`RegisterOffer`]. Resolves the mediator DID via the
    /// supplied [`TDKSharedState`] and extracts its HTTP and WebSocket
    /// service endpoints.
    pub async fn build(self, tdk: &TDKSharedState) -> Result<RegisterOffer> {
        let valid_until = encode_valid_until(self.valid_until)?;

        let mediator_doc = tdk.did_resolver().resolve(&self.mediator_did).await?;
        let (mediator_endpoint, mediator_websocket_endpoint) =
            split_mediator_endpoints(&find_mediator_service_endpoints(&mediator_doc.doc))?;

        Ok(RegisterOffer {
            name: self.name,
            description: self.description,
            didcomm_message: self.didcomm_message,
            vcard: self.vcard.to_base64()?,
            valid_until,
            maximum_usage: self.maximum_usage,
            device_token: self.device_token,
            platform_type: self.platform_type,
            mediator_endpoint,
            mediator_did: self.mediator_did,
            mediator_websocket_endpoint,
            custom_phrase: self.custom_phrase,
            contact_attributes: self.contact_attributes,
        })
    }
}

/// Convert a lifetime duration into the wire-format `validUntil` string.
/// `Duration::ZERO` becomes the empty string (server picks its own
/// maximum); anything else becomes an RFC-3339 timestamp at `now + dur`.
fn encode_valid_until(dur: Duration) -> Result<String> {
    if dur.as_secs() == 0 {
        return Ok(String::new());
    }
    let secs: i64 = dur.as_secs().try_into().map_err(|_| {
        MeetingPlaceError::Configuration(format!(
            "valid_until duration of {} seconds exceeds i64::MAX",
            dur.as_secs()
        ))
    })?;
    let delta = TimeDelta::try_seconds(secs).ok_or_else(|| {
        MeetingPlaceError::Configuration(format!(
            "valid_until duration of {secs} seconds overflows TimeDelta"
        ))
    })?;
    Ok((Local::now() + delta).to_rfc3339())
}

/// Pick the first HTTP(S) and the first WebSocket URI from the mediator's
/// service endpoints. Errors if either is missing.
fn split_mediator_endpoints(uris: &[String]) -> Result<(String, String)> {
    let http = uris
        .iter()
        .find(|u| u.starts_with("http://") || u.starts_with("https://"))
        .cloned()
        .ok_or_else(|| {
            MeetingPlaceError::Configuration(
                "Mediator DID has no HTTP(S) service endpoint".to_string(),
            )
        })?;
    let ws = uris
        .iter()
        .find(|u| u.starts_with("ws://") || u.starts_with("wss://"))
        .cloned()
        .ok_or_else(|| {
            MeetingPlaceError::Configuration(
                "Mediator DID has no WebSocket service endpoint".to_string(),
            )
        })?;
    Ok((http, ws))
}

impl RegisterOffer {
    /// Construct a [`RegisterOfferBuilder`] populated with required
    /// fields. Customise further via the builder methods, then call
    /// [`RegisterOfferBuilder::build`].
    pub fn create(
        name: &str,
        description: &str,
        from_did: &str,
        mediator_did: &str,
    ) -> Result<RegisterOfferBuilder> {
        Ok(RegisterOfferBuilder {
            name: name.to_string(),
            description: description.to_string(),
            didcomm_message: Offer::create_offer_oob_message(from_did)?,
            vcard: Vcard::default(),
            valid_until: Duration::ZERO,
            maximum_usage: 0,
            device_token: "NO_TOKEN".to_string(),
            platform_type: PlatformType::None,
            mediator_did: mediator_did.to_string(),
            custom_phrase: None,
            contact_attributes: ContactAttributeType::Unknown.to_u32(),
        })
    }
}

#[derive(Serialize)]
struct QueryOffer<'a> {
    mnemonic: &'a str,
    did: &'a str,
}

#[derive(Serialize)]
struct DeregisterOfferRequest<'a> {
    mnemonic: &'a str,
    #[serde(rename = "offerLink")]
    offer_link: &'a str,
}

impl Offer {
    /// Build a pending [`Offer`] from a fully-built [`RegisterOffer`].
    pub fn new_from_register_offer(registration: RegisterOffer) -> Self {
        Self {
            status: "PENDING".to_string(),
            message: Some(registration.didcomm_message.clone()),
            offer_link: None,
            valid_until: None,
            registration: Some(registration),
            mnemonic: None,
        }
    }

    /// Register this offer with Meeting Place.
    ///
    /// On success updates `self.{mnemonic, offer_link, valid_until, status}`
    /// from the response.
    pub async fn register_offer(
        &mut self,
        mp: &MeetingPlace,
        tdk: &TDKSharedState,
        profile: &TDKProfile,
    ) -> Result<RegisterOfferResponse> {
        let registration = self.registration.as_ref().ok_or_else(|| {
            MeetingPlaceError::Configuration(
                "Offer has no registration record — call new_from_register_offer first".to_string(),
            )
        })?;

        let tokens = tdk.authenticate_profile(profile, &mp.mp_did).await?;

        let response = http_post::<_, RegisterOfferResponse>(
            tdk.client(),
            &endpoint(&mp.mp_api, "/register-offer"),
            registration,
            &tokens,
        )
        .await?;

        self.mnemonic = Some(response.mnemonic.clone());
        self.offer_link = Some(response.offer_link.clone());
        self.valid_until = Some(response.valid_until.clone());
        self.status = "REGISTERED".to_string();
        Ok(response)
    }

    /// Build a base64 URL-safe (no-pad) encoded DIDComm OOB invitation
    /// message for `from_did`.
    pub fn create_offer_oob_message(from_did: &str) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let msg = Message::build(
            id.clone(),
            "https://didcomm.org/out-of-band/2.0/invitation".to_string(),
            json!({
                "goal_code": "connect",
                "goal": "Start relationship",
                "accept": ["didcomm/v2"]
            }),
        )
        .from(from_did.to_string())
        .thid(id)
        .finalize();

        let bytes = serde_json::to_vec(&msg).map_err(|e| {
            MeetingPlaceError::Serialization(format!("Couldn't serialise OOB message: {e}"))
        })?;
        Ok(BASE64_URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Look up an offer by its phrase.
    pub async fn query_offer(
        mp: &MeetingPlace,
        tdk: &TDKSharedState,
        profile: &TDKProfile,
        offer_phrase: &str,
    ) -> Result<Offer> {
        let tokens = tdk.authenticate_profile(profile, &mp.mp_did).await?;

        let response = http_post::<_, QueryOfferResponse>(
            tdk.client(),
            &endpoint(&mp.mp_api, "/query-offer"),
            &QueryOffer {
                mnemonic: offer_phrase,
                did: &profile.did,
            },
            &tokens,
        )
        .await?;

        Ok(Offer {
            status: "ACTIVE".to_string(),
            message: Some(response.didcomm_message),
            offer_link: Some(response.offer_link),
            valid_until: Some(response.valid_until),
            registration: None,
            mnemonic: Some(offer_phrase.to_string()),
        })
    }

    /// Deregister (remove) this offer from Meeting Place.
    ///
    /// Requires both `self.mnemonic` and `self.offer_link` to be populated
    /// (typically from a prior [`register_offer`](Self::register_offer) or
    /// [`query_offer`](Self::query_offer) call).
    pub async fn deregister_offer(
        &mut self,
        mp: &MeetingPlace,
        tdk: &TDKSharedState,
        profile: &TDKProfile,
    ) -> Result<DeregisterOfferResponse> {
        let mnemonic = self.mnemonic.as_deref().ok_or_else(|| {
            MeetingPlaceError::Configuration(
                "Cannot deregister — Offer has no mnemonic".to_string(),
            )
        })?;
        let offer_link = self.offer_link.as_deref().ok_or_else(|| {
            MeetingPlaceError::Configuration(
                "Cannot deregister — Offer has no offer_link".to_string(),
            )
        })?;

        let tokens = tdk.authenticate_profile(profile, &mp.mp_did).await?;

        http_post::<_, DeregisterOfferResponse>(
            tdk.client(),
            &endpoint(&mp.mp_api, "/deregister-offer"),
            &DeregisterOfferRequest {
                mnemonic,
                offer_link,
            },
            &tokens,
        )
        .await
    }
}

/// Response from `register-offer`.
#[derive(Debug, Deserialize)]
pub struct RegisterOfferResponse {
    pub mnemonic: String,
    #[serde(rename = "validUntil")]
    pub valid_until: String,
    #[serde(rename = "maximumUsage")]
    pub maximum_usage: usize,
    #[serde(rename = "offerLink")]
    pub offer_link: String,
}

/// Response from `query-offer`.
#[derive(Debug, Deserialize)]
pub struct QueryOfferResponse {
    #[serde(rename = "offerLink")]
    pub offer_link: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "validUntil")]
    pub valid_until: String,
    pub vcard: String,
    #[serde(rename = "mediatorEndpoint")]
    pub mediator_endpoint: String,
    #[serde(rename = "mediatorWSSEndpoint")]
    pub mediator_websocket_endpoint: String,
    #[serde(rename = "didcommMessage")]
    pub didcomm_message: String,
}

/// Response from `deregister-offer`.
#[derive(Debug, Deserialize)]
pub struct DeregisterOfferResponse {
    pub status: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_type_parse_known_values() {
        assert_eq!(PlatformType::from_str("apns").unwrap(), PlatformType::Apns);
        assert_eq!(
            PlatformType::from_str("apns_sandbox").unwrap(),
            PlatformType::ApnsSandbox
        );
        assert_eq!(PlatformType::from_str("FCM").unwrap(), PlatformType::Fcm);
        assert_eq!(PlatformType::from_str("none").unwrap(), PlatformType::None);
        assert_eq!(PlatformType::from_str("").unwrap(), PlatformType::None);
    }

    #[test]
    fn platform_type_rejects_unknown() {
        assert!(matches!(
            PlatformType::from_str("garbage"),
            Err(MeetingPlaceError::Configuration(_))
        ));
    }

    #[test]
    fn contact_attribute_type_roundtrips() {
        for v in [
            ContactAttributeType::Unknown,
            ContactAttributeType::Person,
            ContactAttributeType::Adult,
            ContactAttributeType::Robot,
            ContactAttributeType::Service,
            ContactAttributeType::Organisation,
        ] {
            assert_eq!(ContactAttributeType::from_u32(v.to_u32()), v);
        }
    }

    #[test]
    fn contact_attribute_type_unknown_bits_map_to_unknown() {
        assert_eq!(
            ContactAttributeType::from_u32(99),
            ContactAttributeType::Unknown
        );
    }

    #[test]
    fn encode_valid_until_zero_is_empty() {
        assert_eq!(encode_valid_until(Duration::ZERO).unwrap(), "");
    }

    #[test]
    fn encode_valid_until_nonzero_is_rfc3339() {
        let s = encode_valid_until(Duration::from_secs(60)).unwrap();
        assert!(!s.is_empty());
        assert!(chrono::DateTime::parse_from_rfc3339(&s).is_ok());
    }

    #[test]
    fn encode_valid_until_rejects_overflow() {
        assert!(matches!(
            encode_valid_until(Duration::from_secs(u64::MAX)),
            Err(MeetingPlaceError::Configuration(_))
        ));
    }

    #[test]
    fn split_mediator_endpoints_picks_first_of_each_scheme() {
        let uris = vec![
            "https://api.example/inbox".to_string(),
            "wss://api.example/socket".to_string(),
        ];
        let (http, ws) = split_mediator_endpoints(&uris).unwrap();
        assert_eq!(http, "https://api.example/inbox");
        assert_eq!(ws, "wss://api.example/socket");
    }

    #[test]
    fn split_mediator_endpoints_errors_on_missing_http() {
        let uris = vec!["wss://api.example/socket".to_string()];
        assert!(matches!(
            split_mediator_endpoints(&uris),
            Err(MeetingPlaceError::Configuration(_))
        ));
    }

    #[test]
    fn split_mediator_endpoints_errors_on_missing_ws() {
        let uris = vec!["https://api.example/inbox".to_string()];
        assert!(matches!(
            split_mediator_endpoints(&uris),
            Err(MeetingPlaceError::Configuration(_))
        ));
    }

    #[test]
    fn create_offer_oob_message_is_valid_base64_decoding_to_didcomm() {
        let b64 = Offer::create_offer_oob_message("did:example:alice").unwrap();
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(b64.as_bytes()).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["type"],
            "https://didcomm.org/out-of-band/2.0/invitation"
        );
        assert_eq!(json["from"], "did:example:alice");
        assert_eq!(json["body"]["goal_code"], "connect");
    }

    #[test]
    fn platform_type_serializes_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&PlatformType::ApnsSandbox).unwrap(),
            "\"APNS_SANDBOX\""
        );
        assert_eq!(
            serde_json::to_string(&PlatformType::None).unwrap(),
            "\"NONE\""
        );
    }
}
