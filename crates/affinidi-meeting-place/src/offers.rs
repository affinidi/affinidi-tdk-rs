/*!
 * Handles the creation of offers
 */

use crate::{
    _http_post, MeetingPlace,
    errors::{MeetingPlaceError, Result},
    find_mediator_service_endpoints,
    vcard::Vcard,
};
use affinidi_messaging_didcomm::Message;
use affinidi_tdk_common::{TDKSharedState, profiles::TDKProfile};
use base64::prelude::*;
use chrono::{Local, TimeDelta};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{str::FromStr, time::Duration};
use tracing::debug;
use uuid::Uuid;

/// Top-level Meeting Place struct for an Offer
#[derive(Debug)]
pub struct Offer {
    pub status: String,
    /// DIDComm message
    pub message: Option<String>,
    pub offer_link: Option<String>,
    pub valid_until: Option<String>,
    pub registration: Option<RegisterOffer>,
    pub mnemonic: Option<String>,
}

/// Register an offer with Meeting Place
/// https://gitlab.com/affinidi/octo/larter/affinidi-meeting-place/api-meetingplace#post-register-offer
#[derive(Debug, Serialize)]
pub struct RegisterOffer {
    /// Name of the offer that will be displayed to acceptors in their UI
    #[serde(rename = "offerName")]
    name: String,

    /// Description of the offer that will be displayed to potential acceptors
    #[serde(rename = "offerDescription")]
    description: String,

    /// Base64 encoded DIDComm plaintext message containing the invitation
    #[serde(rename = "didcommMessage")]
    didcomm_message: String,

    /// Base64 encoded vCard containing the offerer's contact details
    #[serde(rename = "vcard")]
    vcard: String,

    /// ISO-8601 formatted date/time when the offer expires (e.g., "2024-12-31T23:59:59Z")
    /// If this field is an empty string, the system's maximum expiry date will be set
    #[serde(rename = "validUntil")]
    valid_until: String,

    /// Maximum number of times this offer can be accepted
    /// (0 for maximum number of claims as determined by the system)
    #[serde(rename = "maximumUsage")]
    maximum_usage: usize,

    /// Token received from the device's push notification API/SDK
    #[serde(rename = "deviceToken")]
    device_token: String,

    /// Push notification platform type ("APNS", "APNS_SANDBOX", "FCM",
    /// or "NONE" if push notifications are not supported on the offerer's platform)
    #[serde(rename = "platformType")]
    platform_type: PlatformType,

    /// HTTP(S) endpoint of the DIDComm mediator service for this offer
    #[serde(rename = "mediatorEndpoint")]
    mediator_endpoint: String,

    /// DID of the DIDComm mediator service for this offer
    #[serde(rename = "mediatorDid")]
    mediator_did: String,

    /// WebSocket(S) endpoint of the DIDComm mediator service to be used for this offer
    #[serde(rename = "mediatorWSSEndpoint")]
    mediator_websocket_endpoint: String,

    /// Optional custom phrase to identify this offer (must be unique if provided)
    /// If none is provided, the system will generate a phrase
    #[serde(rename = "customPhrase")]
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_phrase: Option<String>,

    /// Bitfield representing various contact attributes for the offer.
    /// Currently, the API does not enforce nor validate these bits, instead, it is left to the client application to make use/sense of them.
    /// Meeting Place mobile application currently defines the following bits:
    ///   Unknown: 0
    ///   Person: 1
    ///   Adult: 2
    ///   Robot: 4
    ///   Service: 8
    ///   Organisation: 16
    ///
    ///  NOTE: These are subject to change and in future versions, the bitfield may be enforced by the API
    #[serde(rename = "contactAttributes")]
    contact_attributes: u32,
}

#[derive(Clone, Debug, Serialize)]
pub enum PlatformType {
    APNS,
    #[allow(non_camel_case_types)]
    APNS_SANDBOX,
    FCM,
    NONE,
}

impl FromStr for PlatformType {
    type Err = MeetingPlaceError;

    fn from_str(platform_type: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match platform_type.to_uppercase().as_str() {
            "APNS" => PlatformType::APNS,
            "APNS_SANDBOX" => PlatformType::APNS_SANDBOX,
            "FCM" => PlatformType::FCM,
            _ => PlatformType::NONE,
        })
    }
}

/// Used within MeetingPlace to represent the type of contact
/// Subject to change...
#[derive(Clone, Serialize)]
pub enum ContactAttributeType {
    Unknown,
    Person,
    Adult,
    Robot,
    Service,
    Organisation,
}

impl ContactAttributeType {
    pub fn to_u32(&self) -> u32 {
        match self {
            ContactAttributeType::Unknown => 0,
            ContactAttributeType::Person => 1,
            ContactAttributeType::Adult => 2,
            ContactAttributeType::Robot => 4,
            ContactAttributeType::Service => 8,
            ContactAttributeType::Organisation => 16,
        }
    }

    pub fn from_u32(contact_type: u32) -> Self {
        match contact_type {
            0 => ContactAttributeType::Unknown,
            1 => ContactAttributeType::Person,
            2 => ContactAttributeType::Adult,
            4 => ContactAttributeType::Robot,
            8 => ContactAttributeType::Service,
            16 => ContactAttributeType::Organisation,
            _ => ContactAttributeType::Unknown,
        }
    }
}

/// Builder for RegisterOffer
pub struct RegisterOfferBuilder {
    name: String,
    description: String,
    didcomm_message: Option<String>,
    vcard: Vcard,
    valid_until: Duration,
    maximum_usage: usize,
    device_token: String,
    platform_type: PlatformType,
    mediator_did: String,
    custom_phrase: Option<String>,
    contact_attributes: u32,
}

impl Default for RegisterOfferBuilder {
    fn default() -> Self {
        RegisterOfferBuilder {
            name: "Connect with Affinidi!".to_string(),
            description: "If you have the passphrase you can connect via Meeting Place!"
                .to_string(),
            didcomm_message: None,
            vcard: Vcard::default(),
            valid_until: Duration::default(),
            maximum_usage: 0,
            device_token: "NO_TOKEN".to_string(),
            platform_type: PlatformType::NONE,
            mediator_did: "".to_string(),
            custom_phrase: None,
            contact_attributes: ContactAttributeType::Unknown.to_u32(),
        }
    }
}

impl RegisterOfferBuilder {
    /// Set a Vcard for the offer
    pub fn vcard(&mut self, vcard: Vcard) -> &mut Self {
        self.vcard = vcard;
        self
    }

    /// When is this offer valid until?
    /// Defaults: 0 which is for as long as Meeting Place will allow
    pub fn valid_until(&mut self, valid_until: Duration) -> &mut Self {
        self.valid_until = valid_until;
        self
    }

    /// Maximum number of times this offer can be accepted
    /// (0 for maximum number of claims as determined by the system)
    pub fn maximum_usage(&mut self, maximum_usage: usize) -> &mut Self {
        self.maximum_usage = maximum_usage;
        self
    }

    /// Token received from the device's push notification API/SDK
    /// Defaults to `NO_TOKEN`
    pub fn device_token(&mut self, device_token: &str) -> &mut Self {
        self.device_token = device_token.to_string();
        self
    }

    /// Push notification platform type
    /// Defaults to `NONE`
    pub fn platform_type(&mut self, platform_type: PlatformType) -> &mut Self {
        self.platform_type = platform_type;
        self
    }

    /// Optional custom phrase to identify this offer
    pub fn custom_phrase(&mut self, custom_phrase: &str) -> &mut Self {
        self.custom_phrase = Some(custom_phrase.to_string());
        self
    }

    /// Bitfield representing various contact attributes for the offer.
    /// Defaults to `Unknown`
    pub fn contact_attributes(&mut self, contact_attributes: ContactAttributeType) -> &mut Self {
        self.contact_attributes = contact_attributes.to_u32();
        self
    }

    /// Build the RegisterOffer
    pub async fn build(&self, tdk: &TDKSharedState) -> Result<RegisterOffer> {
        let didcomm_message = if let Some(didcomm_message) = &self.didcomm_message {
            didcomm_message.clone()
        } else {
            return Err(MeetingPlaceError::Error(
                "No DIDComm message provided".to_string(),
            ));
        };

        let valid_until = if self.valid_until.as_secs() == 0 {
            "".to_string()
        } else {
            let now = Local::now();
            let delta =
                if let Some(delta) = TimeDelta::try_seconds(self.valid_until.as_secs() as i64) {
                    delta
                } else {
                    return Err(MeetingPlaceError::Error(
                        "Invalid duration provided for valid_until".to_string(),
                    ));
                };
            (now + delta).to_rfc3339()
        };

        let mediator_doc = tdk.did_resolver.resolve(&self.mediator_did).await?;
        let uris = find_mediator_service_endpoints(&mediator_doc.doc);

        let (mediator_endpoint, mediator_websocket_endpoint) = if uris.len() != 2 {
            return Err(MeetingPlaceError::Error(
                "Mediator DID must have 2 service endpoints".to_string(),
            ));
        } else {
            let mediator_endpoint: String = if let Some(uri) = uris
                .iter()
                .filter_map(|e| {
                    debug!("URI: {}", e);
                    if e.starts_with("http") {
                        debug!("Matched");
                        Some(e.to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<String>>()
                .first()
            {
                uri.clone()
            } else {
                return Err(MeetingPlaceError::Error(
                    "Mediator DID must have an HTTP service endpoint".to_string(),
                ));
            };
            let mediator_websocket_endpoint: String = if let Some(uri) = uris
                .iter()
                .filter_map(|e| {
                    if e.starts_with("ws") {
                        Some(e.to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<String>>()
                .first()
            {
                uri.clone()
            } else {
                return Err(MeetingPlaceError::Error(
                    "Mediator DID must have an WebSocket service endpoint".to_string(),
                ));
            };
            (mediator_endpoint, mediator_websocket_endpoint)
        };

        Ok(RegisterOffer {
            name: self.name.clone(),
            description: self.description.clone(),
            didcomm_message,
            vcard: self.vcard.to_base64()?,
            valid_until,
            maximum_usage: self.maximum_usage,
            device_token: self.device_token.clone(),
            platform_type: self.platform_type.clone(),
            mediator_endpoint,
            mediator_did: self.mediator_did.clone(),
            mediator_websocket_endpoint,
            custom_phrase: self.custom_phrase.clone(),
            contact_attributes: self.contact_attributes,
        })
    }
}

impl RegisterOffer {
    /// Creates a new RegisterOfferBuilder, you can further customize the object using the builder methods
    /// Finalize with the `build()` method
    pub fn create(
        name: &str,
        description: &str,
        from_did: &str,
        mediator_did: &str,
    ) -> Result<RegisterOfferBuilder> {
        let didcomm_message = Offer::create_offer_oob_message(from_did)?;

        Ok(RegisterOfferBuilder {
            name: name.to_string(),
            didcomm_message: Some(didcomm_message),
            description: description.to_string(),
            mediator_did: mediator_did.to_string(),
            ..Default::default()
        })
    }
}

/// Query an offer from Meeting Place
/// https://gitlab.com/affinidi/octo/larter/affinidi-meeting-place/api-meetingplace#post-query-offer
#[derive(Serialize)]
pub struct QueryOffer {
    mnemonic: String,
    did: String,
}

/// Query an offer from Meeting Place
/// https://gitlab.com/affinidi/octo/larter/affinidi-meeting-place/api-meetingplace#post-deregister-offer
#[derive(Serialize)]
pub struct DeregisteryOffer {
    mnemonic: String,
    #[serde(rename = "offerLink")]
    offer_link: String,
}

impl Offer {
    /// Create an Offer from a RegisterOffer
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

    /// Register an offer with Meeting Place
    /// Use the RegisterOffer::create() method to create the registration object
    pub async fn register_offer(
        &mut self,
        mp: &MeetingPlace,
        tdk: &TDKSharedState,
        profile: &TDKProfile,
    ) -> Result<RegisterOfferResponse> {
        let Some(registration) = &self.registration else {
            return Err(MeetingPlaceError::Error(
                "there is no offer registration record!".to_string(),
            ));
        };

        let tokens = tdk
            .authentication
            .authenticate(profile.did.to_string(), mp.mp_did.to_string(), 3, None)
            .await?;

        let response = _http_post::<RegisterOfferResponse>(
            &tdk.client,
            &[&mp.mp_api, "/register-offer"].concat(),
            &serde_json::to_string(registration).map_err(|e| {
                MeetingPlaceError::Serialization(format!(
                    "Couldn't serialize register offer request: {e}"
                ))
            })?,
            &tokens,
        )
        .await?;

        self.mnemonic = Some(response.mnemonic.clone());
        self.offer_link = Some(response.offer_link.clone());
        self.valid_until = Some(response.valid_until.clone());
        self.status = "REGISTERED".to_string();
        Ok(response)
    }

    /// Creates the DIDComm OOB Invitation message for the offer
    /// Returns base64 encoded message
    pub fn create_offer_oob_message(from_did: &str) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let msg = Message::build(
            id.clone(),
            "https://didcomm.org/out-of-band/2.0/invitation".to_string(),
            json!({"goal_code": "connect", "goal": "Start relationship", "accept": [ "didcomm/v2"]}),
        ).from(from_did.to_string())
        .thid(id.clone())
        .finalize();

        Ok(
            BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(&msg).map_err(|e| {
                MeetingPlaceError::Serialization(format!(
                    "Couldn't serialize DIDcomm offer message: {e}"
                ))
            })?),
        )
    }

    /// Query Meeting Place for an offer
    pub async fn query_offer(
        mp: &MeetingPlace,
        tdk: &TDKSharedState,
        profile: &TDKProfile,
        offer_phrase: &str,
    ) -> Result<Offer> {
        let tokens = tdk
            .authentication
            .authenticate(profile.did.to_string(), mp.mp_did.to_string(), 3, None)
            .await?;

        let response = _http_post::<QueryOfferResponse>(
            &tdk.client,
            &[&mp.mp_api, "/query-offer"].concat(),
            &serde_json::to_string(&QueryOffer {
                mnemonic: offer_phrase.to_string(),
                did: profile.did.to_string(),
            })
            .map_err(|e| {
                MeetingPlaceError::Serialization(format!(
                    "Couldn't serialize register offer request: {e}"
                ))
            })?,
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

    /// Deregister (remove) an offer from Meeting Place
    pub async fn deregister_offer(
        &mut self,
        mp: &MeetingPlace,
        tdk: &TDKSharedState,
        profile: &TDKProfile,
    ) -> Result<DeregisterOfferResponse> {
        let tokens = tdk
            .authentication
            .authenticate(profile.did.to_string(), mp.mp_did.to_string(), 3, None)
            .await?;

        let mnemonic = if let Some(mnemonic) = &self.mnemonic {
            mnemonic.to_string()
        } else {
            return Err(MeetingPlaceError::Error(
                "No mnemonic provided for deregistering offer".to_string(),
            ));
        };

        let offer_link = if let Some(offer_link) = &self.offer_link {
            offer_link.to_string()
        } else {
            return Err(MeetingPlaceError::Error(
                "No offer_link provided for deregistering offer".to_string(),
            ));
        };

        let response = _http_post::<DeregisterOfferResponse>(
            &tdk.client,
            &[&mp.mp_api, "/deregister-offer"].concat(),
            &serde_json::to_string(&DeregisteryOffer {
                mnemonic,
                offer_link,
            })
            .map_err(|e| {
                MeetingPlaceError::Serialization(format!(
                    "Couldn't serialize register offer request: {e}"
                ))
            })?,
            &tokens,
        )
        .await?;

        Ok(response)
    }
}

// ************************************************************************************************

/// The return value from the register-offer phrase API
/// Need to retain the mnemonic and offer_link for other calls
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

/// The return value from the query-offer API
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

/// The return value from the deregister-offer API
#[derive(Debug, Deserialize)]
pub struct DeregisterOfferResponse {
    pub status: String,
    pub message: String,
}
