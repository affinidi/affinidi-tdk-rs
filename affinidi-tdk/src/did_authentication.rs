/*!
 * Authentication services based on using the DID to authenticate with other services
 *
 * Step 1. Get the challenge from a authentication service
 * Step 2. Create a DIDComm message with the challenge in the body
 * Step 3. Sign and Encrypt the DIDComm message, send to the authentication service
 * Step 4. Receive the tokens from the authentication service
 */

use std::time::SystemTime;
use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use affinidi_tdk_common::{
    errors::{Result, TDKError},
    profiles::TDKProfile,
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{Instrument, Level, debug, info, span};
use uuid::Uuid;
use crate::TDK;

/// The challenge received in the first step of the DID authentication process
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct DidChallenge {
    /// Challenge string from the authentication service
    pub challenge: String,
}

/// The authorization tokens received in the fourth step of the DID authentication process
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthorizationTokens {
    pub access_token: String,
    pub access_expires_at: Option<String>,
    pub refresh_token: String,
    pub refresh_expires_at: Option<String>,
}

impl TDK {
    /// Authenticate with the Affinidi services
    pub async fn authenticate(&mut self, profile: &TDKProfile, ) -> Result<AuthorizationTokens> {
        let _span = span!(Level::DEBUG, "authenticate",);
        async move {
            debug!("Retrieving authentication challenge...");
    
            let mediator_endpoint =
                "https://ib8w1f44k7.execute-api.ap-southeast-1.amazonaws.com/dev/mpx/v1/authenticate";
    
            // Step 1. Get the challenge
            let step1_response = _http_post::<DidChallenge>(
                &self.inner.client,
                &[mediator_endpoint, "/challenge"].concat(),
                &format!("{{\"did\": \"{}\"}}", profile.did).to_string(),
            )
            .await?;
    
            debug!("Challenge received:\n{:#?}", step1_response);
    
            // Step 2. Sign the challenge
    
            let auth_response =
                _create_auth_challenge_response(&profile.did,  &step1_response)?;
            debug!(
                "Auth response message:\n{}",
                serde_json::to_string_pretty(&auth_response).unwrap()
            );
    
            let (auth_msg, _) = auth_response.pack_encrypted("did:web:meetingplace.world", Some(&profile.did), Some(&profile.did), &self.inner.did_resolver, &self.inner.secrets_resolver, &PackEncryptedOptions::default()).await?;
    
            debug!("Successfully packed auth message\n{:#?}", auth_msg);
    
            let step2_response = _http_post::<AuthorizationTokens>(
                &self.inner.client,
                &[mediator_endpoint, ""].concat(),
                &json!({"challenge_response": BASE64_URL_SAFE_NO_PAD.encode(&auth_msg)}).to_string(),
            )
            .await?;
    
            debug!("Tokens received:\n{:#?}", step2_response);
    
            debug!("Successfully authenticated");
    
            Ok(step2_response.clone())
        }
        .instrument(_span)
        .await
    }
}

/// Creates an Affinidi Trusted Messaging Authentication Challenge Response Message
/// # Arguments
/// * `atm_did` - The DID for ATM
/// * `challenge` - The challenge that was sent
/// # Returns
/// A DIDComm message to be sent
///
/// Notes:
/// - This message will expire after 60 seconds
fn _create_auth_challenge_response(
    profile_did: &str,
    body: &DidChallenge,
) -> Result<Message> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Ok(Message::build(
        Uuid::new_v4().into(),
        "https://affinidi.com/atm/1.0/authenticate".to_owned(),
        json!({"challenge": body.challenge}),
    )
    .to("did:web:meetingplace.world".to_string())
    .from(profile_did.to_owned())
    .created_time(now)
    .expires_time(now + 60)
    .finalize())
}

async fn _http_post<T>(client: &Client, url: &str, body: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    debug!("POSTing to {}", url);
    debug!("Body: {}", body);
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| TDKError::Authentication(format!("HTTP POST failed ({}): {:?}", url, e)))?;

    let response_status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| TDKError::Authentication(format!("Couldn't get HTTP body: {:?}", e)))?;

    if !response_status.is_success() {
        if response_status.as_u16() == 401 {
            return Err(TDKError::PermissionDenied("Authentication Denied".into()));
        } else {
            return Err(TDKError::Authentication(format!(
                "Failed to get authentication response. url: {}, status: {}",
                url, response_status
            )));
        }
    }

    debug!("response body: {}", response_body);
    serde_json::from_str::<T>(&response_body).map_err(|e| {
        TDKError::Authentication(format!("Couldn't deserialize AuthorizationResponse: {}", e))
    })
}

async fn _http_check(client: &Client, url: &str, body: &str, authorization: &str) -> Result<()> {
    debug!("POSTing to {}", url);
    debug!("Body: {}", body);
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Authorization", ["Bearer ", authorization].concat())
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| TDKError::Authentication(format!("HTTP POST failed ({}): {:?}", url, e)))?;

    let response_status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| TDKError::Authentication(format!("Couldn't get HTTP body: {:?}", e)))?;

    if !response_status.is_success() {
        if response_status.as_u16() == 401 {
            return Err(TDKError::PermissionDenied("Authentication Denied".into()));
        } else {
            return Err(TDKError::Authentication(format!(
                "Failed to get authentication response. url: {}, status: {}",
                url, response_status
            )));
        }
    }

    info!("response body: {}", response_body);
    Ok(())
}
