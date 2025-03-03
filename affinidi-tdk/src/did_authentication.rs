/*!
 * Authentication services based on using the DID to authenticate with other services
 *
 * Step 1. Get the challenge from a authentication service
 * Step 2. Create a DIDComm message with the challenge in the body
 * Step 3. Sign and Encrypt the DIDComm message, send to the authentication service
 * Step 4. Receive the tokens from the authentication service
 */

use serde::{Deserialize, Serialize};
use tracing::{Level, debug, span};

use crate::errors::TDKError;

/// The challenge received in the first step of the DID authentication process
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct DidChallenge {
    /// Challenge string from the authentication service
    pub challenge: String,
}

/// The authorization tokens received in the fourth step of the DID authentication process
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct AuthorizationTokens {
    pub access_token: String,
    pub access_expires_at: Option<String>,
    pub refresh_token: String,
    pub refresh_expires_at: Option<String>,
}

// Where the bulk of the authentication logic is actually done
async fn _authenticate(client: &mut Client) -> Result<AuthorizationTokens, TDKError> {
    let _span = span!(Level::DEBUG, "authenticate",);
    async move {
        debug!("Retrieving authentication challenge...");

        let profile_did = "did:key:zQ3shX5rNyeLJXqiBoYq9UFGPpi8sSoBqB5VgDS1LA4CyFAZs";
        let mediator_did = "did:web:mediator-nlb.storm.ws:mediator:v1:.well-known";
        let mediator_endpoint =
            "https://ib8w1f44k7.execute-api.ap-southeast-1.amazonaws.com/dev/mpx/v1/authenticate";

        // Step 1. Get the challenge
        let step1_response = _http_post::<AdamChallenge>(
            &client,
            &[&mediator_endpoint, "/challenge"].concat(),
            &format!("{{\"did\": \"{}\"}}", profile_did).to_string(),
        )
        .await?;

        debug!("Challenge received:\n{:#?}", step1_response);

        // Step 2. Sign the challenge

        let auth_response =
            _create_auth_challenge_response(profile_did, mediator_did, &step1_response)?;
        debug!(
            "Auth response message:\n{}",
            serde_json::to_string_pretty(&auth_response).unwrap()
        );

        let (auth_msg, _) = atm
            .pack_encrypted(
                &auth_response,
                "did:web:meetingplace.world",
                Some(profile_did),
                Some(&profile_did),
            )
            .await?;

        debug!("Successfully packed auth message\n{:#?}", auth_msg);

        let step2_response = _http_post::<AuthorizationResponse>(
            &client,
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
    mediator_did: &str,
    body: &AdamChallenge,
) -> Result<Message, ATMError> {
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

async fn _http_post<T: GenericDataStruct>(
    client: &Client,
    url: &str,
    body: &str,
) -> Result<T, ATMError> {
    debug!("POSTing to {}", url);
    debug!("Body: {}", body);
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| ATMError::TransportError(format!("HTTP POST failed ({}): {:?}", url, e)))?;

    let response_status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))?;

    if !response_status.is_success() {
        if response_status.as_u16() == 401 {
            return Err(ATMError::ACLDenied("Authentication Denied".into()));
        } else {
            return Err(ATMError::AuthenticationError(format!(
                "Failed to get authentication response. url: {}, status: {}",
                url, response_status
            )));
        }
    }

    debug!("response body: {}", response_body);
    serde_json::from_str::<T>(&response_body).map_err(|e| {
        ATMError::AuthenticationError(format!("Couldn't deserialize AuthorizationResponse: {}", e))
    })
}

async fn _http_check(
    client: &Client,
    url: &str,
    body: &str,
    authorization: &str,
) -> Result<(), ATMError> {
    debug!("POSTing to {}", url);
    debug!("Body: {}", body);
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Authorization", ["Bearer ", authorization].concat())
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| ATMError::TransportError(format!("HTTP POST failed ({}): {:?}", url, e)))?;

    let response_status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))?;

    if !response_status.is_success() {
        if response_status.as_u16() == 401 {
            return Err(ATMError::ACLDenied("Authentication Denied".into()));
        } else {
            return Err(ATMError::AuthenticationError(format!(
                "Failed to get authentication response. url: {}, status: {}",
                url, response_status
            )));
        }
    }

    info!("response body: {}", response_body);
    Ok(())
}
