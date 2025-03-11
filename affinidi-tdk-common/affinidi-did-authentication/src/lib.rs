/*!
 * Authentication services based on using the DID to authenticate with other services
 *
 * Step 1. Get the challenge from a authentication service
 * Step 2. Create a DIDComm message with the challenge in the body
 * Step 3. Sign and Encrypt the DIDComm message, send to the authentication service
 * Step 4. Receive the tokens from the authentication service
 *
 * NOTE: This library currently supports two different implementations of DID Auth
 * 1. Affinidi Messaging
 * 2. MeetingPlace
 *
 * This needs to be refactored in the future when the services align on implementation
 */

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use affinidi_tdk_common::{
    TDKSharedState,
    environments::TDKProfile,
    errors::{Result, TDKError},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::DateTime;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssi::dids::{Document, document::service::Endpoint};
use std::time::SystemTime;
use tracing::{Instrument, Level, debug, error, info, span};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
enum DidChallenge {
    /// Affinidi Messaging Challenge
    Complex(ComplexDidChallenge),

    /// Affinidi MeetingPlace Challenge
    Simple(SimpleDidChallenge),
}

impl DidChallenge {
    pub fn challenge(&self) -> &str {
        match self {
            DidChallenge::Simple(s) => &s.challenge,
            DidChallenge::Complex(c) => &c.data.challenge,
        }
    }
}

/// Challenge received from MeetingPlace, flattened structure
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct SimpleDidChallenge {
    /// Challenge string from the authentication service
    pub challenge: String,
}

/// Challenge received from Affinidi Messaging, it is a nested structure
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct ComplexDidChallenge {
    #[serde(alias = "sessionId")]
    pub session_id: String,
    pub data: SimpleDidChallenge,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
enum TokensType {
    AffinidiMessaging(ComplexAuthorizationTokens),
    MeetingPlace(MPAuthorizationTokens),
}

impl TokensType {
    pub fn tokens(&self) -> Result<AuthorizationTokens> {
        match self {
            TokensType::AffinidiMessaging(c) => Ok(c.data.clone()),
            TokensType::MeetingPlace(m) => {
                let tokens = AuthorizationTokens {
                    access_token: m.access_token.clone(),
                    access_expires_at: DateTime::parse_from_rfc3339(&m.access_expires_at)
                        .map_err(|err| {
                            TDKError::Authentication(format!(
                                "Invalid access_expires_at timestamp ({}): {}",
                                m.access_expires_at, err
                            ))
                        })?
                        .timestamp() as u64,
                    refresh_token: m.refresh_token.clone(),
                    refresh_expires_at: DateTime::parse_from_rfc3339(&m.refresh_expires_at)
                        .map_err(|err| {
                            TDKError::Authentication(format!(
                                "Invalid refresh_expires_at timestamp ({}): {}",
                                m.access_expires_at, err
                            ))
                        })?
                        .timestamp() as u64,
                };
                Ok(tokens)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct ComplexAuthorizationTokens {
    #[serde(alias = "sessionId")]
    pub session_id: String,
    pub data: AuthorizationTokens,
}

/// The authorization tokens received in the fourth step of the DID authentication process
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct MPAuthorizationTokens {
    pub access_token: String,
    pub access_expires_at: String,
    pub refresh_token: String,
    pub refresh_expires_at: String,
}

/// The authorization tokens received in the fourth step of the DID authentication process
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthorizationTokens {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}

/// The DID Authentication struct
pub struct DIDAuthentication {
    /// Authorization tokens received from the authentication service
    pub tokens: Option<AuthorizationTokens>,

    /// true if authenticated, false otherwise
    pub authenticated: bool,

    /// The endpoint DID to authenticate with
    pub endpoint_did: String,
}

impl DIDAuthentication {
    pub fn new(endpoint: &str) -> Self {
        Self {
            tokens: None,
            authenticated: false,
            endpoint_did: endpoint.to_string(),
        }
    }

    /// Find the [serviceEndpoint](https://www.w3.org/TR/did-1.0/#services) with type `Authentication` from a DID Document
    /// # Arguments
    /// * `doc` - The DID Document to search
    ///
    /// # Returns
    /// URI of the service endpoint if it exists
    pub fn find_service_endpoint(doc: &Document) -> Option<String> {
        if let Some(service) = doc.service("auth") {
            if let Some(endpoint) = &service.service_endpoint {
                if let Some(Endpoint::Uri(e)) = endpoint.first() {
                    debug!("Found service endpoint: {:?}", endpoint);
                    Some(e.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Authenticate with the Affinidi services
    /// This will retry authentication if it fails
    /// If already authenticated, short-circuits and returns immediately
    ///
    /// # Arguments
    /// * `state` - The TDKSharedState to use for authentication
    /// * `profile` - The TDKProfile to use for authentication
    /// * `retry_limit` - The number of times to retry authentication (-1 = unlimited)
    ///
    /// # Returns
    /// Ok if successful, Err if failed
    /// AuthorizationTokens are contained in self
    pub async fn authenticate(
        &mut self,
        state: &TDKSharedState,
        profile: &TDKProfile,
        retry_limit: i32,
    ) -> Result<()> {
        let mut retry_count = 0;
        let mut timer = 1;
        loop {
            match self._authenticate(state, profile).await {
                Ok(_) => {
                    return Ok(());
                }
                Err(TDKError::ACLDenied(err)) => {
                    return Err(TDKError::ACLDenied(err));
                }
                Err(err) => {
                    retry_count += 1;
                    if retry_limit != -1 && retry_count >= retry_limit {
                        return Err(TDKError::AuthenticationAbort(
                            "Maximum number of authentication retries reached".into(),
                        ));
                    }

                    error!(
                        "Profile ({}): Attempt #{}. Error authenticating: {:?} :: Sleeping for ({}) seconds",
                        profile.alias, retry_count, err, timer
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(timer)).await;
                    if timer < 10 {
                        timer += 1;
                    }
                }
            }
        }
    }

    async fn _authenticate(&mut self, state: &TDKSharedState, profile: &TDKProfile) -> Result<()> {
        let _span = span!(Level::DEBUG, "authenticate",);
        async move {
            let endpoint = self
                ._get_endpoint_address(state.did_resolver.clone())
                .await?;

            debug!("Retrieving authentication challenge...");

            // Step 1. Get the challenge
            let step1_response = _http_post::<DidChallenge>(
                &state.client,
                &[&endpoint, "/challenge"].concat(),
                &format!("{{\"did\": \"{}\"}}", profile.did).to_string(),
            )
            .await?;

            debug!("Challenge received:\n{:#?}", step1_response);

            // Step 2. Sign the challenge

            let auth_response =
                _create_auth_challenge_response(&self.endpoint_did, &profile.did, &step1_response)?;
            debug!(
                "Auth response message:\n{}",
                serde_json::to_string_pretty(&auth_response).unwrap()
            );

            let (auth_msg, _) = auth_response
                .pack_encrypted(
                    &self.endpoint_did,
                    Some(&profile.did),
                    Some(&profile.did),
                    &state.did_resolver,
                    &state.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await?;

            debug!("Successfully packed auth message\n{:#?}", auth_msg);

            let step2_body = if let DidChallenge::Complex(_) = step1_response {
                auth_msg
            } else {
                json!({"challenge_response":
                    BASE64_URL_SAFE_NO_PAD.encode(&auth_msg)
                })
                .to_string()
            };

            let step2_response =
                _http_post::<TokensType>(&state.client, &[&endpoint, ""].concat(), &step2_body)
                    .await?;

            debug!("Tokens received:\n{:#?}", step2_response);

            debug!("Successfully authenticated");

            self.authenticated = true;
            self.tokens = Some(step2_response.tokens()?);
            Ok(())
        }
        .instrument(_span)
        .await
    }

    /// Helper function to get the right endpoint address
    /// Returns the endpoint if it's a URL, or resolves the DID to get the endpoint
    /// # Returns
    /// The endpoint address or a AuthenticationAbort error (hard abort)
    async fn _get_endpoint_address(&self, did_resolver: DIDCacheClient) -> Result<String> {
        if self.endpoint_did.starts_with("did:") {
            let doc = did_resolver.resolve(&self.endpoint_did).await?;
            if let Some(endpoint) = DIDAuthentication::find_service_endpoint(&doc.doc) {
                Ok(endpoint)
            } else {
                Err(TDKError::AuthenticationAbort(
                    "No service endpoint found".into(),
                ))
            }
        } else {
            Ok(self.endpoint_did.clone())
        }
    }
}

/// Creates an Affinidi Trusted Messaging Authentication Challenge Response Message
/// # Arguments
/// * `to_did` - Destination for the DID
/// * `from_did` - The DID that is being authenticated
/// * `body` - The challenge body
/// # Returns
/// A DIDComm message to be sent
///
/// Notes:
/// - This message will expire after 60 seconds
fn _create_auth_challenge_response(
    to_did: &str,
    from_did: &str,
    body: &DidChallenge,
) -> Result<Message> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let body = if let DidChallenge::Complex(c) = body {
        json!({"challenge": c.data.challenge, "session_id": c.session_id})
    } else {
        json!({"challenge": body.challenge()})
    };

    Ok(Message::build(
        Uuid::new_v4().into(),
        "https://affinidi.com/atm/1.0/authenticate".to_owned(),
        body,
    )
    .to(to_did.to_string())
    .from(from_did.to_owned())
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
