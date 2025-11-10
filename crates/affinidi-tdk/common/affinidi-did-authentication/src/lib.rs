/*!
 * DID Authentication Library
 *
 * **DID Authentication steps:**
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

use affinidi_did_common::Document;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use affinidi_secrets_resolver::SecretsResolver;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::DateTime;
use errors::{DIDAuthError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::SystemTime;
use tracing::{Instrument, Level, debug, error, info, span};
use uuid::Uuid;

pub mod errors;

/// The authorization tokens received in the fourth step of the DID authentication process
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthorizationTokens {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
enum DidChallenges {
    /// Affinidi Messaging Challenge
    Complex(HTTPResponse<DidChallenge>),

    /// Affinidi MeetingPlace Challenge
    Simple(DidChallenge),
}

impl DidChallenges {
    pub fn challenge(&self) -> &str {
        match self {
            DidChallenges::Simple(s) => &s.challenge,
            DidChallenges::Complex(c) => &c.data.challenge,
        }
    }
}

/// Authentication Challenge
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct DidChallenge {
    /// Challenge string from the authentication service
    pub challenge: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
enum TokensType {
    AffinidiMessaging(HTTPResponse<AuthorizationTokens>),
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
                            DIDAuthError::Authentication(format!(
                                "Invalid access_expires_at timestamp ({}): {}",
                                m.access_expires_at, err
                            ))
                        })?
                        .timestamp() as u64,
                    refresh_token: m.refresh_token.clone(),
                    refresh_expires_at: DateTime::parse_from_rfc3339(&m.refresh_expires_at)
                        .map_err(|err| {
                            DIDAuthError::Authentication(format!(
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

#[derive(Serialize, Deserialize, Debug, Clone)]
struct HTTPResponse<T> {
    #[serde(alias = "sessionId")]
    pub session_id: String,
    pub data: T,
}

/// The authorization tokens received in the fourth step of the DID authentication process
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct MPAuthorizationTokens {
    pub access_token: String,
    pub access_expires_at: String,
    pub refresh_token: String,
    pub refresh_expires_at: String,
}

/// Refresh tokens response from the authentication service
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthRefreshResponse {
    pub access_token: String,
    pub access_expires_at: u64,
}

#[derive(Clone, Debug)]
pub enum AuthenticationType {
    AffinidiMessaging,
    MeetingPlace,
    Unknown,
}

impl AuthenticationType {
    fn is_affinidi_messaging(&self) -> bool {
        matches!(self, AuthenticationType::AffinidiMessaging)
    }
}

/// The DID Authentication struct
#[derive(Clone, Debug)]
pub struct DIDAuthentication {
    /// There are two different DID authentication methods that need to be supported for now
    /// Set to true if
    pub type_: AuthenticationType,

    /// Authorization tokens received from the authentication service
    pub tokens: Option<AuthorizationTokens>,

    /// true if authenticated, false otherwise
    pub authenticated: bool,
}

impl Default for DIDAuthentication {
    fn default() -> Self {
        Self {
            type_: AuthenticationType::Unknown,
            tokens: None,
            authenticated: false,
        }
    }
}

impl DIDAuthentication {
    pub fn new() -> Self {
        Self::default()
    }

    /// Find the [serviceEndpoint](https://www.w3.org/TR/did-1.0/#services) with type `Authentication` from a DID Document
    /// # Arguments
    /// * `doc` - The DID Document to search
    ///
    /// # Returns
    /// URI of the service endpoint if it exists
    pub fn find_service_endpoint(doc: &Document) -> Option<String> {
        if let Some(service) = doc.service.iter().find(|s| {
            if let Some(id) = &s.id {
                id.as_str().ends_with("#auth")
            } else {
                false
            }
        }) {
            service.service_endpoint.get_uri()
        } else {
            None
        }
    }

    /// Authenticate with the Affinidi services
    /// This will retry authentication if it fails
    /// If already authenticated, short-circuits and returns immediately
    ///
    /// # Arguments
    /// * `profile_did` - The DID of the profile to authenticate
    /// * `endpoint_did` - The DID of the service endpoint to authenticate against
    /// * `did_resolver` - The DID Resolver Cache Client
    /// * `secrets_resolver` - The Secrets Resolver
    /// * `client` - The HTTP Client to use for requests
    /// * `retry_limit` - The number of times to retry authentication (-1 = unlimited)
    ///
    /// # Returns
    /// Ok if successful, Err if failed
    /// AuthorizationTokens are contained in self
    pub async fn authenticate<S>(
        &mut self,
        profile_did: &str,
        endpoint_did: &str,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &S,
        client: &Client,
        retry_limit: i32,
    ) -> Result<()>
    where
        S: SecretsResolver,
    {
        let mut retry_count = 0;
        let mut timer = 1;
        loop {
            match self
                ._authenticate(
                    profile_did,
                    endpoint_did,
                    did_resolver,
                    secrets_resolver,
                    client,
                )
                .await
            {
                Ok(_) => {
                    return Ok(());
                }
                Err(DIDAuthError::ACLDenied(err)) => {
                    return Err(DIDAuthError::ACLDenied(err));
                }
                Err(err) => {
                    retry_count += 1;
                    if retry_limit != -1 && retry_count >= retry_limit {
                        return Err(DIDAuthError::AuthenticationAbort(
                            "Maximum number of authentication retries reached".into(),
                        ));
                    }

                    error!(
                        "DID ({}): Attempt #{}. Error authenticating: {:?} :: Sleeping for ({}) seconds",
                        profile_did, retry_count, err, timer
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(timer)).await;
                    if timer < 10 {
                        timer += 1;
                    }
                }
            }
        }
    }

    async fn _authenticate<S>(
        &mut self,
        profile_did: &str,
        endpoint_did: &str,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &S,
        client: &Client,
    ) -> Result<()>
    where
        S: SecretsResolver,
    {
        let _span = span!(Level::DEBUG, "authenticate",);
        async move {
            if self.authenticated && self.type_.is_affinidi_messaging() {
                // Check if we need to refresh the token
                match self
                    ._refresh_authentication(
                        profile_did,
                        endpoint_did,
                        did_resolver,
                        secrets_resolver,
                        client,
                    )
                    .await
                {
                    Ok(_) => {
                        return Ok(());
                    }
                    Err(err) => {
                        error!("Error refreshing token: {:?}", err);
                        info!("Attempting to re-authenticate");
                    }
                }
            }

            let endpoint = self
                ._get_endpoint_address(endpoint_did, did_resolver)
                .await?;

            debug!("Retrieving authentication challenge...");

            // Step 1. Get the challenge
            let step1_response = _http_post::<DidChallenges>(
                client,
                &[&endpoint, "/challenge"].concat(),
                &format!("{{\"did\": \"{profile_did}\"}}").to_string(),
            )
            .await?;

            match step1_response {
                DidChallenges::Simple(_) => {
                    self.type_ = AuthenticationType::MeetingPlace;
                }
                DidChallenges::Complex(_) => {
                    self.type_ = AuthenticationType::AffinidiMessaging;
                }
            }

            debug!("Challenge received:\n{:#?}", step1_response);

            // Step 2. Sign the challenge

            let auth_response =
                self._create_auth_challenge_response(profile_did, endpoint_did, &step1_response)?;
            debug!(
                "Auth response message:\n{}",
                serde_json::to_string_pretty(&auth_response).unwrap()
            );

            let (auth_msg, _) = auth_response
                .pack_encrypted(
                    endpoint_did,
                    Some(profile_did),
                    Some(profile_did),
                    did_resolver,
                    secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await?;

            debug!("Successfully packed auth message\n{:#?}", auth_msg);

            let step2_body = if let DidChallenges::Complex(_) = step1_response {
                auth_msg
            } else {
                json!({"challenge_response":
                    BASE64_URL_SAFE_NO_PAD.encode(&auth_msg)
                })
                .to_string()
            };

            let step2_response =
                _http_post::<TokensType>(client, &[&endpoint, ""].concat(), &step2_body).await?;

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
    async fn _get_endpoint_address(
        &self,
        endpoint_did: &str,
        did_resolver: &DIDCacheClient,
    ) -> Result<String> {
        if endpoint_did.starts_with("did:") {
            let doc = did_resolver.resolve(endpoint_did).await?;
            if let Some(endpoint) = DIDAuthentication::find_service_endpoint(&doc.doc) {
                Ok(endpoint)
            } else {
                Err(DIDAuthError::AuthenticationAbort(
                    "No service endpoint found. DID doesn't contain a #auth service".into(),
                ))
            }
        } else {
            Ok(endpoint_did.to_string())
        }
    }

    /// Refresh the JWT access token
    /// # Arguments
    ///   * `refresh_token` - The refresh token to be used
    /// # Returns
    /// A packed DIDComm message to be sent
    async fn _create_refresh_request<S>(
        &self,
        profile_did: &str,
        endpoint_did: &str,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &S,
    ) -> Result<String>
    where
        S: SecretsResolver,
    {
        let refresh_token = if let Some(tokens) = &self.tokens {
            &tokens.refresh_token
        } else {
            return Err(DIDAuthError::Authentication(
                "No tokens found to refresh".to_owned(),
            ));
        };

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let refresh_message = Message::build(
            Uuid::new_v4().into(),
            "https://affinidi.com/atm/1.0/authenticate/refresh".to_string(),
            json!({"refresh_token": refresh_token}),
        )
        .to(endpoint_did.to_string())
        .from(profile_did.to_owned())
        .created_time(now)
        .expires_time(now + 60)
        .finalize();

        match refresh_message
            .pack_encrypted(
                endpoint_did,
                Some(profile_did),
                Some(profile_did),
                did_resolver,
                secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
        {
            Ok((refresh_msg, _)) => Ok(refresh_msg),
            Err(err) => Err(DIDAuthError::Authentication(format!(
                "Couldn't pack authentication refresh message: {err:?}"
            ))),
        }
    }

    /// Refresh the access tokens as required
    async fn _refresh_authentication<S>(
        &mut self,
        profile_did: &str,
        endpoint_did: &str,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &S,
        client: &Client,
    ) -> Result<()>
    where
        S: SecretsResolver,
    {
        let Some(tokens) = &self.tokens else {
            return Err(DIDAuthError::Authentication(
                "No tokens found to refresh".to_owned(),
            ));
        };

        match refresh_check(tokens) {
            RefreshCheck::Ok => {
                // Tokens are valid, do not need to refresh
                Ok(())
            }
            RefreshCheck::Refresh => {
                // Access token has expired, refresh it
                debug!("Refreshing tokens");
                let refresh_msg = self
                    ._create_refresh_request(
                        profile_did,
                        endpoint_did,
                        did_resolver,
                        secrets_resolver,
                    )
                    .await?;

                let endpoint = self
                    ._get_endpoint_address(endpoint_did, did_resolver)
                    .await?;

                let new_tokens = _http_post::<HTTPResponse<AuthRefreshResponse>>(
                    client,
                    &[&endpoint, "/refresh"].concat(),
                    &refresh_msg,
                )
                .await?;

                let Some(tokens) = &mut self.tokens else {
                    return Err(DIDAuthError::Authentication(
                        "No tokens found to refresh".to_owned(),
                    ));
                };

                tokens.access_token = new_tokens.data.access_token;
                tokens.access_expires_at = new_tokens.data.access_expires_at;

                debug!("JWT successfully refreshed");
                Ok(())
            }
            RefreshCheck::Expired => {
                // Access and refresh tokens have expired, need to re-authenticate
                Err(DIDAuthError::Authentication(
                    "Access and refresh tokens have expired".to_owned(),
                ))
            }
        }
    }

    /// Creates an Affinidi Trusted Messaging Authentication Challenge Response Message
    /// # Arguments
    /// * `body` - The challenge body
    /// # Returns
    /// A DIDComm message to be sent
    ///
    /// Notes:
    /// - This message will expire after 60 seconds
    fn _create_auth_challenge_response(
        &self,
        profile_did: &str,
        endpoint_did: &str,
        body: &DidChallenges,
    ) -> Result<Message> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let body = if let DidChallenges::Complex(c) = body {
            json!({"challenge": c.data.challenge, "session_id": c.session_id})
        } else {
            json!({"challenge": body.challenge()})
        };

        Ok(Message::build(
            Uuid::new_v4().into(),
            "https://affinidi.com/atm/1.0/authenticate".to_owned(),
            body,
        )
        .to(endpoint_did.to_string())
        .from(profile_did.to_owned())
        .created_time(now)
        .expires_time(now + 60)
        .finalize())
    }
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
        .map_err(|e| {
            DIDAuthError::Authentication(format!("HTTP POST failed ({url}): {e:?}"))
        })?;

    let response_status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| DIDAuthError::Authentication(format!("Couldn't get HTTP body: {e:?}")))?;

    debug!(
        "status: {} response body: {}",
        response_status, response_body
    );
    if !response_status.is_success() {
        if response_status.as_u16() == 401 {
            return Err(DIDAuthError::ACLDenied("Authentication Denied".into()));
        } else {
            return Err(DIDAuthError::Authentication(format!(
                "Failed to get authentication response. url: {url}, status: {response_status}"
            )));
        }
    }

    serde_json::from_str::<T>(&response_body).map_err(|e| {
        DIDAuthError::Authentication(format!("Couldn't deserialize AuthorizationResponse: {e}"))
    })
}

/// Possible responses from checking authentication JWT tokens
#[derive(PartialEq, Debug)]
pub enum RefreshCheck {
    /// Tokens are valid, do not need to bre refreshed
    Ok,
    /// Access Token has expired and needs to be refreshed
    Refresh,
    /// Access and Refresh Tokens have expired, need to re-authenticate from scratch
    Expired,
}

/// Checks if the tokens need to be refreshed?
pub fn refresh_check(tokens: &AuthorizationTokens) -> RefreshCheck {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    debug!(
        "checking auth expiry: now({}), access_expires_at({}), delta({}), expired?({}), refresh_expires_at({}), delta({}), expired?({})",
        now,
        tokens.access_expires_at,
        tokens.access_expires_at as i64 - now as i64,
        tokens.access_expires_at - 5 <= now,
        tokens.refresh_expires_at,
        tokens.refresh_expires_at as i64 - now as i64,
        tokens.refresh_expires_at <= now
    );

    if tokens.access_expires_at - 5 <= now {
        if tokens.refresh_expires_at <= now {
            // Both access and refresh tokens have expired
            RefreshCheck::Expired
        } else {
            // Only the access token has expired
            RefreshCheck::Refresh
        }
    } else {
        // Tokens are still valid
        RefreshCheck::Ok
    }
}

#[cfg(test)]
mod tests {
    use crate::{AuthorizationTokens, RefreshCheck, refresh_check};
    use std::time::SystemTime;

    #[test]
    fn refresh_check_valid() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let tokens = AuthorizationTokens {
            access_expires_at: now + 900,
            refresh_expires_at: now + 1800,
            ..Default::default()
        };

        assert_eq!(refresh_check(&tokens), RefreshCheck::Ok);
    }

    #[test]
    fn refresh_check_refresh() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let tokens = AuthorizationTokens {
            access_expires_at: now,
            refresh_expires_at: now + 1800,
            ..Default::default()
        };

        assert_eq!(refresh_check(&tokens), RefreshCheck::Refresh);
    }

    #[test]
    fn refresh_check_expired() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let tokens = AuthorizationTokens {
            access_expires_at: now,
            refresh_expires_at: now,
            ..Default::default()
        };

        assert_eq!(refresh_check(&tokens), RefreshCheck::Expired);
    }
}
