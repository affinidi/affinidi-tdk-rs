//! Pure-TSP client authentication handler.
//!
//! A pure-TSP client has no DIDComm encryption keys to drive the built-in
//! DIDComm authentication flow — it authenticates instead by signing the
//! mediator's challenge with its VID's Ed25519 signing key and POSTing that to
//! the mediator's `POST /tsp/authenticate` endpoint (see the mediator's
//! `handlers::authenticate::tsp`).
//!
//! [`TspAuthHandler`] is an
//! [`affinidi_did_authentication::CustomAuthHandler`]: register it on the TDK at
//! construction and the TDK's `AuthenticationCache` will use it in place of the
//! DIDComm flow, so the existing `atm.tsp().send_raw` / cache path then works
//! for a pure-TSP client unchanged.
//!
//! ## Flow
//!
//! 1. Resolve `endpoint_did`'s DID document and find the `#auth` service — its
//!    URI is the mediator's `.../authenticate` base.
//! 2. **Challenge:** `POST {base}/challenge` with `{"did": profile_did}`; parse
//!    `data.challenge` + `data.session_id` from the mediator's `SuccessResponse`.
//! 3. **Sign:** resolve `profile_did`, take the first Ed25519 `authentication`
//!    verification method, load its private key from the secrets resolver, sign
//!    the challenge, and base64url-encode the 64-byte signature.
//! 4. **Authenticate:** `POST {base}/tsp/authenticate` with `{"vid",
//!    "session_id", "signature"}`; parse the access/refresh tokens + expiries
//!    from the `SuccessResponse`.
//!
//! ## Registering the handler
//!
//! ```no_run
//! # async fn example(
//! #     secrets: affinidi_secrets_resolver::ThreadedSecretsResolver,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use affinidi_did_authentication::CustomAuthHandlers;
//! use affinidi_messaging_sdk::TspAuthHandler;
//!
//! // Build the custom-handler bundle the TDK takes at construction.
//! // `secrets` is the resolver the TDK uses (`ThreadedSecretsResolver`).
//! let handlers = CustomAuthHandlers::default()
//!     .with_auth_handler(Arc::new(TspAuthHandler::new(secrets)));
//!
//! // Pass `Some(handlers)` into the TDK at `TDKSharedState` construction
//! // (e.g. via `TDKConfig`/`TDKSharedState::new(...)`). The TDK's
//! // AuthenticationCache then uses this handler for the TSP profile, so the
//! // usual `atm.tsp()` ops authenticate over `/tsp/authenticate` transparently.
//! # let _ = handlers;
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use affinidi_did_authentication::errors::DIDAuthError;
use affinidi_did_authentication::{AuthorizationTokens, CustomAuthHandler};
use affinidi_did_common::DocumentExt;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use async_trait::async_trait;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

/// Object-safe, `Send`-future view over a secrets source.
///
/// [`SecretsResolver::get_secret`] is an `async fn` in a trait, so for a generic
/// `S` the compiler can't prove its returned future is `Send` — and the
/// [`CustomAuthHandler`] trait (whose `authenticate` returns a `Send` boxed
/// future) requires it. There is no stable way to box a generic
/// `async-fn-in-trait` future as `Send` (that needs return-type-notation), so we
/// implement this `#[async_trait]` (Send-boxing) adapter for the **concrete**
/// [`ThreadedSecretsResolver`] — the resolver the TDK uses. Its `get_secret`
/// future is `Send`, so the boxed body type-checks. (`SimpleSecretsResolver` is
/// `RefCell`-backed and not `Sync`, so it cannot satisfy the `Send`-future
/// contract and is intentionally excluded.) The trait is sealed; extend the
/// concrete impls below if another `Send`-future resolver is added.
///
/// [`ThreadedSecretsResolver`]: affinidi_secrets_resolver::ThreadedSecretsResolver
#[async_trait]
pub trait SendSecrets: sealed::Sealed + Send + Sync {
    /// Look up a secret by `kid`, returning a `Send` future.
    async fn get(&self, kid: &str) -> Option<Secret>;
}

mod sealed {
    /// Seals [`super::SendSecrets`]: only this crate may add implementors.
    pub trait Sealed {}
    impl Sealed for affinidi_secrets_resolver::ThreadedSecretsResolver {}
}

#[async_trait]
impl SendSecrets for affinidi_secrets_resolver::ThreadedSecretsResolver {
    async fn get(&self, kid: &str) -> Option<Secret> {
        self.get_secret(kid).await
    }
}

/// A pure-TSP [`CustomAuthHandler`]: authenticates a TSP-only client by signing
/// the mediator's challenge with its VID's Ed25519 key.
///
/// Holds the secrets resolver (the [`CustomAuthHandler::authenticate`] trait
/// method does not receive one) used to load the profile's Ed25519
/// `authentication` private key. Register it via
/// [`affinidi_did_authentication::CustomAuthHandlers::with_auth_handler`] and
/// pass the bundle into the TDK at construction — see the [module
/// docs](self) for an example.
pub struct TspAuthHandler {
    secrets: Arc<dyn SendSecrets>,
}

impl TspAuthHandler {
    /// Build a handler that signs challenges with keys from `secrets`.
    ///
    /// `secrets` is the [`ThreadedSecretsResolver`] the TDK uses; it produces the
    /// `Send` futures the [`CustomAuthHandler`] contract requires. See
    /// [`SendSecrets`] for why the bound is concrete rather than a blanket
    /// `S: SecretsResolver`.
    ///
    /// [`ThreadedSecretsResolver`]: affinidi_secrets_resolver::ThreadedSecretsResolver
    pub fn new<S: SendSecrets + 'static>(secrets: S) -> Self {
        Self {
            secrets: Arc::new(secrets),
        }
    }
}

/// Inner `data` of the mediator's challenge `SuccessResponse`.
#[derive(Deserialize)]
struct ChallengeData {
    challenge: String,
    session_id: String,
}

/// Inner `data` of the mediator's `/tsp/authenticate` `SuccessResponse`.
///
/// The mediator currently serialises the expiries as JSON numbers, but the
/// upstream `AuthorizationTokens` carries them as `u64`; accept either a number
/// or a numeric string so this stays robust to either wire shape.
#[derive(Deserialize)]
struct TokensData {
    access_token: String,
    #[serde(deserialize_with = "de_u64_lenient")]
    access_expires_at: u64,
    refresh_token: String,
    #[serde(deserialize_with = "de_u64_lenient")]
    refresh_expires_at: u64,
}

/// Minimal view of the mediator's `SuccessResponse<T>` envelope — only `data`.
#[derive(Deserialize)]
struct SuccessEnvelope<T> {
    data: Option<T>,
}

/// Deserialize a `u64` from either a JSON number or a JSON string.
fn de_u64_lenient<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        Num(u64),
        Str(String),
    }
    match NumOrStr::deserialize(deserializer)? {
        NumOrStr::Num(n) => Ok(n),
        NumOrStr::Str(s) => s.parse().map_err(D::Error::custom),
    }
}

/// Derive the `/tsp/authenticate` URL from the `#auth` service's
/// `.../authenticate` base URL.
fn derive_tsp_url(endpoint: &str) -> Result<String, DIDAuthError> {
    let base = endpoint.strip_suffix("/authenticate").ok_or_else(|| {
        DIDAuthError::AuthenticationAbort(format!(
            "auth endpoint did not end in `/authenticate`: {endpoint}"
        ))
    })?;
    Ok(format!("{base}/tsp/authenticate"))
}

/// Sign `challenge` with the Ed25519 `key` and base64url(no-pad)-encode the
/// 64-byte signature.
fn sign_challenge(challenge: &str, key: &[u8; 32]) -> Result<String, DIDAuthError> {
    let sig: [u8; 64] = affinidi_tsp::crypto::signing::sign(challenge.as_bytes(), key)
        .map_err(|e| DIDAuthError::Authentication(format!("couldn't sign TSP challenge: {e}")))?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(sig))
}

/// JSON body for `POST {base}/challenge`.
fn challenge_body(profile_did: &str) -> String {
    json!({ "did": profile_did }).to_string()
}

/// JSON body for `POST {base}/tsp/authenticate`.
fn authenticate_body(vid: &str, session_id: &str, signature: &str) -> String {
    json!({
        "vid": vid,
        "session_id": session_id,
        "signature": signature,
    })
    .to_string()
}

/// Find the `#auth` service endpoint URI in a resolved DID document, mirroring
/// the external crate's `find_service_endpoint`.
fn find_auth_endpoint(doc: &affinidi_did_common::Document) -> Option<String> {
    doc.service
        .iter()
        .find(|s| {
            s.id.as_ref()
                .map(|id| id.as_str().ends_with("#auth"))
                .unwrap_or(false)
        })
        .and_then(|s| s.service_endpoint.get_uri())
}

impl TspAuthHandler {
    /// First `authentication` verification-method secret of `want` type, as a
    /// raw 32-byte private key. Mirrors `TspOps::first_private_key`.
    async fn first_private_key(&self, kids: Vec<&str>, want: KeyType) -> Option<[u8; 32]> {
        for kid in kids {
            if let Some(secret) = self.secrets.get(kid).await
                && secret.get_key_type() == want
                && let Ok(bytes) = <[u8; 32]>::try_from(secret.get_private_bytes())
            {
                return Some(bytes);
            }
        }
        None
    }

    /// The full authenticate flow (challenge → sign → authenticate).
    async fn run(
        &self,
        profile_did: &str,
        endpoint_did: &str,
        did_resolver: &DIDCacheClient,
        client: &Client,
    ) -> Result<AuthorizationTokens, DIDAuthError> {
        // 1. Resolve the auth endpoint from the mediator DID's `#auth` service.
        let endpoint_doc = did_resolver
            .resolve(endpoint_did)
            .await
            .map_err(|e| {
                DIDAuthError::AuthenticationAbort(format!(
                    "couldn't resolve endpoint DID {endpoint_did}: {e}"
                ))
            })?
            .doc;
        let endpoint = find_auth_endpoint(&endpoint_doc).ok_or_else(|| {
            DIDAuthError::AuthenticationAbort(format!(
                "endpoint DID {endpoint_did} has no `#auth` service endpoint"
            ))
        })?;

        // 2. Get the challenge.
        let challenge_res = client
            .post(format!("{endpoint}/challenge"))
            .header("Content-Type", "application/json")
            .body(challenge_body(profile_did))
            .send()
            .await
            .map_err(|e| {
                DIDAuthError::Authentication(format!("couldn't request TSP challenge: {e}"))
            })?;
        if !challenge_res.status().is_success() {
            let status = challenge_res.status();
            let body = challenge_res.text().await.unwrap_or_default();
            return Err(DIDAuthError::Authentication(format!(
                "TSP challenge request failed: status({status}), body({body})"
            )));
        }
        let challenge: SuccessEnvelope<ChallengeData> =
            challenge_res.json().await.map_err(|e| {
                DIDAuthError::Authentication(format!("couldn't parse TSP challenge response: {e}"))
            })?;
        let ChallengeData {
            challenge,
            session_id,
        } = challenge.data.ok_or_else(|| {
            DIDAuthError::Authentication("TSP challenge response had no `data`".into())
        })?;

        // 3. Sign the challenge with the profile's Ed25519 authentication key.
        let profile_doc = did_resolver
            .resolve(profile_did)
            .await
            .map_err(|e| {
                DIDAuthError::Authentication(format!(
                    "couldn't resolve profile DID {profile_did}: {e}"
                ))
            })?
            .doc;
        let key = self
            .first_private_key(profile_doc.find_authentication(None), KeyType::Ed25519)
            .await
            .ok_or_else(|| {
                DIDAuthError::Secrets(format!(
                    "no Ed25519 authentication key available for {profile_did}"
                ))
            })?;
        let signature = sign_challenge(&challenge, &key)?;

        // 4. POST the signature to `/tsp/authenticate`.
        let tsp_url = derive_tsp_url(&endpoint)?;
        let auth_res = client
            .post(&tsp_url)
            .header("Content-Type", "application/json")
            .body(authenticate_body(profile_did, &session_id, &signature))
            .send()
            .await
            .map_err(|e| {
                DIDAuthError::Authentication(format!("couldn't POST TSP authentication: {e}"))
            })?;
        if !auth_res.status().is_success() {
            let status = auth_res.status();
            let body = auth_res.text().await.unwrap_or_default();
            return Err(DIDAuthError::Authentication(format!(
                "TSP authentication failed: status({status}), body({body})"
            )));
        }
        let tokens: SuccessEnvelope<TokensData> = auth_res.json().await.map_err(|e| {
            DIDAuthError::Authentication(format!("couldn't parse TSP authentication response: {e}"))
        })?;
        let TokensData {
            access_token,
            access_expires_at,
            refresh_token,
            refresh_expires_at,
        } = tokens.data.ok_or_else(|| {
            DIDAuthError::Authentication("TSP authentication response had no `data`".into())
        })?;

        Ok(AuthorizationTokens {
            access_token,
            access_expires_at,
            refresh_token,
            refresh_expires_at,
        })
    }
}

impl CustomAuthHandler for TspAuthHandler {
    fn authenticate<'a>(
        &'a self,
        profile_did: &'a str,
        endpoint_did: &'a str,
        did_resolver: &'a DIDCacheClient,
        client: &'a Client,
    ) -> Pin<Box<dyn Future<Output = affinidi_did_authentication::errors::Result<AuthorizationTokens>> + Send + 'a>>
    {
        Box::pin(async move {
            self.run(profile_did, endpoint_did, did_resolver, client)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_tsp_url_happy_path() {
        assert_eq!(
            derive_tsp_url("https://mediator.example.com/authenticate").unwrap(),
            "https://mediator.example.com/tsp/authenticate"
        );
        // Path-prefixed base.
        assert_eq!(
            derive_tsp_url("https://host/atm/v1/authenticate").unwrap(),
            "https://host/atm/v1/tsp/authenticate"
        );
    }

    #[test]
    fn derive_tsp_url_rejects_missing_suffix() {
        let err = derive_tsp_url("https://mediator.example.com/auth").unwrap_err();
        assert!(matches!(err, DIDAuthError::AuthenticationAbort(_)));
    }

    #[test]
    fn sign_challenge_roundtrips_against_verify() {
        use affinidi_tsp::crypto::signing;
        // Generate a key pair via the same crate the mediator verifies with.
        let vid = affinidi_tsp::PrivateVid::generate("did:example:tsp-client");
        let challenge = "a-server-issued-32-char-challenge";

        let b64 = sign_challenge(challenge, &vid.signing_key).unwrap();
        let sig_bytes = BASE64_URL_SAFE_NO_PAD.decode(b64.as_bytes()).unwrap();
        let sig: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();

        // Mirrors the mediator: verify the signature against the VID's public key.
        signing::verify(challenge.as_bytes(), &sig, &vid.verifying_key).unwrap();

        // A signature over a different challenge must not verify.
        let other = sign_challenge("a-different-challenge-string-here", &vid.signing_key).unwrap();
        let other_bytes = BASE64_URL_SAFE_NO_PAD.decode(other.as_bytes()).unwrap();
        let other_sig: [u8; 64] = other_bytes.as_slice().try_into().unwrap();
        assert!(signing::verify(challenge.as_bytes(), &other_sig, &vid.verifying_key).is_err());
    }

    #[test]
    fn challenge_body_shape() {
        let v: serde_json::Value =
            serde_json::from_str(&challenge_body("did:example:alice")).unwrap();
        assert_eq!(v, json!({ "did": "did:example:alice" }));
    }

    #[test]
    fn authenticate_body_shape() {
        let v: serde_json::Value =
            serde_json::from_str(&authenticate_body("did:example:alice", "sess-123", "c2ln")).unwrap();
        assert_eq!(
            v,
            json!({
                "vid": "did:example:alice",
                "session_id": "sess-123",
                "signature": "c2ln",
            })
        );
    }

    #[test]
    fn parses_challenge_envelope() {
        // The mediator's wire shape (camelCase envelope, snake_case data).
        let raw = r#"{
            "sessionId": "abc",
            "httpCode": 200,
            "errorCode": 0,
            "errorCodeStr": "NA",
            "message": "Success",
            "data": { "challenge": "the-challenge", "session_id": "abc" }
        }"#;
        let env: SuccessEnvelope<ChallengeData> = serde_json::from_str(raw).unwrap();
        let data = env.data.unwrap();
        assert_eq!(data.challenge, "the-challenge");
        assert_eq!(data.session_id, "abc");
    }

    #[test]
    fn parses_tokens_envelope_numeric_and_string_expiries() {
        // Numeric expiries (the mediator's actual u64 shape).
        let numeric = r#"{
            "data": {
                "access_token": "at",
                "access_expires_at": 1000,
                "refresh_token": "rt",
                "refresh_expires_at": 2000
            }
        }"#;
        let env: SuccessEnvelope<TokensData> = serde_json::from_str(numeric).unwrap();
        let d = env.data.unwrap();
        assert_eq!(d.access_token, "at");
        assert_eq!(d.access_expires_at, 1000);
        assert_eq!(d.refresh_expires_at, 2000);

        // String expiries (robustness path).
        let string = r#"{
            "data": {
                "access_token": "at",
                "access_expires_at": "1000",
                "refresh_token": "rt",
                "refresh_expires_at": "2000"
            }
        }"#;
        let env: SuccessEnvelope<TokensData> = serde_json::from_str(string).unwrap();
        let d = env.data.unwrap();
        assert_eq!(d.access_expires_at, 1000);
        assert_eq!(d.refresh_expires_at, 2000);
    }
}
