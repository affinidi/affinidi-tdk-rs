/*!
 * The OpenID4VP 1.0 request object, signed as a JWT-Secured Authorization
 * Request (RFC 9101), and the wallet invocation URI that points at it.
 *
 * A verifier builds a [`RequestObject`], signs it with
 * [`RequestObject::sign`] — `typ: oauth-authz-req+jwt`, with the signing key
 * named by `kid` (a DID URL, for `decentralized_identifier`) or by an `x5c`
 * chain (for `x509_hash` / `x509_san_dns`) — serves the result at its
 * `request_uri`, and shows the wallet
 * [`wallet_invocation_uri`](RequestObject::wallet_invocation_uri) as a QR code
 * or deep link. The wallet fetches the signed object and answers to
 * `response_uri`.
 *
 * Only the response shape this crate can receive is modelled as a constructor:
 * `response_type=vp_token` with `response_mode=direct_post.jwt` and a DCQL
 * query. Profiles add members — swiyu puts `profile_version` in the header,
 * HAIP and swiyu put trust material in `verifier_info` — through
 * [`JarHeader::extra`] and [`RequestObject::additional`], never by editing the
 * modelled ones.
 */

use affinidi_oid4vc_core::jwt::{JwtSigner, encode_compact_jws};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::client_id::ClientId;
use crate::dcql::DcqlQuery;
use crate::error::Oid4vpError;

/// The JAR `typ` (RFC 9101 §10.8).
pub const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

/// The `aud` of a request object for a wallet found by static discovery
/// (OpenID4VP 1.0 §5.8): the Self-Issued OP identifier.
pub const STATIC_DISCOVERY_AUDIENCE: &str = "https://self-issued.me/v2";

/// `response_mode` for an encrypted response posted to `response_uri`.
pub const RESPONSE_MODE_DIRECT_POST_JWT: &str = "direct_post.jwt";

/// The verifier metadata a request object carries (`client_metadata`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifierClientMetadata {
    /// The verifier's response-encryption keys, as a JWK Set: `{"keys": [...]}`.
    /// For `direct_post.jwt`, a fresh `ECDH-ES` key per request.
    pub jwks: Value,
    /// The JWE `enc` values the verifier accepts for the response.
    pub encrypted_response_enc_values_supported: Vec<String>,
    /// Credential formats and algorithms the verifier accepts, keyed by format.
    /// Optional; some profiles (swiyu) read the format from the DCQL query
    /// instead and do not send it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_formats_supported: Option<Value>,
    /// Any further members (`client_name`, `logo_uri`, …).
    #[serde(flatten)]
    pub additional: Map<String, Value>,
}

/// An OpenID4VP 1.0 request object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestObject {
    /// The verifier's client identifier, prefix included.
    pub client_id: String,
    /// Always `vp_token` here.
    pub response_type: String,
    /// Always `direct_post.jwt` here.
    pub response_mode: String,
    /// Where the wallet posts the response.
    pub response_uri: String,
    /// The single-use challenge the key-binding proof must commit to.
    pub nonce: String,
    /// Opaque verifier state echoed in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// What the wallet is asked to present.
    pub dcql_query: DcqlQuery,
    /// Verifier metadata, carrying the response-encryption key.
    pub client_metadata: VerifierClientMetadata,
    /// The request object's audience.
    pub aud: String,
    /// Issued-at, seconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Expiry, seconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Attestations about the verifier (`verifier_info`, §5.11): a profile's
    /// trust material, such as a swiyu trust statement or an EUDI registration
    /// certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_info: Option<Vec<Value>>,
    /// Any further claims a profile requires.
    #[serde(flatten)]
    pub additional: Map<String, Value>,
}

impl RequestObject {
    /// A `vp_token` request answered by an encrypted `direct_post.jwt` to
    /// `response_uri`, for `dcql_query`, addressed to a statically discovered
    /// wallet. `client_metadata` must carry the response-encryption key.
    pub fn direct_post_jwt(
        client_id: &ClientId,
        response_uri: impl Into<String>,
        nonce: impl Into<String>,
        dcql_query: DcqlQuery,
        client_metadata: VerifierClientMetadata,
    ) -> Self {
        Self {
            client_id: client_id.to_string(),
            response_type: "vp_token".into(),
            response_mode: RESPONSE_MODE_DIRECT_POST_JWT.into(),
            response_uri: response_uri.into(),
            nonce: nonce.into(),
            state: None,
            dcql_query,
            client_metadata,
            aud: STATIC_DISCOVERY_AUDIENCE.into(),
            iat: None,
            exp: None,
            verifier_info: None,
            additional: Map::new(),
        }
    }

    /// Check what a wallet will check before signing: a valid DCQL query, a
    /// prefixed `client_id`, a nonce, an `https` `response_uri`, and — for
    /// `direct_post.jwt` — at least one encryption key and `enc` value.
    pub fn validate(&self) -> Result<(), Oid4vpError> {
        ClientId::parse(&self.client_id)?;
        self.dcql_query.validate()?;
        if self.nonce.is_empty() {
            return Err(Oid4vpError::InvalidRequest("nonce is empty".into()));
        }
        let response_uri = url::Url::parse(&self.response_uri)
            .map_err(|e| Oid4vpError::InvalidRequest(format!("response_uri is not a URL: {e}")))?;
        if response_uri.scheme() != "https" {
            return Err(Oid4vpError::InvalidRequest(
                "response_uri must be https".into(),
            ));
        }
        if self.response_mode == RESPONSE_MODE_DIRECT_POST_JWT {
            let keys = self
                .client_metadata
                .jwks
                .get("keys")
                .and_then(Value::as_array);
            if keys.is_none_or(|k| k.is_empty()) {
                return Err(Oid4vpError::InvalidRequest(
                    "direct_post.jwt needs a response-encryption key in client_metadata.jwks"
                        .into(),
                ));
            }
            if self
                .client_metadata
                .encrypted_response_enc_values_supported
                .is_empty()
            {
                return Err(Oid4vpError::InvalidRequest(
                    "direct_post.jwt needs encrypted_response_enc_values_supported".into(),
                ));
            }
        }
        Ok(())
    }

    /// Sign the request object as a JAR (`typ: oauth-authz-req+jwt`) after
    /// [`validate`](Self::validate). `header` names the signing key; its `alg`
    /// is the signer's.
    pub fn sign(&self, header: &JarHeader, signer: &dyn JwtSigner) -> Result<String, Oid4vpError> {
        self.validate()?;
        let jose = header.to_json(signer.algorithm())?;
        let claims = serde_json::to_value(self)?;
        encode_compact_jws(&jose, &claims, signer)
            .map_err(|e| Oid4vpError::InvalidRequest(format!("could not sign: {e}")))
    }

    /// The URI a wallet is invoked with: `<scheme>://?client_id=…&request_uri=…`,
    /// both percent-encoded. `scheme` is the wallet ecosystem's —
    /// `openid4vp`, `haip-vp`, `swiyu-verify`, … — without `://`.
    pub fn wallet_invocation_uri(
        scheme: &str,
        client_id: &ClientId,
        request_uri: &str,
    ) -> Result<String, Oid4vpError> {
        if scheme.is_empty()
            || !scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        {
            return Err(Oid4vpError::InvalidRequest(format!(
                "`{scheme}` is not a URI scheme"
            )));
        }
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &client_id.to_string())
            .append_pair("request_uri", request_uri)
            .finish();
        Ok(format!("{scheme}://?{query}"))
    }
}

/// The JOSE header of a request object, less `alg` (the signer's) and `typ`
/// (always `oauth-authz-req+jwt`).
#[derive(Debug, Clone, Default)]
pub struct JarHeader {
    /// The signing key's id — for `decentralized_identifier`, a DID URL under
    /// the client's DID.
    pub kid: Option<String>,
    /// The signing certificate chain, leaf first, each base64 (not base64url)
    /// DER — for `x509_hash` / `x509_san_dns`.
    pub x5c: Option<Vec<String>>,
    /// Further header members a profile requires (swiyu: `profile_version`).
    /// May not set `alg`, `typ`, `kid` or `x5c`.
    pub extra: Map<String, Value>,
}

impl JarHeader {
    /// A header naming the signing key by `kid`.
    pub fn with_kid(kid: impl Into<String>) -> Self {
        Self {
            kid: Some(kid.into()),
            ..Self::default()
        }
    }

    /// A header naming the signing key by its certificate chain.
    pub fn with_x5c(chain: Vec<String>) -> Self {
        Self {
            x5c: Some(chain),
            ..Self::default()
        }
    }

    fn to_json(&self, alg: &str) -> Result<Value, Oid4vpError> {
        if self.kid.is_none() && self.x5c.as_ref().is_none_or(|c| c.is_empty()) {
            return Err(Oid4vpError::InvalidRequest(
                "a request object names its signing key by kid or x5c".into(),
            ));
        }
        for reserved in ["alg", "typ", "kid", "x5c"] {
            if self.extra.contains_key(reserved) {
                return Err(Oid4vpError::InvalidRequest(format!(
                    "`{reserved}` cannot be set as an extra header member"
                )));
            }
        }
        let mut header = self.extra.clone();
        header.insert("alg".into(), json!(alg));
        header.insert("typ".into(), json!(REQUEST_OBJECT_TYP));
        if let Some(kid) = &self.kid {
            header.insert("kid".into(), json!(kid));
        }
        if let Some(x5c) = &self.x5c {
            header.insert("x5c".into(), json!(x5c));
        }
        Ok(Value::Object(header))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_oid4vc_core::es256::{Es256Signer, Es256Verifier};
    use affinidi_oid4vc_core::jwt::decode_compact_jws_verified_with_algs;

    fn query() -> DcqlQuery {
        DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "residence",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.org/residence"] },
                "claims": [{ "path": ["address", "country"] }]
            }]
        }))
        .unwrap()
    }

    fn metadata() -> VerifierClientMetadata {
        VerifierClientMetadata {
            jwks: json!({ "keys": [{ "kty": "EC", "crv": "P-256", "x": "x", "y": "y", "kid": "r1", "use": "enc", "alg": "ECDH-ES" }] }),
            encrypted_response_enc_values_supported: vec!["A256GCM".into()],
            vp_formats_supported: None,
            additional: Map::new(),
        }
    }

    fn request() -> RequestObject {
        let client_id =
            ClientId::decentralized_identifier("did:webvh:Qm1:verifier.example").unwrap();
        RequestObject::direct_post_jwt(
            &client_id,
            "https://community.example/v1/oid4vp/response/s1",
            "n-1",
            query(),
            metadata(),
        )
    }

    /// The signed object verifies under the signer's key and carries the JAR
    /// `typ`, the signer's `alg`, the `kid`, a profile's extra header member,
    /// and the 1.0 claims.
    #[test]
    fn signs_a_direct_post_jwt_request_object() {
        let signer = Es256Signer::generate();
        let verifier = Es256Verifier::from_jwk(&signer.public_key_jwk()).unwrap();
        let mut header = JarHeader::with_kid("did:webvh:Qm1:verifier.example#key-1");
        header.extra.insert(
            "profile_version".into(),
            json!("swiss-profile-verification:1.0.0"),
        );
        let mut req = request();
        req.state = Some("st-1".into());
        req.verifier_info = Some(vec![json!({ "format": "jwt", "data": "eyJ..." })]);

        let jar = req.sign(&header, &signer).unwrap();
        let (jose, claims) =
            decode_compact_jws_verified_with_algs(&jar, &verifier, &["ES256"]).unwrap();
        assert_eq!(jose["typ"], REQUEST_OBJECT_TYP);
        assert_eq!(jose["alg"], "ES256");
        assert_eq!(jose["kid"], "did:webvh:Qm1:verifier.example#key-1");
        assert_eq!(jose["profile_version"], "swiss-profile-verification:1.0.0");
        assert_eq!(
            claims["client_id"],
            "decentralized_identifier:did:webvh:Qm1:verifier.example"
        );
        assert_eq!(claims["response_type"], "vp_token");
        assert_eq!(claims["response_mode"], "direct_post.jwt");
        assert_eq!(claims["aud"], STATIC_DISCOVERY_AUDIENCE);
        assert_eq!(claims["nonce"], "n-1");
        assert_eq!(claims["state"], "st-1");
        assert_eq!(claims["dcql_query"]["credentials"][0]["id"], "residence");
        assert_eq!(
            claims["client_metadata"]["encrypted_response_enc_values_supported"],
            json!(["A256GCM"])
        );
        assert_eq!(claims["verifier_info"][0]["format"], "jwt");

        // And it parses back into the same request object.
        let back: RequestObject = serde_json::from_value(claims).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn a_header_must_name_the_key_and_cannot_override_reserved_members() {
        let signer = Es256Signer::generate();
        assert!(request().sign(&JarHeader::default(), &signer).is_err());
        let mut header = JarHeader::with_x5c(vec!["MIIB...".into()]);
        header.extra.insert("typ".into(), json!("JWT"));
        assert!(request().sign(&header, &signer).is_err());
    }

    #[test]
    fn validate_refuses_what_a_wallet_would() {
        let mut no_key = request();
        no_key.client_metadata.jwks = json!({ "keys": [] });
        assert!(no_key.validate().is_err());

        let mut no_enc = request();
        no_enc
            .client_metadata
            .encrypted_response_enc_values_supported
            .clear();
        assert!(no_enc.validate().is_err());

        let mut plain_http = request();
        plain_http.response_uri = "http://community.example/r".into();
        assert!(plain_http.validate().is_err());

        let mut unprefixed = request();
        unprefixed.client_id = "did:webvh:Qm1:verifier.example".into();
        assert!(unprefixed.validate().is_err());

        let mut no_nonce = request();
        no_nonce.nonce.clear();
        assert!(no_nonce.validate().is_err());
    }

    #[test]
    fn the_invocation_uri_percent_encodes_both_parameters() {
        let id = ClientId::decentralized_identifier("did:webvh:Qm1:verifier.example").unwrap();
        let uri = RequestObject::wallet_invocation_uri(
            "swiyu-verify",
            &id,
            "https://community.example/v1/oid4vp/request/s1",
        )
        .unwrap();
        assert_eq!(
            uri,
            "swiyu-verify://?client_id=decentralized_identifier%3Adid%3Awebvh%3AQm1%3Averifier.example\
             &request_uri=https%3A%2F%2Fcommunity.example%2Fv1%2Foid4vp%2Frequest%2Fs1"
        );
        assert!(RequestObject::wallet_invocation_uri("bad scheme", &id, "https://x").is_err());
    }
}
