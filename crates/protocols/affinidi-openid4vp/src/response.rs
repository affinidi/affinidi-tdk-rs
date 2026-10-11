/*!
 * Receiving an OpenID4VP 1.0 authorization response at `response_uri`
 * (`response_mode=direct_post.jwt`, §8.3).
 *
 * The wallet posts `application/x-www-form-urlencoded`: either `response=<JWE>`
 * — the authorization response encrypted to the key the request object
 * published — or, when it declines or fails, the error parameters (`error`,
 * `error_description`, `state`) in the clear. [`receive_direct_post_jwt`]
 * tells the two apart, decrypts the first with the caller's key and allowed
 * `enc` values, and returns the 1.0 shape: `vp_token` as a map from each DCQL
 * credential query id to the presentations that answer it.
 *
 * Nothing here verifies a presentation. That needs the credential format's own
 * checks — the issuer's signature, the key-binding proof over this request's
 * `nonce` and the verifier's `client_id` — and then
 * [`DcqlQuery::evaluate_presentation`](crate::dcql::DcqlQuery::evaluate_presentation)
 * over what verified.
 */

use std::collections::BTreeMap;

use affinidi_oid4vc_core::jwe::{ContentEncryption, EcdhEsDecryptionKey, decrypt_compact};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Oid4vpError;

/// The 1.0 `vp_token`: each DCQL credential query id mapped to the
/// presentations answering it — a string (an SD-JWT, a base64url mdoc device
/// response) or an object (a JSON-LD presentation).
pub type VpToken = BTreeMap<String, Vec<Value>>;

/// A decrypted authorization response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// The presentations, by credential query id.
    pub vp_token: VpToken,
    /// The request's `state`, echoed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// A wallet's error response (OpenID4VP 1.0 §8.5): it declined, or could not
/// answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletError {
    /// The OAuth / OpenID4VP error code, e.g. `access_denied`.
    pub error: String,
    /// Optional human-readable detail. Untrusted text from the wallet.
    pub error_description: Option<String>,
    /// The request's `state`, echoed.
    pub state: Option<String>,
}

/// What a wallet posted to `response_uri`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum DirectPostJwt {
    /// An authorization response, decrypted.
    Response(AuthorizationResponse),
    /// An error response.
    Error(WalletError),
}

/// Read the form body a wallet posted to `response_uri` and, when it is an
/// authorization response, decrypt it with `key` accepting only `allowed_enc`.
///
/// `form_body` is the raw `application/x-www-form-urlencoded` body. A body
/// carrying both `response` and `error`, neither, or a repeated parameter is
/// refused. The decrypted payload must be a JSON object with a `vp_token` map
/// of non-empty arrays.
pub fn receive_direct_post_jwt(
    form_body: &[u8],
    key: &EcdhEsDecryptionKey,
    allowed_enc: &[ContentEncryption],
) -> Result<DirectPostJwt, Oid4vpError> {
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(form_body) {
        if params
            .insert(name.to_string(), value.into_owned())
            .is_some()
        {
            return Err(Oid4vpError::InvalidResponse(format!(
                "parameter `{name}` appears more than once"
            )));
        }
    }

    match (params.remove("response"), params.remove("error")) {
        (Some(_), Some(_)) => Err(Oid4vpError::InvalidResponse(
            "a response carries `response` or `error`, not both".into(),
        )),
        (None, None) => Err(Oid4vpError::InvalidResponse(
            "the body has neither `response` nor `error`".into(),
        )),
        (None, Some(error)) => Ok(DirectPostJwt::Error(WalletError {
            error,
            error_description: params.remove("error_description"),
            state: params.remove("state"),
        })),
        (Some(jwe), None) => {
            let opened = decrypt_compact(&jwe, key, allowed_enc).map_err(|e| {
                Oid4vpError::InvalidResponse(format!("the response did not decrypt: {e}"))
            })?;
            let response: AuthorizationResponse = serde_json::from_slice(&opened.plaintext)
                .map_err(|e| {
                    Oid4vpError::InvalidResponse(format!(
                        "the decrypted response is not an authorization response: {e}"
                    ))
                })?;
            if let Some((id, _)) = response.vp_token.iter().find(|(_, v)| v.is_empty()) {
                return Err(Oid4vpError::InvalidVpToken(format!(
                    "credential query `{id}` is answered by an empty array"
                )));
            }
            Ok(DirectPostJwt::Response(response))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_oid4vc_core::jwe::encrypt_compact;
    use serde_json::json;

    const ENC: &[ContentEncryption] = &[ContentEncryption::A256Gcm];

    fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut s = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            s.append_pair(k, v);
        }
        s.finish().into_bytes()
    }

    fn encrypted(key: &EcdhEsDecryptionKey, payload: &Value) -> String {
        encrypt_compact(
            &serde_json::to_vec(payload).unwrap(),
            &key.public_jwk().unwrap(),
            ContentEncryption::A256Gcm,
            b"",
            b"",
        )
        .unwrap()
    }

    #[test]
    fn decrypts_a_response_into_the_vp_token_map() {
        let key = EcdhEsDecryptionKey::generate("r1");
        let jwe = encrypted(
            &key,
            &json!({ "vp_token": { "residence": ["eyJ...~disclosure~kb"] }, "state": "st-1" }),
        );
        let DirectPostJwt::Response(resp) =
            receive_direct_post_jwt(&form(&[("response", &jwe)]), &key, ENC).unwrap()
        else {
            panic!("expected a response");
        };
        assert_eq!(resp.state.as_deref(), Some("st-1"));
        assert_eq!(
            resp.vp_token["residence"],
            vec![json!("eyJ...~disclosure~kb")]
        );
    }

    #[test]
    fn reads_a_wallet_error_in_the_clear() {
        let key = EcdhEsDecryptionKey::generate("r1");
        let body = form(&[
            ("error", "access_denied"),
            ("error_description", "the user declined"),
            ("state", "st-1"),
        ]);
        assert_eq!(
            receive_direct_post_jwt(&body, &key, ENC).unwrap(),
            DirectPostJwt::Error(WalletError {
                error: "access_denied".into(),
                error_description: Some("the user declined".into()),
                state: Some("st-1".into()),
            })
        );
    }

    #[test]
    fn ambiguous_or_empty_bodies_are_refused() {
        let key = EcdhEsDecryptionKey::generate("r1");
        let jwe = encrypted(&key, &json!({ "vp_token": { "a": ["x"] } }));
        for body in [
            form(&[("response", &jwe), ("error", "access_denied")]),
            form(&[("state", "st-1")]),
            form(&[("response", &jwe), ("response", &jwe)]),
        ] {
            assert!(receive_direct_post_jwt(&body, &key, ENC).is_err());
        }
    }

    #[test]
    fn a_response_for_another_key_or_an_unshaped_payload_is_refused() {
        let key = EcdhEsDecryptionKey::generate("r1");
        let other = EcdhEsDecryptionKey::generate("r1");
        let jwe = encrypted(&other, &json!({ "vp_token": { "a": ["x"] } }));
        assert!(receive_direct_post_jwt(&form(&[("response", &jwe)]), &key, ENC).is_err());

        // The pre-1.0 shape (a bare vp_token plus presentation_submission) is
        // not a 1.0 response.
        let old = encrypted(
            &key,
            &json!({ "vp_token": "eyJ...", "presentation_submission": {} }),
        );
        assert!(receive_direct_post_jwt(&form(&[("response", &old)]), &key, ENC).is_err());

        let empty = encrypted(&key, &json!({ "vp_token": { "a": [] } }));
        assert!(matches!(
            receive_direct_post_jwt(&form(&[("response", &empty)]), &key, ENC),
            Err(Oid4vpError::InvalidVpToken(_))
        ));
    }
}
