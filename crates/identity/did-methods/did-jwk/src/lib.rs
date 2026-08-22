/*!
 * did:jwk — JSON Web Key DID method resolver.
 *
 * Implements resolution of `did:jwk` identifiers per the
 * [did:jwk method specification](https://github.com/quartzjer/did-jwk/blob/main/spec.md).
 *
 * # DID Format
 *
 * ```text
 * did:jwk:{base64url-nopad(utf8(jwk))}
 * ```
 *
 * The whole document is derived from the identifier — there is no network step
 * and no state, so resolution cannot fail for any reason other than the DID
 * being malformed.
 *
 * # Relationship to the `use` member
 *
 * Per the specification, a key restricts which verification relationships it
 * appears in:
 *
 * - `"use": "sig"` — every relationship except `keyAgreement`
 * - `"use": "enc"` — `keyAgreement` only
 * - no `use` — all five relationships
 *
 * # Why this crate exists
 *
 * The spruceid `did-jwk` crate reaches the rest of the `ssi-*` stack, which
 * pulls `derivative` (RUSTSEC-2024-0388, unmaintained) along with the `im` /
 * `sized-chunks` / `bitmaps` / `smallstr` cluster shared with `did:ethr` and
 * `did:pkh`. See the sibling `affinidi-did-ethr` crate for the full rationale.
 *
 * # Deviation from the crate this replaced
 *
 * The spruceid implementation emitted `Multikey` verification methods with
 * `publicKeyMultibase`, and applied every verification relationship regardless
 * of the key's `use`. Both diverge from the specification, which mandates
 * `JsonWebKey2020` with `publicKeyJwk` and honours `use`. This crate follows
 * the specification. No production caller consumed the old shape — the
 * `did-jwk` feature was not enabled by any crate in the workspace.
 *
 * # Usage
 *
 * ```
 * # fn main() -> Result<(), affinidi_did_jwk::DidJwkError> {
 * let did = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
 * let doc = affinidi_did_jwk::resolve(did)?;
 * assert_eq!(doc.verification_method.len(), 1);
 * # Ok(()) }
 * ```
 */

use affinidi_did_common::{DocumentBuilder, VerificationMethodBuilder};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use thiserror::Error;

pub use affinidi_did_common::Document;

/// did:jwk resolver errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DidJwkError {
    /// The supplied string was not a `did:jwk` DID.
    #[error("not a did:jwk DID: {0}")]
    NotJwk(String),

    /// The identifier was not base64url (no padding).
    #[error("did:jwk identifier is not base64url: {0}")]
    InvalidBase64(String),

    /// The decoded identifier was not a JSON object.
    #[error("did:jwk identifier does not decode to a JSON object")]
    InvalidJwk,

    /// The encoded key carries private material.
    ///
    /// A DID is a public identifier. Resolving a private key into a DID
    /// Document would publish the secret to every party that resolves the DID,
    /// so this is refused rather than stripped — silently discarding the
    /// private half would leave the holder believing the secret was never
    /// there.
    #[error("did:jwk identifier contains private key material ({0})")]
    PrivateKeyMaterial(&'static str),

    /// The DID could not be expressed as a document (unparseable as a URL).
    #[error("did:jwk document could not be built: {0}")]
    InvalidDocument(String),
}

/// JWK members that only ever appear on a private (or symmetric) key.
///
/// `d` covers both EC/OKP private scalars and the RSA private exponent; the
/// rest are RSA CRT parameters; `k` is a symmetric key.
const PRIVATE_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];

/// Resolve a `did:jwk` DID into its DID Document.
pub fn resolve(did: &str) -> Result<Document, DidJwkError> {
    let identifier = did
        .strip_prefix("did:jwk:")
        .ok_or_else(|| DidJwkError::NotJwk(did.to_string()))?;
    resolve_identifier(identifier)
}

/// Resolve the method-specific identifier of a `did:jwk` DID — everything after
/// `did:jwk:` — into its DID Document.
pub fn resolve_identifier(identifier: &str) -> Result<Document, DidJwkError> {
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(identifier)
        .map_err(|_| DidJwkError::InvalidBase64(identifier.to_string()))?;

    let jwk: Value = serde_json::from_slice(&decoded).map_err(|_| DidJwkError::InvalidJwk)?;
    let members = jwk.as_object().ok_or(DidJwkError::InvalidJwk)?;

    if let Some(member) = PRIVATE_MEMBERS
        .iter()
        .find(|member| members.contains_key(**member))
    {
        return Err(DidJwkError::PrivateKeyMaterial(member));
    }

    // `use` selects which relationships the key may appear in. An unrecognised
    // value is treated as unrestricted, matching the specification's silence.
    let key_use = members.get("use").and_then(Value::as_str);
    let signing = key_use != Some("enc");
    let key_agreement = key_use != Some("sig");

    let did = format!("did:jwk:{identifier}");
    let vm_id = format!("{did}#0");

    let vm = VerificationMethodBuilder::new(&vm_id, "JsonWebKey2020", &did)
        .map_err(|e| DidJwkError::InvalidDocument(format!("{vm_id}: {e}")))?
        .public_key_jwk(jwk)
        .build();

    let mut builder = DocumentBuilder::new(&did)
        .map_err(|e| DidJwkError::InvalidDocument(format!("{did}: {e}")))?
        .context(json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ]))
        .verification_method(vm);

    let to_document_error = |e: affinidi_did_common::DocumentError| {
        DidJwkError::InvalidDocument(format!("{vm_id}: {e}"))
    };

    if signing {
        builder = builder
            .assertion_method_reference(&vm_id)
            .and_then(|b| b.authentication_reference(&vm_id))
            .and_then(|b| b.capability_invocation_reference(&vm_id))
            .and_then(|b| b.capability_delegation_reference(&vm_id))
            .map_err(to_document_error)?;
    }
    if key_agreement {
        builder = builder
            .key_agreement_reference(&vm_id)
            .map_err(to_document_error)?;
    }

    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P-256 key from the did:jwk specification's own example.
    const P256_DID: &str = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";

    fn resolved(did: &str) -> Value {
        serde_json::to_value(resolve(did).unwrap()).unwrap()
    }

    #[test]
    fn resolves_the_specification_example() {
        assert_eq!(
            resolved(P256_DID),
            json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
              ],
              "id": P256_DID,
              "verificationMethod": [{
                "id": format!("{P256_DID}#0"),
                "type": "JsonWebKey2020",
                "controller": P256_DID,
                "publicKeyJwk": {
                  "crv": "P-256",
                  "kty": "EC",
                  "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
                  "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
                }
              }],
              "assertionMethod": [format!("{P256_DID}#0")],
              "authentication": [format!("{P256_DID}#0")],
              "capabilityInvocation": [format!("{P256_DID}#0")],
              "capabilityDelegation": [format!("{P256_DID}#0")],
              "keyAgreement": [format!("{P256_DID}#0")]
            })
        );
    }

    fn did_for(jwk: Value) -> String {
        format!(
            "did:jwk:{}",
            BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&jwk).unwrap())
        )
    }

    #[test]
    fn use_sig_drops_key_agreement() {
        let doc = resolved(&did_for(json!({
            "kty": "OKP", "crv": "Ed25519", "use": "sig",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        })));
        assert!(doc.get("keyAgreement").is_none());
        assert!(doc.get("authentication").is_some());
        assert!(doc.get("assertionMethod").is_some());
    }

    #[test]
    fn use_enc_keeps_only_key_agreement() {
        let doc = resolved(&did_for(json!({
            "kty": "OKP", "crv": "X25519", "use": "enc",
            "x": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
        })));
        assert!(doc.get("keyAgreement").is_some());
        for omitted in [
            "authentication",
            "assertionMethod",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            assert!(doc.get(omitted).is_none(), "{omitted} should be absent");
        }
    }

    #[test]
    fn private_key_material_is_refused() {
        for member in PRIVATE_MEMBERS {
            let did = did_for(json!({
                "kty": "OKP", "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                member: "c2VjcmV0"
            }));
            assert!(
                matches!(resolve(&did), Err(DidJwkError::PrivateKeyMaterial(_))),
                "{member} should be refused"
            );
        }
    }

    #[test]
    fn non_jwk_did_is_rejected() {
        assert!(matches!(
            resolve("did:key:z6Mk"),
            Err(DidJwkError::NotJwk(_))
        ));
    }

    #[test]
    fn non_base64_identifier_is_rejected() {
        assert!(matches!(
            resolve("did:jwk:not!base64"),
            Err(DidJwkError::InvalidBase64(_))
        ));
    }

    #[test]
    fn non_object_payload_is_rejected() {
        let did = format!("did:jwk:{}", BASE64_URL_SAFE_NO_PAD.encode("[1,2,3]"));
        assert!(matches!(resolve(&did), Err(DidJwkError::InvalidJwk)));
    }

    /// The JWK is embedded verbatim, so member order and unknown members
    /// survive resolution — a resolver must not silently rewrite the key.
    #[test]
    fn unknown_members_are_preserved() {
        let did = did_for(json!({
            "kty": "OKP", "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "kid": "key-1", "alg": "EdDSA"
        }));
        let doc = resolved(&did);
        let jwk = &doc["verificationMethod"][0]["publicKeyJwk"];
        assert_eq!(jwk["kid"], json!("key-1"));
        assert_eq!(jwk["alg"], json!("EdDSA"));
    }
}
