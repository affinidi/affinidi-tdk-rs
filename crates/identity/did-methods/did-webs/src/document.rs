//! Building a DID document from verified KERI key state.
//!
//! The published `did.json` is a cache. What a resolver returns must be
//! *derived* from the key event log it verified, so this module takes the
//! current signing keys and produces the document they imply — and nothing
//! else. Anything a `did.json` claims beyond that (services, `alsoKnownAs`)
//! is not asserted here, because nothing in the KEL alone establishes it.

use affinidi_cesr::Matter;
use affinidi_did_common::{Document, DocumentBuilder, VerificationMethodBuilder};
use serde_json::json;

use crate::errors::DidWebsError;
use crate::identifier::DidWebs;

/// Build the DID document implied by a set of verified current signing keys.
///
/// Verification method ids are `#<key qb64>`, which is what `did:webs`
/// artifacts use: the key's own CESR encoding is its identifier, so a
/// reference cannot drift from the key it names.
///
/// # Errors
/// Returns [`DidWebsError::Kel`] if a key is not a CESR primitive this
/// implementation can express as a JWK.
pub fn document_from_keys(did: &DidWebs, keys: &[String]) -> Result<Document, DidWebsError> {
    if keys.is_empty() {
        return Err(DidWebsError::Kel(
            "verified key state has no signing keys".into(),
        ));
    }

    let controller = did.did();
    let mut builder = DocumentBuilder::new(controller)
        .map_err(|e| DidWebsError::Kel(format!("{controller} is not a usable document id: {e}")))?
        .context_did_v1();

    // The did:web twin shares this document at the same location. Recording it
    // as `equivalentId` is what lets a consumer that only speaks did:web be
    // pointed at the same identifier.
    builder = builder.also_known_as(did.did_web_twin());

    for key in keys {
        let jwk = jwk_from_cesr_key(key)?;
        let vm_id = format!("{controller}#{key}");
        let vm = VerificationMethodBuilder::new(&vm_id, "JsonWebKey", controller)
            .map_err(|e| DidWebsError::Kel(format!("could not build {vm_id}: {e}")))?
            .property("publicKeyJwk", jwk)
            .build();

        builder = builder.verification_method(vm);
        builder = builder
            .authentication_reference(&vm_id)
            .map_err(|e| DidWebsError::Kel(format!("could not reference {vm_id}: {e}")))?;
        builder = builder
            .assertion_method_reference(&vm_id)
            .map_err(|e| DidWebsError::Kel(format!("could not reference {vm_id}: {e}")))?;
    }

    Ok(builder.build())
}

/// Turn a CESR-encoded public key into a JWK.
///
/// `did:webs` documents carry `JsonWebKey` verification methods with the CESR
/// key as the `kid`, so a published document can be compared field for field
/// against a derived one.
///
/// The conversion goes through `affinidi_crypto`, which validates that an EC
/// point is actually on its curve while decompressing it. That check matters:
/// a compressed point is 33 bytes of attacker-supplied data, and a key that is
/// not on the curve must be refused rather than published in a document.
fn jwk_from_cesr_key(key_qb64: &str) -> Result<serde_json::Value, DidWebsError> {
    let matter = Matter::from_qb64(key_qb64)
        .map_err(|e| DidWebsError::Kel(format!("key {key_qb64:?} is not a CESR primitive: {e}")))?;

    let raw = matter.raw();
    let jwk = match matter.code() {
        // Ed25519 verification key, non-transferable ("B") and transferable ("D").
        "B" | "D" => affinidi_crypto::ed25519::public_jwk(raw),
        // secp256k1, non-transferable and transferable.
        "1AAA" | "1AAB" => affinidi_crypto::secp256k1::public_jwk(raw),
        // NIST P-256, non-transferable and transferable.
        "1AAI" | "1AAJ" => affinidi_crypto::p256::public_jwk(raw),
        other => {
            return Err(DidWebsError::Kel(format!(
                "key {key_qb64:?} uses CESR code {other:?}, which this implementation \
                 cannot express as a JWK"
            )));
        }
    }
    .map_err(|e| DidWebsError::Kel(format!("key {key_qb64:?} is not a valid public key: {e}")))?;

    let mut value = serde_json::to_value(&jwk)?;
    // The CESR form is the key's identity in a did:webs document, and it is
    // what the verification method id references.
    if let Some(obj) = value.as_object_mut() {
        obj.insert("kid".to_string(), json!(key_qb64));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_KEY: &str = "DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr";
    const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

    fn did() -> DidWebs {
        DidWebs::parse(&format!("did:webs:example.com:{AID}")).expect("valid did")
    }

    #[test]
    fn builds_a_document_for_an_ed25519_key() {
        let doc = document_from_keys(&did(), &[ED25519_KEY.to_string()]).expect("builds");

        assert_eq!(doc.id.as_str(), format!("did:webs:example.com:{AID}"));
        assert_eq!(doc.verification_method.len(), 1);

        let vm = &doc.verification_method[0];
        assert_eq!(vm.type_, "JsonWebKey");
        assert!(vm.id.as_str().ends_with(&format!("#{ED25519_KEY}")));

        let jwk = vm.property_set.get("publicKeyJwk").expect("has a jwk");
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["kid"], ED25519_KEY);
        // The published artifact for this AID carries exactly this `x`, so a
        // change here is a change in what we would compare did.json against.
        assert_eq!(jwk["x"], "evT4j6Yw3uHpwsw5NEmSR8-4x3S-BA-s6Thjd51oeOs");
    }

    #[test]
    fn records_the_did_web_twin() {
        let doc = document_from_keys(&did(), &[ED25519_KEY.to_string()]).expect("builds");
        let aka: Vec<&str> = doc.also_known_as.iter().map(String::as_str).collect();
        assert!(
            aka.contains(&format!("did:web:example.com:{AID}").as_str()),
            "got {aka:?}",
        );
    }

    #[test]
    fn every_key_is_an_authentication_and_assertion_method() {
        let doc = document_from_keys(&did(), &[ED25519_KEY.to_string()]).expect("builds");
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
    }

    #[test]
    fn rejects_an_empty_key_state() {
        assert!(document_from_keys(&did(), &[]).is_err());
    }

    #[test]
    fn rejects_a_key_that_is_not_a_cesr_primitive() {
        assert!(document_from_keys(&did(), &["not-a-key".to_string()]).is_err());
    }

    #[test]
    fn rejects_a_non_key_cesr_primitive() {
        // A digest is a valid CESR primitive but not a public key: it must not
        // silently become a verification method.
        assert!(document_from_keys(&did(), &[AID.to_string()]).is_err());
    }
}
