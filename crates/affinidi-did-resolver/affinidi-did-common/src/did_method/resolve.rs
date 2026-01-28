use crate::{DID, DIDMethod};

const PUBLIC_KEY_MULTIBASE: &str = "publicKeyMultibase";
const MULTIKEY_TYPE: &str = "Multikey";


impl super::DIDMethod {
    pub fn resolve(&self, did: &DID) -> &'static str {
        match self {
            DIDMethod::Key { identifier, .. } => {
                // Safe to unwrap: DID parsing already validated the encoding
                let (codec, _) = affinidi_encoding::decode_multikey_with_codec(&identifier)
                    .expect("DID was validated at parse time");

                let mut vm_id = did.url();
                vm_id.set_fragment(Some(&identifier));

                let mut vms = Vec::new();
                let mut key_agreement = Vec::new();

                match codec {
                    ED25519_PUB => {
                        // ED25519 keys also derive an X25519 key for key agreement
                        let (x25519_encoded, _) = ed25519_public_to_x25519_public_key(&identifier)
                            .map_err(|e| {
                                Error::InvalidPublicKey(format!(
                                    "Couldn't convert ed25519 to x25519 public-key: {e}"
                                ))
                            })?;

                        let mut x25519_vm_id = did.url();
                        x25519_vm_id.set_fragment(Some(&x25519_encoded));

                        vms.push(VerificationMethod {
                            id: x25519_vm_id.clone(),
                            type_: MULTIKEY_TYPE.to_string(),
                            controller: did.url(),
                            expires: None,
                            revoked: None,
                            property_set: HashMap::from([(
                                PUBLIC_KEY_MULTIBASE.to_string(),
                                Value::String(x25519_encoded),
                            )]),
                        });

                        key_agreement.push(VerificationRelationship::Reference(x25519_vm_id));
                    }
                    P256_PUB | P384_PUB | SECP256K1_PUB | X25519_PUB => {
                        key_agreement.push(VerificationRelationship::Reference(vm_id.clone()));
                    }
                    _ => unreachable!(
                        "DID parsing validates only known public key codecs are accepted"
                    ),
                }

                // Primary verification method
                vms.insert(
                    0,
                    VerificationMethod {
                        id: vm_id.clone(),
                        type_: MULTIKEY_TYPE.to_string(),
                        controller: did.url(),
                        expires: None,
                        revoked: None,
                        property_set: HashMap::from([(
                            PUBLIC_KEY_MULTIBASE.to_string(),
                            Value::String(identifier),
                        )]),
                    },
                );

                let vm_relationship = VerificationRelationship::Reference(vm_id);

                Ok(Document {
                    id: did.url(),
                    verification_method: vms,
                    authentication: vec![vm_relationship.clone()],
                    assertion_method: vec![vm_relationship.clone()],
                    key_agreement,
                    capability_invocation: vec![vm_relationship.clone()],
                    capability_delegation: vec![vm_relationship],
                    service: vec![],
                    parameters_set: HashMap::from([(
                        "@context".to_string(),
                        json!([
                            "https://www.w3.org/ns/did/v1",
                            "https://w3id.org/security/multikey/v1",
                        ]),
                    )]),
                })
            }
            _ => unimplemented!(),
        }
    }
}
