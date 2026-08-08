//! The mediator's own DIDComm v1 identity.
//!
//! A v1 client anoncrypts a `routing/1.0/forward` **to the mediator's routing
//! verkey** — a bare base58 Ed25519 key, because v1 envelopes carry no DID
//! (see [`affinidi_messaging_didcomm_v1::identity`]). To open that forward the
//! mediator needs the private half.
//!
//! It does not need a *new* key. The mediator already holds an Ed25519
//! authentication key for its DID, and v1 does key agreement on that key's
//! Montgomery form, so its v1 routing verkey is simply that key seen through a
//! v1 lens. This mirrors [`crate::tsp_identity`], which derives the mediator's
//! TSP identity from the same material for the same reason: one set of
//! operating secrets, three protocols.
//!
//! # What clients need
//!
//! The base58 form of [`MediatorDidCommV1Identity::verkey`] is what a v1 client
//! puts in its `routingKeys`. It is logged at startup and reported by
//! `mediator-setup`, because there is nowhere in a DID document that a v1
//! client would look for it — v1 predates DID documents as a discovery
//! mechanism, and Aries clients are configured with routing keys out of band.

use affinidi_did_common::document::DocumentExt;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm_v1::{PrivateIdentity, Verkey};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_secrets_resolver::{SecretsResolver, secrets::KeyType};

/// The mediator's v1 identity, derived from its DID document + operating secrets.
pub struct MediatorDidCommV1Identity {
    /// The v1 identity used to open forwards addressed to this mediator.
    pub identity: PrivateIdentity,
}

impl MediatorDidCommV1Identity {
    /// The routing verkey clients address forwards to.
    pub fn verkey(&self) -> Verkey {
        self.identity.verkey
    }

    /// Derive from the mediator's DID document and operating secrets.
    ///
    /// Fails with a config error when the DID cannot be resolved or its
    /// document has no Ed25519 authentication key whose private half the
    /// mediator holds — the same precondition [`crate::tsp_identity`] has.
    pub(crate) async fn derive(
        did: &str,
        did_resolver: &DIDCacheClient,
        secrets: &impl SecretsResolver,
    ) -> Result<Self, MediatorError> {
        let doc = did_resolver
            .resolve(did)
            .await
            .map_err(|e| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!(
                        "couldn't resolve mediator DID {did} to derive its DIDComm v1 identity: {e}"
                    ),
                )
            })?
            .doc;

        let signing_key = first_ed25519_private(doc.find_authentication(None), secrets)
            .await
            .ok_or_else(|| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!(
                        "mediator DID {did} has no Ed25519 authentication key, so it cannot \
                         derive a DIDComm v1 routing key"
                    ),
                )
            })?;

        let identity = PrivateIdentity::from_signing_key(did, &signing_key).map_err(|e| {
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("couldn't build the mediator's DIDComm v1 identity: {e}"),
            )
        })?;

        Ok(Self { identity })
    }
}

/// First authentication `kid` whose secret is an Ed25519 key, as raw bytes.
async fn first_ed25519_private(
    kids: Vec<&str>,
    secrets: &impl SecretsResolver,
) -> Option<[u8; 32]> {
    for kid in kids {
        if let Some(secret) = secrets.get_secret(kid).await
            && secret.get_key_type() == KeyType::Ed25519
            && let Ok(bytes) = <[u8; 32]>::try_from(secret.get_private_bytes())
        {
            return Some(bytes);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The routing verkey must be the plain Ed25519 verkey, in the base58 form
    /// an Aries client puts in its `routingKeys`.
    ///
    /// Pinned against a value produced by a real Credo agent for this seed (the
    /// `alice` party in `affinidi-messaging-didcomm-v1`'s Credo fixtures), so
    /// this asserts interop-visible output rather than restating the derivation.
    #[test]
    fn routing_verkey_is_the_base58_ed25519_verkey() {
        const SEED_HEX: &str = "3da13d1f57cf58ddeebae88c92679c2c88dc792423e971b3c17f5ab83b79ad89";
        const CREDO_VERKEY: &str = "3hLMcPh9X6vtEJfuJmCinWRHAYFMjea1cfLA2eCvWA5A";

        let seed: [u8; 32] = <[u8; 32]>::try_from(hex_to_bytes(SEED_HEX).as_slice()).unwrap();
        let identity = PrivateIdentity::from_signing_key("did:example:mediator", &seed).unwrap();
        let derived = MediatorDidCommV1Identity { identity };

        assert_eq!(derived.verkey().to_base58(), CREDO_VERKEY);
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
