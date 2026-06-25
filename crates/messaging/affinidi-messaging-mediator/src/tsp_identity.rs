//! The mediator's own TSP identity.
//!
//! For TSP **Direct** delivery the mediator is a blind store-and-forward and
//! needs no keys. To act as a **routed relay hop**, though, it must unpack a
//! `Routed` message *sealed to it* (its X25519 decryption key) and re-seal the
//! onward message as the sender (its Ed25519 signing + X25519 encryption keys).
//!
//! The mediator already has a DID and operating secrets (the same ones it uses
//! to decrypt inbound DIDComm). Its TSP identity is simply those keys viewed
//! through a TSP lens: the Ed25519 key from `authentication` and the X25519 key
//! from `keyAgreement`. No new key management — we derive it on first use from
//! the configured DID document + secrets resolver.

use affinidi_did_common::document::DocumentExt;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_secrets_resolver::{SecretsResolver, secrets::KeyType};

/// The mediator's TSP keys, derived from its DID document + operating secrets.
pub struct MediatorTspIdentity {
    /// The mediator's VID — its configured DID.
    pub vid: String,
    /// Ed25519 signing private key (from `authentication`).
    pub signing_key: [u8; 32],
    /// X25519 decryption/encryption private key (from `keyAgreement`).
    pub decryption_key: [u8; 32],
}

impl MediatorTspIdentity {
    /// Derive the mediator's TSP identity from its DID document and operating
    /// secrets. Fails with a config error if the DID can't be resolved or its
    /// document lacks an Ed25519 authentication / X25519 keyAgreement key whose
    /// private half the mediator holds.
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
                    format!("couldn't resolve mediator DID {did} to derive its TSP identity: {e}"),
                )
            })?
            .doc;

        let signing_key =
            first_private_key(doc.find_authentication(None), secrets, KeyType::Ed25519)
                .await
                .ok_or_else(|| {
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!(
                            "mediator DID {did} has no Ed25519 authentication key for TSP relay"
                        ),
                    )
                })?;
        let decryption_key =
            first_private_key(doc.find_key_agreement(None), secrets, KeyType::X25519)
                .await
                .ok_or_else(|| {
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!("mediator DID {did} has no X25519 keyAgreement key for TSP relay"),
                    )
                })?;

        Ok(Self {
            vid: did.to_string(),
            signing_key,
            decryption_key,
        })
    }
}

/// First verification-method `kid` whose secret is of `want` type, as a raw
/// 32-byte private key.
async fn first_private_key(
    kids: Vec<&str>,
    secrets: &impl SecretsResolver,
    want: KeyType,
) -> Option<[u8; 32]> {
    for kid in kids {
        if let Some(secret) = secrets.get_secret(kid).await
            && secret.get_key_type() == want
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
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use affinidi_secrets_resolver::{ThreadedSecretsResolver, secrets::Secret};

    /// `derive` extracts the Ed25519 key from `authentication` and the X25519 key
    /// from `keyAgreement`, keyed by the document's published verification-method
    /// ids. Uses a `did:key` (resolved locally) and secrets keyed under its actual
    /// kids — proving the extraction picks the right key per relationship + type.
    #[tokio::test]
    async fn derive_extracts_signing_and_decryption_keys() {
        const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let doc = resolver.resolve(DID_KEY).await.unwrap().doc;
        let auth_kid = doc
            .find_authentication(None)
            .first()
            .copied()
            .expect("did:key publishes an authentication key")
            .to_string();
        let ka_kid = doc
            .find_key_agreement(None)
            .first()
            .copied()
            .expect("did:key publishes a keyAgreement key")
            .to_string();

        let ed = Secret::generate_ed25519(Some(&auth_kid), Some(&[3u8; 32]));
        let x = Secret::generate_x25519(Some(&ka_kid), Some(&[5u8; 32])).unwrap();
        let expected_signing: [u8; 32] = ed.get_private_bytes().try_into().unwrap();
        let expected_decryption: [u8; 32] = x.get_private_bytes().try_into().unwrap();

        let (secrets, _h) = ThreadedSecretsResolver::new(None).await;
        secrets.insert_vec(&[ed, x]).await;

        let identity = MediatorTspIdentity::derive(DID_KEY, &resolver, &secrets)
            .await
            .expect("derive the mediator TSP identity");

        assert_eq!(identity.vid, DID_KEY);
        assert_eq!(
            identity.signing_key, expected_signing,
            "Ed25519 from authentication"
        );
        assert_eq!(
            identity.decryption_key, expected_decryption,
            "X25519 from keyAgreement"
        );
    }

    /// A document whose keys the mediator doesn't hold yields a clear config error.
    #[tokio::test]
    async fn derive_errors_when_secrets_missing() {
        const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let (secrets, _h) = ThreadedSecretsResolver::new(None).await;

        assert!(
            MediatorTspIdentity::derive(DID_KEY, &resolver, &secrets)
                .await
                .is_err(),
            "no operating secrets → derivation fails"
        );
    }
}
