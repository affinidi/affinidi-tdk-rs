//! Trust Spanning Protocol (TSP) client support.
//!
//! Accessed via [`crate::ATM::tsp`]. The TSP sibling of `atm.routing()` etc.
//!
//! ## Storage-format codec
//!
//! A mediator stores a TSP message `base64url(qb2)` — its CESR **qb64** text form
//! (`1AAF…`) — so it rides the same string store/pickup pipeline as a DIDComm
//! JSON envelope. [`TspOps::is_tsp`] / [`TspOps::decode`] / [`TspOps::encode`]
//! convert a fetched message to/from raw qb2 bytes.
//!
//! ## Send / receive
//!
//! [`TspOps::pack`] builds a TSP **Direct** message from a profile to a recipient
//! DID (extracting the profile's Ed25519 signing + X25519 encryption keys from
//! the secrets resolver, and resolving the recipient's keys from its DID
//! document). [`TspOps::send`] packs and POSTs it to the mediator `/inbound`
//! (reusing the existing DIDComm-authenticated session — the mediator sniffs the
//! `0xD4` magic byte and routes it to its TSP handler). [`TspOps::unpack`]
//! reverses a fetched message: decode → resolve the sender → decrypt + verify
//! with the profile's key.

use std::sync::Arc;

use affinidi_did_common::DocumentExt;
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::KeyType;
use affinidi_tsp::message::direct;
use affinidi_tsp::{DidVidResolver, MessageType, MetaEnvelope};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use tracing::debug;

use crate::ATM;
use crate::errors::ATMError;
use crate::profiles::ATMProfile;

/// TSP protocol operations, obtained from [`crate::ATM::tsp`].
pub struct TspOps<'a> {
    pub(crate) atm: &'a ATM,
}

impl TspOps<'_> {
    // ── Storage-format codec ────────────────────────────────────────────────

    /// Whether a fetched/stored message is a TSP message (base64url-decode +
    /// magic-byte check). DIDComm JSON / compact JWS is not valid base64url of a
    /// TSP message, so it returns `false`.
    pub fn is_tsp(&self, stored: &str) -> bool {
        BASE64_URL_SAFE_NO_PAD
            .decode(stored.as_bytes())
            .map(|bytes| affinidi_tsp::is_tsp(&bytes))
            .unwrap_or(false)
    }

    /// Decode a stored TSP message (`base64url(qb2)`) back to its raw qb2 bytes.
    pub fn decode(&self, stored: &str) -> Result<Vec<u8>, ATMError> {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(stored.as_bytes())
            .map_err(|e| ATMError::MsgReceiveError(format!("not valid base64url: {e}")))?;
        if !affinidi_tsp::is_tsp(&bytes) {
            return Err(ATMError::MsgReceiveError(
                "decoded bytes are not a TSP message".into(),
            ));
        }
        Ok(bytes)
    }

    /// Encode raw qb2 TSP bytes to the stored/transit string form.
    pub fn encode(&self, qb2: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(qb2)
    }

    // ── Send / receive ──────────────────────────────────────────────────────

    /// Build a TSP **Direct** message from `profile` to `to_did` carrying
    /// `payload`, returning the raw qb2 bytes.
    pub async fn pack(
        &self,
        profile: &Arc<ATMProfile>,
        to_did: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, ATMError> {
        let (from_did, _) = profile.dids()?;
        let (signing_key, decryption_key) = self.profile_tsp_keys(from_did).await?;
        let recipient = self.resolve_vid(to_did).await?;

        let packed = direct::pack(
            payload,
            MessageType::Direct,
            from_did,
            to_did,
            &signing_key,
            &decryption_key,
            &recipient.encryption_key,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack TSP message: {e}")))?;

        Ok(packed.bytes)
    }

    /// Pack a TSP Direct message and send it to the mediator `/inbound`.
    ///
    /// Reuses the profile's existing (DIDComm) authenticated session for the
    /// bearer token; the mediator sniffs the TSP magic byte and routes it to its
    /// TSP handler.
    pub async fn send(
        &self,
        profile: &Arc<ATMProfile>,
        to_did: &str,
        payload: &[u8],
    ) -> Result<(), ATMError> {
        let bytes = self.pack(profile, to_did, payload).await?;

        let mediator_url = profile.get_mediator_rest_endpoint().ok_or_else(|| {
            ATMError::MsgSendError("Profile is missing a valid mediator URL".into())
        })?;
        let (profile_did, mediator_did) = profile.dids()?;
        let tokens = self
            .atm
            .get_tdk()
            .authentication()
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;

        let res = self
            .atm
            .inner
            .tdk_common
            .client()
            .post([&mediator_url, "/inbound"].concat())
            .header("Content-Type", "application/tsp")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(bytes)
            .send()
            .await
            .map_err(|e| ATMError::TransportError(format!("Could not send TSP message: {e:?}")))?;

        let status = res.status();
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(ATMError::TransportError(format!(
                "Mediator rejected TSP message: status({status}), body({body})"
            )));
        }
        debug!("TSP message sent to {to_did}");
        Ok(())
    }

    /// Unpack a fetched TSP message (stored `base64url(qb2)`): decode, resolve the
    /// sender's keys, then decrypt + verify with the profile's decryption key.
    /// Returns `(payload, sender_vid)`.
    pub async fn unpack(
        &self,
        profile: &Arc<ATMProfile>,
        stored: &str,
    ) -> Result<(Vec<u8>, String), ATMError> {
        let qb2 = self.decode(stored)?;
        let meta = MetaEnvelope::parse(&qb2)
            .map_err(|e| ATMError::MsgReceiveError(format!("couldn't parse TSP envelope: {e}")))?;

        let (profile_did, _) = profile.dids()?;
        if meta.receiver != profile_did {
            return Err(ATMError::MsgReceiveError(format!(
                "TSP message addressed to {}, not this profile ({profile_did})",
                meta.receiver
            )));
        }

        let (_signing_key, decryption_key) = self.profile_tsp_keys(profile_did).await?;
        let sender = self.resolve_vid(&meta.sender).await?;

        let unpacked = direct::unpack(
            &qb2,
            &decryption_key,
            &sender.encryption_key,
            &sender.signing_key,
        )
        .map_err(|e| ATMError::MsgReceiveError(format!("couldn't unpack TSP message: {e}")))?;

        Ok((unpacked.payload, unpacked.sender))
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// Resolve a DID-based VID to its TSP public keys + endpoints.
    async fn resolve_vid(&self, did: &str) -> Result<affinidi_tsp::ResolvedVid, ATMError> {
        let resolver = DidVidResolver::new(self.atm.inner.tdk_common.did_resolver().clone());
        resolver
            .resolve_did(did)
            .await
            .map_err(|e| ATMError::DIDError(format!("couldn't resolve TSP VID {did}: {e}")))
    }

    /// Extract this profile's TSP private keys `(signing_key, decryption_key)`:
    /// the Ed25519 key from its `authentication` relationship and the X25519 key
    /// from its `keyAgreement`, pulled from the secrets resolver.
    async fn profile_tsp_keys(&self, did: &str) -> Result<([u8; 32], [u8; 32]), ATMError> {
        let doc = self
            .atm
            .inner
            .tdk_common
            .did_resolver()
            .resolve(did)
            .await
            .map_err(|e| ATMError::DIDError(format!("couldn't resolve own DID {did}: {e}")))?
            .doc;

        let signing_key = self
            .first_private_key(doc.find_authentication(None), KeyType::Ed25519)
            .await
            .ok_or_else(|| {
                ATMError::SecretsError(format!("no Ed25519 authentication key for {did}"))
            })?;
        let decryption_key = self
            .first_private_key(doc.find_key_agreement(None), KeyType::X25519)
            .await
            .ok_or_else(|| {
                ATMError::SecretsError(format!("no X25519 keyAgreement key for {did}"))
            })?;
        Ok((signing_key, decryption_key))
    }

    /// First verification-method `kid` whose secret is of `want` type, as a raw
    /// 32-byte private key.
    async fn first_private_key(&self, kids: Vec<&str>, want: KeyType) -> Option<[u8; 32]> {
        for kid in kids {
            if let Some(secret) = self.atm.inner.tdk_common.secrets_resolver().get_secret(kid).await
                && secret.get_key_type() == want
                && let Ok(bytes) = <[u8; 32]>::try_from(secret.get_private_bytes())
            {
                return Some(bytes);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use affinidi_tsp::message::direct;
    use affinidi_tsp::{MessageType, PrivateVid};
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    fn is_tsp(stored: &str) -> bool {
        BASE64_URL_SAFE_NO_PAD
            .decode(stored.as_bytes())
            .map(|b| affinidi_tsp::is_tsp(&b))
            .unwrap_or(false)
    }

    /// Codec + a pack/unpack round-trip using `direct::pack`/`unpack` with the
    /// same keys the `TspOps` pack/unpack drive through the secrets resolver and
    /// DID resolution. (The full profile/mediator path is exercised by the
    /// end-to-end test in `affinidi-messaging-test-mediator`.)
    #[test]
    fn pack_unpack_roundtrip_via_codec() {
        let alice = PrivateVid::generate("did:example:alice");
        let bob = PrivateVid::generate("did:example:bob");

        // alice packs to bob (as TspOps::pack does, with direct::pack).
        let packed = direct::pack(
            b"secret payload",
            MessageType::Direct,
            "did:example:alice",
            "did:example:bob",
            &alice.signing_key,
            &alice.decryption_key,
            &bob.encryption_key,
        )
        .unwrap();

        // Stored/transit form, recognised on pickup.
        let stored = BASE64_URL_SAFE_NO_PAD.encode(&packed.bytes);
        assert!(is_tsp(&stored));
        let qb2 = BASE64_URL_SAFE_NO_PAD.decode(stored.as_bytes()).unwrap();

        // bob unpacks (as TspOps::unpack does, with direct::unpack).
        let unpacked =
            direct::unpack(&qb2, &bob.decryption_key, &alice.encryption_key, &alice.verifying_key)
                .unwrap();
        assert_eq!(unpacked.payload, b"secret payload");
        assert_eq!(unpacked.sender, "did:example:alice");
        assert_eq!(unpacked.receiver, "did:example:bob");
    }

    #[test]
    fn rejects_didcomm_and_garbage() {
        assert!(!is_tsp("{\"protected\":\"...\"}"));
        assert!(!is_tsp("eyJhbGciOiJ..."));
        assert!(!is_tsp(""));
    }
}
