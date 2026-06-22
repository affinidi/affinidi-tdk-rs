//! Trust Spanning Protocol (TSP) client support.
//!
//! Accessed via [`crate::ATM::tsp`]. This is the SDK's TSP entry point, the
//! sibling of `atm.routing()` etc. for the DIDComm protocols.
//!
//! This first slice provides the **storage-format codec** the SDK needs to
//! recognise and decode TSP messages on pickup. A mediator stores a TSP message
//! `base64url(qb2)` — which is its CESR **qb64** text form (`1AAF…`) — so it
//! rides the same string store/pickup pipeline as a DIDComm JSON envelope (see
//! `affinidi-messaging-mediator` 0.16.6). When a client fetches messages it gets
//! a mix of DIDComm JSON (`{…}` / `ey…`) and TSP qb64 (`1AAF…`) strings;
//! [`TspOps::is_tsp`] tells them apart and [`TspOps::decode`] recovers the qb2
//! bytes for unpacking.
//!
//! The TSP message-construction (pack/send) and decrypt (unpack) paths build on
//! this codec and land in a later change.

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

use crate::ATM;

/// TSP protocol operations, obtained from [`crate::ATM::tsp`].
pub struct TspOps<'a> {
    #[allow(dead_code)]
    pub(crate) atm: &'a ATM,
}

impl TspOps<'_> {
    /// Whether a fetched/stored message is a TSP message.
    ///
    /// The mediator stores TSP messages base64url-encoded; this base64url-decodes
    /// and checks for the TSP magic byte. A DIDComm JSON envelope (`{…}`) or
    /// compact JWS/JWE (`ey…`) is not valid base64url of a TSP message, so it
    /// returns `false`. Cheap and key-free — for routing a fetched message to the
    /// TSP vs DIDComm unpack path.
    pub fn is_tsp(&self, stored: &str) -> bool {
        BASE64_URL_SAFE_NO_PAD
            .decode(stored.as_bytes())
            .map(|bytes| affinidi_tsp::is_tsp(&bytes))
            .unwrap_or(false)
    }

    /// Decode a stored TSP message (`base64url(qb2)` / CESR qb64 text) back to its
    /// raw qb2 bytes, ready to hand to a TSP unpack. Errors if the input is not
    /// valid base64url of a TSP message.
    pub fn decode(&self, stored: &str) -> Result<Vec<u8>, crate::errors::ATMError> {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(stored.as_bytes())
            .map_err(|e| crate::errors::ATMError::MsgSendError(format!("not valid base64url: {e}")))?;
        if !affinidi_tsp::is_tsp(&bytes) {
            return Err(crate::errors::ATMError::MsgSendError(
                "decoded bytes are not a TSP message".into(),
            ));
        }
        Ok(bytes)
    }

    /// Encode raw qb2 TSP bytes to the stored/transit string form
    /// (`base64url(qb2)` = CESR qb64 text), as the mediator stores them.
    pub fn encode(&self, qb2: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(qb2)
    }
}

#[cfg(test)]
mod tests {
    use affinidi_tsp::message::direct;
    use affinidi_tsp::{MessageType, PrivateVid};
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    // The codec functions are pure, so test them without an ATM instance.
    fn is_tsp(stored: &str) -> bool {
        BASE64_URL_SAFE_NO_PAD
            .decode(stored.as_bytes())
            .map(|b| affinidi_tsp::is_tsp(&b))
            .unwrap_or(false)
    }

    fn packed_tsp() -> Vec<u8> {
        let alice = PrivateVid::generate("did:example:alice");
        let bob = PrivateVid::generate("did:example:bob");
        direct::pack(
            b"hi",
            MessageType::Direct,
            "did:example:alice",
            "did:example:bob",
            &alice.signing_key,
            &alice.decryption_key,
            &bob.encryption_key,
        )
        .unwrap()
        .bytes
    }

    #[test]
    fn recognises_and_roundtrips_tsp() {
        let qb2 = packed_tsp();
        let stored = BASE64_URL_SAFE_NO_PAD.encode(&qb2);

        assert!(is_tsp(&stored), "a stored TSP message is recognised");
        assert!(stored.starts_with("1AAF"), "stored form is CESR qb64 text");
        // Decode round-trips back to the exact qb2 bytes.
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(stored.as_bytes()).unwrap();
        assert_eq!(decoded, qb2);
    }

    #[test]
    fn rejects_didcomm_and_garbage() {
        assert!(!is_tsp("{\"protected\":\"...\"}"), "DIDComm JSON is not TSP");
        assert!(!is_tsp("eyJhbGciOiJ..."), "compact JWS/JWE is not TSP");
        assert!(!is_tsp(""), "empty is not TSP");
    }
}
