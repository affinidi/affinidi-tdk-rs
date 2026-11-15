//! `did:key` framing: `did:key:` followed by a base58btc multikey.
//!
//! These helpers only frame and validate bytes (multibase, multicodec and the
//! codec's key length). They do not check that the key is a valid curve point.
//!
//! See: <https://w3c-ccg.github.io/did-key-spec/>

use crate::EncodingError;
use crate::multibase::{decode_multikey_checked, decode_multikey_expecting, encode_multikey};
use crate::multicodec::Codec;

/// The `did:key` method prefix.
pub const DID_KEY_PREFIX: &str = "did:key:";

/// Strip the `did:key:` prefix, returning the multikey.
fn multikey(did: &str) -> Result<&str, EncodingError> {
    did.strip_prefix(DID_KEY_PREFIX)
        .ok_or_else(|| EncodingError::InvalidDidKey(format!("expected '{DID_KEY_PREFIX}' prefix")))
}

/// Decode a `did:key` DID to its codec and key bytes, enforcing the codec's
/// key length as [`decode_multikey_checked`] does.
///
/// The input is the bare DID: a DID URL with a `#fragment` or path is not
/// accepted. Strip the fragment first if you hold a verification-method id.
pub fn decode(did: &str) -> Result<(Codec, Vec<u8>), EncodingError> {
    decode_multikey_checked(multikey(did)?)
}

/// Decode a `did:key` DID that must carry the `expected` codec, returning its
/// key bytes with the codec's key length enforced.
pub fn decode_expecting(did: &str, expected: Codec) -> Result<Vec<u8>, EncodingError> {
    decode_multikey_expecting(multikey(did)?, expected)
}

/// Encode key bytes under the given multicodec as a `did:key` DID.
pub fn encode(codec: u64, key_bytes: &[u8]) -> String {
    format!("{DID_KEY_PREFIX}{}", encode_multikey(codec, key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ED25519_PUB, X25519_PUB};

    #[test]
    fn round_trip() {
        let did = encode(ED25519_PUB, &[3u8; 32]);
        assert!(did.starts_with("did:key:z6Mk"));
        assert_eq!(decode(&did).unwrap(), (Codec::Ed25519Pub, vec![3u8; 32]));
        assert_eq!(
            decode_expecting(&did, Codec::Ed25519Pub).unwrap(),
            [3u8; 32]
        );
    }

    #[test]
    fn known_vector() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let (codec, bytes) = decode(did).unwrap();
        assert_eq!(codec, Codec::Ed25519Pub);
        assert_eq!(encode(ED25519_PUB, &bytes), did);
    }

    #[test]
    fn refuses_bad_framing() {
        assert!(matches!(
            decode("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap_err(),
            EncodingError::InvalidDidKey(_)
        ));
        assert!(matches!(
            decode("did:key:6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap_err(),
            EncodingError::InvalidMultibasePrefix('6')
        ));
        let truncated = encode(ED25519_PUB, &[3u8; 16]);
        assert!(matches!(
            decode(&truncated).unwrap_err(),
            EncodingError::InvalidKeyLength { .. }
        ));
        let other = encode(X25519_PUB, &[3u8; 32]);
        assert!(matches!(
            decode_expecting(&other, Codec::Ed25519Pub).unwrap_err(),
            EncodingError::UnexpectedCodec { .. }
        ));
    }
}
