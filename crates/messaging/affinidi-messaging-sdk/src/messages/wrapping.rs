//! DIDComm message *wrapping types* — the envelope-combination taxonomy from
//! the DIDComm v2 IANA media types.
//!
//! A message is unwrapped into an ordered stack of cryptographic layers
//! (outer → inner). [`MessageWrappingType::classify`] maps that *ordered* stack
//! into a single named wrapping so an [`crate::config::UnpackPolicy`] can
//! accept or reject it (downgrade-attack prevention), and so consumers can
//! reason about the security guarantees a received message actually carries.
//! Layer *order* is significant — `sign(authcrypt(pt))` and `authcrypt(sign(pt))`
//! are different envelopes and only the latter is a defined wrapping.

use serde::{Deserialize, Serialize};

/// The full combination of signing/encryption envelopes wrapping a plaintext
/// DIDComm message, outermost layer first in the name.
///
/// Layer semantics (per DIDComm v2 §IANA media types):
/// - `authcrypt` — authenticated encryption (ECDH-1PU): confidential + sender
///   authenticated to the recipient.
/// - `anoncrypt` — anonymous encryption (ECDH-ES): confidential, sender hidden.
/// - `sign` — a JWS signature layer: non-repudiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum MessageWrappingType {
    /// No protection. Sender-controlled, unauthenticated, unencrypted.
    #[default]
    Plaintext,
    /// `sign(plaintext)` — signed but not encrypted.
    SignedPlaintext,
    /// `anoncrypt(plaintext)` — anonymous encryption.
    AnoncryptPlaintext,
    /// `authcrypt(plaintext)` — authenticated encryption (the DIDComm v2
    /// default and the secure `unpack` default).
    AuthcryptPlaintext,
    /// `anoncrypt(sign(plaintext))` — confidential + non-repudiable, sender
    /// anonymous to intermediaries.
    AnoncryptSignPlaintext,
    /// `authcrypt(sign(plaintext))` — authenticated encryption over a signed
    /// message.
    AuthcryptSignPlaintext,
    /// `anoncrypt(authcrypt(plaintext))` — authcrypt wrapped in an anoncrypt
    /// layer that hides the sender key id (`skid`) from intermediaries.
    AnoncryptAuthcryptPlaintext,
}

/// A single decrypted encryption layer's authentication mode, in the order the
/// layers were removed (outermost first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncLayerKind {
    /// ECDH-ES (`anoncrypt`) — no bound sender.
    Anoncrypt,
    /// ECDH-1PU (`authcrypt`) — sender bound via `skid`.
    Authcrypt,
}

/// A single cryptographic layer removed while unwrapping a message, in
/// outermost-first order.
///
/// Records *where* a signature sat relative to the encryption layers, which the
/// taxonomy depends on: `authcrypt(sign(pt))` (signature inside) and
/// `sign(authcrypt(pt))` (signature outside) are different envelopes and only
/// the former is defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoLayer {
    /// A JWS signature layer.
    Sign,
    /// An encryption layer (JWE), tagged authcrypt (ECDH-1PU) or anoncrypt
    /// (ECDH-ES).
    Encrypted(EncLayerKind),
}

impl MessageWrappingType {
    /// Classify an unwrapped layer stack into a wrapping type.
    ///
    /// `layers` lists every cryptographic layer outermost-first, preserving
    /// each signature's position relative to the encryption layers. Returns
    /// `None` for any ordering outside the DIDComm-defined taxonomy, including:
    /// a signature *outside* all encryption (`sign(authcrypt(pt))`); a repeated
    /// encryption kind (`anoncrypt(anoncrypt(pt))`); the `authcrypt(anoncrypt(pt))`
    /// inversion; more than one signature layer; and the spec-forbidden (MUST
    /// NOT, DIDComm v2 §IANA Media Types) `anoncrypt(authcrypt(sign(pt)))` triple.
    pub fn classify(layers: &[CryptoLayer]) -> Option<Self> {
        use CryptoLayer::{Encrypted, Sign};
        use EncLayerKind::{Anoncrypt, Authcrypt};
        match layers {
            [] => Some(Self::Plaintext),
            [Sign] => Some(Self::SignedPlaintext),
            [Encrypted(Anoncrypt)] => Some(Self::AnoncryptPlaintext),
            [Encrypted(Authcrypt)] => Some(Self::AuthcryptPlaintext),
            // Signature *inside* the encryption (sign-then-encrypt) — the only
            // defined position for a signed-and-encrypted message.
            [Encrypted(Anoncrypt), Sign] => Some(Self::AnoncryptSignPlaintext),
            [Encrypted(Authcrypt), Sign] => Some(Self::AuthcryptSignPlaintext),
            // Nested encryption is defined *only* as anoncrypt-over-authcrypt
            // (hides the `skid` from intermediaries). Every other pairing —
            // `anoncrypt(anoncrypt)`, `authcrypt(anoncrypt)`, `authcrypt(authcrypt)`
            // — is rejected here.
            [Encrypted(Anoncrypt), Encrypted(Authcrypt)] => Some(Self::AnoncryptAuthcryptPlaintext),
            _ => None,
        }
    }

    /// Whether this wrapping carries a cryptographically authenticated sender
    /// (an authcrypt layer). `false` for plaintext, signed-only, and
    /// anoncrypt-only.
    pub fn is_authenticated(self) -> bool {
        matches!(
            self,
            Self::AuthcryptPlaintext
                | Self::AuthcryptSignPlaintext
                | Self::AnoncryptAuthcryptPlaintext
        )
    }

    /// Whether this wrapping carries a signature (non-repudiation) layer.
    pub fn is_signed(self) -> bool {
        matches!(
            self,
            Self::SignedPlaintext | Self::AnoncryptSignPlaintext | Self::AuthcryptSignPlaintext
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use CryptoLayer::{Encrypted, Sign};
    use EncLayerKind::{Anoncrypt, Authcrypt};

    #[test]
    fn classify_covers_the_taxonomy() {
        assert_eq!(
            MessageWrappingType::classify(&[]),
            Some(MessageWrappingType::Plaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[Sign]),
            Some(MessageWrappingType::SignedPlaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[Encrypted(Anoncrypt)]),
            Some(MessageWrappingType::AnoncryptPlaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[Encrypted(Authcrypt)]),
            Some(MessageWrappingType::AuthcryptPlaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[Encrypted(Anoncrypt), Sign]),
            Some(MessageWrappingType::AnoncryptSignPlaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[Encrypted(Authcrypt), Sign]),
            Some(MessageWrappingType::AuthcryptSignPlaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[Encrypted(Anoncrypt), Encrypted(Authcrypt)]),
            Some(MessageWrappingType::AnoncryptAuthcryptPlaintext)
        );
    }

    #[test]
    fn classify_rejects_undefined_combos() {
        // Nested encryption is only defined as anoncrypt-over-authcrypt; every
        // other pairing is outside the taxonomy.
        assert_eq!(
            MessageWrappingType::classify(&[Encrypted(Authcrypt), Encrypted(Authcrypt)]),
            None
        );
        assert_eq!(
            MessageWrappingType::classify(&[Encrypted(Anoncrypt), Encrypted(Anoncrypt)]),
            None
        );
        assert_eq!(
            MessageWrappingType::classify(&[Encrypted(Authcrypt), Encrypted(Anoncrypt)]),
            None
        );
        // `anoncrypt(authcrypt(sign(plaintext)))` — the DIDComm v2 spec
        // explicitly says this MUST NOT be used; classify must reject it.
        assert_eq!(
            MessageWrappingType::classify(&[Encrypted(Anoncrypt), Encrypted(Authcrypt), Sign]),
            None
        );
    }

    #[test]
    fn classify_is_order_sensitive_for_signatures() {
        // A signature *outside* the encryption is not a defined wrapping: an
        // intermediary could strip the outer JWS and forward the bare
        // encryption. Only sign-then-encrypt (signature inside) is defined, so
        // these must NOT collapse to the same wrapping.
        assert_eq!(
            MessageWrappingType::classify(&[Encrypted(Authcrypt), Sign]),
            Some(MessageWrappingType::AuthcryptSignPlaintext),
            "authcrypt(sign(pt)) — signature inside — is defined"
        );
        assert_eq!(
            MessageWrappingType::classify(&[Sign, Encrypted(Authcrypt)]),
            None,
            "sign(authcrypt(pt)) — signature outside — must be rejected"
        );
        assert_eq!(
            MessageWrappingType::classify(&[Sign, Encrypted(Anoncrypt)]),
            None,
            "sign(anoncrypt(pt)) — signature outside — must be rejected"
        );
        // More than one signature layer is also outside the taxonomy.
        assert_eq!(MessageWrappingType::classify(&[Sign, Sign]), None);
    }
}
