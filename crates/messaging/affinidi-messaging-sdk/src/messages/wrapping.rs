//! DIDComm message *wrapping types* — the envelope-combination taxonomy from
//! the DIDComm v2 IANA media types.
//!
//! A message is unwrapped into an ordered stack of cryptographic layers
//! (outer → inner). [`MessageWrappingType::classify`] collapses that stack
//! into a single named wrapping so an [`crate::config::UnpackPolicy`] can
//! accept or reject it (downgrade-attack prevention), and so consumers can
//! reason about the security guarantees a received message actually carries.

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

impl MessageWrappingType {
    /// Classify an unwrapped layer stack into a wrapping type.
    ///
    /// `enc_layers` lists the encryption layers outermost-first; `signed`
    /// indicates whether a JWS signature layer wrapped the plaintext. Returns
    /// `None` for a layer combination outside the DIDComm-defined taxonomy
    /// (e.g. two authcrypt layers, or a signature outside all encryption).
    pub fn classify(enc_layers: &[EncLayerKind], signed: bool) -> Option<Self> {
        use EncLayerKind::{Anoncrypt, Authcrypt};
        match (enc_layers, signed) {
            ([], false) => Some(Self::Plaintext),
            ([], true) => Some(Self::SignedPlaintext),
            ([Anoncrypt], false) => Some(Self::AnoncryptPlaintext),
            ([Authcrypt], false) => Some(Self::AuthcryptPlaintext),
            ([Anoncrypt], true) => Some(Self::AnoncryptSignPlaintext),
            ([Authcrypt], true) => Some(Self::AuthcryptSignPlaintext),
            ([Anoncrypt, Authcrypt], false) => Some(Self::AnoncryptAuthcryptPlaintext),
            // `anoncrypt(authcrypt(sign(plaintext)))` is explicitly a MUST NOT
            // in the DIDComm v2 spec (§IANA Media Types); reject it.
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
    use EncLayerKind::{Anoncrypt, Authcrypt};

    #[test]
    fn classify_covers_the_taxonomy() {
        assert_eq!(
            MessageWrappingType::classify(&[], false),
            Some(MessageWrappingType::Plaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[], true),
            Some(MessageWrappingType::SignedPlaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[Anoncrypt], false),
            Some(MessageWrappingType::AnoncryptPlaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[Authcrypt], false),
            Some(MessageWrappingType::AuthcryptPlaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[Anoncrypt], true),
            Some(MessageWrappingType::AnoncryptSignPlaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[Authcrypt], true),
            Some(MessageWrappingType::AuthcryptSignPlaintext)
        );
        assert_eq!(
            MessageWrappingType::classify(&[Anoncrypt, Authcrypt], false),
            Some(MessageWrappingType::AnoncryptAuthcryptPlaintext)
        );
    }

    #[test]
    fn classify_rejects_undefined_combos() {
        // Two authcrypt layers, or authcrypt-then-anoncrypt, are not in the taxonomy.
        assert_eq!(
            MessageWrappingType::classify(&[Authcrypt, Authcrypt], false),
            None
        );
        assert_eq!(
            MessageWrappingType::classify(&[Authcrypt, Anoncrypt], false),
            None
        );
        // `anoncrypt(authcrypt(sign(plaintext)))` — the DIDComm v2 spec
        // explicitly says this MUST NOT be used; classify must reject it.
        assert_eq!(
            MessageWrappingType::classify(&[Anoncrypt, Authcrypt], true),
            None
        );
    }
}
