/*!
 * BBS ciphersuite definitions per IETF draft §4.
 *
 * Two ciphersuites are defined:
 * - **BLS12-381-SHA-256**: Uses SHA-256 (XMD) for expand_message
 * - **BLS12-381-SHAKE-256**: Uses SHAKE-256 (XOF) for expand_message
 *
 * The ciphersuite determines the hash function, scalar length, and
 * ciphersuite-specific identifiers used throughout the BBS protocol.
 */

/// A BBS ciphersuite configuration.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Ciphersuite {
    /// BLS12-381 with SHA-256 (XMD).
    #[default]
    Bls12381Sha256,
    /// BLS12-381 with SHAKE-256 (XOF).
    Bls12381Shake256,
}

impl Ciphersuite {
    /// Reject ciphersuites that are *defined* by this enum but **not implemented**
    /// by the hash layer.
    ///
    /// `Bls12381Shake256` carries the SHAKE-256 id strings and a 64-byte scalar
    /// length, but every hashing path (`hash::hash_to_scalar`,
    /// `generators::create_generators*`, `hash::expand_msg_xmd`) is
    /// SHA-256/XMD-only. Running it would silently emit SHA-256 output under a
    /// SHAKE domain-separation tag, truncated to 32-byte scalars — a result that
    /// is neither correct nor interoperable. Fail loudly instead of producing
    /// wrong cryptographic output. See `docs/security/bbs-audit-readiness.md` §5(4).
    pub fn ensure_supported(&self) -> crate::error::Result<()> {
        match self {
            Self::Bls12381Sha256 => Ok(()),
            Self::Bls12381Shake256 => Err(crate::error::BbsError::Unsupported(
                "BLS12-381-SHAKE-256 ciphersuite is not implemented (the hash \
                 layer is SHA-256/XMD only); use Ciphersuite::Bls12381Sha256"
                    .into(),
            )),
        }
    }

    /// The ciphersuite identifier string.
    pub fn id(&self) -> &'static str {
        match self {
            Self::Bls12381Sha256 => "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
            Self::Bls12381Shake256 => "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_",
        }
    }

    /// The API identifier (ciphersuite_id || "H2G_HM2S_").
    pub fn api_id(&self) -> Vec<u8> {
        let mut id = self.id().as_bytes().to_vec();
        id.extend_from_slice(b"H2G_HM2S_");
        id
    }

    /// The blind-BBS API identifier (ciphersuite_id || "BLIND_H2G_HM2S_").
    ///
    /// Per `draft-irtf-cfrg-bbs-blind-signatures`, blind issuance namespaces its
    /// generators and hashing under this api_id (distinct from the core
    /// [`api_id`](Self::api_id)); the blind generators prepend a further
    /// `"BLIND_"` to it.
    pub fn blind_api_id(&self) -> Vec<u8> {
        let mut id = self.id().as_bytes().to_vec();
        id.extend_from_slice(b"BLIND_H2G_HM2S_");
        id
    }

    /// The per-verifier-pseudonym API identifier
    /// (ciphersuite_id || "H2G_HM2S_PSEUDONYM_").
    ///
    /// Per `draft-irtf-cfrg-bbs-per-verifier-linkability`, nym issuance/proof
    /// namespaces its generators and hashing under this api_id (distinct from
    /// both [`api_id`](Self::api_id) and [`blind_api_id`](Self::blind_api_id));
    /// its blind (committed-message) generators prepend `"BLIND_"` to it.
    pub fn pseudonym_api_id(&self) -> Vec<u8> {
        let mut id = self.id().as_bytes().to_vec();
        id.extend_from_slice(b"H2G_HM2S_PSEUDONYM_");
        id
    }

    /// The octet length of a scalar in the output.
    pub fn octet_scalar_length(&self) -> usize {
        match self {
            Self::Bls12381Sha256 => 32,
            Self::Bls12381Shake256 => 64,
        }
    }

    /// The expand length for hash_to_scalar.
    pub fn expand_len(&self) -> usize {
        // expand_len = ceil((ceil(log2(r)) + k) / 8) where k=128
        // For BLS12-381: ceil((255 + 128) / 8) = ceil(383/8) = 48
        48
    }

    /// The point serialization length (compressed G1).
    pub fn octet_point_length(&self) -> usize {
        48
    }

    /// The signature byte length.
    pub fn signature_length(&self) -> usize {
        self.octet_point_length() + self.octet_scalar_length()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_suite_properties() {
        let cs = Ciphersuite::Bls12381Sha256;
        assert_eq!(cs.octet_scalar_length(), 32);
        assert_eq!(cs.octet_point_length(), 48);
        assert_eq!(cs.signature_length(), 80);
        assert_eq!(cs.expand_len(), 48);
    }

    #[test]
    fn shake256_suite_properties() {
        let cs = Ciphersuite::Bls12381Shake256;
        assert_eq!(cs.octet_scalar_length(), 64);
        assert_eq!(cs.signature_length(), 112);
    }

    #[test]
    fn api_id_suffix() {
        let cs = Ciphersuite::Bls12381Sha256;
        let api_id = cs.api_id();
        assert!(api_id.ends_with(b"H2G_HM2S_"));
    }

    #[test]
    fn sha256_is_supported_shake256_is_not() {
        assert!(Ciphersuite::Bls12381Sha256.ensure_supported().is_ok());
        // SHAKE-256 is defined but unimplemented — must fail loudly rather than
        // silently emit SHA-256 output (audit Finding §5(4)).
        assert!(matches!(
            Ciphersuite::Bls12381Shake256.ensure_supported(),
            Err(crate::error::BbsError::Unsupported(_))
        ));
    }
}
