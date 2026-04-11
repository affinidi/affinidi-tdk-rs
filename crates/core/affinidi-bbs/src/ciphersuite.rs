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
}
