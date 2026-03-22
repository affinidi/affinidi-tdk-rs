/*!
 * Pluggable hash functions for SD-JWT disclosure digests.
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Trait for hash functions used to compute disclosure digests.
pub trait SdHasher: Send + Sync {
    /// The hash algorithm name as registered in IANA (e.g. "sha-256").
    fn alg_name(&self) -> &str;

    /// Compute the raw hash of the input bytes.
    fn hash(&self, input: &[u8]) -> Vec<u8>;

    /// Compute the base64url-no-pad encoded hash of the input.
    fn hash_b64(&self, input: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.hash(input))
    }
}

/// SHA-256 hasher (default for SD-JWT).
#[derive(Debug, Clone, Default)]
pub struct Sha256Hasher;

impl SdHasher for Sha256Hasher {
    fn alg_name(&self) -> &str {
        "sha-256"
    }

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        Sha256::digest(input).to_vec()
    }
}

/// SHA-384 hasher.
#[derive(Debug, Clone, Default)]
pub struct Sha384Hasher;

impl SdHasher for Sha384Hasher {
    fn alg_name(&self) -> &str {
        "sha-384"
    }

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        Sha384::digest(input).to_vec()
    }
}

/// SHA-512 hasher.
#[derive(Debug, Clone, Default)]
pub struct Sha512Hasher;

impl SdHasher for Sha512Hasher {
    fn alg_name(&self) -> &str {
        "sha-512"
    }

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        Sha512::digest(input).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        let hasher = Sha256Hasher;
        assert_eq!(hasher.alg_name(), "sha-256");
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = hasher.hash(b"");
        assert_eq!(hash.len(), 32);
        assert_eq!(
            hex::encode(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha384_output_length() {
        let hasher = Sha384Hasher;
        assert_eq!(hasher.alg_name(), "sha-384");
        assert_eq!(hasher.hash(b"test").len(), 48);
    }

    #[test]
    fn sha512_output_length() {
        let hasher = Sha512Hasher;
        assert_eq!(hasher.alg_name(), "sha-512");
        assert_eq!(hasher.hash(b"test").len(), 64);
    }

    #[test]
    fn hash_b64_is_url_safe_no_pad() {
        let hasher = Sha256Hasher;
        let result = hasher.hash_b64(b"test");
        // No padding characters
        assert!(!result.contains('='));
        // No standard base64 chars
        assert!(!result.contains('+'));
        assert!(!result.contains('/'));
    }

    // Hex helper for tests only
    mod hex {
        pub fn encode(data: &[u8]) -> String {
            data.iter().map(|b| format!("{b:02x}")).collect()
        }
    }
}
