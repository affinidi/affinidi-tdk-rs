//! JOSE Concat KDF (NIST SP 800-56A single-pass, SHA-256).
//!
//! Two flavours, both stateless over the raw shared secret `z` (the
//! ECDH key-agreement step that produces `z` lands in a later #327 PR):
//!
//! - [`concat_kdf`] — ECDH-ES (RFC 7518 §4.6).
//! - [`concat_kdf_1pu`] — ECDH-1PU (draft-madden-jose-ecdh-1pu-04 §2.3),
//!   which appends the content-encryption authentication tag (`cc_tag`)
//!   as the final, **length-prefixed** OtherInfo field. The missing
//!   length prefix was bug #322; [`concat_kdf_1pu_legacy`] preserves the
//!   pre-fix behaviour for the decrypt-fallback migration path only.
//!
//! Both run the SP 800-56A §5.8.2.1 counter loop, so any whole-byte output
//! length up to [`MAX_KEY_LEN_BITS`] is supported. A length of zero, one
//! that is not a whole number of bytes, or one above the maximum is an
//! error. Byte-level output is locked by [`super::kat`].

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::CryptoError;

/// Largest output, in bits, either Concat KDF produces (64 SHA-256 rounds).
/// JOSE needs at most 512 bits (`A256CBC-HS512` with direct key agreement).
pub const MAX_KEY_LEN_BITS: u32 = 16_384;

/// JOSE Concat KDF for ECDH-ES (RFC 7518 §4.6).
///
/// For each round `i = 1, 2, …`: `SHA-256(i || Z || len‖AlgorithmID ||
/// len‖PartyUInfo || len‖PartyVInfo || keydatalen)`. The rounds are
/// concatenated and truncated to `key_len_bits`.
///
/// `key_len_bits` must be a non-zero multiple of 8, at most
/// [`MAX_KEY_LEN_BITS`]; anything else is [`CryptoError::KeyDerivation`].
pub fn concat_kdf(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
) -> Result<Vec<u8>, CryptoError> {
    derive(z, alg, apu, apv, key_len_bits, None)
}

/// JOSE Concat KDF for ECDH-1PU. The content-encryption authentication
/// tag is fed as the final OtherInfo entry, **length-prefixed** with a
/// 32-bit big-endian length exactly like every other variable-length
/// field (draft-madden-jose-ecdh-1pu-04 §2.3 / Appendix B.9; matches
/// askar / didcomm-python). An empty `cc_tag` is identical to
/// [`concat_kdf`]. `key_len_bits` is checked as in [`concat_kdf`].
pub fn concat_kdf_1pu(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
    cc_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    concat_kdf_1pu_inner(z, alg, apu, apv, key_len_bits, cc_tag, false)
}

/// Pre-fix ECDH-1PU Concat KDF that fed `cc_tag` **without** a length
/// prefix — non-conformant, see #322. Retained only for the decrypt
/// fallback during migration; never use it for packing.
pub fn concat_kdf_1pu_legacy(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
    cc_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    concat_kdf_1pu_inner(z, alg, apu, apv, key_len_bits, cc_tag, true)
}

fn concat_kdf_1pu_inner(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
    cc_tag: &[u8],
    legacy_tag_encoding: bool,
) -> Result<Vec<u8>, CryptoError> {
    // No tag — identical to standard Concat KDF (matches ECDH-ES). The
    // legacy/spec distinction only concerns the tag encoding, so an empty
    // tag is identical either way.
    let tag = (!cc_tag.is_empty()).then_some(CcTag {
        value: cc_tag,
        length_prefixed: !legacy_tag_encoding,
    });
    derive(z, alg, apu, apv, key_len_bits, tag)
}

/// The ECDH-1PU SuppPrivInfo entry. The legacy encoding omits the length
/// prefix (#322) and exists only for the decrypt fallback.
struct CcTag<'a> {
    value: &'a [u8],
    length_prefixed: bool,
}

fn output_len_bytes(key_len_bits: u32) -> Result<usize, CryptoError> {
    if key_len_bits == 0 || key_len_bits % 8 != 0 || key_len_bits > MAX_KEY_LEN_BITS {
        return Err(CryptoError::KeyDerivation(format!(
            "Concat KDF output length must be a non-zero multiple of 8 bits, at most \
             {MAX_KEY_LEN_BITS}; got {key_len_bits}"
        )));
    }
    Ok((key_len_bits / 8) as usize)
}

fn derive(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
    cc_tag: Option<CcTag<'_>>,
) -> Result<Vec<u8>, CryptoError> {
    let key_len_bytes = output_len_bytes(key_len_bits)?;
    let mut derived = Vec::with_capacity(key_len_bytes);

    let mut round: u32 = 1;
    while derived.len() < key_len_bytes {
        let mut hasher = Sha256::new();
        hasher.update(round.to_be_bytes());
        hasher.update(z);
        hasher.update((alg.len() as u32).to_be_bytes());
        hasher.update(alg);
        hasher.update((apu.len() as u32).to_be_bytes());
        hasher.update(apu);
        hasher.update((apv.len() as u32).to_be_bytes());
        hasher.update(apv);
        // SuppPubInfo: the output length in bits.
        hasher.update(key_len_bits.to_be_bytes());
        if let Some(tag) = &cc_tag {
            if tag.length_prefixed {
                hasher.update((tag.value.len() as u32).to_be_bytes());
            }
            hasher.update(tag.value);
        }

        let mut block = hasher.finalize();
        let take = (key_len_bytes - derived.len()).min(block.len());
        derived.extend_from_slice(&block[..take]);
        block[..].zeroize();
        round += 1;
    }

    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_lengths_that_are_not_whole_bytes_or_out_of_range() {
        for bits in [0, 1, 7, 9, 255, 257, MAX_KEY_LEN_BITS + 8, u32::MAX] {
            for result in [
                concat_kdf(b"z", b"alg", b"", b"", bits),
                concat_kdf_1pu(b"z", b"alg", b"", b"", bits, b"tag"),
                concat_kdf_1pu_legacy(b"z", b"alg", b"", b"", bits, b"tag"),
            ] {
                assert!(
                    matches!(result, Err(CryptoError::KeyDerivation(_))),
                    "{bits} bits: {result:?}"
                );
            }
        }
    }

    #[test]
    fn every_whole_byte_length_up_to_the_maximum_has_that_length() {
        for bits in (8..=MAX_KEY_LEN_BITS).step_by(8) {
            let derived = concat_kdf(b"z", b"alg", b"", b"", bits).unwrap();
            assert_eq!(derived.len() * 8, bits as usize);
            let derived = concat_kdf_1pu(b"z", b"alg", b"", b"", bits, b"tag").unwrap();
            assert_eq!(derived.len() * 8, bits as usize);
        }
    }

    // Expected values computed independently from the SP 800-56A §5.8.2.1
    // definition (Python `hashlib.sha256`, rounds concatenated and
    // truncated).
    #[test]
    fn multi_round_output_matches_the_counter_construction() {
        let z = [0x5au8; 32];
        let es_512 = concat_kdf(&z, b"A256CBC-HS512", b"Alice", b"Bob", 512).unwrap();
        assert_eq!(hex(&es_512), ES_512);

        let es_384 = concat_kdf(&z, b"ECDH-ES", b"", b"", 384).unwrap();
        assert_eq!(hex(&es_384), ES_384);

        let tag = [0x11u8; 16];
        let one_pu_512 =
            concat_kdf_1pu(&z, b"ECDH-1PU+A256KW", b"Alice", b"Bob", 512, &tag).unwrap();
        assert_eq!(hex(&one_pu_512), ONE_PU_512);

        let legacy_512 =
            concat_kdf_1pu_legacy(&z, b"ECDH-1PU+A256KW", b"Alice", b"Bob", 512, &tag).unwrap();
        assert_eq!(hex(&legacy_512), ONE_PU_LEGACY_512);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    const ES_512: &str = "91cf2ade954401728da5e17c9ded3c8150a1f767e7cab8e5b590b9b1b57d2093ea065c28e9ce4bbf9193081849aca3f5e35327d9495c668266e52f7f48739a06";
    const ES_384: &str = "db23c0d65c889af6c9b52a20bacb6f10110065e1fccd6ed7c03f93186f9aba85ca4c57e45ab77d3d1af3a1c317cc8f5e";
    const ONE_PU_512: &str = "7388feb77b1501dd7248b2d529c69b5d8f90152edef39a2b6c8d5dc242baa1df4a3d702d0623f52e8906f1fb462838b46cc9a03dcc2eff42b91e49332af0e26e";
    const ONE_PU_LEGACY_512: &str = "2894c4a6064ff923ccfa12e136985ed973ae0207a2a910af97a30b249c35b539e1c44bfaa33e66c6789bccfbb273deb52b74698c0fe2b28e40616034a06e7960";
}
