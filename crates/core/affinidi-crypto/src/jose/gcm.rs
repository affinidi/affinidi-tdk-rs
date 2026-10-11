//! AES-GCM content encryption — `A128GCM` and `A256GCM` (RFC 7518 §5.3).
//!
//! The JWE `enc` values OpenID4VP 1.0 and HAIP use for an encrypted
//! authorization response (`direct_post.jwt`): `ECDH-ES` direct key agreement
//! derives the CEK, and one of these seals the payload. A 96-bit IV and a
//! 128-bit tag, as RFC 7518 fixes them; the tag is returned and taken
//! detached, the shape JWE serializes.
//!
//! The IV must never repeat under one key. Callers draw it from
//! [`generate_iv`]; a JWE built on `ECDH-ES` derives a fresh CEK per message
//! anyway, so a CEK and IV are never reused together in practice.

use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit, Nonce, Tag};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use rand_10::Rng;

use crate::error::CryptoError;

/// IV length for both `A128GCM` and `A256GCM` (96 bits).
pub const IV_SIZE: usize = 12;

/// Authentication tag length for both (128 bits).
pub const TAG_SIZE: usize = 16;

/// CEK length for `A128GCM`.
pub const A128_CEK_SIZE: usize = 16;

/// CEK length for `A256GCM`.
pub const A256_CEK_SIZE: usize = 32;

/// Generate a random 96-bit IV.
pub fn generate_iv() -> [u8; IV_SIZE] {
    let mut iv = [0u8; IV_SIZE];
    rand_10::rng().fill_bytes(&mut iv);
    iv
}

/// Encrypt with `A128GCM`. Returns `(ciphertext, tag)`.
pub fn encrypt_a128(
    plaintext: &[u8],
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    seal::<Aes128Gcm>("A128GCM", A128_CEK_SIZE, plaintext, cek, iv, aad)
}

/// Verify the tag and decrypt with `A128GCM`.
pub fn decrypt_a128(
    ciphertext: &[u8],
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    open::<Aes128Gcm>("A128GCM", A128_CEK_SIZE, ciphertext, cek, iv, aad, tag)
}

/// Encrypt with `A256GCM`. Returns `(ciphertext, tag)`.
pub fn encrypt_a256(
    plaintext: &[u8],
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    seal::<Aes256Gcm>("A256GCM", A256_CEK_SIZE, plaintext, cek, iv, aad)
}

/// Verify the tag and decrypt with `A256GCM`.
pub fn decrypt_a256(
    ciphertext: &[u8],
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    open::<Aes256Gcm>("A256GCM", A256_CEK_SIZE, ciphertext, cek, iv, aad, tag)
}

fn check_lengths(enc: &str, cek_len: usize, cek: &[u8], iv: &[u8]) -> Result<(), CryptoError> {
    if cek.len() != cek_len {
        return Err(CryptoError::ContentEncryption(format!(
            "{enc} CEK must be {cek_len} bytes, got {}",
            cek.len()
        )));
    }
    if iv.len() != IV_SIZE {
        return Err(CryptoError::ContentEncryption(format!(
            "{enc} IV must be {IV_SIZE} bytes, got {}",
            iv.len()
        )));
    }
    Ok(())
}

fn seal<C: AeadInOut + KeyInit>(
    enc: &str,
    cek_len: usize,
    plaintext: &[u8],
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    check_lengths(enc, cek_len, cek, iv)?;
    let cipher = C::new_from_slice(cek)
        .map_err(|_| CryptoError::ContentEncryption(format!("{enc} key init failed")))?;
    let nonce = nonce::<C>(enc, iv)?;
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into())
        .map_err(|_| CryptoError::ContentEncryption(format!("{enc} encryption failed")))?;
    Ok((buf, tag.to_vec()))
}

fn open<C: AeadInOut + KeyInit>(
    enc: &str,
    cek_len: usize,
    ciphertext: &[u8],
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_lengths(enc, cek_len, cek, iv)?;
    let cipher = C::new_from_slice(cek)
        .map_err(|_| CryptoError::ContentEncryption(format!("{enc} key init failed")))?;
    let nonce = nonce::<C>(enc, iv)?;
    let tag = Tag::<C>::try_from(tag).map_err(|_| {
        CryptoError::ContentEncryption(format!("{enc} tag must be {TAG_SIZE} bytes"))
    })?;
    let mut buf = ciphertext.to_vec();
    cipher
        .decrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into(), &tag)
        .map_err(|_| CryptoError::ContentEncryption("authentication tag mismatch".into()))?;
    Ok(buf)
}

fn nonce<C: AeadCore>(enc: &str, iv: &[u8]) -> Result<Nonce<C>, CryptoError> {
    Nonce::<C>::try_from(iv)
        .map_err(|_| CryptoError::ContentEncryption(format!("{enc} IV must be {IV_SIZE} bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 7516 Appendix A.1: the JWE content encryption step, A256GCM over
    /// the protected header as AAD.
    #[test]
    fn a256gcm_rfc7516_a1() {
        let cek: [u8; 32] = [
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7,
            110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252,
        ];
        let iv: [u8; 12] = [227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219];
        let aad = b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
        let plaintext = b"The true sign of intelligence is not knowledge but imagination.";

        let (ct, tag) = encrypt_a256(plaintext, &cek, &iv, aad).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&ct),
            "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A"
        );
        assert_eq!(URL_SAFE_NO_PAD.encode(&tag), "XFBoMYUZodetZdvTiFvSkQ");
        assert_eq!(decrypt_a256(&ct, &cek, &iv, aad, &tag).unwrap(), plaintext);
    }

    /// The GCM specification's test case 4 (AES-128, with AAD).
    #[test]
    fn a128gcm_gcm_spec_case_4() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let iv = hex("cafebabefacedbaddecaf888");
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let (ct, tag) = encrypt_a128(&pt, &key, &iv, &aad).unwrap();
        assert_eq!(
            ct,
            hex(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
            )
        );
        assert_eq!(tag, hex("5bc94fbc3221a5db94fae95ae7121a47"));
        assert_eq!(decrypt_a128(&ct, &key, &iv, &aad, &tag).unwrap(), pt);
    }

    /// RFC 7518 Appendix C: `ECDH-ES` direct key agreement for `A128GCM`
    /// derives the CEK through the Concat KDF with the `enc` value as the
    /// AlgorithmID — the shape an OpenID4VP `direct_post.jwt` response uses.
    #[test]
    fn ecdh_es_direct_cek_rfc7518_appendix_c() {
        use crate::jose::ecdh::derive_key_es_recipient;
        use crate::jose::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};

        let alice_epk = PublicKeyAgreement::from_jwk(&serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
        }))
        .unwrap();
        let bob = PrivateKeyAgreement::from_raw_bytes(
            Curve::P256,
            &URL_SAFE_NO_PAD
                .decode("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw")
                .unwrap(),
        )
        .unwrap();

        let cek =
            derive_key_es_recipient(&bob, &alice_epk, b"A128GCM", b"Alice", b"Bob", 128).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(&cek), "VqqN6vgjbSBcIijNcacQGg");
    }

    #[test]
    fn a_changed_ciphertext_aad_or_tag_is_refused() {
        let cek = [7u8; 32];
        let iv = generate_iv();
        let (ct, tag) = encrypt_a256(b"payload", &cek, &iv, b"aad").unwrap();

        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert!(decrypt_a256(&bad_ct, &cek, &iv, b"aad", &tag).is_err());
        assert!(decrypt_a256(&ct, &cek, &iv, b"other", &tag).is_err());
        let mut bad_tag = tag.clone();
        bad_tag[15] ^= 1;
        assert!(decrypt_a256(&ct, &cek, &iv, b"aad", &bad_tag).is_err());
    }

    #[test]
    fn wrong_lengths_are_refused_not_panicked_on() {
        let iv = generate_iv();
        // A 32-byte key is not an A128GCM key, nor a 16-byte one an A256GCM key.
        assert!(encrypt_a128(b"x", &[0u8; 32], &iv, b"").is_err());
        assert!(encrypt_a256(b"x", &[0u8; 16], &iv, b"").is_err());
        assert!(encrypt_a256(b"x", &[0u8; 32], &[0u8; 16], b"").is_err());
        assert!(decrypt_a256(b"x", &[0u8; 32], &iv, b"", &[0u8; 8]).is_err());
    }
}
