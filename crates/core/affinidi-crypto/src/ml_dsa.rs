//! ML-DSA (FIPS 204) key operations.
//!
//! Private key material is stored as the 32-byte seed `xi`; the expanded
//! signing key is derived on demand via `<Params as KeyGen>::from_seed`.
//! Public key material is the FIPS 204 encoded verifying key.

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{B32, KeyGen, MlDsa44, MlDsa65, MlDsa87, Signature};
use rand_10::RngExt;

use crate::{CryptoError, KeyType, error::Result};

/// Generated ML-DSA key pair. `private_bytes` is always the 32-byte seed.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub key_type: KeyType,
    pub private_bytes: Vec<u8>,
    pub public_bytes: Vec<u8>,
}

fn random_seed() -> [u8; 32] {
    let mut rng = rand_10::rng();
    let mut s = [0u8; 32];
    rng.fill(&mut s);
    s
}

fn seed_from(seed: Option<&[u8; 32]>) -> B32 {
    match seed {
        Some(s) => B32::from(*s),
        None => B32::from(random_seed()),
    }
}

/// Generates an ML-DSA-44 key pair, optionally from a 32-byte seed.
pub fn generate_ml_dsa_44(seed: Option<&[u8; 32]>) -> KeyPair {
    let xi = seed_from(seed);
    let sk = <MlDsa44 as KeyGen>::from_seed(&xi);
    let vk_bytes: &[u8] = &sk.verifying_key().encode();
    KeyPair {
        key_type: KeyType::MlDsa44,
        private_bytes: AsRef::<[u8]>::as_ref(&xi).to_vec(),
        public_bytes: vk_bytes.to_vec(),
    }
}

/// Generates an ML-DSA-65 key pair, optionally from a 32-byte seed.
pub fn generate_ml_dsa_65(seed: Option<&[u8; 32]>) -> KeyPair {
    let xi = seed_from(seed);
    let sk = <MlDsa65 as KeyGen>::from_seed(&xi);
    let vk_bytes: &[u8] = &sk.verifying_key().encode();
    KeyPair {
        key_type: KeyType::MlDsa65,
        private_bytes: AsRef::<[u8]>::as_ref(&xi).to_vec(),
        public_bytes: vk_bytes.to_vec(),
    }
}

/// Generates an ML-DSA-87 key pair, optionally from a 32-byte seed.
pub fn generate_ml_dsa_87(seed: Option<&[u8; 32]>) -> KeyPair {
    let xi = seed_from(seed);
    let sk = <MlDsa87 as KeyGen>::from_seed(&xi);
    let vk_bytes: &[u8] = &sk.verifying_key().encode();
    KeyPair {
        key_type: KeyType::MlDsa87,
        private_bytes: AsRef::<[u8]>::as_ref(&xi).to_vec(),
        public_bytes: vk_bytes.to_vec(),
    }
}

fn seed_to_b32(seed: &[u8]) -> Result<B32> {
    if seed.len() != 32 {
        return Err(CryptoError::KeyError(format!(
            "Invalid ML-DSA seed length: expected 32, got {}",
            seed.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(seed);
    Ok(B32::from(arr))
}

/// Signs `data` with ML-DSA-44, given a 32-byte seed.
pub fn sign_ml_dsa_44(seed: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let xi = seed_to_b32(seed)?;
    let sk = <MlDsa44 as KeyGen>::from_seed(&xi);
    let sig: Signature<MlDsa44> = sk.sign(data);
    let bytes: &[u8] = &sig.encode();
    Ok(bytes.to_vec())
}

/// Signs `data` with ML-DSA-65, given a 32-byte seed.
pub fn sign_ml_dsa_65(seed: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let xi = seed_to_b32(seed)?;
    let sk = <MlDsa65 as KeyGen>::from_seed(&xi);
    let sig: Signature<MlDsa65> = sk.sign(data);
    let bytes: &[u8] = &sig.encode();
    Ok(bytes.to_vec())
}

/// Signs `data` with ML-DSA-87, given a 32-byte seed.
pub fn sign_ml_dsa_87(seed: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let xi = seed_to_b32(seed)?;
    let sk = <MlDsa87 as KeyGen>::from_seed(&xi);
    let sig: Signature<MlDsa87> = sk.sign(data);
    let bytes: &[u8] = &sig.encode();
    Ok(bytes.to_vec())
}

fn vk_bytes_to_array<const N: usize>(vk: &[u8]) -> Result<[u8; N]> {
    if vk.len() != N {
        return Err(CryptoError::KeyError(format!(
            "Invalid ML-DSA public key length: expected {}, got {}",
            N,
            vk.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(vk);
    Ok(arr)
}

/// Verifies an ML-DSA-44 signature.
pub fn verify_ml_dsa_44(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    let vk_arr: [u8; 1312] = vk_bytes_to_array(public_key)?;
    let enc = ml_dsa::EncodedVerifyingKey::<MlDsa44>::from(vk_arr);
    let vk = ml_dsa::VerifyingKey::<MlDsa44>::decode(&enc);
    let sig_bytes: [u8; 2420] = signature.try_into().map_err(|_| {
        CryptoError::KeyError(format!(
            "Invalid ML-DSA-44 signature length: expected 2420, got {}",
            signature.len()
        ))
    })?;
    let sig_enc = ml_dsa::EncodedSignature::<MlDsa44>::from(sig_bytes);
    let sig = Signature::<MlDsa44>::decode(&sig_enc)
        .ok_or_else(|| CryptoError::KeyError("Invalid ML-DSA-44 signature encoding".into()))?;
    vk.verify(data, &sig)
        .map_err(|e| CryptoError::KeyError(format!("ML-DSA-44 verification failed: {e}")))
}

/// Verifies an ML-DSA-65 signature.
pub fn verify_ml_dsa_65(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    let vk_arr: [u8; 1952] = vk_bytes_to_array(public_key)?;
    let enc = ml_dsa::EncodedVerifyingKey::<MlDsa65>::from(vk_arr);
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);
    let sig_bytes: [u8; 3309] = signature.try_into().map_err(|_| {
        CryptoError::KeyError(format!(
            "Invalid ML-DSA-65 signature length: expected 3309, got {}",
            signature.len()
        ))
    })?;
    let sig_enc = ml_dsa::EncodedSignature::<MlDsa65>::from(sig_bytes);
    let sig = Signature::<MlDsa65>::decode(&sig_enc)
        .ok_or_else(|| CryptoError::KeyError("Invalid ML-DSA-65 signature encoding".into()))?;
    vk.verify(data, &sig)
        .map_err(|e| CryptoError::KeyError(format!("ML-DSA-65 verification failed: {e}")))
}

/// Verifies an ML-DSA-87 signature.
pub fn verify_ml_dsa_87(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    let vk_arr: [u8; 2592] = vk_bytes_to_array(public_key)?;
    let enc = ml_dsa::EncodedVerifyingKey::<MlDsa87>::from(vk_arr);
    let vk = ml_dsa::VerifyingKey::<MlDsa87>::decode(&enc);
    let sig_bytes: [u8; 4627] = signature.try_into().map_err(|_| {
        CryptoError::KeyError(format!(
            "Invalid ML-DSA-87 signature length: expected 4627, got {}",
            signature.len()
        ))
    })?;
    let sig_enc = ml_dsa::EncodedSignature::<MlDsa87>::from(sig_bytes);
    let sig = Signature::<MlDsa87>::decode(&sig_enc)
        .ok_or_else(|| CryptoError::KeyError("Invalid ML-DSA-87 signature encoding".into()))?;
    vk.verify(data, &sig)
        .map_err(|e| CryptoError::KeyError(format!("ML-DSA-87 verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_44_roundtrip() {
        let kp = generate_ml_dsa_44(Some(&[7u8; 32]));
        assert_eq!(kp.private_bytes.len(), 32);
        assert_eq!(kp.public_bytes.len(), 1312);

        let msg = b"hello pqc";
        let sig = sign_ml_dsa_44(&kp.private_bytes, msg).unwrap();
        assert_eq!(sig.len(), 2420);
        verify_ml_dsa_44(&kp.public_bytes, msg, &sig).unwrap();
    }

    #[test]
    fn ml_dsa_65_roundtrip() {
        let kp = generate_ml_dsa_65(Some(&[9u8; 32]));
        assert_eq!(kp.public_bytes.len(), 1952);
        let sig = sign_ml_dsa_65(&kp.private_bytes, b"x").unwrap();
        assert_eq!(sig.len(), 3309);
        verify_ml_dsa_65(&kp.public_bytes, b"x", &sig).unwrap();
    }

    #[test]
    fn ml_dsa_87_roundtrip() {
        let kp = generate_ml_dsa_87(Some(&[3u8; 32]));
        assert_eq!(kp.public_bytes.len(), 2592);
        let sig = sign_ml_dsa_87(&kp.private_bytes, b"y").unwrap();
        assert_eq!(sig.len(), 4627);
        verify_ml_dsa_87(&kp.public_bytes, b"y", &sig).unwrap();
    }

    #[test]
    fn ml_dsa_44_tampered_sig_fails() {
        let kp = generate_ml_dsa_44(Some(&[1u8; 32]));
        let mut sig = sign_ml_dsa_44(&kp.private_bytes, b"m").unwrap();
        sig[0] ^= 0xff;
        assert!(verify_ml_dsa_44(&kp.public_bytes, b"m", &sig).is_err());
    }

    #[test]
    fn ml_dsa_deterministic_from_seed() {
        let a = generate_ml_dsa_44(Some(&[42u8; 32]));
        let b = generate_ml_dsa_44(Some(&[42u8; 32]));
        assert_eq!(a.public_bytes, b.public_bytes);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn seed_32(h: &str) -> [u8; 32] {
        let v = hex(h);
        assert_eq!(v.len(), 32);
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    /// NIST ACVP ML-DSA-keyGen-FIPS204 known-answer vectors. Each test pins
    /// SHA-256 of the full encoded public key derived from the NIST seed —
    /// every byte of the pk is committed, so param-set routing, encoding,
    /// or RNG regressions fail the test.
    ///
    /// Source: <https://github.com/usnistgov/ACVP-Server>
    /// `gen-val/json-files/ML-DSA-keyGen-FIPS204/{prompt,expectedResults}.json`
    /// — tcId=1 (ML-DSA-44), tcId=26 (ML-DSA-65), tcId=51 (ML-DSA-87).
    /// Hashes were computed from the NIST-published pk values.
    fn sha256(b: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(b).into()
    }

    #[test]
    fn ml_dsa_44_nist_kat_keygen() {
        let seed = seed_32("D71361C000F9A7BC99DFB425BCB6BB27C32C36AB444FF3708B2D93B4E66D5B5B");
        let expected_pk_prefix =
            hex("B845FA2881407A59183071629B08223128116014FB58FF6BB4C8C9FE19CF5B0B");
        let expected_pk_sha256 =
            hex("451A808C522218FADBDAB146FC12004B0741C7D069F238F43AD77216159F6A34");
        let kp = generate_ml_dsa_44(Some(&seed));
        assert_eq!(kp.public_bytes.len(), 1312);
        assert_eq!(&kp.public_bytes[..32], expected_pk_prefix.as_slice());
        assert_eq!(
            sha256(&kp.public_bytes).as_slice(),
            expected_pk_sha256.as_slice()
        );
    }

    #[test]
    fn ml_dsa_65_nist_kat_keygen() {
        let seed = seed_32("1BD67DC782B2958E189E315C040DD1F64C8AB232A6A170E1A7A52C33F10851B1");
        let expected_pk_prefix =
            hex("43AD6560D3BB684667A559EE6EC7C816020E5B65671F270F2353A8C912B6C26B");
        let expected_pk_sha256 =
            hex("6FB1146B85539FB5C53D35B66DAE94202FCD5575A537172CF1156220476F7920");
        let kp = generate_ml_dsa_65(Some(&seed));
        assert_eq!(kp.public_bytes.len(), 1952);
        assert_eq!(&kp.public_bytes[..32], expected_pk_prefix.as_slice());
        assert_eq!(
            sha256(&kp.public_bytes).as_slice(),
            expected_pk_sha256.as_slice()
        );
    }

    #[test]
    fn ml_dsa_87_nist_kat_keygen() {
        let seed = seed_32("F7052FBB921759CD8716773BA6355630121D6927899FDDA5768E2BC240FCCB7B");
        let expected_pk_prefix =
            hex("18DFF392DEF5756EA23519A240E6B5CDCF912D89CD94DEC9DC71E53F8CDF37D9");
        let expected_pk_sha256 =
            hex("40298270777D3306D2FCB6B4691D7A7AB799CD1069EEA88F843CF0EC26D4B01F");
        let kp = generate_ml_dsa_87(Some(&seed));
        assert_eq!(kp.public_bytes.len(), 2592);
        assert_eq!(&kp.public_bytes[..32], expected_pk_prefix.as_slice());
        assert_eq!(
            sha256(&kp.public_bytes).as_slice(),
            expected_pk_sha256.as_slice()
        );
    }

    /// Param-set routing guard: the same seed must produce *different* public
    /// keys across parameter sets. If dispatch ever routes MlDsa65 to MlDsa44
    /// internals (or similar), this fails.
    #[test]
    fn ml_dsa_param_sets_are_distinct() {
        let seed = [11u8; 32];
        let k44 = generate_ml_dsa_44(Some(&seed));
        let k65 = generate_ml_dsa_65(Some(&seed));
        let k87 = generate_ml_dsa_87(Some(&seed));
        assert_ne!(&k44.public_bytes[..32], &k65.public_bytes[..32]);
        assert_ne!(&k44.public_bytes[..32], &k87.public_bytes[..32]);
        assert_ne!(&k65.public_bytes[..32], &k87.public_bytes[..32]);
    }
}
