//! HPKE-Base over the post-quantum hybrid KEM (Rev 3 §8.2.1).
//!
//! Post-quantum support in TSP is not a separate mode and not a separate
//! ciphertext code. It is the same HPKE-Base, the same `HKDF-SHA256`, the same
//! `ChaCha20Poly1305`, the same `4F`/`5F`/`6F` ciphertext codes, the same
//! `YTSP-` info and the same `CONCAT(TSP_Version, VID_sndr, VID_rcvr)` aad —
//! with one substitution, the KEM. Everything a receiver needs in order to
//! split `CONCAT(enc, ct)` follows from the recipient VID's encryption key
//! type, because that is what fixes `Nenc` at 1120 rather than 32.
//!
//! # Which hybrid, and why the name is a trap
//!
//! The KEM is `MLKEM768-X25519`, codepoint `0x647a`, from
//! [draft-ietf-hpke-pq]. IANA currently assigns `0x647a` to **X-Wing**
//! ([draft-connolly-cfrg-xwing-kem]), and `draft-ietf-hpke-pq` §8.2 asks to
//! *replace* that entry. The two have identical `Nsecret`, `Nenc`, `Npk` and
//! `Nsk`, so an implementation that resolves the codepoint against IANA and
//! builds the other one gets a decapsulation failure with no length mismatch to
//! catch it — the failure looks like a bad key, not like a wrong algorithm.
//!
//! Rev 3 spelled this `X25519MLKEM768`, which is the TLS name and belongs to
//! neither draft. We raised it against PR #63 and the spec now says
//! `MLKEM768-X25519`.
//!
//! Which makes the type this module uses look wrong and is not: the `hpke`
//! crate calls it [`hpke::kem::XWing`] because the *construction* is X-Wing —
//! `draft-ietf-hpke-pq` defers its combiner to the CFRG hybrid-KEM draft, whose
//! concrete `QSF` instantiation is X-Wing — while pinning `KEM_ID = 0x647a` and
//! the hpke-pq `DeriveKeyPair`. Same bytes, two names, and the arbiter is the
//! specification's own `direct-hpke-base-pq` vector, which this module opens.
//!
//! # Key sizes
//!
//! The private key is **32 bytes** and that is the whole key, not a truncation
//! of one: `draft-ietf-hpke-pq` defines this KEM's private key as a seed from
//! which `DeriveKeyPair` produces the ML-KEM-768 and X25519 halves. We asked
//! upstream whether the published 32-byte value was complete, and Rev 3 gained
//! a sentence saying so.
//!
//! Note the asymmetry with the signature side of the same VID: there the
//! published private key is the *expanded* 4032-byte ML-DSA-65 key rather than
//! its seed. See [`crate::crypto::ml_dsa::SK_LEN`].
//!
//! [draft-ietf-hpke-pq]: https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/
//! [draft-connolly-cfrg-xwing-kem]: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/

use hpke::aead::{AeadTag, ChaCha20Poly1305};
use hpke::inout::InOutBuf;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    single_shot_open_inout_detached, single_shot_seal_inout_detached_with_rng,
};

use crate::error::TspError;

/// The encapsulated key is 1120 bytes, where the X25519 KEM's is 32.
///
/// This is the number that makes a post-quantum ciphertext parseable: `4F`
/// carries `CONCAT(enc, ct)` with nothing between them, so the split is by
/// length alone and the length comes from the recipient's key type.
pub const ENC_LEN: usize = 1120;

/// The public encryption key is 1216 bytes: ML-KEM-768's 1184 plus X25519's 32.
pub const PK_LEN: usize = 1216;

/// The private key is 32 bytes — a seed, and the whole key. See the module docs.
pub const SK_LEN: usize = 32;

/// The ChaCha20Poly1305 tag, the same 16 bytes as the classical path.
pub const TAG_LEN: usize = 16;

/// Result of sealing under the post-quantum KEM.
pub struct SealResult {
    /// The encapsulated key, 1120 bytes.
    pub enc: Box<[u8; ENC_LEN]>,
    /// The ciphertext, plaintext length plus the 16-byte tag.
    pub ciphertext: Vec<u8>,
}

/// Seal a plaintext for a recipient whose VID declares a post-quantum
/// encryption key.
///
/// `aad` and `info` carry exactly what the classical path carries; §8.2.1 says
/// "all other HPKE-Base processing, framing, and AAD are unchanged", and that
/// is load-bearing rather than a convenience — the AAD is what binds the
/// ciphertext to `VID_sndr` now that Base mode no longer authenticates the
/// sender at the HPKE layer.
pub fn seal(
    plaintext: &[u8],
    aad: &[u8],
    recipient_pk: &[u8; PK_LEN],
    info: &[u8],
) -> Result<SealResult, TspError> {
    let pk = <XWing as KemTrait>::PublicKey::from_bytes(recipient_pk)
        .map_err(|e| TspError::Hpke(format!("invalid post-quantum encryption key: {e:?}")))?;

    let mut buffer = plaintext.to_vec();
    let (encapped, tag): (_, AeadTag<ChaCha20Poly1305>) =
        single_shot_seal_inout_detached_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeS::Base,
            &pk,
            info,
            InOutBuf::from(buffer.as_mut_slice()),
            aad,
            &mut rand_10::rng(),
        )
        .map_err(|e| TspError::Hpke(format!("post-quantum HPKE seal failed: {e:?}")))?;

    buffer.extend_from_slice(&tag.to_bytes());

    let enc: Box<[u8; ENC_LEN]> = encapped
        .to_bytes()
        .to_vec()
        .into_boxed_slice()
        .try_into()
        .map_err(|_| TspError::Hpke("encapsulated key is not 1120 bytes".into()))?;

    Ok(SealResult {
        enc,
        ciphertext: buffer,
    })
}

/// Open a ciphertext sealed under the post-quantum KEM.
///
/// `ciphertext` is the AEAD ciphertext with its tag appended — the wire layout
/// after `enc` has been split off the front of the `4F` field.
pub fn open(
    ciphertext: &[u8],
    aad: &[u8],
    enc: &[u8; ENC_LEN],
    recipient_sk: &[u8; SK_LEN],
    info: &[u8],
) -> Result<Vec<u8>, TspError> {
    let Some(split) = ciphertext.len().checked_sub(TAG_LEN) else {
        return Err(TspError::Hpke("ciphertext shorter than its tag".into()));
    };

    let sk = <XWing as KemTrait>::PrivateKey::from_bytes(recipient_sk)
        .map_err(|e| TspError::Hpke(format!("invalid post-quantum decryption key: {e:?}")))?;
    let encapped = <XWing as KemTrait>::EncappedKey::from_bytes(enc)
        .map_err(|e| TspError::Hpke(format!("invalid encapsulated key: {e:?}")))?;
    let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(&ciphertext[split..])
        .map_err(|e| TspError::Hpke(format!("invalid AEAD tag: {e:?}")))?;

    let mut buffer = ciphertext[..split].to_vec();
    single_shot_open_inout_detached::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &sk,
        &encapped,
        info,
        InOutBuf::from(buffer.as_mut_slice()),
        aad,
        &tag,
    )
    .map_err(|_| {
        TspError::Hpke("post-quantum HPKE open failed: authentication tag mismatch".into())
    })?;

    Ok(buffer)
}

/// Derive the public encryption key from a private one.
pub fn public_key_from_private(private_key: &[u8; SK_LEN]) -> Result<Box<[u8; PK_LEN]>, TspError> {
    let sk = <XWing as KemTrait>::PrivateKey::from_bytes(private_key)
        .map_err(|e| TspError::Hpke(format!("invalid post-quantum decryption key: {e:?}")))?;
    <XWing as KemTrait>::sk_to_pk(&sk)
        .to_bytes()
        .to_vec()
        .into_boxed_slice()
        .try_into()
        .map_err(|_| TspError::Hpke("derived key is not 1216 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The codepoint and sizes are the whole compatibility surface with any
    /// other implementation, and all four are things a round-trip test agrees
    /// with itself about. Pin them.
    #[test]
    fn the_kem_is_the_one_the_specification_names() {
        assert_eq!(<XWing as KemTrait>::KEM_ID, 0x647a);
        assert_eq!(<XWing as KemTrait>::EncappedKey::size(), ENC_LEN);
        assert_eq!(<XWing as KemTrait>::PublicKey::size(), PK_LEN);
        assert_eq!(<XWing as KemTrait>::PrivateKey::size(), SK_LEN);
    }

    #[test]
    fn seal_open_round_trip() {
        let sk = [7u8; SK_LEN];
        let pk = public_key_from_private(&sk).expect("derive");

        let sealed = seal(b"hello world", b"aad", &pk, b"YTSP-").expect("seal");
        assert_eq!(sealed.ciphertext.len(), 11 + TAG_LEN);

        let opened = open(&sealed.ciphertext, b"aad", &sealed.enc, &sk, b"YTSP-").expect("open");
        assert_eq!(opened, b"hello world");
    }

    /// The AAD is what carries the ESSR sender binding in Base mode, so a
    /// mismatch has to be a hard failure rather than a recoverable one.
    #[test]
    fn a_different_aad_does_not_open() {
        let sk = [7u8; SK_LEN];
        let pk = public_key_from_private(&sk).expect("derive");
        let sealed = seal(b"hello world", b"aad", &pk, b"YTSP-").expect("seal");
        assert!(open(&sealed.ciphertext, b"other", &sealed.enc, &sk, b"YTSP-").is_err());
    }

    #[test]
    fn a_different_info_does_not_open() {
        let sk = [7u8; SK_LEN];
        let pk = public_key_from_private(&sk).expect("derive");
        let sealed = seal(b"hello world", b"aad", &pk, b"YTSP-").expect("seal");
        assert!(open(&sealed.ciphertext, b"aad", &sealed.enc, &sk, b"OTHER").is_err());
    }
}
