use affinidi_crypto::JWK;
use askar_crypto::{
    alg::{
        aes::{A128Kw, A256Kw, AesKey},
        ed25519::Ed25519KeyPair,
        k256::K256KeyPair,
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    kdf::{FromKeyDerivation, KeyExchange, ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs},
    repr::{KeySecretBytes, ToSecretBytes},
};

use crate::error::{Error, ErrorKind, Result, err_msg};

/// Note this trait is compatible with KW algorithms only
pub(crate) trait KeyWrap: KeyAeadInPlace {
    fn wrap_key<K: KeyAeadInPlace + ToSecretBytes>(&self, key: &K) -> Result<SecretBytes> {
        let params = self.aead_params();

        let key_len = key.secret_bytes_length().map_err(|err| {
            Error::msg(
                ErrorKind::InvalidState,
                format!("{}: {}", "Unable get key len", err.message()),
            )
        })?;

        let mut buf = SecretBytes::with_capacity(key_len + params.tag_length);

        key.write_secret_bytes(&mut buf).map_err(|err| {
            Error::msg(
                ErrorKind::InvalidState,
                format!("{}: {}", "Unable encrypt", err.message()),
            )
        })?;

        self.encrypt_in_place(&mut buf, &[], &[]).map_err(|err| {
            Error::msg(
                ErrorKind::InvalidState,
                format!("{}: {}", "Unable encrypt", err.message()),
            )
        })?;

        Ok(buf)
    }

    fn unwrap_key<K: KeyAeadInPlace + KeySecretBytes>(&self, ciphertext: &[u8]) -> Result<K> {
        let mut buf = SecretBytes::from_slice(ciphertext);

        self.decrypt_in_place(&mut buf, &[], &[]).map_err(|err| {
            Error::msg(
                ErrorKind::Malformed,
                format!("{}: {}", "Unable decrypt key", err.message()),
            )
        })?;

        let key = K::from_secret_bytes(buf.as_ref()).map_err(|err| {
            Error::msg(
                ErrorKind::Malformed,
                format!("{}: {}", "Unable create key", err.message()),
            )
        })?;

        Ok(key)
    }
}

impl KeyWrap for AesKey<A256Kw> {}

impl KeyWrap for AesKey<A128Kw> {}

#[allow(clippy::too_many_arguments)]
pub(crate) trait JoseKDF<Key: KeyExchange, KW: KeyWrap + Sized> {
    fn derive_key(
        ephem_key: &Key,
        send_key: Option<&Key>,
        recip_key: &Key,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<KW>;
}

impl<Key: KeyExchange, KW: KeyWrap + FromKeyDerivation + Sized> JoseKDF<Key, KW>
    for Ecdh1PU<'_, Key>
{
    fn derive_key(
        ephem_key: &Key,
        send_key: Option<&Key>,
        recip_key: &Key,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<KW> {
        let send_key = send_key
            .ok_or_else(|| err_msg(ErrorKind::InvalidState, "No sender key for ecdh-1pu"))?;
        let deriviation = Ecdh1PU::new(
            ephem_key, send_key, recip_key, alg, apu, apv, cc_tag, receive,
        );

        let kw = KW::from_key_derivation(deriviation).map_err(|err| {
            Error::msg(
                ErrorKind::InvalidState,
                format!("{}: {}", "Unable derive kw", err.message()),
            )
        })?;

        Ok(kw)
    }
}

impl<Key: KeyExchange, KW: KeyWrap + FromKeyDerivation + Sized> JoseKDF<Key, KW>
    for EcdhEs<'_, Key>
{
    fn derive_key(
        ephem_key: &Key,
        _send_key: Option<&Key>,
        recip_key: &Key,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        _cc_tag: &[u8],
        receive: bool,
    ) -> Result<KW> {
        let deriviation = EcdhEs::new(ephem_key, recip_key, alg, apu, apv, receive);

        let kw = KW::from_key_derivation(deriviation).map_err(|err| {
            Error::msg(
                ErrorKind::InvalidState,
                format!("{}: {}", "Unable derive kw", err.message()),
            )
        })?;

        Ok(kw)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KnownKeyAlg {
    Ed25519,
    X25519,
    P256,
    K256,
    Unsupported,
}

#[derive(Debug)]
pub enum KnownKeyPair {
    Ed25519(Ed25519KeyPair),
    X25519(X25519KeyPair),
    P256(P256KeyPair),
    K256(K256KeyPair),
}

pub trait AsKnownKeyPair {
    fn key_alg(&self, jwk: &JWK) -> KnownKeyAlg;
    fn as_key_pair(&self, jwk: &JWK) -> Result<KnownKeyPair>;

    fn as_ed25519(&self, jwk: &JWK) -> Result<Ed25519KeyPair> {
        if self.key_alg(jwk) != KnownKeyAlg::Ed25519 {
            Err(err_msg(
                ErrorKind::InvalidState,
                "as_ed25519(): Unexpected key alg",
            ))?
        }

        match self.as_key_pair(jwk)? {
            KnownKeyPair::Ed25519(k) => Ok(k),
            _ => Err(err_msg(
                ErrorKind::InvalidState,
                "as_ed25519(): Unexpected key pair type",
            ))?,
        }
    }

    fn as_x25519(&self, jwk: &JWK) -> Result<X25519KeyPair> {
        if self.key_alg(jwk) != KnownKeyAlg::X25519 {
            Err(err_msg(
                ErrorKind::InvalidState,
                "as_x25519(): Unexpected key alg",
            ))?
        }

        match self.as_key_pair(jwk)? {
            KnownKeyPair::X25519(k) => Ok(k),
            _ => Err(err_msg(
                ErrorKind::InvalidState,
                "as_x25519(): Unexpected key pair type",
            ))?,
        }
    }

    fn as_p256(&self, jwk: &JWK) -> Result<P256KeyPair> {
        if self.key_alg(jwk) != KnownKeyAlg::P256 {
            Err(err_msg(
                ErrorKind::InvalidState,
                "as_p256(): Unexpected key alg",
            ))?
        }

        match self.as_key_pair(jwk)? {
            KnownKeyPair::P256(k) => Ok(k),
            _ => Err(err_msg(
                ErrorKind::InvalidState,
                "as_p256(): Unexpected key pair type",
            ))?,
        }
    }

    fn as_k256(&self, jwk: &JWK) -> Result<K256KeyPair> {
        if self.key_alg(jwk) != KnownKeyAlg::K256 {
            Err(err_msg(
                ErrorKind::InvalidState,
                "as_k256(): Unexpected key alg",
            ))?
        }

        match self.as_key_pair(jwk)? {
            KnownKeyPair::K256(k) => Ok(k),
            _ => Err(err_msg(
                ErrorKind::InvalidState,
                "as_k256(): Unexpected key pair type",
            ))?,
        }
    }
}

/// Older trait form original crate
pub trait AsKnownKeyPairSecret {
    fn key_alg(&self) -> KnownKeyAlg;
    fn as_key_pair(&self) -> Result<KnownKeyPair>;

    /*fn as_ed25519(&self) -> Result<Ed25519KeyPair> {
        if self.key_alg() != KnownKeyAlg::Ed25519 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::Ed25519(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }*/

    fn as_x25519(&self) -> Result<X25519KeyPair> {
        if self.key_alg() != KnownKeyAlg::X25519 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::X25519(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }

    fn as_p256(&self) -> Result<P256KeyPair> {
        if self.key_alg() != KnownKeyAlg::P256 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::P256(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }

    fn as_k256(&self) -> Result<K256KeyPair> {
        if self.key_alg() != KnownKeyAlg::K256 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::K256(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }
}
