use ring::signature::Ed25519KeyPair;

/// Generate a random JWT signing secret as raw Ed25519 PKCS8 bytes.
///
/// The secret is provisioned into the unified `[secrets]` backend under
/// the well-known key `mediator/jwt/secret`; the mediator reads the raw
/// bytes back via `MediatorSecrets::load_jwt_secret` and feeds them to
/// `EncodingKey::from_ed_der` / `Ed25519KeyPair::from_pkcs8`. There is no
/// longer any inline-string form to encode for.
pub fn generate_jwt_secret() -> anyhow::Result<Vec<u8>> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|e| anyhow::anyhow!("Failed to generate JWT key pair: {e}"))?;

    Ok(pkcs8.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_jwt_secret() {
        let secret = generate_jwt_secret().unwrap();
        assert!(!secret.is_empty());
        // Should round-trip as a real Ed25519 PKCS8 keypair.
        assert!(Ed25519KeyPair::from_pkcs8(&secret).is_ok());
    }
}
