use base64::prelude::*;
use ring::signature::Ed25519KeyPair;

/// Generate a random JWT signing secret (Ed25519 PKCS8, base64url-encoded).
pub fn generate_jwt_secret() -> anyhow::Result<String> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|e| anyhow::anyhow!("Failed to generate JWT key pair: {e}"))?;

    Ok(BASE64_URL_SAFE_NO_PAD.encode(pkcs8.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_jwt_secret() {
        let secret = generate_jwt_secret().unwrap();
        assert!(!secret.is_empty());
        // Should be valid base64url
        assert!(BASE64_URL_SAFE_NO_PAD.decode(&secret).is_ok());
    }
}
