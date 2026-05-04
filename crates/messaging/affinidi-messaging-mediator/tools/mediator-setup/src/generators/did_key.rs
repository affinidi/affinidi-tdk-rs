use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk::dids::{DID, KeyType};

/// Generate a did:key for use as an admin DID.
/// Returns (did_string, secret).
pub fn generate_admin_did_key() -> anyhow::Result<(String, Secret)> {
    let (did, secret) = DID::generate_did_key(KeyType::Ed25519)
        .map_err(|e| anyhow::anyhow!("Failed to generate admin did:key: {e}"))?;

    Ok((did, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_admin_did_key() {
        let (did, secret) = generate_admin_did_key().unwrap();
        assert!(did.starts_with("did:key:z6Mk"));
        assert!(!secret.id.is_empty());
    }
}
