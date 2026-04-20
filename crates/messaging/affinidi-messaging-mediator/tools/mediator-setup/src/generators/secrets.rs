use affinidi_secrets_resolver::secrets::Secret;
use std::{fs, path::Path};

/// Write secrets to a JSON file in the format expected by the mediator.
/// The mediator expects a JSON array of Secret objects.
pub fn write_secrets_file(secrets: &[Secret], path: &str) -> anyhow::Result<()> {
    let dir = Path::new(path).parent();
    if let Some(parent) = dir {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(secrets)?;
    fs::write(path, json)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_secrets_resolver::secrets::Secret;

    #[test]
    fn test_write_secrets_file() {
        let secret = Secret::generate_ed25519(Some("test#key-1"), None);
        let path = std::env::temp_dir()
            .join("mediator-setup-test-secrets.json")
            .to_string_lossy()
            .into_owned();

        write_secrets_file(&[secret], &path).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("test#key-1"));

        let _ = fs::remove_file(&path);
    }
}
