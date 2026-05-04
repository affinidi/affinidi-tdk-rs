use std::{fs, path::Path};

use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, PKCS_ED25519};

/// Generate a self-signed SSL certificate and key for local development.
/// Writes files to the specified directory and returns (cert_path, key_path).
pub fn generate_self_signed_cert(output_dir: &str) -> anyhow::Result<(String, String)> {
    fs::create_dir_all(output_dir)?;

    let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Affinidi Mediator (self-signed)");
    dn.push(DnType::OrganizationName, "Affinidi");
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;

    let cert = params.self_signed(&key_pair)?;

    let cert_path = Path::new(output_dir).join("end.cert");
    let key_path = Path::new(output_dir).join("end.key");

    fs::write(&cert_path, cert.pem())?;
    fs::write(&key_path, key_pair.serialize_pem())?;

    Ok((
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed_cert() {
        let dir = std::env::temp_dir()
            .join("mediator-setup-test-ssl")
            .to_string_lossy()
            .into_owned();
        let (cert_path, key_path) = generate_self_signed_cert(&dir).unwrap();
        assert!(Path::new(&cert_path).exists());
        assert!(Path::new(&key_path).exists());

        let cert_content = fs::read_to_string(&cert_path).unwrap();
        assert!(cert_content.contains("BEGIN CERTIFICATE"));

        let key_content = fs::read_to_string(&key_path).unwrap();
        assert!(key_content.contains("BEGIN PRIVATE KEY"));

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }
}
