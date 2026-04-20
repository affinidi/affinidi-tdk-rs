pub mod keyring_backend;

use affinidi_secrets_resolver::secrets::Secret;

/// Store secrets in the appropriate backend based on the storage scheme.
pub fn provision_secrets(
    storage: &str,
    secrets: &[Secret],
    mediator_did: &str,
) -> anyhow::Result<()> {
    match storage {
        "file://" => {
            // Handled by config_writer's secrets.json write — nothing to
            // do here. (`string://` is no longer supported.)
            Ok(())
        }
        "keyring://" => keyring_backend::store_secrets(mediator_did, secrets),
        "aws_secrets://" => {
            println!("  Note: AWS Secrets Manager provisioning requires AWS credentials.");
            println!("  Secrets will be referenced as aws_secrets://mediator/secrets");
            println!("  You must manually store the secrets in AWS Secrets Manager.");
            Ok(())
        }
        "gcp_secrets://" => {
            println!("  Note: Google Cloud Secret Manager support is coming soon.");
            println!("  Secrets will be referenced as gcp_secrets://mediator/secrets");
            Ok(())
        }
        "azure_keyvault://" => {
            println!("  Note: Azure Key Vault support is coming soon.");
            println!("  Secrets will be referenced as azure_keyvault://mediator-secrets");
            Ok(())
        }
        "vault://" => {
            println!("  Note: HashiCorp Vault support is coming soon.");
            println!("  Secrets will be referenced as vault://secret/mediator/secrets");
            Ok(())
        }
        "string://" => Err(anyhow::anyhow!(
            "string:// is no longer supported — use file:// (with optional encryption) instead"
        )),
        "vta://" => Err(anyhow::anyhow!(
            "vta:// is not a storage backend — VTA is a key source; choose a real store (keyring://, file://, aws_secrets://, …)"
        )),
        _ => Err(anyhow::anyhow!("Unknown storage backend: {storage}")),
    }
}
