use std::{collections::HashMap, sync::Mutex};

use vta_sdk::{
    context_provision::ContextProvisionBundle,
    credentials::CredentialBundle,
    session::{SessionBackend, SessionStore},
};

/// Ephemeral in-memory session backend for the setup wizard.
struct InMemoryBackend {
    data: Mutex<HashMap<String, String>>,
}

impl SessionBackend for InMemoryBackend {
    fn load(&self, key: &str) -> Option<String> {
        self.data.lock().unwrap().get(key).cloned()
    }
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn clear(&self, key: &str) {
        self.data.lock().unwrap().remove(key);
    }
}

/// Parsed VTA input — either a full provision bundle or a plain credential.
pub enum VtaInput {
    /// Full provision bundle from `pnm contexts provision`
    Provision {
        bundle: ContextProvisionBundle,
        credential_raw: String,
    },
    /// Plain credential from `cnm-cli auth credentials generate`
    Credential { credential_raw: String },
}

/// Result of VTA setup.
pub struct VtaSetupResult {
    /// The credential string (for storage in backend)
    pub credential_raw: String,
    /// Context ID to use
    pub context_id: String,
    /// VTA REST URL override (if discovered)
    pub vta_url: Option<String>,
}

/// Parse a VTA credential or provision bundle from raw input.
pub fn parse_vta_input(raw: &str) -> anyhow::Result<VtaInput> {
    let trimmed = raw.trim();

    // Try to parse as a provision bundle first
    if let Ok(bundle) = ContextProvisionBundle::decode(trimmed) {
        let credential_raw = bundle.credential.clone();
        return Ok(VtaInput::Provision {
            bundle,
            credential_raw,
        });
    }

    // Try as a plain credential
    if CredentialBundle::decode(trimmed).is_ok() {
        return Ok(VtaInput::Credential {
            credential_raw: trimmed.to_string(),
        });
    }

    Err(anyhow::anyhow!(
        "Invalid VTA input. Expected a Context Provision Bundle or Credential Bundle."
    ))
}

/// Authenticate to VTA and set up a basic session.
pub async fn setup_vta(input: VtaInput) -> anyhow::Result<VtaSetupResult> {
    let credential_raw = match &input {
        VtaInput::Provision { credential_raw, .. } => credential_raw.clone(),
        VtaInput::Credential { credential_raw } => credential_raw.clone(),
    };

    // Decode the credential to find the VTA URL
    let credential = CredentialBundle::decode(&credential_raw)
        .map_err(|e| anyhow::anyhow!("Invalid credential: {e}"))?;

    let vta_url = credential
        .vta_url
        .ok_or_else(|| anyhow::anyhow!("VTA URL not found in credential"))?;

    // Create an in-memory session store and authenticate
    let backend = InMemoryBackend {
        data: Mutex::new(HashMap::new()),
    };
    let store = SessionStore::with_backend(Box::new(backend));
    let session_key = "mediator-setup";

    store
        .login(&credential_raw, &vta_url, session_key)
        .await
        .map_err(|e| anyhow::anyhow!("VTA authentication failed: {e}"))?;

    // Determine context ID
    let context_id = match &input {
        VtaInput::Provision { bundle, .. } => {
            if bundle.context_id.is_empty() {
                "mediator".to_string()
            } else {
                bundle.context_id.clone()
            }
        }
        VtaInput::Credential { .. } => "mediator".to_string(),
    };

    // Get VTA client to verify context
    let client = store
        .connect(session_key, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to VTA: {e}"))?;

    match client.get_context(&context_id).await {
        Ok(_) => {
            println!("  VTA context '{context_id}' found.");
        }
        Err(_) => {
            println!(
                "  VTA context '{context_id}' not found. It will need to be created manually."
            );
        }
    }

    Ok(VtaSetupResult {
        credential_raw,
        context_id,
        vta_url: Some(vta_url),
    })
}
