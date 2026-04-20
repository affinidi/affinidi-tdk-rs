//! Re-run safety + uninstall flow.
//!
//! Two related concerns live here:
//!
//! 1. **Re-run safety**: when the wizard starts and detects an existing
//!    `mediator.toml` whose backend already holds well-known mediator
//!    keys, refuse to proceed unless `--force-reprovision` is passed.
//!    Silently rotating the JWT or admin credential of a running
//!    mediator would invalidate every issued token / VTA session.
//! 2. **Uninstall**: a deliberate teardown — list every well-known key
//!    present in the configured backend, ask the operator to confirm,
//!    then delete each key + the local config + secret files.
//!
//! Both flows go through the same backend-introspection helper so
//! the two surfaces report a consistent set of keys.

use std::io::Write;
use std::path::{Path, PathBuf};

use affinidi_messaging_mediator_common::{
    ADMIN_CREDENTIAL, JWT_SECRET, MediatorSecrets, OPERATING_DID_DOCUMENT, OPERATING_SECRETS,
    VTA_LAST_KNOWN_BUNDLE,
};
use tracing::{info, warn};

/// Every well-known mediator key the wizard knows how to provision.
/// When checking existing setups we probe each one; when uninstalling
/// we delete each one if present. Order is presentation-only.
const WELL_KNOWN_KEYS: &[&str] = &[
    ADMIN_CREDENTIAL,
    JWT_SECRET,
    OPERATING_SECRETS,
    OPERATING_DID_DOCUMENT,
    VTA_LAST_KNOWN_BUNDLE,
];

/// What the wizard inferred from a still-on-disk mediator.toml.
pub struct ExistingSetup {
    /// Backend URL recovered from `[secrets].backend`.
    pub backend_url: String,
    /// Subset of [`WELL_KNOWN_KEYS`] that returned a value from the backend.
    pub provisioned_keys: Vec<&'static str>,
}

impl ExistingSetup {
    pub fn is_provisioned(&self) -> bool {
        !self.provisioned_keys.is_empty()
    }
}

/// Read the backend URL out of an existing `mediator.toml`. Returns
/// `Ok(None)` when the file is missing or has no `[secrets].backend` —
/// neither is fatal, the wizard just treats them as "nothing to check".
fn read_backend_url(config_path: &Path) -> anyhow::Result<Option<String>> {
    if !config_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(config_path)?;
    let doc: toml::Value = toml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {e}", config_path.display()))?;
    let url = doc
        .get("secrets")
        .and_then(|s| s.get("backend"))
        .and_then(|b| b.as_str())
        .map(|s| s.to_string());
    Ok(url)
}

/// Inspect the backend for any provisioned mediator keys. Returns
/// `Ok(None)` when there's nothing to inspect (no config file or no
/// backend URL) so the caller can let the wizard proceed normally.
pub async fn inspect_existing(config_path: &Path) -> anyhow::Result<Option<ExistingSetup>> {
    let Some(backend_url) = read_backend_url(config_path)? else {
        return Ok(None);
    };
    let secrets = MediatorSecrets::from_url(&backend_url).map_err(|e| {
        anyhow::anyhow!(
            "Could not open backend '{backend_url}' from {}: {e}",
            config_path.display()
        )
    })?;
    let mut provisioned: Vec<&'static str> = Vec::new();
    for key in WELL_KNOWN_KEYS {
        match secrets.store().get(key).await {
            Ok(Some(_)) => provisioned.push(*key),
            Ok(None) => {}
            Err(e) => {
                warn!(
                    backend = %backend_url,
                    key = %key,
                    error = %e,
                    "Could not probe well-known key during re-run safety check"
                );
            }
        }
    }
    Ok(Some(ExistingSetup {
        backend_url,
        provisioned_keys: provisioned,
    }))
}

/// Render the "refusing to overwrite" message and exit non-zero. Called
/// from `main` when an existing provisioned setup is detected without
/// `--force-reprovision`.
pub fn refuse_overwrite(config_path: &Path, setup: &ExistingSetup) -> ! {
    eprintln!();
    eprintln!(
        "\x1b[31mRefusing to overwrite an existing mediator setup at {}.\x1b[0m",
        config_path.display()
    );
    eprintln!(
        "Backend \x1b[1m{}\x1b[0m already contains the following provisioned keys:",
        setup.backend_url
    );
    for key in &setup.provisioned_keys {
        eprintln!("  - {key}");
    }
    eprintln!();
    eprintln!(
        "Re-running the wizard will rotate every key listed above. That \
         invalidates issued JWTs, breaks any active VTA session, and \
         requires every client to re-authenticate."
    );
    eprintln!();
    eprintln!("To proceed anyway:    \x1b[36mmediator-setup --force-reprovision\x1b[0m");
    eprintln!("To tear down cleanly: \x1b[36mmediator-setup --uninstall\x1b[0m");
    std::process::exit(1);
}

/// Files the wizard wrote alongside `mediator.toml` that should be
/// removed during uninstall. Each path is relative to the config
/// directory (`mediator.toml`'s parent).
const COMPANION_FILES: &[&str] = &[
    "atm-functions.lua",
    "secrets.json",
    "mediator_did.json",
    "mediator-build.toml",
];

/// Run the uninstall flow. Loads the backend, lists keys, prompts for a
/// typed `DELETE` confirmation, then deletes the keys and removes the
/// config + companion files. Idempotent: missing files / already-deleted
/// keys are reported as "skipped" rather than failing.
pub async fn run_uninstall(config_path: &str) -> anyhow::Result<()> {
    let path = PathBuf::from(config_path);
    let setup = inspect_existing(&path).await?;

    match &setup {
        None => {
            println!(
                "No mediator configuration found at {} — nothing to uninstall.",
                path.display()
            );
            return Ok(());
        }
        Some(s) if s.provisioned_keys.is_empty() => {
            println!(
                "Backend {} has no provisioned mediator keys; only local files will be removed.",
                s.backend_url
            );
        }
        Some(s) => {
            println!("Mediator setup at {} will be removed.", path.display());
            println!("Backend: \x1b[1m{}\x1b[0m", s.backend_url);
            println!("Keys to delete:");
            for key in &s.provisioned_keys {
                println!("  - {key}");
            }
        }
    }
    println!();
    print!("Type \x1b[1mDELETE\x1b[0m (uppercase) to confirm, anything else aborts: ");
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "DELETE" {
        eprintln!("\nAborted — nothing was changed.");
        return Ok(());
    }

    info!(config_path = %path.display(), "Starting mediator uninstall");

    if let Some(setup) = setup {
        let secrets = MediatorSecrets::from_url(&setup.backend_url).map_err(|e| {
            anyhow::anyhow!("Could not reopen backend '{}': {e}", setup.backend_url)
        })?;
        for key in &setup.provisioned_keys {
            match secrets.store().delete(key).await {
                Ok(()) => {
                    info!(backend = %setup.backend_url, key = %key, "Deleted well-known key");
                    println!("  \x1b[32m\u{2714}\x1b[0m deleted {key}");
                }
                Err(e) => {
                    warn!(
                        backend = %setup.backend_url,
                        key = %key,
                        error = %e,
                        "Failed to delete well-known key"
                    );
                    eprintln!("  \x1b[33m\u{26A0}\x1b[0m {key}: {e}");
                }
            }
        }
    }

    if path.exists() {
        std::fs::remove_file(&path)?;
        info!(path = %path.display(), "Removed config file");
        println!("  \x1b[32m\u{2714}\x1b[0m removed {}", path.display());
    }
    if let Some(parent) = path.parent() {
        for name in COMPANION_FILES {
            let companion = parent.join(name);
            if companion.exists() {
                std::fs::remove_file(&companion)?;
                info!(path = %companion.display(), "Removed companion file");
                println!("  \x1b[32m\u{2714}\x1b[0m removed {}", companion.display());
            }
        }
    }

    println!("\n\x1b[32mUninstall complete.\x1b[0m");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_returns_none_for_missing_config() {
        // Sync wrapper around the async helper. Missing config = no
        // setup; the wizard should treat this as a fresh install.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let path = std::env::temp_dir().join("mediator-setup-nonexistent-9241.toml");
        let _ = std::fs::remove_file(&path);
        let result = rt.block_on(inspect_existing(&path)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_backend_url_pulls_from_secrets_section() {
        let toml = r#"
mediator_did = "did:peer:foo"
[secrets]
backend = "keyring://test-mediator"
"#;
        let path = std::env::temp_dir().join("mediator-setup-read-backend-test.toml");
        std::fs::write(&path, toml).unwrap();
        let url = read_backend_url(&path).unwrap();
        assert_eq!(url, Some("keyring://test-mediator".to_string()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_backend_url_returns_none_when_missing() {
        // No `[secrets]` table at all is treated as "no backend
        // configured" — the wizard then can't perform the safety
        // check and proceeds as if for a fresh install.
        let toml = "mediator_did = \"did:peer:foo\"\n";
        let path = std::env::temp_dir().join("mediator-setup-read-backend-empty-test.toml");
        std::fs::write(&path, toml).unwrap();
        let url = read_backend_url(&path).unwrap();
        assert!(url.is_none());
        let _ = std::fs::remove_file(&path);
    }
}
