//! Opening the unified secret backend (`MediatorSecrets`).
//!
//! Every provisioning flow (online via `provision_secret_backend`, and the
//! sealed/headless flows in `bootstrap_headless`) opens the configured secret
//! store the same way: `MediatorSecrets::from_url` with consistent error
//! context, optionally followed by a liveness `probe()`. Centralised here so
//! that `from_url` + probe + error-mapping isn't re-inlined per flow.
//!
//! These take an already-resolved `backend_url` (from
//! [`config_writer::build_backend_url`](crate::config_writer::build_backend_url))
//! rather than the wizard config, so callers that also need the URL for their
//! own output — e.g. the keyring first-access note — resolve it once and pass it
//! in.

use affinidi_messaging_mediator_common::MediatorSecrets;

/// Open the unified secret backend at `backend_url` (no liveness probe).
/// Prefer [`open_and_probe_secret_backend`] when you want to fail fast on a
/// misconfigured/unreachable store before doing real work.
pub fn open_secret_backend(backend_url: &str) -> anyhow::Result<MediatorSecrets> {
    MediatorSecrets::from_url(backend_url)
        .map_err(|e| anyhow::anyhow!("open secret backend '{backend_url}': {e}"))
}

/// Which liveness probe to run when opening the backend for provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionProbe {
    /// Write → read → delete a random `mediator_probe_<uuid>` sentinel. Fails
    /// fast on missing **write** permissions before any crypto material is
    /// minted. Used by the interactive wizard, which may be pointed at a fresh
    /// backend the operator must be able to create secrets in.
    ReadWrite,
    /// Read-only reachability check (fixed `mediator_probe_readonly` sentinel,
    /// never written — `Ok` even when absent). Used by the **headless / recipe**
    /// flow, where the backend's well-known keys are provisioned out-of-band
    /// (e.g. CDK pre-creates the Secrets Manager entries) so setup only
    /// overwrites them and never needs create/delete rights — matching the
    /// mediator runtime, which also probes read-only at boot and on `/readyz`.
    ReadOnly,
}

/// Open the unified secret backend and probe it, so a misconfigured or
/// unreachable store (e.g. `aws_secrets://` with no credentials) fails fast with
/// an actionable error instead of part-way through provisioning. The `probe`
/// mode selects a write round-trip (interactive) or a read-only check (headless).
pub async fn open_and_probe_secret_backend(
    backend_url: &str,
    probe: ProvisionProbe,
) -> anyhow::Result<MediatorSecrets> {
    let store = open_secret_backend(backend_url)?;
    let result = match probe {
        ProvisionProbe::ReadWrite => store.probe().await,
        ProvisionProbe::ReadOnly => store.probe_readonly().await,
    };
    result.map_err(|e| anyhow::anyhow!("secret backend '{backend_url}' failed probe: {e}"))?;
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_round_trips_a_file_backend_url() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let url = format!("file://{}", dir.path().join("secrets.json").display());
        assert!(
            open_secret_backend(&url).is_ok(),
            "a file:// backend URL should open"
        );
    }
}
