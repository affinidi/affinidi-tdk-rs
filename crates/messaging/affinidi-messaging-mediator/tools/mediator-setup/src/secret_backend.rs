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

/// Open the unified secret backend and probe it, so a misconfigured or
/// unreachable store (e.g. `aws_secrets://` with no credentials) fails fast with
/// an actionable error instead of part-way through provisioning.
pub async fn open_and_probe_secret_backend(backend_url: &str) -> anyhow::Result<MediatorSecrets> {
    let store = open_secret_backend(backend_url)?;
    store
        .probe()
        .await
        .map_err(|e| anyhow::anyhow!("secret backend '{backend_url}' failed probe: {e}"))?;
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
