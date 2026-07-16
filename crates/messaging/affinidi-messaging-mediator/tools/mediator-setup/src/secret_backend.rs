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
    /// never written — `Ok` even when absent). Requested by the **headless /
    /// recipe** flow, but honoured **only for `aws_secrets://`** backends,
    /// where the Secrets Manager entries are provisioned out-of-band (e.g. CDK
    /// pre-creates them) so setup only overwrites them and never needs
    /// create/delete rights — the IaC-owns-lifecycle contract, matching the
    /// mediator runtime, which also probes read-only at boot and on `/readyz`.
    ///
    /// For every other backend (`file://`, `keyring://`, `vault://`, …) the
    /// setup tool itself creates the secrets, so a requested `ReadOnly` is
    /// narrowed back to [`ReadWrite`](Self::ReadWrite) by
    /// [`open_and_probe_secret_backend`] — the write round-trip still fails
    /// fast on missing permissions, even headless.
    ReadOnly,
}

/// Whether `backend_url` names an AWS-managed secret store (`aws_secrets://`).
/// Only these follow the IaC-owns-lifecycle principle and are eligible for the
/// read-only provisioning probe; see [`ProvisionProbe::ReadOnly`].
fn is_aws_secrets_backend(backend_url: &str) -> bool {
    backend_url.starts_with("aws_secrets://")
}

/// Resolve the probe actually run for `backend_url` from the one `requested`.
/// A `ReadOnly` request is honoured only for AWS-managed backends; for anything
/// else it falls back to `ReadWrite`. `ReadWrite` requests pass through
/// unchanged. Pure so the narrowing rule can be unit-tested directly.
fn effective_probe(backend_url: &str, requested: ProvisionProbe) -> ProvisionProbe {
    match requested {
        ProvisionProbe::ReadOnly if !is_aws_secrets_backend(backend_url) => {
            ProvisionProbe::ReadWrite
        }
        other => other,
    }
}

/// Open the unified secret backend and probe it, so a misconfigured or
/// unreachable store (e.g. `aws_secrets://` with no credentials) fails fast with
/// an actionable error instead of part-way through provisioning.
///
/// A requested [`ProvisionProbe::ReadOnly`] is honoured **only for
/// `aws_secrets://`** backends (the IaC-owns-lifecycle contract); for every
/// other backend it is narrowed back to [`ProvisionProbe::ReadWrite`], so the
/// setup tool — which creates those secrets itself — keeps the write round-trip
/// that fails fast on missing permissions, even in headless flows. Interactive
/// callers always pass `ReadWrite` and are unaffected.
pub async fn open_and_probe_secret_backend(
    backend_url: &str,
    probe: ProvisionProbe,
) -> anyhow::Result<MediatorSecrets> {
    let store = open_secret_backend(backend_url)?;
    let probe = effective_probe(backend_url, probe);
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

    #[test]
    fn readonly_probe_is_honoured_only_for_aws_secrets() {
        // AWS-managed store: IaC owns the lifecycle, so ReadOnly stands.
        assert_eq!(
            effective_probe(
                "aws_secrets://us-east-1/mediator/",
                ProvisionProbe::ReadOnly
            ),
            ProvisionProbe::ReadOnly,
        );
        // Every other backend creates its own secrets → narrow to ReadWrite.
        for url in [
            "file:///tmp/secrets.json",
            "keyring://affinidi-mediator",
            "vault://vault.example.com/secret",
            "gcp_secrets://proj/mediator/",
        ] {
            assert_eq!(
                effective_probe(url, ProvisionProbe::ReadOnly),
                ProvisionProbe::ReadWrite,
                "{url} should fall back to a write round-trip",
            );
        }
    }

    #[test]
    fn readwrite_probe_passes_through_for_every_backend() {
        for url in [
            "aws_secrets://us-east-1/mediator/",
            "file:///tmp/secrets.json",
            "keyring://affinidi-mediator",
        ] {
            assert_eq!(
                effective_probe(url, ProvisionProbe::ReadWrite),
                ProvisionProbe::ReadWrite,
                "{url} must keep an explicit ReadWrite request",
            );
        }
    }
}
