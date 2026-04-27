//! Async secret-name discovery for the KeyStorage sub-flow.
//!
//! Operators can hit `F5` on the AwsNamespace / GcpNamespace / AzureVault /
//! VaultMount screens to trigger a backend `list_namespace` call. The
//! returned names are shown raw (sorted + deduplicated) so the operator
//! can see exactly what's already in the backend and pick a namespace
//! that doesn't collide.
//!
//! The overlay is informational: Esc and Enter both dismiss it. The
//! operator types the namespace into the prompt themselves rather than
//! having the wizard derive a candidate from existing secret names —
//! the earlier "11 prefixes from 14 secrets" projection was confusing
//! and risked picking a deeply-nested key as a namespace.
//!
//! Discovery runs as a `tokio::spawn`'d task so the TUI keeps redrawing
//! while the SDK call is in flight. Results travel back over an
//! [`UnboundedSender`]; the wizard's main-loop ticker drains the
//! receiver into [`crate::app::WizardApp::discovery`] state.
//!
//! Authentication for each backend is the same as the runtime's: the
//! wizard does *not* prompt for credentials. Operators must have:
//! - AWS:   ambient credentials (env, profile, instance role)
//! - GCP:   Application Default Credentials
//! - Azure: `az login` (DeveloperToolsCredential chain)
//! - Vault: `VAULT_TOKEN` env var
//!
//! Auth failures surface as `Failed { message }` with the SDK's own
//! error string verbatim — most are actionable already.

use affinidi_messaging_mediator_common::secrets::open_store;
use tokio::sync::mpsc::UnboundedSender;

/// Snapshot of the discovery sub-flow, owned by [`crate::app::WizardApp`]
/// and drained from the channel on each tick.
#[derive(Debug, Clone)]
pub enum DiscoveryState {
    /// Background task running. Render a one-line spinner row over the
    /// usual prompt.
    Loading,
    /// Backend returned a list. Render scrollable, dismissable overlay.
    Loaded {
        /// Raw secret names returned by the backend, sorted + deduped.
        items: Vec<String>,
        /// Operator's current selection. Always within `items.len()`.
        /// Tracked for highlight only — selection has no side effect.
        cursor: usize,
        /// Vertical scroll offset.
        scroll: usize,
    },
    /// Backend errored. Render the message; any key dismisses.
    Failed { message: String },
}

/// Async-side discovery result. Sent from the spawned task back to the
/// main loop, where [`crate::app::WizardApp::drain_discovery_events`]
/// consumes it.
#[derive(Debug)]
pub enum DiscoveryEvent {
    Loaded { items: Vec<String> },
    Failed(String),
}

/// What the wizard is asking discovery to enumerate. Carries every
/// piece of partial-URL config the spawned task needs to reach the
/// backend without going back through the wizard for more state.
#[derive(Debug, Clone)]
pub enum DiscoveryRequest {
    /// `aws_secrets://<region>/` — list every secret in the region.
    Aws { region: String },
    /// `gcp_secrets://<project>/` — list every secret in the project.
    Gcp { project: String },
    /// `azure_keyvault://<vault>` — list every secret name in the vault.
    Azure { vault: String },
    /// `vault://<endpoint>/<mount>` — list keys at the mount root. Both
    /// folders (entries ending with `/`) and leaves are surfaced raw so
    /// the operator can see the live layout.
    Vault { endpoint: String, mount: String },
}

impl DiscoveryRequest {
    /// Render the partial URL the backend factory expects. The body
    /// is intentionally minimal — only enough config to reach the
    /// namespace, not a per-secret namespace (which is what discovery
    /// is meant to *find*).
    fn url(&self) -> String {
        match self {
            // The trailing `/` after the region is a separator the AWS
            // URL parser requires. Empty body after the slash means
            // "no operator-side namespace yet" — list_namespace ignores
            // the namespace anyway.
            Self::Aws { region } => format!("aws_secrets://{region}/"),
            Self::Gcp { project } => format!("gcp_secrets://{project}/"),
            Self::Azure { vault } => format!("azure_keyvault://{vault}"),
            // Vault's URL parser uses the first path segment as the
            // KV v2 mount; everything after becomes the namespace. We
            // pass the operator's typed value through verbatim so a
            // partial mount like `secret` → mount=secret, no namespace.
            Self::Vault { endpoint, mount } => format!("vault://{endpoint}/{mount}"),
        }
    }
}

/// Spawn a background task that opens the partial backend URL, calls
/// `list_namespace`, sorts + dedupes the result onto a wizard-shaped
/// [`DiscoveryEvent`], and sends it back over `tx`.
///
/// The caller is responsible for setting [`DiscoveryState::Loading`]
/// on the wizard before spawning so the UI shows a spinner immediately.
/// The receiver side ([`crate::app::WizardApp::drain_discovery_events`])
/// transitions to `Loaded` / `Failed` when the event arrives.
pub fn spawn(req: DiscoveryRequest, tx: UnboundedSender<DiscoveryEvent>) {
    tokio::spawn(async move {
        let url = req.url();
        let store = match open_store(&url) {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(DiscoveryEvent::Failed(format!("open backend: {e}")));
                return;
            }
        };
        let raw = match store.list_namespace().await {
            Ok(names) => names,
            Err(e) => {
                let _ = tx.send(DiscoveryEvent::Failed(format!("list_namespace: {e}")));
                return;
            }
        };
        let mut items = raw;
        items.sort();
        items.dedup();
        let _ = tx.send(DiscoveryEvent::Loaded { items });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_url_shapes() {
        assert_eq!(
            DiscoveryRequest::Aws {
                region: "us-west-2".into()
            }
            .url(),
            "aws_secrets://us-west-2/"
        );
        assert_eq!(
            DiscoveryRequest::Gcp {
                project: "my-proj".into()
            }
            .url(),
            "gcp_secrets://my-proj/"
        );
        assert_eq!(
            DiscoveryRequest::Azure {
                vault: "my-vault".into()
            }
            .url(),
            "azure_keyvault://my-vault"
        );
        assert_eq!(
            DiscoveryRequest::Vault {
                endpoint: "vault.internal:8200".into(),
                mount: "secret".into(),
            }
            .url(),
            "vault://vault.internal:8200/secret"
        );
    }
}
