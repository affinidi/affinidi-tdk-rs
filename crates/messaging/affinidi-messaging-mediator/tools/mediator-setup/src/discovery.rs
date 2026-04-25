//! Async secret-name discovery for the KeyStorage sub-flow.
//!
//! Operators can hit `F5` on the AwsPrefix / GcpPrefix / AzureVault /
//! VaultMount screens to trigger a backend `list_namespace` call. The
//! returned names are projected into either:
//!
//! - **Pick mode** — derived prefixes the operator can scroll and select
//!   to populate the current text input. Used for AWS and Vault where
//!   the URL has a clean separator (`/`) for deriving deployment-scope
//!   namespaces.
//! - **Confirm mode** — raw names shown as a "backend reachable" sanity
//!   check. Used for GCP (its `[A-Za-z0-9_-]` names have no canonical
//!   separator the wizard can derive against) and Azure Key Vault
//!   (whose URL today carries no per-deployment prefix at all).
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

/// Whether the discovery overlay applies its selection back to the text
/// input on Enter, or is purely informational (Esc dismisses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMode {
    /// Selecting an entry replaces the current text input value with
    /// the picked string and dismisses the overlay.
    Pick,
    /// Selecting an entry dismisses without changing the text input.
    /// Used when the discovered names don't map cleanly onto the field
    /// the operator is editing — F5 still serves as a "yes I can reach
    /// this backend with these creds" signal.
    Confirm,
}

/// Snapshot of the discovery sub-flow, owned by [`crate::app::WizardApp`]
/// and drained from the channel on each tick.
#[derive(Debug, Clone)]
pub enum DiscoveryState {
    /// Background task running. Render a one-line spinner row over the
    /// usual prompt.
    Loading,
    /// Backend returned a list. Render scrollable selection overlay.
    Loaded {
        mode: DiscoveryMode,
        /// Items already projected onto the wizard's needs: candidate
        /// prefixes for `Pick` mode, raw names for `Confirm`. Sorted +
        /// deduplicated.
        items: Vec<String>,
        /// Total raw key count returned by the backend (for the
        /// "showing N derived from M raw secrets" footer).
        total: usize,
        /// Operator's current selection. Always within `items.len()`.
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
    Loaded {
        mode: DiscoveryMode,
        items: Vec<String>,
        total: usize,
    },
    Failed(String),
}

/// What the wizard is asking discovery to enumerate. Carries every
/// piece of partial-URL config the spawned task needs to reach the
/// backend without going back through the wizard for more state.
#[derive(Debug, Clone)]
pub enum DiscoveryRequest {
    /// `aws_secrets://<region>/` — list every secret in the region,
    /// derive unique slash-prefixes (the namespace the operator would
    /// type).
    Aws { region: String },
    /// `gcp_secrets://<project>/` — list every secret in the project.
    /// Confirm mode: GCP names are flat (no `/` allowed) so there's no
    /// canonical prefix separator — the operator reads the names and
    /// picks a prefix manually.
    Gcp { project: String },
    /// `azure_keyvault://<vault>` — list every secret name in the vault.
    /// Confirm mode: Azure URLs carry no prefix segment today.
    Azure { vault: String },
    /// `vault://<endpoint>/<mount>` — list keys at the mount root,
    /// keep the "folders" (entries ending with `/`). Each candidate
    /// prefix is rendered as `<typed_mount>/<folder>` so picking one
    /// gives the operator a complete mount+prefix string.
    Vault { endpoint: String, mount: String },
}

impl DiscoveryRequest {
    /// Render the partial URL the backend factory expects. The body
    /// is intentionally minimal — only enough config to reach the
    /// namespace, not a per-secret prefix (which is what discovery is
    /// meant to *find*).
    fn url(&self) -> String {
        match self {
            // The trailing `/` after the region is a separator the AWS
            // URL parser requires. Empty body after the slash means
            // "no operator-side prefix yet" — list_namespace ignores
            // the prefix anyway.
            Self::Aws { region } => format!("aws_secrets://{region}/"),
            Self::Gcp { project } => format!("gcp_secrets://{project}/"),
            Self::Azure { vault } => format!("azure_keyvault://{vault}"),
            // Vault's URL parser uses the first path segment as the
            // KV v2 mount; everything after becomes the prefix. We
            // pass the operator's typed value through verbatim so
            // a partial mount like `secret` → mount=secret, no prefix.
            Self::Vault { endpoint, mount } => format!("vault://{endpoint}/{mount}"),
        }
    }

    /// Per-backend mode (Pick vs Confirm). See [`DiscoveryMode`].
    fn mode(&self) -> DiscoveryMode {
        match self {
            Self::Aws { .. } | Self::Vault { .. } => DiscoveryMode::Pick,
            Self::Gcp { .. } | Self::Azure { .. } => DiscoveryMode::Confirm,
        }
    }
}

/// Spawn a background task that opens the partial backend URL, calls
/// `list_namespace`, projects the result onto the wizard-shaped
/// [`DiscoveryEvent`], and sends it back over `tx`.
///
/// The caller is responsible for setting [`DiscoveryState::Loading`]
/// on the wizard before spawning so the UI shows a spinner immediately.
/// The receiver side ([`crate::app::WizardApp::drain_discovery_events`])
/// transitions to `Loaded` / `Failed` when the event arrives.
pub fn spawn(req: DiscoveryRequest, tx: UnboundedSender<DiscoveryEvent>) {
    tokio::spawn(async move {
        let url = req.url();
        let mode = req.mode();
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
        let total = raw.len();
        let items = match &req {
            DiscoveryRequest::Aws { .. } => derive_slash_prefixes(&raw),
            DiscoveryRequest::Vault { mount, .. } => derive_vault_folders(&raw, mount),
            DiscoveryRequest::Gcp { .. } | DiscoveryRequest::Azure { .. } => {
                let mut items = raw;
                items.sort();
                items.dedup();
                items
            }
        };
        let _ = tx.send(DiscoveryEvent::Loaded { mode, items, total });
    });
}

/// Group keys by their slash-prefix (everything up to and including the
/// last `/`). Skips entries without `/` — those are flat secrets that
/// don't define a namespace.
fn derive_slash_prefixes(raw: &[String]) -> Vec<String> {
    let mut prefixes: Vec<String> = raw
        .iter()
        .filter_map(|name| name.rfind('/').map(|i| name[..=i].to_string()))
        .collect();
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

/// Vault's `kv2::list` returns leaves and "folders" (entries ending
/// with `/`). Folders define the per-deployment namespace; we keep just
/// those and prefix each with the operator's typed `mount` so picking
/// yields a complete mount+prefix string the operator can paste back.
fn derive_vault_folders(raw: &[String], mount: &str) -> Vec<String> {
    // Strip an operator-typed trailing `/` so we don't end up with
    // `secret//mediator/` after the join.
    let mount_clean = mount.trim_end_matches('/');
    let mut folders: Vec<String> = raw
        .iter()
        .filter(|n| n.ends_with('/'))
        .map(|f| {
            if mount_clean.is_empty() {
                f.clone()
            } else {
                format!("{mount_clean}/{f}")
            }
        })
        .collect();
    folders.sort();
    folders.dedup();
    folders
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_prefixes_dedup_and_sort() {
        let raw = vec![
            "prod/mediator/admin_did".to_string(),
            "prod/mediator/jwt_secret".to_string(),
            "staging/mediator/admin_did".to_string(),
            "prod/other/key".to_string(),
        ];
        assert_eq!(
            derive_slash_prefixes(&raw),
            vec!["prod/mediator/", "prod/other/", "staging/mediator/",]
        );
    }

    #[test]
    fn slash_prefixes_skips_flat_keys() {
        // GCP-style flat names (no '/') don't define a slash-prefix,
        // so they're filtered out — the wizard renders an empty list
        // rather than dropping these into the prefix field as-is.
        let raw = vec!["flat_one".to_string(), "flat_two".to_string()];
        assert!(derive_slash_prefixes(&raw).is_empty());
    }

    #[test]
    fn vault_folders_prefixed_with_mount() {
        let raw = vec![
            "mediator/".to_string(),
            "staging/".to_string(),
            "leaf-secret".to_string(),
        ];
        // Operator typed `secret` → folders become `secret/<f>`.
        assert_eq!(
            derive_vault_folders(&raw, "secret"),
            vec!["secret/mediator/", "secret/staging/"]
        );
    }

    #[test]
    fn vault_folders_strip_trailing_mount_slash() {
        // The text input may carry a stray trailing `/` (operator
        // habit). The derivation strips it so the joined prefix is
        // `<mount>/<folder>`, not `<mount>//<folder>`.
        let raw = vec!["mediator/".to_string()];
        assert_eq!(
            derive_vault_folders(&raw, "secret/"),
            vec!["secret/mediator/"]
        );
    }

    #[test]
    fn vault_folders_empty_mount_keeps_folder_verbatim() {
        // Edge case — operator opened the prefix screen with an empty
        // mount value. The folder name is the candidate prefix on its
        // own.
        let raw = vec!["mediator/".to_string()];
        assert_eq!(derive_vault_folders(&raw, ""), vec!["mediator/"]);
    }

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

    #[test]
    fn request_modes_match_backend_capability() {
        // AWS / Vault have prefix-shaped namespaces — Pick mode.
        // GCP / Azure don't — Confirm-only.
        assert_eq!(
            DiscoveryRequest::Aws {
                region: "us-east-1".into()
            }
            .mode(),
            DiscoveryMode::Pick
        );
        assert_eq!(
            DiscoveryRequest::Vault {
                endpoint: "v".into(),
                mount: "s".into()
            }
            .mode(),
            DiscoveryMode::Pick
        );
        assert_eq!(
            DiscoveryRequest::Gcp {
                project: "p".into()
            }
            .mode(),
            DiscoveryMode::Confirm
        );
        assert_eq!(
            DiscoveryRequest::Azure { vault: "v".into() }.mode(),
            DiscoveryMode::Confirm
        );
    }
}
