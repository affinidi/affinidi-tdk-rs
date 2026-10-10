//! `mediator rotate-admin` — rotate the admin credential the mediator
//! uses to authenticate against its VTA.
//!
//! ## What it does
//!
//! 1. Load the config file (default `conf/mediator.toml`) so we know
//!    which secret backend to talk to.
//! 2. Open the unified secret backend and read the current
//!    [`affinidi_messaging_mediator_common::AdminCredential`] under the
//!    well-known key `mediator_admin_credential`.
//! 3. Authenticate to the VTA using the existing credential.
//! 4. Read the existing ACL entry (`role`, `allowed_contexts`, optional
//!    `expires_at`) so the new entry is a faithful mirror — losing
//!    `allowed_contexts` here would silently scope-shrink production
//!    access.
//! 5. Mint a fresh Ed25519 did:key locally.
//! 6. `POST /acl` with the new DID and the mirrored scope.
//! 7. Write the new [`AdminCredential`] into the unified backend
//!    (replacing the old well-known entry).
//! 8. `DELETE /acl/{old_did}` to revoke the previous identity. If the
//!    backend write succeeded but the delete fails, the new entry is
//!    already live — the mediator keeps working — so we surface the
//!    leftover-ACL warning rather than rolling back.
//! 9. Log the old + new DIDs so the rotation is auditable.
//!
//! ## `--dry-run`
//!
//! Performs steps 1–4 (read-only against the VTA), prints the plan,
//! and exits without touching the backend or the ACL. Use it before
//! the real rotation in production.
//!
//! ## Failure semantics
//!
//! - **VTA unreachable** → exit non-zero before any state change.
//! - **`create_acl` fails** → exit non-zero, no backend write.
//! - **Backend write fails after `create_acl`** → the new ACL entry
//!   exists on the VTA but the mediator still has the old credential.
//!   Surfaces a clear remediation message ("rerun with the new key
//!   manually pasted") and exits non-zero. We do *not* try to rollback
//!   the ACL because the wizard's logs are the audit trail.
//! - **`delete_acl(old)` fails** → the rotation succeeded; the old
//!   entry is still active. Surface as a warning and exit zero, with
//!   the operator instructed to remove it via `pnm acl delete`.

use affinidi_messaging_mediator_common::{AdminCredential, MediatorSecrets};
use std::time::Duration;
use tracing::{error, info, warn};
use vta_sdk::client::CreateAclRequest;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::integration::{TransportPreference, VtaServiceConfig, authenticate};

/// Top-level entry called from the CLI dispatcher in `main.rs`.
/// Pick the transport preference from whether the credential carries a
/// usable REST URL. Pure so the choice is testable without a VTA — the
/// rationale lives at the call site.
fn transport_preference_for(vta_url: Option<&str>) -> TransportPreference {
    if vta_url.is_some_and(|u| !u.is_empty()) {
        TransportPreference::PreferRest
    } else {
        TransportPreference::Auto
    }
}

pub async fn run(config_path: &str, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config '{config_path}': {e}"))?;
    let doc: toml::Value =
        toml::from_str(&raw).map_err(|e| format!("Failed to parse '{config_path}': {e}"))?;
    let backend_url = doc
        .get("secrets")
        .and_then(|s| s.get("backend"))
        .and_then(|b| b.as_str())
        .ok_or_else(|| {
            "Config has no `[secrets].backend` — Phase C+D added the unified backend; \
             this command requires a `[secrets]` section pointing at a real store. \
             Re-run `mediator-setup` to migrate."
                .to_string()
        })?;
    info!(
        backend = backend_url,
        config = config_path,
        dry_run,
        "Starting admin rotation",
    );

    let secrets = MediatorSecrets::from_url(backend_url)
        .map_err(|e| format!("Could not open backend '{backend_url}': {e}"))?;
    secrets
        .probe()
        .await
        .map_err(|e| format!("Backend '{backend_url}' failed probe: {e}"))?;

    let current = secrets
        .load_admin_credential()
        .await
        .map_err(|e| format!("Could not load admin credential: {e}"))?
        .ok_or_else(|| {
            "No admin credential present in the backend. Nothing to rotate — \
             bootstrap with `mediator-setup` first."
                .to_string()
        })?;

    // rotate-admin is exclusively a VTA operation: it re-registers
    // the admin identity with the VTA's ACL. A self-hosted admin
    // credential (no VTA DID/URL) has nothing to rotate against.
    if !current.is_vta_linked() {
        return Err(
            "Admin credential is self-hosted (no VTA linkage). `mediator rotate-admin` only \
             works for VTA-linked deployments — nothing to rotate against."
                .into(),
        );
    }
    let old_did = current.did.clone();
    let context = current.context.clone();
    let vta_did = current
        .vta_did
        .clone()
        .expect("is_vta_linked() guarantees vta_did is Some");
    let vta_url = current.vta_url.clone();

    info!(
        admin_did = %old_did,
        vta_did = %vta_did,
        context = %context,
        "Loaded current admin credential — authenticating to VTA",
    );

    let bundle = CredentialBundle {
        did: old_did.clone(),
        private_key_multibase: current.private_key_multibase.clone(),
        vta_did: vta_did.clone(),
        vta_url: vta_url.clone(),
    };
    // vta-sdk 0.6.x split `VtaServiceConfig` into `auth` + `context`.
    //
    // Transport preference is chosen from whether we have a REST URL,
    // because `PreferRest` unconditionally is a dead end for a VTA that
    // has no REST endpoint: the SDK maps it to `TransportPlan::RestOnly`
    // with no DIDComm fallback, so rotation against a DIDComm-only VTA
    // could not authenticate at all.
    //
    // The original reason for pinning REST here — that `get_acl` /
    // `create_acl` needed the synchronous REST API — no longer holds.
    // Both go through `rpc_tt` -> `dispatch_trust_task`, which is
    // identical for the REST, DIDComm and TSP transports; REST's bespoke
    // per-operation routes were removed upstream. The operation is a
    // Trust Task on every transport, so the wire document is the same.
    //
    // - `vta_url` present: keep `PreferRest`. It is known-good for
    //   existing deployments, and it avoids dialling DIDComm in the
    //   self-mediated topology, where the VTA's DIDComm mediator is this
    //   very process — which may not be running when an operator invokes
    //   `rotate-admin` from the CLI.
    // - `vta_url` absent: `Auto`. With `mediator_did: None` the SDK
    //   resolves the VTA's DIDComm mediator from its DID document and
    //   tries DIDComm with a REST fallback; if the DID document
    //   advertises no `DIDCommMessaging` service it degrades to
    //   `RestOnly`, exactly the behaviour this branch had before.
    //
    // NOTE: `Auto` cannot select TSP — `decide_transport` has no TSP arm,
    // and `Transport::Tsp` is only reachable through the explicit
    // `VtaClient::connect_tsp`. A TSP-only VTA still cannot be rotated
    // against; that gap has to close in vta-sdk, not here.
    let transport_preference = transport_preference_for(vta_url.as_deref());
    let svc = VtaServiceConfig {
        auth: vta_sdk::integration::VtaAuthConfig {
            credential: bundle,
            url_override: vta_url.clone().filter(|u| !u.is_empty()),
            timeout: None,
        },
        context: vta_sdk::integration::VtaContextConfig {
            id: context.clone(),
            mediator_did: None,
            transport_preference,
            did_resolver: None,
        },
    };
    let client = authenticate(&svc)
        .await
        .map_err(|e| format!("Could not authenticate to VTA: {e}"))?;

    // Mirror the existing ACL scope so we don't silently shrink
    // permissions. `expires_at` is intentionally NOT mirrored — the
    // operator is rotating because they want a long-lived production
    // entry; ad-hoc setup ACLs were never meant to survive rotation.
    let existing_acl = client
        .get_acl(&old_did)
        .await
        .map_err(|e| format!("Could not read existing ACL for {old_did}: {e}"))?;
    info!(
        role = %existing_acl.role,
        allowed_contexts = ?existing_acl.allowed_contexts,
        label = ?existing_acl.label,
        "Existing ACL scope read — will mirror onto the new DID",
    );

    let (new_did, new_private_key_multibase) = mint_did_key()?;
    info!(new_admin_did = %new_did, "Minted new admin did:key");

    if dry_run {
        println!();
        println!("\x1b[1mDry run — no changes made.\x1b[0m");
        println!();
        println!("Would rotate:");
        println!("  Old DID:           {old_did}");
        println!("  New DID:           {new_did}");
        println!("  VTA:               {vta_did}");
        println!("  Context:           {context}");
        println!("  Role to mirror:    {}", existing_acl.role);
        println!("  Contexts to mirror: {:?}", existing_acl.allowed_contexts);
        if let Some(label) = existing_acl.label.as_ref() {
            println!("  Label:             {label}");
        }
        println!();
        println!(
            "Re-run without --dry-run to perform the rotation. The new key \
             will be displayed once on success — capture it before the wizard exits."
        );
        return Ok(());
    }

    let mut create_req = CreateAclRequest::new(&new_did, &existing_acl.role);
    create_req.allowed_contexts = existing_acl.allowed_contexts.clone();
    if let Some(label) = existing_acl.label.clone() {
        create_req = create_req.label(label);
    }

    client
        .create_acl(create_req)
        .await
        .map_err(|e| format!("Could not register new ACL entry for {new_did}: {e}"))?;
    info!(new_admin_did = %new_did, "New ACL entry registered on the VTA");

    let new_credential = AdminCredential {
        did: new_did.clone(),
        private_key_multibase: new_private_key_multibase,
        vta_did: Some(vta_did.clone()),
        vta_url: vta_url.clone(),
        context: context.clone(),
    };

    if let Err(e) = write_admin_credential_checked(&secrets, &new_credential).await {
        error!(
            new_admin_did = %new_did,
            error = %e,
            "ACL was created on the VTA but writing the new credential to the backend failed. \
             The backend still holds the OLD credential, which keeps working; the new \
             ACL entry is live but unused, and its key was not kept. Recovery: remove \
             the new ACL entry on the VTA (e.g. `pnm acl delete <new DID>`), fix the \
             cause above, then run `mediator rotate-admin` again."
        );
        return Err(format!("backend write failed after ACL create: {e}").into());
    }
    info!(new_admin_did = %new_did, "New admin credential written to backend");

    match client.delete_acl(&old_did).await {
        Ok(()) => info!(old_admin_did = %old_did, "Old ACL entry removed from the VTA"),
        Err(e) => warn!(
            old_admin_did = %old_did,
            error = %e,
            "Rotation succeeded but the old ACL entry could not be deleted. \
             The mediator now uses the new credential; the old entry remains \
             on the VTA until you remove it (e.g. via `pnm acl delete <did>`). \
             This does not block the mediator but is worth cleaning up."
        ),
    }

    println!();
    println!("\x1b[32m\u{2714}\x1b[0m Admin rotation complete.");
    println!("  Old DID: \x1b[2m{old_did}\x1b[0m");
    println!("  New DID: \x1b[36m{new_did}\x1b[0m");
    println!();
    println!(
        "The mediator will use the new credential on its next start. \
         If a mediator process is currently running, restart it to pick up the rotation."
    );
    Ok(())
}

/// How many times to write the new credential before giving up.
const WRITE_ATTEMPTS: u32 = 3;
/// Pause between writing the credential and reading it back.
const WRITE_SETTLE: Duration = Duration::from_secs(2);

/// Write `credential`, then read it back from the backend after a pause and
/// write again if it is gone. The secret store has no compare-and-swap, and
/// on per-key backends every entry shares one secret: a running mediator
/// rewriting its VTA cache can read the bundle just before this write and
/// put it back just after, losing the new credential. The old ACL entry is
/// revoked only once this returns `Ok`, so a lost write must not go unseen.
async fn write_admin_credential_checked(
    secrets: &MediatorSecrets,
    credential: &AdminCredential,
) -> Result<(), String> {
    for attempt in 1..=WRITE_ATTEMPTS {
        secrets
            .store_admin_credential(credential)
            .await
            .map_err(|e| e.to_string())?;
        // Let a read-modify-write that began before ours land first.
        tokio::time::sleep(WRITE_SETTLE).await;
        match secrets.reload_admin_credential().await {
            Ok(Some(stored))
                if stored.did == credential.did
                    && stored.private_key_multibase == credential.private_key_multibase =>
            {
                return Ok(());
            }
            Ok(_) => warn!(
                attempt,
                "the new admin credential was overwritten by another writer; writing it again"
            ),
            Err(e) => warn!(
                attempt,
                error = %e,
                "could not read the new admin credential back; writing it again"
            ),
        }
    }
    Err(format!(
        "the new admin credential did not persist after {WRITE_ATTEMPTS} attempts — \
         another process kept overwriting the secret store; stop it and retry"
    ))
}

/// Mint a fresh Ed25519 did:key locally. Returns `(did, private_key_multibase)`
/// in the same shape the wizard's setup-key generator uses, so callers can
/// reuse `AdminCredential::private_key_multibase` end-to-end without
/// re-encoding.
///
/// Mirrors `vta_sdk::session::generate_did_key` semantics but uses
/// `affinidi-tdk` primitives via the `affinidi-secrets-resolver` crate
/// already in our dep tree.
fn mint_did_key() -> Result<(String, String), Box<dyn std::error::Error>> {
    use affinidi_secrets_resolver::secrets::Secret;

    let secret = Secret::generate_ed25519(None, None);
    let did = secret
        .id
        .split_once('#')
        .map(|(d, _)| d.to_string())
        .unwrap_or_else(|| secret.id.clone());
    let private_key_multibase = secret
        .get_private_keymultibase()
        .map_err(|e| format!("could not extract private key multibase: {e}"))?;
    // Sanity check — `Secret::generate_ed25519` should always yield a
    // did:key, but if the generator ever returns something else we want
    // to fail loudly rather than ship a non-rotatable identity.
    if !did.starts_with("did:key:") {
        return Err(format!("expected did:key, generator produced '{did}'").into());
    }
    Ok((did, private_key_multibase))
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_mediator_common::ADMIN_CREDENTIAL;
    use affinidi_messaging_mediator_common::secrets::{
        Result as SecretsResult, SecretStore, backends::MemoryStore,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Silently drops the first `lost` admin-credential writes, as a
    /// concurrent read-modify-write would.
    struct LosesWrites {
        inner: MemoryStore,
        lost: AtomicU32,
    }

    #[async_trait::async_trait]
    impl SecretStore for LosesWrites {
        fn backend(&self) -> &'static str {
            "loses-writes"
        }
        async fn get(&self, key: &str) -> SecretsResult<Option<Vec<u8>>> {
            self.inner.get(key).await
        }
        async fn put(&self, key: &str, value: &[u8]) -> SecretsResult<()> {
            if key == ADMIN_CREDENTIAL
                && self
                    .lost
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
            {
                return Ok(());
            }
            self.inner.put(key, value).await
        }
        async fn delete(&self, key: &str) -> SecretsResult<()> {
            self.inner.delete(key).await
        }
        fn is_single_object(&self) -> bool {
            true
        }
    }

    fn secrets_losing(lost: u32) -> MediatorSecrets {
        MediatorSecrets::new(Arc::new(LosesWrites {
            inner: MemoryStore::new("memory"),
            lost: AtomicU32::new(lost),
        }))
    }

    fn credential() -> AdminCredential {
        AdminCredential {
            did: "did:key:z6MkNEW".into(),
            private_key_multibase: "z3u2NEW".into(),
            vta_did: Some("did:webvh:vta.example.com".into()),
            vta_url: None,
            context: "mediator".into(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_credential_write_is_written_again() {
        let secrets = secrets_losing(1);
        write_admin_credential_checked(&secrets, &credential())
            .await
            .unwrap();
        let stored = secrets.reload_admin_credential().await.unwrap().unwrap();
        assert_eq!(stored.did, "did:key:z6MkNEW");
    }

    #[tokio::test(start_paused = true)]
    async fn a_credential_that_never_persists_is_an_error() {
        let secrets = secrets_losing(WRITE_ATTEMPTS);
        assert!(
            write_admin_credential_checked(&secrets, &credential())
                .await
                .is_err()
        );
    }

    #[test]
    fn a_credential_with_a_rest_url_prefers_rest() {
        // Known-good for existing deployments, and it avoids dialling
        // DIDComm in the self-mediated topology where the VTA's mediator
        // is this very process.
        assert!(matches!(
            transport_preference_for(Some("https://vta.example.com")),
            TransportPreference::PreferRest
        ));
    }

    #[test]
    fn a_credential_without_a_rest_url_uses_auto() {
        // `PreferRest` here maps to `RestOnly` with no DIDComm fallback,
        // which cannot authenticate against a DIDComm-only VTA at all.
        assert!(matches!(
            transport_preference_for(None),
            TransportPreference::Auto
        ));
    }

    #[test]
    fn an_empty_rest_url_is_treated_as_absent() {
        // `url_override` filters empties, so an empty string would
        // otherwise select RestOnly with no URL to resolve against.
        assert!(matches!(
            transport_preference_for(Some("")),
            TransportPreference::Auto
        ));
    }
}
