//! `mediator rotate-admin` — rotate the admin credential the mediator
//! uses to authenticate against its VTA.
//!
//! ## What it does
//!
//! 1. Load the config file (default `conf/mediator.toml`) so we know
//!    which secret backend to talk to.
//! 2. Open the unified secret backend and read the current
//!    [`affinidi_messaging_mediator_common::AdminCredential`] under the
//!    well-known key `mediator/admin/credential`.
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
use tracing::{error, info, warn};
use vta_sdk::client::CreateAclRequest;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::integration::{TransportPreference, VtaServiceConfig, authenticate};

/// Top-level entry called from the CLI dispatcher in `main.rs`.
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
            "No admin credential present in the backend (well-known key \
             `mediator/admin/credential`). Nothing to rotate — bootstrap with \
             `mediator-setup` first."
                .to_string()
        })?;

    let old_did = current.did.clone();
    let context = current.context.clone();
    let vta_did = current.vta_did.clone();
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
    let svc = VtaServiceConfig {
        credential: bundle,
        context: context.clone(),
        url_override: vta_url.clone().filter(|u| !u.is_empty()),
        timeout: None,
        // Admin rotation is a one-shot operator command, not a hot
        // path — REST is the right fit. Explicit `PreferRest` keeps
        // the ACL create/rotate calls off the DIDComm channel (where
        // they'd need to negotiate an async reply envelope) and lands
        // on the synchronous REST API that `get_acl` / `create_acl`
        // are built for.
        mediator_did: None,
        transport_preference: TransportPreference::PreferRest,
        did_resolver: None,
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
        vta_did: vta_did.clone(),
        vta_url: vta_url.clone(),
        context: context.clone(),
    };

    if let Err(e) = secrets.store_admin_credential(&new_credential).await {
        error!(
            new_admin_did = %new_did,
            error = %e,
            "ACL was created on the VTA but writing the new credential to the backend failed. \
             The mediator still holds the OLD credential; the new ACL entry is live but \
             unused. Recovery: re-run with `mediator-setup --force-reprovision` to write \
             the new credential, or remove the new ACL entry on the VTA before retrying."
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
