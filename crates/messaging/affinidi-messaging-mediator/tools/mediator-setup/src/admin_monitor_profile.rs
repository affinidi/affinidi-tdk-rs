//! Emit a TDKProfile-shaped JSON file the operator can hand to
//! `mediator-monitor --admin-profile <path>` (and any other tool that
//! consumes the standard `affinidi_tdk_common::profiles::TDKProfile`
//! shape, e.g. the mediator-administration helper).
//!
//! Written only when the wizard has the admin DID's secret material
//! in memory — i.e., the `ADMIN_GENERATE` path where the wizard
//! freshly minted a `did:key:z6Mk…` admin and holds its Ed25519
//! private key in `MintedArtefacts.admin_secret`.
//!
//! For VTA-managed admins the secret material is in the VTA session
//! and gets handed to the configured secret backend by
//! `provision_secret_backend`; we deliberately do NOT re-derive a
//! flat-file profile from the backend here because:
//!
//! 1. Cloud backends (AWS Secrets Manager, GCP Secret Manager,
//!    Azure Key Vault, Vault) are usually chosen specifically to
//!    keep admin material off the local filesystem. Pulling the
//!    secret back to disk would defeat that choice.
//! 2. The `AdminCredential` envelope stores a single multibase key
//!    (Ed25519); reconstructing a `Secret` for the runtime auth
//!    flow needs a small amount of round-tripping that doesn't
//!    earn its keep here. A separate `mediator-setup
//!    export-admin-profile` subcommand can do it for VTA
//!    deployments — out of scope for this commit.
//!
//! The file is owner-only on Unix (0o600) via [`secure_fs::write_sensitive`].

use affinidi_secrets_resolver::secrets::Secret;
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::secure_fs;

/// Wire shape for the on-disk JSON. Mirrors
/// `affinidi_tdk_common::profiles::TDKProfile` so the file
/// round-trips through `serde_json::from_slice::<TDKProfile>(...)`
/// without translation. Built locally rather than depending on
/// `affinidi-tdk-common` so the wizard's dep graph stays lean.
#[derive(Serialize)]
struct WireProfile<'a> {
    alias: &'a str,
    did: &'a str,
    /// The mediator's DID — the JWT audience that
    /// `mediator-monitor` uses when minting access tokens.
    mediator: &'a str,
    secrets: Vec<&'a Secret>,
}

/// Filename written next to `mediator.toml`. Stable so tools and docs
/// can refer to it by name.
pub const PROFILE_FILENAME: &str = "admin-monitor.json";

/// Write `<conf-dir>/admin-monitor.json` and return the resolved path.
///
/// `config_path` is the wizard's `mediator.toml` path; the profile
/// lands in the same directory.
pub fn write(
    config_path: &str,
    mediator_did: &str,
    admin_did: &str,
    admin_secret: &Secret,
) -> anyhow::Result<PathBuf> {
    let dir = Path::new(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let out_path = dir.join(PROFILE_FILENAME);

    let wire = WireProfile {
        alias: "admin",
        did: admin_did,
        mediator: mediator_did,
        secrets: vec![admin_secret],
    };
    let json = serde_json::to_vec_pretty(&wire)
        .map_err(|e| anyhow::anyhow!("could not serialise admin monitor profile: {e}"))?;

    secure_fs::write_sensitive(&out_path, &json).map_err(|e| {
        anyhow::anyhow!(
            "could not write admin monitor profile to {}: {e}",
            out_path.display()
        )
    })?;
    Ok(out_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::dids::{DID, KeyType};
    use serde_json::Value;

    #[test]
    fn write_round_trips_through_tdk_profile_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("mediator.toml");
        // The wizard's `generate_admin_did_key()` mints exactly this
        // shape — one Ed25519 key, multibase-encoded — so use the
        // same generator here to keep the test honest.
        let (admin_did, admin_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("admin did:key");

        let out = write(
            config_path.to_str().expect("utf-8 config path"),
            "did:peer:2.Vz6MkMediatorExample",
            &admin_did,
            &admin_secret,
        )
        .expect("write admin monitor profile");

        assert_eq!(
            out.file_name().and_then(|s| s.to_str()),
            Some(PROFILE_FILENAME)
        );
        assert_eq!(out.parent(), Some(dir.path()));

        // Top-level shape: TDKProfile JSON has alias / did / mediator
        // / secrets. Don't go deeper into the secret material — the
        // upstream `Secret` Deserialize implementation owns that
        // contract; we only assert wire-level integration here.
        let raw = std::fs::read(&out).expect("read back");
        let v: Value = serde_json::from_slice(&raw).expect("parse json");
        let obj = v.as_object().expect("top-level object");
        assert_eq!(obj.get("alias").and_then(Value::as_str), Some("admin"));
        assert_eq!(obj.get("did").and_then(Value::as_str), Some(&admin_did[..]));
        assert_eq!(
            obj.get("mediator").and_then(Value::as_str),
            Some("did:peer:2.Vz6MkMediatorExample"),
        );
        let secrets = obj
            .get("secrets")
            .and_then(Value::as_array)
            .expect("secrets array");
        assert_eq!(secrets.len(), 1, "single Ed25519 admin secret");
        // Secret JSON carries its own `id` (the DID-relative key URL).
        let secret_id = secrets[0].get("id").and_then(Value::as_str).unwrap_or("");
        assert!(
            secret_id.starts_with(&admin_did),
            "secret id ({secret_id}) must reference admin DID ({admin_did})",
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("mediator.toml");
        let (admin_did, admin_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("admin did:key");

        let out = write(
            config_path.to_str().unwrap(),
            "did:peer:2.Vz6MkMediator",
            &admin_did,
            &admin_secret,
        )
        .expect("write");

        let perms = std::fs::metadata(&out).expect("stat").permissions();
        // 0o600 — owner-only is the floor; check no group / other bits.
        assert_eq!(
            perms.mode() & 0o077,
            0,
            "admin profile must not be group/world-readable: {:o}",
            perms.mode()
        );
    }
}
