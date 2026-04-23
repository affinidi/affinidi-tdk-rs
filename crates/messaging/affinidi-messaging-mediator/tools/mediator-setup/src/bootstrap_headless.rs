//! Non-interactive sealed-handoff driver — the headless equivalent of
//! the TUI's `SealedHandoffState` state machine.
//!
//! `--from recipe.toml` drives a fully declarative setup. For the two
//! sealed modes (`sealed-mint`, `sealed-export`) the flow splits into
//! two invocations with a physical file handoff between them:
//!
//! **Phase 1** — mediator host emits a request file and persists an
//! ephemeral seed under `bootstrap-secrets/<bundle_id_hex>.key`. The
//! operator ships the request file to the VTA host, the VTA admin
//! runs the appropriate `vta …` command, and ships back a
//! `bundle.armor`.
//!
//! **Phase 2** — mediator host is re-run with `--bundle <path>`. The
//! wizard looks up the matching seed by bundle id, unseals, projects
//! onto a [`VtaSession`], runs the same `generate_and_write` pipeline
//! the TUI uses, and cleans up the request + seed artefacts on
//! success.
//!
//! The live-DIDComm `online` path is intentionally NOT supported here
//! — the VTA's `pnm acl create` step is inherently operator-gated and
//! can't be automated from a recipe. Operators who want online setup
//! use the interactive TUI.
//!
//! This module does *not* own the `WizardConfig → mediator.toml`
//! pipeline — that lives in `main::generate_and_write`. Phase 2
//! produces a fully-populated `VtaSession` and hands control back
//! to the outer recipe driver.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::consts::{VTA_MODE_ONLINE, VTA_MODE_SEALED_EXPORT, VTA_MODE_SEALED_MINT};
use crate::sealed_handoff::{SealedHandoffState, SealedPhase};
use crate::vta_connect::{VtaIntent, VtaSession};

/// Outcome of the phase dispatcher. Phase 1 exits the process after
/// writing the request; phase 2 returns a session for the outer
/// pipeline to consume.
#[derive(Debug)]
pub enum HeadlessOutcome {
    /// Phase 1: request file + seed written. The caller should print
    /// the operator instructions and exit with code 0.
    RequestEmitted {
        request_path: PathBuf,
        bundle_id_hex: String,
        producer_command: String,
    },
    /// Phase 2: sealed bundle opened, session materialised. Caller
    /// passes this to the generate-and-write pipeline, then invokes
    /// [`cleanup_artifacts`].
    Applied {
        session: VtaSession,
        artifacts: BootstrapArtifacts,
    },
}

/// The on-disk artefacts created during a sealed-handoff round. Passed
/// to [`cleanup_artifacts`] after a successful apply so the setup
/// directory is returned to a clean state.
#[derive(Debug, Clone)]
pub struct BootstrapArtifacts {
    /// The request JSON file the wizard wrote in phase 1. `None` when
    /// phase 1's best-effort write failed (we don't track what we
    /// didn't create).
    pub request_path: Option<PathBuf>,
    /// The ephemeral Ed25519 seed under
    /// `bootstrap-secrets/<bundle_id_hex>.key`. `None` when phase 1's
    /// best-effort write failed.
    pub seed_path: Option<PathBuf>,
}

/// Dispatch into phase 1 (request emission) or phase 2 (bundle apply)
/// based on whether `--bundle` was supplied.
///
/// Also enforces "don't clobber an in-flight bootstrap": if a seed
/// file exists under `bootstrap-secrets/` and the caller is attempting
/// phase 1 (no `--bundle`), we error rather than overwrite — the
/// operator must either finalise with `--bundle` or explicitly wipe
/// the directory.
pub async fn dispatch(
    config: &crate::app::WizardConfig,
    bundle_path: Option<&Path>,
    digest: Option<&str>,
) -> anyhow::Result<HeadlessOutcome> {
    match bundle_path {
        Some(path) => phase2_apply(config, path, digest).await,
        None => phase1_emit_request(config).await,
    }
}

/// Phase 1 — mint the ephemeral keypair, build the request (shape
/// depends on `config.vta_mode`), write the request JSON + seed, and
/// return the operator's next-step command for the caller to print.
async fn phase1_emit_request(config: &crate::app::WizardConfig) -> anyhow::Result<HeadlessOutcome> {
    // Refuse to clobber an in-flight bootstrap. The seed directory is
    // our only cross-invocation state; its presence means "a request
    // is out to a VTA operator, waiting for a bundle". Silently
    // regenerating would invalidate whatever comes back.
    let request_filename = default_request_filename(&config.vta_mode);
    let request_dir = std::env::current_dir()?;
    let secrets_dir = request_dir.join("bootstrap-secrets");
    if secrets_dir.is_dir() {
        let has_seeds = std::fs::read_dir(&secrets_dir)
            .map(|entries| {
                entries
                    .flatten()
                    .any(|e| e.path().extension().is_some_and(|x| x == "key"))
            })
            .unwrap_or(false);
        if has_seeds {
            anyhow::bail!(
                "A bootstrap is already in progress.\n  \
                 Seeds: {}/*.key\n  \
                 Request (likely): ./{request_filename}\n\n\
                 To finalise: re-run `mediator-setup --from <recipe> --bundle bundle.armor`\n\
                 To restart:  rm -rf {} ./{request_filename}  # destroys the in-flight request",
                secrets_dir.display(),
                secrets_dir.display(),
            );
        }
    }

    let intent = intent_for_mode(&config.vta_mode)?;
    let mut state = SealedHandoffState::new(
        intent,
        Some(format!("mediator setup — {}", config.vta_context)),
    );
    state.context_id = config.vta_context.clone();

    // Wire the mode-specific template vars onto the state before
    // finalising. sealed-mint needs the mediator URL (fed to the
    // VTA's `didcomm-mediator` template as `URL`); sealed-export
    // carries no template ask so these fields are inert.
    if intent == VtaIntent::FullSetup {
        if config.public_url.is_empty() {
            anyhow::bail!(
                "sealed-mint requires identity.public_url in the recipe \
                 (passed to the VTA's didcomm-mediator template as `URL`)"
            );
        }
        state.mediator_url = config.public_url.clone();
        if let Some(ref server) = config.vta_webvh_server_id {
            state.webvh_server = server.clone();
        }
    }

    state
        .finalize_request()
        .map_err(|e| anyhow::anyhow!("Could not build bootstrap request: {e}"))?;

    // `finalize_request` landed on `RequestGenerated`; the state now
    // holds the persisted paths. Mirror into our headless outcome.
    debug_assert_eq!(state.phase, SealedPhase::RequestGenerated);
    let request_path = state.request_path.clone().ok_or_else(|| {
        anyhow::anyhow!("wizard could not persist the request JSON; check directory permissions")
    })?;
    let bundle_id_hex = hex_lower(&state.nonce);
    let producer_command = state.primary_command();

    info!(
        bundle_id = %bundle_id_hex,
        intent = ?intent,
        request = %request_path.display(),
        "Sealed-handoff phase 1 complete — request emitted"
    );

    Ok(HeadlessOutcome::RequestEmitted {
        request_path,
        bundle_id_hex,
        producer_command,
    })
}

/// Phase 2 — ingest the armored bundle, look up the seed by bundle
/// id, unseal, and return a populated `VtaSession`.
async fn phase2_apply(
    config: &crate::app::WizardConfig,
    bundle_path: &Path,
    digest: Option<&str>,
) -> anyhow::Result<HeadlessOutcome> {
    let intent = intent_for_mode(&config.vta_mode)?;

    let armored = std::fs::read_to_string(bundle_path)
        .map_err(|e| anyhow::anyhow!("could not read bundle '{}': {e}", bundle_path.display()))?;

    // Reconstruct a synthetic `SealedHandoffState` keyed to this
    // bundle. The reconstructed state doesn't need the ephemeral
    // pub/private pair — `ingest_armored` just parses the armor and
    // computes the digest. The seed lookup happens between ingest
    // and `open_with_digest`.
    let mut state = SealedHandoffState::new(intent, None);
    state.context_id = config.vta_context.clone();

    crate::sealed_handoff::ingest_armored(&mut state, &armored).map_err(|e| {
        anyhow::anyhow!(
            "could not parse '{}' as an armored sealed bundle: {e}",
            bundle_path.display()
        )
    })?;

    // Pull bundle_id out of the parsed bundle directly — `state.nonce`
    // is only populated by the TUI's `finalize_request` (phase-1
    // write-side). In the headless phase-2 path we never call that,
    // so reading `state.nonce` would give the zero default. Sync
    // `state.nonce` from the bundle so downstream logs and the seed
    // filename stay consistent.
    let bundle_id = state
        .bundle
        .as_ref()
        .expect("ingest_armored populates state.bundle on success")
        .bundle_id;
    state.nonce = bundle_id;
    let bundle_id_hex = hex_lower(&bundle_id);
    let seed_path = locate_seed(bundle_path, &bundle_id_hex)?;
    let seed_bytes = load_seed(&seed_path)?;
    state.recipient_secret = *vta_sdk::sealed_transfer::ed25519_seed_to_x25519_secret(&seed_bytes);
    state.seed_path = Some(seed_path.clone());

    crate::sealed_handoff::open_with_digest(&mut state, digest.unwrap_or("")).map_err(|e| {
        anyhow::anyhow!(
            "could not open sealed bundle: {e}. \
             Verify the digest matches what the VTA admin printed, and \
             that the bundle belongs to this setup's request (seed: {})",
            seed_path.display()
        )
    })?;

    let session = state.session.take().ok_or_else(|| {
        anyhow::anyhow!("open_with_digest reported success but produced no session")
    })?;

    // Probe the bundle_id-keyed request filename next to the bundle.
    // Best-effort — we only use this to clean up after a successful
    // apply. If we can't find it, the seed-file cleanup still
    // happens.
    let request_path = probe_request_path(bundle_path, &config.vta_mode);

    info!(
        bundle_id = %bundle_id_hex,
        admin_did = %session.admin_did(),
        integration_did = session.integration_did().unwrap_or("(none)"),
        "Sealed-handoff phase 2 complete — bundle applied"
    );

    Ok(HeadlessOutcome::Applied {
        session,
        artifacts: BootstrapArtifacts {
            request_path,
            seed_path: Some(seed_path),
        },
    })
}

/// Remove the request JSON, the ephemeral seed file, and the
/// `bootstrap-secrets/` directory if it's now empty. Called from
/// both the non-interactive path (phase 2 success) and the TUI path
/// (post-Complete). Best-effort — any I/O failure logs a warning
/// but doesn't abort the caller; the mediator config is already
/// written at this point, and the operator can clean up manually.
pub fn cleanup_artifacts(artifacts: &BootstrapArtifacts) {
    if let Some(ref p) = artifacts.seed_path {
        remove_best_effort(p, "ephemeral seed");
        // Try to remove the parent `bootstrap-secrets/` directory if
        // empty — leaves the operator's CWD tidy. Non-empty dir is
        // left alone (other in-flight rounds may still be present).
        if let Some(parent) = p.parent()
            && parent.file_name().is_some_and(|n| n == "bootstrap-secrets")
            && parent
                .read_dir()
                .map(|mut d| d.next().is_none())
                .unwrap_or(false)
        {
            remove_dir_best_effort(parent);
        }
    }
    if let Some(ref p) = artifacts.request_path {
        remove_best_effort(p, "bootstrap request");
    }
}

fn intent_for_mode(vta_mode: &str) -> anyhow::Result<VtaIntent> {
    match vta_mode {
        VTA_MODE_SEALED_MINT => Ok(VtaIntent::FullSetup),
        VTA_MODE_SEALED_EXPORT => Ok(VtaIntent::OfflineExport),
        VTA_MODE_ONLINE => anyhow::bail!(
            "vta_mode = \"online\" is not supported by `--from` yet — the live DIDComm \
             setup requires the `pnm acl create` step which is operator-gated. Use the \
             interactive TUI (`mediator-setup` with no `--from`) for online VTA setup."
        ),
        "" => anyhow::bail!(
            "recipe has use_vta = true but no vta_mode — set deployment.vta_mode to one of \
             \"sealed-mint\", \"sealed-export\", or \"online\""
        ),
        other => anyhow::bail!(
            "unsupported vta_mode '{other}' — expected \"sealed-mint\" or \"sealed-export\" \
             for headless setup"
        ),
    }
}

fn default_request_filename(vta_mode: &str) -> &'static str {
    match vta_mode {
        // sealed-mint produces a VP-framed request (signed VP
        // structure); sealed-export produces the simpler v1 shape.
        // File names match the TUI's convention in `finalize_request`.
        VTA_MODE_SEALED_MINT => "bootstrap-request-vp.json",
        _ => "bootstrap-request.json",
    }
}

/// Locate the ephemeral seed for a bundle. Looks next to the bundle
/// file first (most common operator layout) and falls back to CWD.
fn locate_seed(bundle_path: &Path, bundle_id_hex: &str) -> anyhow::Result<PathBuf> {
    let candidates = [
        bundle_path
            .parent()
            .unwrap_or(Path::new("."))
            .join("bootstrap-secrets")
            .join(format!("{bundle_id_hex}.key")),
        Path::new(".")
            .join("bootstrap-secrets")
            .join(format!("{bundle_id_hex}.key")),
    ];
    for c in &candidates {
        if c.is_file() {
            return Ok(c.clone());
        }
    }
    anyhow::bail!(
        "could not locate the ephemeral seed for bundle id {bundle_id_hex} — \
         expected one of:\n  - {}\n  - {}\n\
         The seed is written by `mediator-setup --from <recipe>` during phase 1 \
         (bootstrap request emission). Run phase 1 on the same host as phase 2.",
        candidates[0].display(),
        candidates[1].display(),
    )
}

fn load_seed(path: &Path) -> anyhow::Result<[u8; 32]> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("could not read seed '{}': {e}", path.display()))?;
    bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "seed file '{}' must be exactly 32 bytes (got a different length)",
            path.display()
        )
    })
}

fn probe_request_path(bundle_path: &Path, vta_mode: &str) -> Option<PathBuf> {
    let filename = default_request_filename(vta_mode);
    let candidates = [
        bundle_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(filename),
        Path::new(".").join(filename),
    ];
    candidates.into_iter().find(|c| c.is_file())
}

fn remove_best_effort(path: &Path, what: &str) {
    match std::fs::remove_file(path) {
        Ok(()) => info!(path = %path.display(), "Setup cleanup: removed {what}"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            path = %path.display(),
            error = %e,
            "Setup cleanup: could not remove {what} (continuing)",
        ),
    }
}

fn remove_dir_best_effort(path: &Path) {
    match std::fs::remove_dir(path) {
        Ok(()) => info!(path = %path.display(), "Setup cleanup: removed empty dir"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            path = %path.display(),
            error = %e,
            "Setup cleanup: could not remove dir (continuing)",
        ),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_for_mode_maps_canonical_values() {
        assert_eq!(
            intent_for_mode(VTA_MODE_SEALED_MINT).unwrap(),
            VtaIntent::FullSetup
        );
        assert_eq!(
            intent_for_mode(VTA_MODE_SEALED_EXPORT).unwrap(),
            VtaIntent::OfflineExport
        );
    }

    #[test]
    fn intent_for_mode_rejects_online_with_pointer_at_tui() {
        let err = intent_for_mode(VTA_MODE_ONLINE).unwrap_err().to_string();
        assert!(err.contains("interactive TUI"));
    }

    #[test]
    fn intent_for_mode_rejects_unknown() {
        let err = intent_for_mode("carrier-pigeon").unwrap_err().to_string();
        assert!(err.contains("unsupported vta_mode"));
    }

    #[test]
    fn intent_for_mode_rejects_empty_with_help() {
        let err = intent_for_mode("").unwrap_err().to_string();
        assert!(err.contains("no vta_mode"));
    }

    #[test]
    fn cleanup_removes_seed_and_dir_and_request() {
        let tmp = tempfile::tempdir().unwrap();
        let secrets = tmp.path().join("bootstrap-secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let seed = secrets.join("abcd1234.key");
        std::fs::write(&seed, [0u8; 32]).unwrap();
        let req = tmp.path().join("bootstrap-request.json");
        std::fs::write(&req, b"{}").unwrap();

        cleanup_artifacts(&BootstrapArtifacts {
            request_path: Some(req.clone()),
            seed_path: Some(seed.clone()),
        });

        assert!(!seed.exists(), "seed should be removed");
        assert!(!req.exists(), "request file should be removed");
        assert!(
            !secrets.exists(),
            "empty bootstrap-secrets dir should be removed"
        );
    }

    #[test]
    fn cleanup_leaves_non_empty_secrets_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let secrets = tmp.path().join("bootstrap-secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let our_seed = secrets.join("ours.key");
        let other_seed = secrets.join("other-in-flight.key");
        std::fs::write(&our_seed, [0u8; 32]).unwrap();
        std::fs::write(&other_seed, [0u8; 32]).unwrap();

        cleanup_artifacts(&BootstrapArtifacts {
            request_path: None,
            seed_path: Some(our_seed.clone()),
        });

        assert!(!our_seed.exists());
        assert!(other_seed.exists(), "other in-flight seed must survive");
        assert!(secrets.exists(), "non-empty dir must survive");
    }

    #[test]
    fn cleanup_is_idempotent_when_nothing_exists() {
        // Re-running cleanup after a successful run (or a partial
        // failure that already removed artifacts) should be silent,
        // not error.
        let tmp = tempfile::tempdir().unwrap();
        cleanup_artifacts(&BootstrapArtifacts {
            request_path: Some(tmp.path().join("does-not-exist.json")),
            seed_path: Some(tmp.path().join("also-missing.key")),
        });
    }

    /// RAII guard: pin CWD to a fresh tempdir for the test's
    /// lifetime, restore on drop (even on panic). The tempdir's
    /// `TempDir` handle holds the directory alive until the guard
    /// drops, so paths handed to the test body stay valid.
    /// `#[serial_test::serial]` on each caller prevents the CWD
    /// mutations from racing with other tests.
    struct CwdGuard {
        _tmp: tempfile::TempDir,
        path: std::path::PathBuf,
        prev: std::path::PathBuf,
    }

    impl CwdGuard {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let prev = std::env::current_dir().unwrap();
            let path = tmp.path().to_path_buf();
            std::env::set_current_dir(&path).unwrap();
            Self {
                _tmp: tmp,
                path,
                prev,
            }
        }
        fn dir(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            // Best-effort restore. If the previous CWD no longer
            // exists (rare but possible if something deleted it),
            // we silently leave the test harness in tmp CWD — the
            // next test's CwdGuard will set its own.
            let _ = std::env::set_current_dir(&self.prev);
        }
    }

    fn sealed_export_config(context: &str) -> crate::app::WizardConfig {
        crate::app::WizardConfig {
            use_vta: true,
            vta_mode: VTA_MODE_SEALED_EXPORT.into(),
            vta_context: context.into(),
            ..crate::app::WizardConfig::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn phase1_sealed_export_writes_request_and_seed() {
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let config = sealed_export_config("prod-mediator");
        let outcome = dispatch(&config, None, None)
            .await
            .expect("phase 1 dispatch");
        let HeadlessOutcome::RequestEmitted {
            request_path,
            bundle_id_hex,
            producer_command,
        } = outcome
        else {
            panic!("phase 1 with no --bundle must emit a request, not apply");
        };
        assert!(request_path.is_file(), "request JSON must be on disk");
        assert!(
            producer_command.contains("vta context reprovision"),
            "operator instructions must name the VTA-side command: {producer_command}"
        );
        assert!(
            producer_command.contains("--id prod-mediator"),
            "context id must propagate into the command: {producer_command}"
        );
        let seed = dir
            .join("bootstrap-secrets")
            .join(format!("{bundle_id_hex}.key"));
        assert!(seed.is_file(), "seed file must exist at {}", seed.display());
        let meta = std::fs::metadata(&seed).unwrap();
        assert_eq!(meta.len(), 32, "seed file is 32 bytes (raw Ed25519 seed)");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn phase1_refuses_double_run_while_seed_exists() {
        let _cwd = CwdGuard::new();
        let config = sealed_export_config("prod-mediator");
        let first = dispatch(&config, None, None).await;
        assert!(first.is_ok(), "first phase-1 run must succeed");

        // Second run without --bundle must refuse rather than clobber
        // the in-flight seed — the VTA may still respond with a
        // bundle tied to the first request.
        let second = dispatch(&config, None, None).await;
        let err = match second {
            Err(e) => e.to_string(),
            Ok(_) => panic!("second phase-1 run must refuse while a seed is in flight"),
        };
        assert!(
            err.contains("bootstrap is already in progress"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains("--bundle"),
            "error must point at finalisation path: {err}"
        );
        assert!(
            err.contains("rm -rf"),
            "error must name the restart path: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn phase2_errors_when_no_matching_seed() {
        // Write a syntactically-valid armored bundle (single chunk,
        // produced by the sealed-transfer producer side of vta-sdk)
        // and point phase 2 at it without any matching seed on disk.
        // Should fail with the specific "could not locate the
        // ephemeral seed" error.
        use vta_sdk::credentials::CredentialBundle;
        use vta_sdk::sealed_transfer::{
            AssertionProof, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1, armor,
            generate_ed25519_keypair, seal_payload,
        };

        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();

        let (_prod_seed, prod_ed_pub) = generate_ed25519_keypair();
        let (_consumer_seed, consumer_ed_pub) = generate_ed25519_keypair();
        let recipient_pk = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&consumer_ed_pub)
            .expect("x25519 derivation from ed25519 pub");

        let nonce = [0xAAu8; 16]; // fixed nonce → deterministic bundle id
        let assertion = ProducerAssertion {
            producer_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(&prod_ed_pub),
            proof: AssertionProof::PinnedOnly,
        };
        let payload = SealedPayloadV1::AdminCredential(Box::new(CredentialBundle::new(
            "did:key:z6MkAdmin",
            "zAdminPrivate",
            "did:webvh:vta.example.com",
        )));
        let store = InMemoryNonceStore::new();
        let bundle = seal_payload(&recipient_pk, nonce, assertion, &payload, &store)
            .await
            .unwrap();
        let armored = armor::encode(&bundle);
        let bundle_path = dir.join("bundle.armor");
        std::fs::write(&bundle_path, armored).unwrap();

        let config = sealed_export_config("prod-mediator");
        let err = match dispatch(&config, Some(&bundle_path), None).await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("phase 2 must fail when no seed is present"),
        };
        assert!(
            err.contains("could not locate the ephemeral seed"),
            "unexpected error: {err}"
        );
        // And it tells the operator where it looked — seed-id in
        // the message narrows the diagnosis to "I ran phase 1 from
        // a different CWD" vs "I wiped the seed dir".
        assert!(
            err.contains("aaaaaaaa"),
            "error should name the bundle id it searched for: {err}"
        );
    }
}
