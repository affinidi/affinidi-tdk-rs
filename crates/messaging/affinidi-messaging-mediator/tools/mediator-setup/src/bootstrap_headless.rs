//! Non-interactive sealed-handoff driver — the headless equivalent of
//! the TUI's `SealedHandoffState` state machine.
//!
//! `--from recipe.toml` drives a fully declarative setup. For the two
//! sealed modes (`sealed-mint`, `sealed-export`) the flow splits into
//! two invocations with a handoff between them:
//!
//! **Phase 1** — mediator host emits a request file and persists the
//! ephemeral HPKE recipient seed into the configured secret backend
//! under `mediator_bootstrap_ephemeral_seed_<bundle_id_hex>`. The
//! operator ships the request file to the VTA host, the VTA admin
//! runs the appropriate `vta …` command, and ships back a
//! `bundle.armor`.
//!
//! **Phase 2** — mediator host is re-run with `--bundle <path>`. The
//! wizard looks up the matching seed in the same backend, derives the
//! X25519 recipient secret, unseals the bundle, projects onto a
//! [`VtaSession`], runs the same `generate_and_write` pipeline the
//! TUI uses, and deletes the seed from the backend on success.
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
use std::time::Duration;

use affinidi_messaging_mediator_common::MediatorSecrets;
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
///
/// The ephemeral HPKE seed is no longer an on-disk artefact — it lives
/// in the configured secret backend (see
/// `MediatorSecrets::store_bootstrap_seed`) and is deleted directly
/// from the backend on successful phase-2 apply.
#[derive(Debug, Clone)]
pub struct BootstrapArtifacts {
    /// The request JSON file the wizard wrote in phase 1. `None` when
    /// phase 1's best-effort write failed (we don't track what we
    /// didn't create). Contains public data only (the operator's
    /// ephemeral pubkey, nonce, and VP framing) — safe to leave
    /// behind on a failure, but cleaner to delete on success.
    pub request_path: Option<PathBuf>,
}

/// Dispatch into phase 1 (request emission) or phase 2 (bundle apply)
/// based on whether `--bundle` was supplied.
///
/// Also enforces "don't clobber an in-flight bootstrap": if the
/// configured backend's sweep index has any entries and the caller
/// is attempting phase 1 (no `--bundle`), we error rather than
/// overwrite — the operator must either finalise with `--bundle` or
/// re-run with `--force-reprovision` (which wipes the existing
/// setup).
pub async fn dispatch(
    config: &crate::app::WizardConfig,
    bundle_path: Option<&Path>,
    digest: Option<&str>,
) -> anyhow::Result<HeadlessOutcome> {
    // Sweep any stranded phase-1 seeds before branching. This
    // piggybacks on the backend handle the phase-1/phase-2 code
    // would open anyway, but runs BEFORE the "don't clobber" check
    // in phase-1 so recently-expired entries don't spuriously block
    // a fresh run. Best-effort — a sweep failure (e.g. backend
    // briefly unreachable) is logged and the flow proceeds; the
    // phase code will surface a richer error if the backend stays
    // down.
    sweep_stale_bootstrap_seeds(config).await;

    match bundle_path {
        Some(path) => phase2_apply(config, path, digest).await,
        None => phase1_emit_request(config).await,
    }
}

/// Env var the sealed-handoff sweeper consults for its TTL. Accepts
/// any `humantime`-parseable duration (`"30m"`, `"6h"`, `"7d"`).
/// Absent or unparseable → [`DEFAULT_BOOTSTRAP_SEED_TTL`].
const BOOTSTRAP_SEED_TTL_ENV: &str = "MEDIATOR_BOOTSTRAP_SEED_TTL";

/// Default age beyond which a phase-1 seed is considered abandoned
/// and swept on the next wizard run. 24h matches the spec's
/// "Resolved design decisions" §4 and the hint surfaced in the
/// "bootstrap is already in progress" error.
const DEFAULT_BOOTSTRAP_SEED_TTL: Duration = Duration::from_secs(24 * 3600);

fn resolve_bootstrap_seed_ttl() -> Duration {
    match std::env::var(BOOTSTRAP_SEED_TTL_ENV) {
        Ok(s) if !s.is_empty() => match humantime::parse_duration(&s) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    env = BOOTSTRAP_SEED_TTL_ENV,
                    value = %s,
                    error = %e,
                    "could not parse bootstrap seed TTL override; using the 24h default",
                );
                DEFAULT_BOOTSTRAP_SEED_TTL
            }
        },
        _ => DEFAULT_BOOTSTRAP_SEED_TTL,
    }
}

/// Open the configured backend and sweep bootstrap seeds older than
/// the resolved TTL. Best-effort: if the backend can't be opened,
/// probed, or the sweep itself errors, we log and move on. The
/// phase-specific code that runs immediately after will surface a
/// more actionable error if the backend is actually broken.
async fn sweep_stale_bootstrap_seeds(config: &crate::app::WizardConfig) {
    let backend_url = crate::config_writer::build_backend_url(config);
    let store = match MediatorSecrets::from_url(&backend_url) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                backend = %backend_url,
                error = %e,
                "could not open backend for bootstrap-seed sweep; skipping",
            );
            return;
        }
    };
    let ttl = resolve_bootstrap_seed_ttl();
    match store.sweep_bootstrap_seeds(ttl).await {
        Ok(swept) if !swept.is_empty() => {
            info!(
                backend = %backend_url,
                ttl_s = ttl.as_secs(),
                swept = ?swept,
                "swept stale bootstrap seeds before dispatch",
            );
        }
        Ok(_) => {}
        Err(e) => warn!(
            backend = %backend_url,
            error = %e,
            "bootstrap-seed sweep failed; phase-specific code will re-surface if fatal",
        ),
    }
}

/// Phase 1 — mint the ephemeral keypair, build the request (shape
/// depends on `config.vta_mode`), persist the HPKE recipient seed
/// into the configured secret backend, and return the operator's
/// next-step command for the caller to print.
async fn phase1_emit_request(config: &crate::app::WizardConfig) -> anyhow::Result<HeadlessOutcome> {
    // Open the backend first so we fail fast on a misconfigured
    // secret store — no point minting a request, writing it to disk,
    // and then discovering `aws_secrets://...` can't talk to AWS.
    let backend_url = crate::config_writer::build_backend_url(config);
    let store = MediatorSecrets::from_url(&backend_url)
        .map_err(|e| anyhow::anyhow!("open secret backend '{backend_url}': {e}"))?;
    store
        .probe()
        .await
        .map_err(|e| anyhow::anyhow!("secret backend '{backend_url}' failed probe: {e}"))?;

    // Refuse to clobber an in-flight bootstrap. The backend index is
    // our cross-invocation state now; any entry means "a request is
    // out to a VTA operator, waiting for a bundle". Silently
    // regenerating would invalidate whatever comes back. Stale
    // entries are removed by the sweeper (wired in T11) before we
    // reach this check.
    let in_flight = store
        .bootstrap_seed_index()
        .await
        .map_err(|e| anyhow::anyhow!("read bootstrap seed index: {e}"))?;
    if !in_flight.entries.is_empty() {
        let ids: Vec<_> = in_flight
            .entries
            .iter()
            .map(|e| e.bundle_id_hex.as_str())
            .collect();
        anyhow::bail!(
            "A bootstrap is already in progress in backend '{backend_url}'.\n  \
             In-flight bundle id(s): {}\n\n\
             To finalise: re-run `mediator-setup --from <recipe> --bundle bundle.armor`\n\
             To restart:  wait {BOOTSTRAP_SEED_TTL_HINT} for auto-cleanup, \
             or re-run with `--force-reprovision` to wipe.",
            ids.join(", "),
        );
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

    // Persist the HPKE recipient seed into the configured backend.
    // Phase 2 reads it back by bundle id to derive `recipient_secret`
    // without asking the operator for anything.
    store
        .store_bootstrap_seed(&bundle_id_hex, &state.seed_bytes)
        .await
        .map_err(|e| anyhow::anyhow!("could not persist ephemeral seed to '{backend_url}': {e}"))?;

    info!(
        bundle_id = %bundle_id_hex,
        intent = ?intent,
        request = %request_path.display(),
        backend = %backend_url,
        "Sealed-handoff phase 1 complete — request emitted, seed stored in backend"
    );

    Ok(HeadlessOutcome::RequestEmitted {
        request_path,
        bundle_id_hex,
        producer_command,
    })
}

/// Default cleanup hint shown when an in-flight bootstrap blocks
/// phase-1. Kept as a constant so the wording stays consistent if the
/// sweeper TTL is raised later.
const BOOTSTRAP_SEED_TTL_HINT: &str = "24h";

/// Phase 2 — ingest the armored bundle, look up the seed in the
/// configured backend, unseal, and return a populated `VtaSession`.
/// The seed is deleted from the backend on successful open so a
/// stale index entry doesn't linger.
async fn phase2_apply(
    config: &crate::app::WizardConfig,
    bundle_path: &Path,
    digest: Option<&str>,
) -> anyhow::Result<HeadlessOutcome> {
    let intent = intent_for_mode(&config.vta_mode)?;

    let armored = std::fs::read_to_string(bundle_path)
        .map_err(|e| anyhow::anyhow!("could not read bundle '{}': {e}", bundle_path.display()))?;

    // Open the backend up front; a broken store is a phase-2 fatal.
    let backend_url = crate::config_writer::build_backend_url(config);
    let store = MediatorSecrets::from_url(&backend_url)
        .map_err(|e| anyhow::anyhow!("open secret backend '{backend_url}': {e}"))?;

    // Reconstruct a synthetic `SealedHandoffState` keyed to this
    // bundle. The reconstructed state doesn't need the ephemeral
    // pub/private pair up front — `ingest_armored` just parses the
    // armor and computes the digest. The seed lookup happens between
    // ingest and `open_with_digest`.
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
    // lookup key stay consistent.
    let bundle_id = state
        .bundle
        .as_ref()
        .expect("ingest_armored populates state.bundle on success")
        .bundle_id;
    state.nonce = bundle_id;
    let bundle_id_hex = hex_lower(&bundle_id);

    let seed_bytes = store
        .load_bootstrap_seed(&bundle_id_hex)
        .await
        .map_err(|e| anyhow::anyhow!("read ephemeral seed from '{backend_url}': {e}"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "could not locate the ephemeral seed for bundle id {bundle_id_hex} in backend \
                 '{backend_url}'. Run phase 1 of `mediator-setup --from <recipe>` against the \
                 same backend before supplying `--bundle`."
            )
        })?;
    state.recipient_secret = *vta_sdk::sealed_transfer::ed25519_seed_to_x25519_secret(&seed_bytes);

    crate::sealed_handoff::open_with_digest(&mut state, digest.unwrap_or("")).map_err(|e| {
        anyhow::anyhow!(
            "could not open sealed bundle: {e}. \
             Verify the digest matches what the VTA admin printed, and \
             that the bundle belongs to this setup's request (bundle id: {bundle_id_hex})."
        )
    })?;

    let session = state.session.take().ok_or_else(|| {
        anyhow::anyhow!("open_with_digest reported success but produced no session")
    })?;

    // Seed has served its purpose. Best-effort delete so the index
    // doesn't carry stale entries. Failure here doesn't abort phase 2
    // — the mediator boot config is already valid at this point and
    // the sweeper will eventually reap the entry on a future run.
    if let Err(e) = store.delete_bootstrap_seed(&bundle_id_hex).await {
        warn!(
            bundle_id = %bundle_id_hex,
            backend = %backend_url,
            error = %e,
            "phase-2 seed delete failed; the sweeper will retry later",
        );
    }

    // Probe the bundle_id-keyed request filename next to the bundle.
    // Best-effort — we only use this to clean up after a successful
    // apply.
    let request_path = probe_request_path(bundle_path, &config.vta_mode);

    info!(
        bundle_id = %bundle_id_hex,
        admin_did = %session.admin_did(),
        integration_did = session.integration_did().unwrap_or("(none)"),
        backend = %backend_url,
        "Sealed-handoff phase 2 complete — bundle applied, seed removed"
    );

    Ok(HeadlessOutcome::Applied {
        session,
        artifacts: BootstrapArtifacts { request_path },
    })
}

/// Remove the request JSON. Called from both the non-interactive path
/// (phase 2 success) and the TUI path (post-Complete). Best-effort —
/// any I/O failure logs a warning but doesn't abort the caller; the
/// mediator config is already written at this point.
///
/// The ephemeral HPKE seed is no longer a file — it's removed
/// directly from the secret backend at the end of `phase2_apply`.
pub fn cleanup_artifacts(artifacts: &BootstrapArtifacts) {
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
    fn cleanup_removes_request_file() {
        let tmp = tempfile::tempdir().unwrap();
        let req = tmp.path().join("bootstrap-request.json");
        std::fs::write(&req, b"{}").unwrap();

        cleanup_artifacts(&BootstrapArtifacts {
            request_path: Some(req.clone()),
        });

        assert!(!req.exists(), "request file should be removed");
    }

    #[test]
    fn cleanup_is_idempotent_when_nothing_exists() {
        // Re-running cleanup after a successful run (or a partial
        // failure that already removed artifacts) should be silent,
        // not error.
        let tmp = tempfile::tempdir().unwrap();
        cleanup_artifacts(&BootstrapArtifacts {
            request_path: Some(tmp.path().join("does-not-exist.json")),
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

    /// Wire the config up with a per-test `file://` backend rooted in
    /// the CWD tempdir so phase-1/phase-2 exercise the real
    /// `MediatorSecrets` path without hitting a cloud backend. `dir`
    /// must be the same tempdir `CwdGuard` pins.
    fn sealed_export_config(context: &str, dir: &std::path::Path) -> crate::app::WizardConfig {
        let secrets_path = dir.join("secrets.json");
        crate::app::WizardConfig {
            use_vta: true,
            vta_mode: VTA_MODE_SEALED_EXPORT.into(),
            vta_context: context.into(),
            secret_storage: crate::consts::STORAGE_FILE.into(),
            secret_file_path: secrets_path.to_string_lossy().into_owned(),
            secret_file_encrypted: false,
            ..crate::app::WizardConfig::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn phase1_sealed_export_writes_request_and_stores_seed_in_backend() {
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let config = sealed_export_config("prod-mediator", &dir);
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

        // Seed must be reachable via the backend, not via any
        // `bootstrap-secrets/*.key` file.
        let backend_url = crate::config_writer::build_backend_url(&config);
        let store =
            affinidi_messaging_mediator_common::MediatorSecrets::from_url(&backend_url).unwrap();
        let loaded = store
            .load_bootstrap_seed(&bundle_id_hex)
            .await
            .expect("read seed from backend")
            .expect("seed must exist after phase 1");
        assert_eq!(loaded.len(), 32, "seed is 32 bytes (raw Ed25519 seed)");

        let index = store.bootstrap_seed_index().await.unwrap();
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].bundle_id_hex, bundle_id_hex);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn phase1_refuses_double_run_while_index_has_a_seed() {
        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let config = sealed_export_config("prod-mediator", &dir);
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
            err.contains("--force-reprovision"),
            "error must name the restart path: {err}"
        );
    }

    #[test]
    fn resolve_bootstrap_seed_ttl_defaults_to_24h() {
        // SAFETY: whole-process env var mutation; `serial_test` is
        // relied on globally by the other CWD-mutating tests.
        // Reading + unsetting here under unsafe is the standard rust
        // 2024-edition shape.
        unsafe {
            std::env::remove_var(BOOTSTRAP_SEED_TTL_ENV);
        }
        assert_eq!(resolve_bootstrap_seed_ttl(), DEFAULT_BOOTSTRAP_SEED_TTL);
    }

    #[test]
    #[serial_test::serial]
    fn resolve_bootstrap_seed_ttl_parses_humantime_override() {
        unsafe {
            std::env::set_var(BOOTSTRAP_SEED_TTL_ENV, "2h");
        }
        assert_eq!(resolve_bootstrap_seed_ttl(), Duration::from_secs(2 * 3600));
        unsafe {
            std::env::remove_var(BOOTSTRAP_SEED_TTL_ENV);
        }
    }

    #[test]
    #[serial_test::serial]
    fn resolve_bootstrap_seed_ttl_falls_back_on_unparseable_input() {
        unsafe {
            std::env::set_var(BOOTSTRAP_SEED_TTL_ENV, "carrier-pigeon");
        }
        assert_eq!(resolve_bootstrap_seed_ttl(), DEFAULT_BOOTSTRAP_SEED_TTL);
        unsafe {
            std::env::remove_var(BOOTSTRAP_SEED_TTL_ENV);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn dispatch_sweeps_aged_seed_before_phase1() {
        // Pre-seed the backend with an in-flight entry whose
        // timestamp we manually backdate past the 24h cutoff. A
        // follow-up phase-1 dispatch should see an EMPTY index and
        // succeed (rather than bailing on the don't-clobber check).
        use affinidi_messaging_mediator_common::MediatorSecrets;

        unsafe {
            std::env::remove_var(BOOTSTRAP_SEED_TTL_ENV);
        }

        let cwd = CwdGuard::new();
        let dir = cwd.dir().to_path_buf();
        let config = sealed_export_config("prod-mediator", &dir);

        // Seed the backend with an aged entry directly — we don't
        // care about the bundle contents, just that the index has
        // one entry older than the TTL so the sweeper is exercised.
        let backend_url = crate::config_writer::build_backend_url(&config);
        let store = MediatorSecrets::from_url(&backend_url).unwrap();
        let aged_id = "deadbeefdeadbeefdeadbeefdeadbeef";
        store
            .store_bootstrap_seed(aged_id, &[9u8; 32])
            .await
            .unwrap();

        // Reach around and backdate the index entry so the sweeper
        // decides to delete it. `bootstrap_seed_index` is the only
        // public read; for the write we exploit the generic
        // `store_entry` accessor which exists on `MediatorSecrets`.
        let mut index = store.bootstrap_seed_index().await.unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for entry in index.entries.iter_mut() {
            entry.created_at = now.saturating_sub(48 * 3600);
        }
        store
            .store_entry(
                affinidi_messaging_mediator_common::BOOTSTRAP_SEED_INDEX,
                "bootstrap-seed-index",
                &index,
            )
            .await
            .unwrap();

        // Dispatch: phase-1 (no --bundle). The sweeper should clean
        // the aged entry, leaving the index empty before the
        // "don't clobber" check runs — so phase-1 succeeds.
        let outcome = dispatch(&config, None, None)
            .await
            .expect("dispatch must succeed once sweeper clears the aged entry");
        assert!(matches!(outcome, HeadlessOutcome::RequestEmitted { .. }));

        // Verify through a FRESH backend handle — the file-backend
        // cache is per-instance, so the `store` we used for setup
        // still holds the pre-sweep bytes in memory.
        let verify = MediatorSecrets::from_url(&backend_url).unwrap();
        let loaded = verify.load_bootstrap_seed(aged_id).await.unwrap();
        assert!(
            loaded.is_none(),
            "aged seed must be gone after dispatch's sweep",
        );
        let index_after = verify.bootstrap_seed_index().await.unwrap();
        assert!(
            !index_after
                .entries
                .iter()
                .any(|e| e.bundle_id_hex == aged_id),
            "aged entry must be removed from the sweep index",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[serial_test::serial]
    async fn phase2_errors_when_no_matching_seed_in_backend() {
        // Write a syntactically-valid armored bundle (single chunk,
        // produced by the sealed-transfer producer side of vta-sdk)
        // and point phase 2 at it without any matching seed in the
        // backend. Should fail with the "could not locate the
        // ephemeral seed" error that names the bundle id.
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

        let config = sealed_export_config("prod-mediator", &dir);
        let err = match dispatch(&config, Some(&bundle_path), None).await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("phase 2 must fail when no seed is present"),
        };
        assert!(
            err.contains("could not locate the ephemeral seed"),
            "unexpected error: {err}"
        );
        // And it tells the operator the bundle id it searched for —
        // narrows the diagnosis to "I ran phase 1 against a different
        // backend" vs "the backend was wiped".
        assert!(
            err.contains("aaaaaaaa"),
            "error should name the bundle id it searched for: {err}"
        );
    }
}
