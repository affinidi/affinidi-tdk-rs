//! Non-interactive entry points for the online-VTA sub-flow.
//!
//! The wizard otherwise drives the connection via its TUI, but orchestrated
//! deploys need a scriptable way to run the same flow:
//!
//! - **Phase 1** (`--setup-key-out`): generate an ephemeral did:key, persist
//!   it, print the `pnm acl create` command, and exit. The operator (or
//!   automation) registers the ACL on the VTA between phases.
//! - **Phase 2** (`--setup-key-file`): reload the persisted key, run the
//!   diagnostic + auth runner, stream checklist lines to stdout, and exit
//!   with a non-zero status on failure.
//!
//! Both phases accept `--vta-did` and `--vta-context` for the inputs the TUI
//! would otherwise collect via text fields.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::consts::DEFAULT_VTA_CONTEXT;
use crate::vta_connect::{
    DiagCheck, DiagStatus, EphemeralSetupKey, VtaEvent, VtaIntent, run_connection_test,
};

/// Phase 1: generate + persist ephemeral key, print ACL command.
pub async fn run_phase1_init(
    out_path: &Path,
    vta_did: Option<&str>,
    context_id: Option<&str>,
) -> anyhow::Result<()> {
    let key = EphemeralSetupKey::generate()?;
    key.persist_to(out_path)?;

    let ctx = context_id.unwrap_or(DEFAULT_VTA_CONTEXT);

    println!();
    println!("  Setup DID (ephemeral):");
    println!("    {}", key.did);
    println!();
    println!("  Key stored at {} (0600)", out_path.display());
    println!();
    println!("  Using your Personal Network Manager (PNM) connected to this VTA,");
    println!("  create the mediator context and grant admin access to the setup DID:");
    println!();
    println!(
        "    pnm contexts create --id {ctx} --name \"Mediator\" \\\n      --admin-did {} --admin-expires {}",
        key.did,
        crate::consts::DEFAULT_VTA_SETUP_EXPIRY,
    );
    println!();
    println!("  --name is a human-readable label — change \"Mediator\" to anything");
    println!("  that fits your naming conventions.");
    println!();
    println!("  --admin-expires defaults to 1h. Use 24h, 7d, etc. for longer");
    println!("  roll-outs; the entry is promoted to permanent on first auth.");
    println!();
    println!("  Then finalise with:");
    let mut finalise = format!(
        "    mediator-setup --setup-key-file {} --vta-context {ctx}",
        out_path.display()
    );
    if let Some(did) = vta_did {
        finalise.push_str(&format!(" --vta-did {did}"));
    } else {
        finalise.push_str(" --vta-did <vta-did>");
    }
    finalise.push_str(" --non-interactive");
    println!("{finalise}");
    println!();
    Ok(())
}

/// Phase 2: reload key + run runner + stream diagnostics to stdout. Exits Ok
/// only on a successful auth; on failure bails with a descriptive error.
pub async fn run_phase2_connect(
    key_path: &Path,
    vta_did: &str,
    context_id: Option<&str>,
    mediator_url: &str,
    wait_for_acl: Option<u64>,
) -> anyhow::Result<()> {
    let key = EphemeralSetupKey::load_from(key_path)?;
    let ctx = context_id.unwrap_or(DEFAULT_VTA_CONTEXT);

    println!();
    println!("  VTA DID:      {vta_did}");
    println!("  Context:      {ctx}");
    println!("  Mediator URL: {mediator_url}");
    println!("  Setup DID:    {}", key.did);
    println!();

    let deadline = wait_for_acl.map(|s| Instant::now() + Duration::from_secs(s));
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        if attempt > 1 {
            println!("  Retrying (attempt {attempt})…");
        }

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<VtaEvent>();
        let vta_did_owned = vta_did.to_string();
        let setup_did = key.did.clone();
        let privkey_mb = key.private_key_multibase().to_string();
        // `ctx` / `mediator_url` are captured only for the CLI
        // operator message below; AdminOnly doesn't use them in the
        // runner.
        let _ = ctx;
        let _ = mediator_url;

        let runner = tokio::spawn(async move {
            // CLI phase-2 is AdminOnly — the interactive
            // FullSetup flow now splits into preflight + webvh
            // picker + provision, which doesn't fit a one-shot
            // CLI surface. If FullSetup via CLI is wanted later,
            // expose a `--webvh-server <id>` flag and call
            // `run_connection_test` + `run_provision_flight` in
            // sequence here, auto-picking when only one server is
            // registered.
            run_connection_test(
                VtaIntent::AdminOnly,
                vta_did_owned,
                setup_did,
                privkey_mb,
                tx,
            )
            .await;
        });

        let mut connected = false;
        let mut last_failure: Option<String> = None;
        while let Some(event) = rx.recv().await {
            match event {
                VtaEvent::CheckStart(c) => {
                    println!("  [..] {}", c.label());
                }
                VtaEvent::CheckDone(c, status) => {
                    println!("  {}", format_check_line(c, &status));
                }
                VtaEvent::Connected { protocol, .. } => {
                    connected = true;
                    println!();
                    println!("  Connected via {}", protocol.label());
                }
                VtaEvent::PreflightDone { .. } => {
                    // AdminOnly never emits PreflightDone. Ignore
                    // defensively rather than panic if a future
                    // runner change breaks that invariant.
                }
                VtaEvent::Failed(reason) => {
                    last_failure = Some(reason);
                }
            }
        }
        let _ = runner.await;

        if connected {
            return Ok(());
        }

        let reason = last_failure.unwrap_or_else(|| "unknown failure".into());
        if let Some(deadline) = deadline {
            if Instant::now() < deadline && retryable(&reason) {
                let remaining = deadline.saturating_duration_since(Instant::now()).as_secs();
                println!();
                println!("  ACL not yet present — waiting up to {remaining}s more…");
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        }
        anyhow::bail!("{reason}");
    }
}

fn format_check_line(c: DiagCheck, status: &DiagStatus) -> String {
    match status {
        DiagStatus::Pending => format!("[  ] {}", c.label()),
        DiagStatus::Running => format!("[..] {}", c.label()),
        DiagStatus::Ok(d) => format!("[OK] {}  {d}", c.label()),
        DiagStatus::Skipped(d) => format!("[--] {}  {d}", c.label()),
        DiagStatus::Failed(d) => format!("[!!] {}  {d}", c.label()),
    }
}

/// Rough heuristic for "worth retrying under --wait-for-acl": auth failures
/// are usually just waiting on ACL propagation; resolve / network errors
/// are unlikely to self-heal quickly.
fn retryable(reason: &str) -> bool {
    reason.contains("401")
        || reason.contains("403")
        || reason.contains("Authentication rejected")
        || reason.contains("ACL")
}

/// Validate that Phase 2 has all it needs before we start generating events.
pub fn validate_phase2_args(vta_did: &Option<String>) -> anyhow::Result<&str> {
    match vta_did {
        Some(d) => Ok(d),
        None => Err(anyhow::anyhow!(
            "--vta-did is required when --setup-key-file is used"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_hits_common_acl_errors() {
        assert!(retryable("authentication failed (401): ..."));
        assert!(retryable("authentication failed (403): ..."));
        assert!(retryable("Authentication rejected — confirm the ACL..."));
    }

    #[test]
    fn retryable_skips_network_errors() {
        assert!(!retryable("could not connect to VTA at ..."));
        assert!(!retryable("DID resolver init failed: ..."));
    }

    #[test]
    fn validate_phase2_args_requires_did() {
        let none: Option<String> = None;
        assert!(validate_phase2_args(&none).is_err());
        let some = Some("did:webvh:vta.example.com".into());
        assert_eq!(
            validate_phase2_args(&some).unwrap(),
            "did:webvh:vta.example.com"
        );
    }

    #[test]
    fn format_check_line_uses_expected_tags() {
        let ok = format_check_line(
            DiagCheck::ResolveDid,
            &DiagStatus::Ok("did:webvh:...".into()),
        );
        assert!(ok.contains("[OK]"));
        assert!(ok.contains("Resolve VTA DID"));

        let failed = format_check_line(
            DiagCheck::AuthenticateDIDComm,
            &DiagStatus::Failed("boom".into()),
        );
        assert!(failed.contains("[!!]"));
    }

    // Phase 1 writes a file and prints stdout; we cover the file-write
    // contract in `setup_key::tests::persist_roundtrip`. Full end-to-end
    // phase-2 tests require a live VTA, which isn't appropriate for a unit
    // suite — those are exercised via the local-dev integration loop
    // described in the crate README once this branch lands.

    #[tokio::test]
    async fn phase1_writes_a_valid_key_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        run_phase1_init(&path, Some("did:webvh:vta.example.com"), Some("mediator"))
            .await
            .unwrap();
        let reloaded = EphemeralSetupKey::load_from(&path).unwrap();
        assert!(reloaded.did.starts_with("did:key:z6Mk"));
    }
}
