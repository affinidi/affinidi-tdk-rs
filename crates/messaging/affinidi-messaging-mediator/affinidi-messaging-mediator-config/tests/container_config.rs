//! Drift guard for the config baked into the published container image
//! (`docker/conf/mediator.toml`, shipped by `docker/mediator.Dockerfile`).
//!
//! The image is built with `secrets-aws` and no identity of its own, so its
//! config is NOT the annotated template in `../conf/mediator.toml` — it is a
//! container profile with an empty `mediator_did` / `admin_did` and a backend
//! the binary actually compiles. Image builds are opt-in (they only run on a
//! release tag, a manual dispatch, or a PR labelled `ci:image`), so without
//! this test a newly-required config field would rot the shipped image silently
//! and only surface at release.
//!
//! Lives in `tests/` rather than a `#[cfg(test)]` module so the file it reads
//! stays outside the crate's own source tree — `docker/` is a workspace path,
//! not part of the published crate.

use std::path::PathBuf;

use affinidi_messaging_mediator_config::ConfigRaw;

/// `docker/conf/mediator.toml`, relative to this crate's manifest.
fn container_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../docker/conf/mediator.toml")
}

#[test]
fn container_mediator_toml_parses() {
    let path = container_config_path();
    if !path.exists() {
        // Built from the published .crate tarball rather than the workspace:
        // `docker/` isn't packaged, so there is nothing to guard here.
        eprintln!(
            "skipping: {} not present (not a workspace checkout)",
            path.display()
        );
        return;
    }

    let toml = std::fs::read_to_string(&path).expect("read docker/conf/mediator.toml");
    let raw: ConfigRaw =
        toml::from_str(&toml).expect("docker/conf/mediator.toml parses as ConfigRaw");

    // A published image must carry no identity: both DIDs come from the
    // environment at run time (MEDIATOR_DID / ADMIN_DID).
    assert!(
        raw.mediator_did.is_empty(),
        "image must ship no mediator_did"
    );
    assert!(
        raw.server.admin_did.is_empty(),
        "image must ship no admin_did"
    );

    // The image compiles `secrets-aws` (plus the always-available `file://`
    // backend) — `keyring://` is NOT compiled in, and naming it here is exactly
    // what used to make `docker run <image>` hard-fail at startup.
    assert!(
        raw.secrets.backend.starts_with("file://"),
        "container backend must be file:// (cloud overrides it via \
         MEDIATOR_SECRETS_BACKEND), got '{}'",
        raw.secrets.backend
    );
}
