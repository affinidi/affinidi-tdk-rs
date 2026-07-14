//! Optional publishing of the minted public DID and its did:webvh log.
//!
//! Publishes the mediator's public DID string (`[output].did_target`) and/or
//! its did:webvh log document (`[output].did_log_target`) to a store the
//! runtime (or a relying party) reads, so a one-shot `mediator-setup` task can
//! hand off the identity directly.
//!
//! Opt-in: both targets default to `None`, so interactive/local setups are
//! unaffected. Supported targets:
//!
//! - `aws_parameter_store://<name>[?region=<region>]` — write it to an SSM
//!   parameter (gated by the `publish-aws` build feature).
//! - `s3://<bucket>/<key>[?region=<region>]` — write it to an S3 object
//!   (gated by the `publish-aws` build feature). Preferred for the DID *log*,
//!   which grows with key rotation and can outgrow Parameter Store's value
//!   limit.
//! - `file://<path>` — write the value to a local file.
//!
//! # Only the parameter-store target round-trips
//!
//! The parameter-store grammar is `mediator-common`'s
//! [`affinidi_messaging_mediator_common::parameter_store`], the same one the
//! runtime uses to *read* `mediator_did`. That is deliberate: the target
//! published here is the string an operator pastes into `mediator.toml`, so
//! producer and consumer must not drift. A hierarchical parameter name keeps
//! its leading slash (`aws_parameter_store:///mediator/did`) because AWS
//! rejects a hierarchy without one, and the region is a `?region=` query
//! parameter rather than a leading path segment, which would be ambiguous
//! against that slash. Without `?region=`, the ambient AWS chain is used —
//! never the secret-storage backend's region.
//!
//! **A `file://` target does not round-trip.** The runtime resolves
//! `mediator_did` / `admin_did` from `did://<did>` or `aws_parameter_store://`
//! only — `read_did_config` rejects `file://`, because a config field pointing
//! at a file the mediator must read at boot is a deployment coupling the
//! unified-secrets migration deliberately removed. So a file target is for
//! out-of-band consumers: a relying party, a CI step, an operator reading the
//! value. To use it in `mediator.toml`, paste the file's contents in as
//! `mediator_did = "did://<did>"`, not the `file://` URL.
//!
//! (`did_web_self_hosted` is unrelated and *does* accept `file://` — it names
//! a DID *document*, not a DID string, and is read by `read_document`.)

use affinidi_messaging_mediator_common::parameter_store::{
    PARAMETER_STORE_SCHEME, ParameterStoreTarget, parse_parameter_store_target,
};
use affinidi_messaging_mediator_common::s3_target::{S3_SCHEME, S3Target, parse_s3_target};
use anyhow::{Context, anyhow, bail};

/// Publish the minted public DID string to the optional `[output].did_target`.
/// A no-op when the target is `None`.
pub async fn publish_did_artefacts(did: &str, did_target: Option<&str>) -> anyhow::Result<()> {
    let Some(target) = did_target else {
        return Ok(());
    };

    println!("\n\x1b[1mPublishing public identity\x1b[0m");
    publish_value(target, did, "DID")
        .await
        .with_context(|| format!("publishing DID to '{target}'"))
}

/// Publish the minted did:webvh log (`did.jsonl` content) to the optional
/// `[output].did_log_target`. A no-op when the target is `None` or there is no
/// log to publish (non-webvh deployments).
///
/// Unlike [`publish_did_artefacts`] (the DID *string*), every supported log
/// target round-trips into the runtime's `did_web_self_hosted`, which reads a
/// DID *document* via `read_document` — `file://`, `aws_parameter_store://`,
/// and `s3://` are all accepted there. `s3://` is the intended target for a
/// self-hosted mediator on ephemeral compute: the log grows with each key
/// rotation (did:webvh v1.0 embeds the full document per entry, no JSON
/// Patch), so it can outgrow Parameter Store's value-size limit — S3 has no
/// such ceiling.
pub async fn publish_did_log_artefacts(
    log_content: Option<&str>,
    did_log_target: Option<&str>,
) -> anyhow::Result<()> {
    let (Some(target), Some(log)) = (did_log_target, log_content) else {
        return Ok(());
    };

    println!("\n\x1b[1mPublishing DID log\x1b[0m");
    // Strict JSON-Lines requires each record to end with `\n`; normalise to
    // exactly one so the served `/.well-known/did.jsonl` is well-formed and
    // future log entries append cleanly.
    let normalised = format!("{}\n", log.trim_end_matches('\n'));
    publish_value(target, &normalised, "DID log")
        .await
        .with_context(|| format!("publishing DID log to '{target}'"))
}

/// Validate a publish target without performing any I/O. Called at recipe-load
/// time so a bad target fails before anything is minted, provisioned, or
/// written.
///
/// Rejects an `aws_parameter_store://` target in a build without the
/// `publish-aws` feature: that is knowable here, and failing at publish time
/// would leave a provisioned-but-unreported setup.
pub fn validate_target(target: &str) -> anyhow::Result<()> {
    let (scheme, rest) = split_target(target)?;
    match scheme {
        "file" => {
            if rest.is_empty() {
                bail!("invalid target '{target}': file:// needs a path");
            }
            Ok(())
        }
        PARAMETER_STORE_SCHEME => {
            #[cfg(not(feature = "publish-aws"))]
            {
                bail!(
                    "invalid target '{target}': publishing to {PARAMETER_STORE_SCHEME}:// \
                     requires the 'publish-aws' build feature; rebuild with \
                     `--features publish-aws`, or use a file:// target"
                );
            }
            #[cfg(feature = "publish-aws")]
            {
                parse_target(target).map(|_| ())
            }
        }
        S3_SCHEME => {
            #[cfg(not(feature = "publish-aws"))]
            {
                bail!(
                    "invalid target '{target}': publishing to {S3_SCHEME}:// \
                     requires the 'publish-aws' build feature; rebuild with \
                     `--features publish-aws`, or use a file:// target"
                );
            }
            #[cfg(feature = "publish-aws")]
            {
                parse_s3(target).map(|_| ())
            }
        }
        other => bail!(
            "unsupported target scheme '{other}://' for publishing (expected \
             '{PARAMETER_STORE_SCHEME}://<name>[?region=<region>]', \
             '{S3_SCHEME}://<bucket>/<key>[?region=<region>]', or 'file://<path>')"
        ),
    }
}

fn split_target(target: &str) -> anyhow::Result<(&str, &str)> {
    target
        .split_once("://")
        .ok_or_else(|| anyhow!("invalid target '{target}': expected '<scheme>://<location>'"))
}

/// Parse an `aws_parameter_store://` target through the shared grammar,
/// surfacing its error verbatim — it already names the correct form.
fn parse_target(target: &str) -> anyhow::Result<ParameterStoreTarget> {
    parse_parameter_store_target(target).map_err(|e| anyhow!("{e}"))
}

/// Parse an `s3://` target through the shared grammar, surfacing its error
/// verbatim — it already names the correct form.
fn parse_s3(target: &str) -> anyhow::Result<S3Target> {
    parse_s3_target(target).map_err(|e| anyhow!("{e}"))
}

/// Route a single value to its target based on the URI scheme.
async fn publish_value(target: &str, value: &str, label: &str) -> anyhow::Result<()> {
    // Re-validate rather than assume the caller did: `publish_value` is the
    // last gate before an external write.
    validate_target(target)?;

    match split_target(target)? {
        ("file", path) => {
            let path = std::path::Path::new(path);
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating parent directory for '{target}'"))?;
            }
            std::fs::write(path, value)
                .with_context(|| format!("writing {label} to file '{target}'"))?;
            println!(
                "  \x1b[32m\u{2714}\x1b[0m Published {label} \u{2192} \x1b[36m{target}\x1b[0m"
            );
            Ok(())
        }
        (PARAMETER_STORE_SCHEME, _) => {
            put_ssm_parameter(&parse_target(target)?, value, label).await
        }
        (S3_SCHEME, _) => put_s3_object(&parse_s3(target)?, value, label).await,
        (other, _) => bail!(
            "unsupported target scheme '{other}://' for {label} (expected \
             '{PARAMETER_STORE_SCHEME}://<name>[?region=<region>]', \
             '{S3_SCHEME}://<bucket>/<key>[?region=<region>]', or 'file://<path>')"
        ),
    }
}

/// Write `value` to the SSM parameter named by `target`, overwriting any
/// existing value. The DID string is small, so the default Standard tier
/// (4 KB) is always sufficient — no tier handling needed.
#[cfg(feature = "publish-aws")]
async fn put_ssm_parameter(
    target: &ParameterStoreTarget,
    value: &str,
    label: &str,
) -> anyhow::Result<()> {
    use aws_sdk_ssm::error::DisplayErrorContext;
    use aws_sdk_ssm::types::ParameterType;

    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    // No `?region=` means the ambient chain (AWS_REGION, profile, IMDS) —
    // the same resolution the mediator runtime performs when it reads back.
    if let Some(region) = &target.region {
        loader = loader.region(aws_sdk_ssm::config::Region::new(region.clone()));
    }
    let config = loader.load().await;
    let ssm = aws_sdk_ssm::Client::new(&config);

    let name = &target.name;
    ssm.put_parameter()
        .name(name)
        .value(value)
        .r#type(ParameterType::String)
        .overwrite(true)
        .send()
        .await
        // DisplayErrorContext walks the SDK error's source chain so the service
        // message (e.g. AccessDenied, throttling) is surfaced, not just Debug.
        .map_err(|e| {
            anyhow!(
                "SSM PutParameter({name}) failed: {}",
                DisplayErrorContext(&e)
            )
        })?;

    println!(
        "  \x1b[32m\u{2714}\x1b[0m Published {label} \u{2192} \x1b[36m{}\x1b[0m",
        render_target(target)
    );
    Ok(())
}

/// Render a parsed target back to the string an operator can paste into
/// `mediator.toml` as `mediator_did`.
#[cfg(feature = "publish-aws")]
fn render_target(target: &ParameterStoreTarget) -> String {
    match &target.region {
        Some(region) => format!("{PARAMETER_STORE_SCHEME}://{}?region={region}", target.name),
        None => format!("{PARAMETER_STORE_SCHEME}://{}", target.name),
    }
}

#[cfg(not(feature = "publish-aws"))]
async fn put_ssm_parameter(
    _target: &ParameterStoreTarget,
    _value: &str,
    label: &str,
) -> anyhow::Result<()> {
    // Unreachable in practice — `validate_target` rejects the scheme at recipe
    // load in this build — but kept so the call site type-checks either way.
    bail!(
        "publishing {label} to {PARAMETER_STORE_SCHEME}:// requires the 'publish-aws' \
         build feature; rebuild with `--features publish-aws`"
    )
}

/// Write `value` to the S3 object named by `target`, overwriting any existing
/// object. Unlike Parameter Store there is no value-size ceiling, so this is
/// the target of choice for a did:webvh log that grows with key rotation.
#[cfg(feature = "publish-aws")]
async fn put_s3_object(target: &S3Target, value: &str, label: &str) -> anyhow::Result<()> {
    use aws_sdk_s3::error::DisplayErrorContext;
    use aws_sdk_s3::primitives::ByteStream;

    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    // No `?region=` means the ambient chain (AWS_REGION, profile, IMDS) —
    // the same resolution the mediator runtime performs when it reads back.
    if let Some(region) = &target.region {
        loader = loader.region(aws_sdk_s3::config::Region::new(region.clone()));
    }
    let config = loader.load().await;
    let s3 = aws_sdk_s3::Client::new(&config);

    s3.put_object()
        .bucket(&target.bucket)
        .key(&target.key)
        .body(ByteStream::from(value.as_bytes().to_vec()))
        .content_type("application/jsonl")
        .send()
        .await
        // DisplayErrorContext walks the SDK error's source chain so the service
        // message (e.g. AccessDenied, NoSuchBucket) is surfaced, not just Debug.
        .map_err(|e| {
            anyhow!(
                "S3 PutObject(s3://{}/{}) failed: {}",
                target.bucket,
                target.key,
                DisplayErrorContext(&e)
            )
        })?;

    println!(
        "  \x1b[32m\u{2714}\x1b[0m Published {label} \u{2192} \x1b[36m{}\x1b[0m",
        render_s3_target(target)
    );
    Ok(())
}

/// Render a parsed S3 target back to the string an operator pastes into
/// `mediator.toml` as `did_web_self_hosted`.
#[cfg(feature = "publish-aws")]
fn render_s3_target(target: &S3Target) -> String {
    match &target.region {
        Some(region) => format!("{S3_SCHEME}://{}/{}?region={region}", target.bucket, target.key),
        None => format!("{S3_SCHEME}://{}/{}", target.bucket, target.key),
    }
}

#[cfg(not(feature = "publish-aws"))]
async fn put_s3_object(_target: &S3Target, _value: &str, label: &str) -> anyhow::Result<()> {
    // Unreachable in practice — `validate_target` rejects the scheme at recipe
    // load in this build — but kept so the call site type-checks either way.
    bail!(
        "publishing {label} to {S3_SCHEME}:// requires the 'publish-aws' \
         build feature; rebuild with `--features publish-aws`"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_target_is_a_noop() {
        // No target set: publishing must succeed without touching anything —
        // this is the interactive/local default.
        publish_did_artefacts("did:webvh:abc", None)
            .await
            .expect("no-op publish should succeed");
    }

    #[tokio::test]
    async fn file_target_writes_bare_value() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let did_path = dir.path().join("nested/did.txt");
        let did_target = format!("file://{}", did_path.display());

        publish_did_artefacts("did:webvh:abc", Some(&did_target))
            .await
            .expect("file publish should succeed");

        assert_eq!(std::fs::read_to_string(&did_path).unwrap(), "did:webvh:abc");
    }

    #[test]
    fn validate_accepts_a_file_target() {
        validate_target("file:///tmp/mediator-did.txt").expect("file target is valid");
    }

    #[test]
    fn validate_rejects_unsupported_scheme() {
        let err = validate_target("gs://bucket/key").expect_err("unknown scheme must fail");
        assert!(
            err.to_string()
                .contains("unsupported target scheme 'gs://'"),
            "{err}"
        );
    }

    #[test]
    fn validate_rejects_missing_scheme_separator() {
        let err = validate_target("not-a-uri").expect_err("missing '://' must fail");
        assert!(
            err.to_string().contains("expected '<scheme>://<location>'"),
            "{err}"
        );
    }

    #[test]
    fn validate_rejects_empty_file_path() {
        let err = validate_target("file://").expect_err("empty path must fail");
        assert!(err.to_string().contains("needs a path"), "{err}");
    }

    #[tokio::test]
    async fn unsupported_scheme_errors_at_publish_time() {
        let err = publish_value("gs://bucket/key", "did:webvh:abc", "DID")
            .await
            .expect_err("unknown scheme must error");
        assert!(
            err.to_string()
                .contains("unsupported target scheme 'gs://'"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn publish_did_log_no_target_or_no_log_is_a_noop() {
        // Both must be present to publish anything.
        publish_did_log_artefacts(Some("{\"log\":1}"), None)
            .await
            .expect("no target = no-op");
        publish_did_log_artefacts(None, Some("file:///tmp/should-not-write"))
            .await
            .expect("no log = no-op");
    }

    #[tokio::test]
    async fn publish_did_log_file_target_normalises_trailing_newline() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let log_path = dir.path().join("nested/did.jsonl");
        let target = format!("file://{}", log_path.display());

        // Input has no trailing newline; strict JSON-Lines needs exactly one.
        publish_did_log_artefacts(Some("{\"versionId\":\"1-abc\"}"), Some(&target))
            .await
            .expect("file log publish should succeed");

        assert_eq!(
            std::fs::read_to_string(&log_path).unwrap(),
            "{\"versionId\":\"1-abc\"}\n"
        );
    }

    #[cfg(feature = "publish-aws")]
    #[test]
    fn validate_accepts_an_s3_target() {
        for target in [
            "s3://my-bucket/did.jsonl",
            "s3://my-bucket/mediator/did.jsonl",
            "s3://my-bucket/mediator/did.jsonl?region=eu-west-1",
        ] {
            validate_target(target).unwrap_or_else(|e| panic!("{target} should validate: {e}"));
        }
    }

    /// The published S3 target must be pasteable into `mediator.toml` as
    /// `did_web_self_hosted`, so the wizard and the runtime have to agree on
    /// the grammar. Assert against the shared parser rather than a local copy.
    #[cfg(feature = "publish-aws")]
    #[test]
    fn published_s3_target_round_trips_through_the_shared_grammar() {
        for target in [
            "s3://my-bucket/mediator/did.jsonl?region=eu-west-1",
            "s3://my-bucket/did.jsonl",
        ] {
            validate_target(target).unwrap_or_else(|e| panic!("{target} should validate: {e}"));
            let parsed = parse_s3(target).expect("shared parser accepts it");
            assert_eq!(render_s3_target(&parsed), target, "round-trip must be exact");
        }
    }

    /// The published target must be pasteable into `mediator.toml` as
    /// `mediator_did`, so the wizard and the runtime have to agree on the
    /// grammar. Assert against the shared parser rather than a local copy.
    #[cfg(feature = "publish-aws")]
    #[test]
    fn published_target_round_trips_through_the_shared_grammar() {
        for target in [
            "aws_parameter_store:///mediator/did?region=eu-west-1",
            "aws_parameter_store:///mediator/did",
            "aws_parameter_store://mediator-did",
        ] {
            validate_target(target).unwrap_or_else(|e| panic!("{target} should validate: {e}"));
            let parsed = parse_target(target).expect("shared parser accepts it");
            assert_eq!(render_target(&parsed), target, "round-trip must be exact");
        }
    }

    #[cfg(feature = "publish-aws")]
    #[test]
    fn validate_rejects_a_hierarchy_without_its_leading_slash() {
        // AWS rejects the name `mediator/did`; catch it at recipe load, not
        // after provisioning. This is also the shape the old
        // `<region>/<name>` grammar produced.
        let err = validate_target("aws_parameter_store://eu-west-1/mediator/did")
            .expect_err("unqualified hierarchy must fail");
        assert!(err.to_string().contains("must begin with '/'"), "{err}");
    }

    #[cfg(feature = "publish-aws")]
    #[test]
    fn validate_rejects_an_unknown_query_parameter() {
        let err = validate_target("aws_parameter_store:///mediator/did?profile=prod")
            .expect_err("unknown query parameter must fail");
        assert!(
            err.to_string().contains("only 'region' is supported"),
            "{err}"
        );
    }

    /// Without the feature, an SSM target must fail at *recipe load* rather
    /// than after `mint_artefacts` / `provision_secret_backend` have run.
    #[cfg(not(feature = "publish-aws"))]
    #[test]
    fn validate_rejects_ssm_target_when_publish_aws_is_off() {
        let err = validate_target("aws_parameter_store:///mediator/did")
            .expect_err("ssm target must fail without the publish-aws feature");
        assert!(err.to_string().contains("publish-aws"), "{err}");
    }
}
