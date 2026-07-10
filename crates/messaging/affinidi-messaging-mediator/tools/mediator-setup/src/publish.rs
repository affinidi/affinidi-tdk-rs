//! Optional publishing of the minted public DID.
//!
//! Publishes the mediator's public DID string to a store the runtime (or a
//! relying party) reads, so a one-shot `mediator-setup` task can hand off the
//! identity directly.
//!
//! Opt-in: the recipe's `[output].did_target` defaults to `None`, so
//! interactive/local setups are unaffected. Supported targets:
//!
//! - `file://<path>` — write the DID string to a local file.
//! - `aws_parameter_store://<name>[?region=<region>]` — write it to an SSM
//!   parameter (gated by the `publish-aws` build feature).
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

use affinidi_messaging_mediator_common::parameter_store::{
    PARAMETER_STORE_SCHEME, ParameterStoreTarget, parse_parameter_store_target,
};
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
        other => bail!(
            "unsupported target scheme '{other}://' for DID publishing (expected \
             '{PARAMETER_STORE_SCHEME}://<name>[?region=<region>]' or 'file://<path>')"
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
        (other, _) => bail!(
            "unsupported target scheme '{other}://' for {label} (expected \
             '{PARAMETER_STORE_SCHEME}://<name>[?region=<region>]' or 'file://<path>')"
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
        let err = validate_target("s3://bucket/key").expect_err("unknown scheme must fail");
        assert!(
            err.to_string()
                .contains("unsupported target scheme 's3://'"),
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
        let err = publish_value("s3://bucket/key", "did:webvh:abc", "DID")
            .await
            .expect_err("unknown scheme must error");
        assert!(
            err.to_string()
                .contains("unsupported target scheme 's3://'"),
            "{err}"
        );
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
