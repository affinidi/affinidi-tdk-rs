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
//! - `aws_parameter_store://<region>/<name>` — write it to an SSM parameter in
//!   the given region (gated by the `publish-aws` build feature). The region is
//!   part of the target so the publish destination is self-describing and never
//!   silently inherits the secret-storage backend's region.

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

/// Validate a publish target's scheme (and, for SSM, that a region and name are
/// present) without performing any I/O. Called at recipe-load time so a bad
/// target fails before anything is minted, provisioned, or written.
pub fn validate_target(target: &str) -> anyhow::Result<()> {
    let (scheme, rest) = split_target(target)?;
    match scheme {
        "file" => {
            if rest.is_empty() {
                bail!("invalid target '{target}': file:// needs a path");
            }
            Ok(())
        }
        "aws_parameter_store" => parse_ssm_target(rest, target).map(|_| ()),
        other => bail!(
            "unsupported target scheme '{other}://' for DID publishing \
             (expected 'aws_parameter_store://<region>/<name>' or 'file://<path>')"
        ),
    }
}

fn split_target(target: &str) -> anyhow::Result<(&str, &str)> {
    target
        .split_once("://")
        .ok_or_else(|| anyhow!("invalid target '{target}': expected '<scheme>://<location>'"))
}

/// Split an `aws_parameter_store://` body `<region>/<name>` into its parts.
fn parse_ssm_target<'a>(rest: &'a str, target: &str) -> anyhow::Result<(&'a str, &'a str)> {
    let (region, name) = rest.split_once('/').ok_or_else(|| {
        anyhow!(
            "invalid target '{target}': aws_parameter_store:// needs \
             '<region>/<name>' (e.g. aws_parameter_store://eu-west-1/mediator/did)"
        )
    })?;
    if region.is_empty() || name.is_empty() {
        bail!(
            "invalid target '{target}': aws_parameter_store:// needs a non-empty \
             region and name as '<region>/<name>'"
        );
    }
    Ok((region, name))
}

/// Route a single value to its target based on the URI scheme.
async fn publish_value(target: &str, value: &str, label: &str) -> anyhow::Result<()> {
    let (scheme, rest) = split_target(target)?;

    match scheme {
        "file" => {
            let path = std::path::Path::new(rest);
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating parent directory for '{rest}'"))?;
            }
            std::fs::write(path, value)
                .with_context(|| format!("writing {label} to file '{rest}'"))?;
            println!(
                "  \x1b[32m\u{2714}\x1b[0m Published {label} \u{2192} \x1b[36m{target}\x1b[0m"
            );
            Ok(())
        }
        "aws_parameter_store" => {
            let (region, name) = parse_ssm_target(rest, target)?;
            put_ssm_parameter(name, value, label, region).await
        }
        other => bail!(
            "unsupported target scheme '{other}://' for {label} \
             (expected 'aws_parameter_store://<region>/<name>' or 'file://<path>')"
        ),
    }
}

/// Write `value` to SSM Parameter Store parameter `name`, overwriting any
/// existing value. The DID string is small, so the default Standard tier
/// (4 KB) is always sufficient.
#[cfg(feature = "publish-aws")]
async fn put_ssm_parameter(
    name: &str,
    value: &str,
    label: &str,
    region: &str,
) -> anyhow::Result<()> {
    use aws_sdk_ssm::error::DisplayErrorContext;
    use aws_sdk_ssm::types::ParameterType;

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_ssm::config::Region::new(region.to_string()))
        .load()
        .await;
    let ssm = aws_sdk_ssm::Client::new(&config);

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
        "  \x1b[32m\u{2714}\x1b[0m Published {label} \u{2192} \
         \x1b[36maws_parameter_store://{region}/{name}\x1b[0m"
    );
    Ok(())
}

#[cfg(not(feature = "publish-aws"))]
async fn put_ssm_parameter(
    _name: &str,
    _value: &str,
    label: &str,
    _region: &str,
) -> anyhow::Result<()> {
    bail!(
        "publishing {label} to aws_parameter_store:// requires the 'publish-aws' build feature; \
         rebuild with `--features publish-aws`"
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
    fn validate_accepts_file_and_ssm_targets() {
        validate_target("file:///tmp/mediator-did.txt").expect("file target is valid");
        validate_target("aws_parameter_store://eu-west-1/mediator/did")
            .expect("ssm target with region is valid");
    }

    #[test]
    fn validate_rejects_ssm_target_without_region() {
        let err = validate_target("aws_parameter_store://mediator-did")
            .expect_err("ssm target without '<region>/<name>' must fail");
        assert!(err.to_string().contains("<region>/<name>"), "{err}");
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
}
