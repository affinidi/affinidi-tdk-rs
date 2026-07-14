//! `s3://` target parsing.
//!
//! One grammar, one parser, shared by the two sides that must agree on it:
//! the mediator runtime reads its self-hosted `did.jsonl` log from an S3
//! object (`did_web_self_hosted`), and the `mediator-setup` wizard publishes
//! the minted log to one (`[output].did_log_target`). The string the wizard
//! writes is the string the operator pastes into `mediator.toml`, so the two
//! cannot be allowed to drift.
//!
//! ```text
//! s3://my-bucket/mediator/did.jsonl?region=eu-west-1   explicit region
//! s3://my-bucket/mediator/did.jsonl                    ambient region chain
//! s3://my-bucket/did.jsonl                             key at bucket root
//! ```
//!
//! The bucket is everything between `://` and the first `/`; the key is
//! everything after that first `/` up to the query string. Both must be
//! non-empty — S3 has no "bucket-only" object. Region is a query parameter
//! (not a path segment) so it can never be confused with a key that itself
//! contains slashes.
//!
//! Region is optional. When absent the caller falls back to the ambient AWS
//! chain (`AWS_REGION`, then the profile, then IMDS), which is what the
//! runtime already resolves for its shared `SdkConfig`.
//!
//! `url::Url::parse` is deliberately not used here for symmetry with the
//! `aws_parameter_store` / `aws_secrets` schemes, which cannot use it
//! (underscores are illegal in a URI scheme). Keeping one hand-split parser
//! style across every target scheme avoids surprising divergence.

use thiserror::Error;

/// URI scheme for an Amazon S3 object target.
pub const S3_SCHEME: &str = "s3";

/// Why an `s3://` target could not be parsed.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum S3TargetError {
    /// No `://` separator, or a scheme other than `s3`.
    #[error("invalid target '{target}': expected '{S3_SCHEME}://<bucket>/<key>'")]
    NotS3 {
        /// The offending target, verbatim.
        target: String,
    },
    /// The bucket name was empty (`s3:///key`).
    #[error("invalid target '{target}': bucket name is empty")]
    EmptyBucket {
        /// The offending target, verbatim.
        target: String,
    },
    /// No key was supplied (`s3://bucket` or `s3://bucket/`). S3 has no
    /// bucket-only object, so an empty key is always an error.
    #[error(
        "invalid target '{target}': object key is empty \
         (write '{S3_SCHEME}://<bucket>/<key>')"
    )]
    EmptyKey {
        /// The offending target, verbatim.
        target: String,
    },
    /// `?region=` was present but empty.
    #[error("invalid target '{target}': 'region' query parameter is empty")]
    EmptyRegion {
        /// The offending target, verbatim.
        target: String,
    },
    /// A query parameter other than `region` was supplied.
    #[error(
        "invalid target '{target}': unknown query parameter '{key}' (only 'region' is supported)"
    )]
    UnknownQueryParameter {
        /// The offending target, verbatim.
        target: String,
        /// The unrecognised key.
        key: String,
    },
}

/// A parsed `s3://` target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Target {
    /// S3 bucket name.
    pub bucket: String,
    /// S3 object key (no leading slash — everything after `bucket/`).
    pub key: String,
    /// Region from `?region=`. `None` means "use the ambient AWS chain".
    pub region: Option<String>,
}

/// True when `target` uses the `s3://` scheme. Cheap prefix test for callers
/// deciding whether they need an AWS client at all.
pub fn is_s3_target(target: &str) -> bool {
    target.starts_with(S3_SCHEME) && target[S3_SCHEME.len()..].starts_with("://")
}

/// Parse a full `s3://…` target.
///
/// Validates the scheme, a non-empty bucket and key, and that the only query
/// parameter is `region`. Does no I/O, so callers can validate a target up
/// front — before minting, provisioning, or writing anything.
pub fn parse_s3_target(target: &str) -> Result<S3Target, S3TargetError> {
    let err_target = || target.to_string();

    let rest = target
        .strip_prefix(S3_SCHEME)
        .and_then(|r| r.strip_prefix("://"))
        .ok_or_else(|| S3TargetError::NotS3 {
            target: err_target(),
        })?;

    // Path is everything before the query string; region lives in the query
    // so a key with internal slashes survives untouched.
    let (path, query) = match rest.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (rest, None),
    };

    // Bucket is up to the first '/', key is the remainder.
    let (bucket, key) = match path.split_once('/') {
        Some((bucket, key)) => (bucket, key),
        None => (path, ""),
    };

    if bucket.is_empty() {
        return Err(S3TargetError::EmptyBucket {
            target: err_target(),
        });
    }
    if key.is_empty() {
        return Err(S3TargetError::EmptyKey {
            target: err_target(),
        });
    }

    let mut region = None;
    if let Some(query) = query {
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, value) = pair.split_once('=').unwrap_or((pair, ""));
            match k {
                "region" => {
                    if value.is_empty() {
                        return Err(S3TargetError::EmptyRegion {
                            target: err_target(),
                        });
                    }
                    region = Some(value.to_string());
                }
                other => {
                    return Err(S3TargetError::UnknownQueryParameter {
                        target: err_target(),
                        key: other.to_string(),
                    });
                }
            }
        }
    }

    Ok(S3Target {
        bucket: bucket.to_string(),
        key: key.to_string(),
        region,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(t: &str) -> S3Target {
        parse_s3_target(t).expect("target should parse")
    }

    #[test]
    fn bucket_and_key_split_on_first_slash() {
        let t = parse("s3://my-bucket/mediator/did.jsonl");
        assert_eq!(t.bucket, "my-bucket");
        assert_eq!(t.key, "mediator/did.jsonl");
        assert_eq!(t.region, None);
    }

    #[test]
    fn key_at_bucket_root() {
        let t = parse("s3://my-bucket/did.jsonl");
        assert_eq!(t.bucket, "my-bucket");
        assert_eq!(t.key, "did.jsonl");
    }

    #[test]
    fn region_query_parameter_is_extracted() {
        let t = parse("s3://my-bucket/mediator/did.jsonl?region=eu-west-1");
        assert_eq!(t.bucket, "my-bucket");
        assert_eq!(t.key, "mediator/did.jsonl");
        assert_eq!(t.region.as_deref(), Some("eu-west-1"));
    }

    #[test]
    fn region_does_not_eat_the_key() {
        // The key keeps every slash; region is only ever the query value.
        let t = parse("s3://b/a/b/c/did.jsonl?region=us-east-1");
        assert_eq!(t.key, "a/b/c/did.jsonl");
        assert_eq!(t.region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn wrong_scheme_is_rejected() {
        assert_eq!(
            parse_s3_target("file:///tmp/did.jsonl"),
            Err(S3TargetError::NotS3 {
                target: "file:///tmp/did.jsonl".into()
            })
        );
        assert!(!is_s3_target("file:///tmp/did.jsonl"));
        assert!(is_s3_target("s3://b/k"));
    }

    #[test]
    fn empty_bucket_is_rejected() {
        assert_eq!(
            parse_s3_target("s3:///did.jsonl"),
            Err(S3TargetError::EmptyBucket {
                target: "s3:///did.jsonl".into()
            })
        );
    }

    #[test]
    fn empty_key_is_rejected() {
        for t in ["s3://my-bucket", "s3://my-bucket/"] {
            assert_eq!(
                parse_s3_target(t),
                Err(S3TargetError::EmptyKey { target: t.into() })
            );
        }
    }

    #[test]
    fn empty_region_is_rejected() {
        assert_eq!(
            parse_s3_target("s3://b/k?region="),
            Err(S3TargetError::EmptyRegion {
                target: "s3://b/k?region=".into()
            })
        );
    }

    #[test]
    fn unknown_query_parameter_is_rejected() {
        assert_eq!(
            parse_s3_target("s3://b/k?acl=public"),
            Err(S3TargetError::UnknownQueryParameter {
                target: "s3://b/k?acl=public".into(),
                key: "acl".into()
            })
        );
    }
}
