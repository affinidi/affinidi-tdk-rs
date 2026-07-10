//! `aws_parameter_store://` target parsing.
//!
//! One grammar, one parser, shared by the two sides that must agree on it:
//! the mediator runtime reads `mediator_did` / `admin_did` /
//! `did_web_self_hosted` from a parameter, and the `mediator-setup` wizard
//! publishes the minted DID to one. The string the wizard writes is the
//! string the operator pastes into `mediator.toml`, so the two cannot be
//! allowed to drift.
//!
//! ```text
//! aws_parameter_store:///mediator/did?region=eu-west-1   explicit region
//! aws_parameter_store:///mediator/did                    ambient region chain
//! aws_parameter_store://mediator-did                     flat name
//! ```
//!
//! The parameter name is everything between `://` and `?`. AWS requires a
//! hierarchical name to carry a leading `/` — `/Dev/DBServer/MySQL/db-string13`
//! is valid, `Dev/DBServer` is not — so the name is passed through verbatim
//! rather than being split on `/`. That is why the region is a query
//! parameter and not a leading path segment: a path segment would be
//! ambiguous against the name's own leading slash.
//!
//! Region is optional. When absent the caller falls back to the ambient AWS
//! chain (`AWS_REGION`, then the profile, then IMDS), which is what the
//! runtime already resolves for its shared `SdkConfig`.
//!
//! `url::Url::parse` is deliberately not used: underscores are illegal in a
//! URI scheme, so it rejects `aws_parameter_store://` outright. The same
//! hand-split applies to the `aws_secrets` / `gcp_secrets` / `azure_keyvault`
//! schemes in `secrets::url`.

use thiserror::Error;

/// URI scheme for a Systems Manager Parameter Store target.
pub const PARAMETER_STORE_SCHEME: &str = "aws_parameter_store";

/// Why an `aws_parameter_store://` target could not be parsed.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParameterStoreTargetError {
    /// No `://` separator, or a scheme other than `aws_parameter_store`.
    #[error("invalid target '{target}': expected '{PARAMETER_STORE_SCHEME}://<name>'")]
    NotParameterStore {
        /// The offending target, verbatim.
        target: String,
    },
    /// The parameter name was empty.
    #[error("invalid target '{target}': parameter name is empty")]
    EmptyName {
        /// The offending target, verbatim.
        target: String,
    },
    /// The name contains a `/` but does not begin with one. AWS rejects
    /// these, so catch it before the API call rather than after.
    #[error(
        "invalid target '{target}': a hierarchical parameter name must begin with '/' \
         (AWS rejects '{name}'; write '{PARAMETER_STORE_SCHEME}:///{name}')"
    )]
    UnqualifiedHierarchy {
        /// The offending target, verbatim.
        target: String,
        /// The name as written, without its required leading slash.
        name: String,
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

/// A parsed `aws_parameter_store://` target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterStoreTarget {
    /// Fully qualified SSM parameter name, passed to the API verbatim.
    pub name: String,
    /// Region from `?region=`. `None` means "use the ambient AWS chain".
    pub region: Option<String>,
}

/// True when `target` uses the `aws_parameter_store://` scheme. Cheap
/// prefix test for callers deciding whether they need an AWS client at all.
pub fn is_parameter_store_target(target: &str) -> bool {
    target.starts_with(PARAMETER_STORE_SCHEME)
        && target[PARAMETER_STORE_SCHEME.len()..].starts_with("://")
}

/// Parse a full `aws_parameter_store://…` target.
///
/// Validates the scheme, a non-empty name, AWS's leading-slash rule for
/// hierarchical names, and that the only query parameter is `region`. Does
/// no I/O, so callers can validate a target up front — before minting,
/// provisioning, or writing anything.
pub fn parse_parameter_store_target(
    target: &str,
) -> Result<ParameterStoreTarget, ParameterStoreTargetError> {
    let err_target = || target.to_string();

    let rest = target
        .strip_prefix(PARAMETER_STORE_SCHEME)
        .and_then(|r| r.strip_prefix("://"))
        .ok_or_else(|| ParameterStoreTargetError::NotParameterStore {
            target: err_target(),
        })?;

    // Name is everything before the query string, so a leading '/' and any
    // internal hierarchy separators survive untouched.
    let (name, query) = match rest.split_once('?') {
        Some((name, query)) => (name, Some(query)),
        None => (rest, None),
    };

    if name.is_empty() {
        return Err(ParameterStoreTargetError::EmptyName {
            target: err_target(),
        });
    }
    if name.contains('/') && !name.starts_with('/') {
        return Err(ParameterStoreTargetError::UnqualifiedHierarchy {
            target: err_target(),
            name: name.to_string(),
        });
    }

    let mut region = None;
    if let Some(query) = query {
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            match key {
                "region" => {
                    if value.is_empty() {
                        return Err(ParameterStoreTargetError::EmptyRegion {
                            target: err_target(),
                        });
                    }
                    region = Some(value.to_string());
                }
                other => {
                    return Err(ParameterStoreTargetError::UnknownQueryParameter {
                        target: err_target(),
                        key: other.to_string(),
                    });
                }
            }
        }
    }

    Ok(ParameterStoreTarget {
        name: name.to_string(),
        region,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(t: &str) -> ParameterStoreTarget {
        parse_parameter_store_target(t).expect("target should parse")
    }

    #[test]
    fn hierarchical_name_keeps_its_leading_slash() {
        // The whole reason region is a query param: the name's own leading
        // slash must survive, and AWS requires it for a hierarchy.
        let t = parse("aws_parameter_store:///mediator/did");
        assert_eq!(t.name, "/mediator/did");
        assert_eq!(t.region, None);
    }

    #[test]
    fn flat_name_needs_no_leading_slash() {
        let t = parse("aws_parameter_store://mediator-did");
        assert_eq!(t.name, "mediator-did");
        assert_eq!(t.region, None);
    }

    #[test]
    fn region_query_parameter_is_extracted() {
        let t = parse("aws_parameter_store:///mediator/did?region=eu-west-1");
        assert_eq!(t.name, "/mediator/did");
        assert_eq!(t.region.as_deref(), Some("eu-west-1"));
    }

    #[test]
    fn region_does_not_eat_the_name() {
        // Regression guard for the `<region>/<name>` grammar this replaced,
        // which would have parsed the region out of the path and left the
        // name as `mediator/did` — a name AWS rejects.
        let t = parse("aws_parameter_store:///mediator/did?region=us-east-1");
        assert_eq!(t.name, "/mediator/did");
        assert!(!t.name.starts_with("us-east-1"));
    }

    #[test]
    fn hierarchical_name_without_leading_slash_is_rejected() {
        // AWS: "For parameters in a hierarchy, you must include a leading
        // forward slash character (/)". Catch it before the API call.
        let err = parse_parameter_store_target("aws_parameter_store://mediator/did").unwrap_err();
        assert_eq!(
            err,
            ParameterStoreTargetError::UnqualifiedHierarchy {
                target: "aws_parameter_store://mediator/did".into(),
                name: "mediator/did".into(),
            }
        );
        // The message tells the operator exactly what to write instead.
        assert!(
            err.to_string()
                .contains("aws_parameter_store:///mediator/did")
        );
    }

    #[test]
    fn old_region_in_path_grammar_is_now_a_clear_error() {
        // `aws_parameter_store://eu-west-1/mediator/did` used to mean
        // region=eu-west-1, name=mediator/did. It now fails loudly rather
        // than silently writing to an AWS-invalid name.
        let err = parse_parameter_store_target("aws_parameter_store://eu-west-1/mediator/did")
            .unwrap_err();
        assert!(matches!(
            err,
            ParameterStoreTargetError::UnqualifiedHierarchy { .. }
        ));
    }

    #[test]
    fn wrong_scheme_is_rejected() {
        for target in ["s3://bucket/key", "not-a-uri", "aws_parameter_store:/x"] {
            assert!(matches!(
                parse_parameter_store_target(target).unwrap_err(),
                ParameterStoreTargetError::NotParameterStore { .. }
            ));
        }
    }

    #[test]
    fn empty_name_is_rejected() {
        assert!(matches!(
            parse_parameter_store_target("aws_parameter_store://").unwrap_err(),
            ParameterStoreTargetError::EmptyName { .. }
        ));
        assert!(matches!(
            parse_parameter_store_target("aws_parameter_store://?region=eu-west-1").unwrap_err(),
            ParameterStoreTargetError::EmptyName { .. }
        ));
    }

    #[test]
    fn empty_and_unknown_query_parameters_are_rejected() {
        assert!(matches!(
            parse_parameter_store_target("aws_parameter_store:///a?region=").unwrap_err(),
            ParameterStoreTargetError::EmptyRegion { .. }
        ));
        assert!(matches!(
            parse_parameter_store_target("aws_parameter_store:///a?profile=prod").unwrap_err(),
            ParameterStoreTargetError::UnknownQueryParameter { .. }
        ));
    }

    #[test]
    fn scheme_predicate_matches_the_parser() {
        assert!(is_parameter_store_target("aws_parameter_store:///a"));
        assert!(is_parameter_store_target("aws_parameter_store://a"));
        assert!(!is_parameter_store_target("aws_parameter_store:/a"));
        assert!(!is_parameter_store_target("aws_parameter_storex://a"));
        assert!(!is_parameter_store_target("file:///a"));
    }
}
