//! Config-loading helpers for the mediator.
//!
//! After the unified secrets migration, credentials and operating keys
//! are loaded through `MediatorSecrets` rather than per-field URL schemes.
//! The helpers that remain here handle:
//!
//! - Reading the TOML file + applying env overrides.
//! - Resolving `mediator_did` / `admin_did` from either a literal DID or
//!   `aws_parameter_store://<name>[?region=<region>]`.
//! - Reading the self-hosted DID document from `file://`,
//!   `aws_parameter_store://`, or `s3://`.
//! - Hostname resolution and forwarding-loop protection.
//!
//! The `aws_parameter_store://` grammar lives in `mediator-common`'s
//! `parameter_store` module, shared with the `mediator-setup` wizard that
//! publishes to it, so the string the wizard writes is the string read here.

use affinidi_did_common::{Document, DocumentExt, service::Endpoint};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_mediator_common::errors::MediatorError;
#[cfg(feature = "aws")]
use affinidi_messaging_mediator_common::parameter_store::parse_parameter_store_target;
use affinidi_messaging_mediator_common::parameter_store::{
    PARAMETER_STORE_SCHEME, is_parameter_store_target,
};
#[cfg(feature = "aws")]
use affinidi_messaging_mediator_common::s3_target::parse_s3_target;
use affinidi_messaging_mediator_common::s3_target::{S3_SCHEME, is_s3_target};
use affinidi_secrets_resolver::SecretsResolver;
#[cfg(feature = "aws")]
use aws_config::{Region, SdkConfig};
#[cfg(feature = "aws")]
use aws_sdk_ssm::types::ParameterType;
use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
};
use tracing::{error, info, warn};

use super::AwsConfig;
use super::processors::ForwardingConfig;

/// Check if any DID-resolution field uses `aws_parameter_store://` or
/// `s3://`, requiring the AWS SDK to be initialised. Secret-store backends
/// are excluded — those are handled via `MediatorSecrets`, which owns its own
/// AWS SDK client when the `secrets-aws` feature is enabled.
pub(crate) fn config_needs_aws(raw: &super::ConfigRaw) -> bool {
    is_parameter_store_target(&raw.mediator_did)
        || is_parameter_store_target(&raw.server.admin_did)
        || raw
            .server
            .did_web_self_hosted
            .as_deref()
            .is_some_and(|t| is_parameter_store_target(t) || is_s3_target(t))
}

/// Extract the AWS `SdkConfig` from an `Option<AwsConfig>`, returning a clear
/// error when AWS is needed but not available.
#[cfg(feature = "aws")]
fn require_aws_config<'a>(
    aws_config: &'a Option<AwsConfig>,
    context: &str,
) -> Result<&'a SdkConfig, MediatorError> {
    aws_config.as_ref().ok_or_else(|| {
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("{context} requires AWS but AWS SDK was not initialized"),
        )
    })
}

fn parse_scheme<'a>(input: &'a str, field_name: &str) -> Result<(&'a str, &'a str), MediatorError> {
    input.split_once("://").ok_or_else(|| {
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Invalid `{field_name}` format: expected scheme://path, got '{input}'"),
        )
    })
}

/// Resolve a DID-producing config field.
///
/// Supported schemes:
/// - `did://<did-string>` — literal DID.
/// - `aws_parameter_store://<parameter-name>[?region=<region>]` — fetched at
///   startup. See [`affinidi_messaging_mediator_common::parameter_store`] for
///   the grammar; `mediator-setup` publishes to the same one.
///
/// `vta://` is no longer supported here; when VTA integration is enabled
/// the mediator DID is discovered from the admin credential at startup.
pub(crate) async fn read_did_config(
    did_config: &str,
    #[cfg_attr(not(feature = "aws"), allow(unused_variables))] aws_config: &Option<AwsConfig>,
    field_name: &str,
) -> Result<String, MediatorError> {
    let (scheme, path) = parse_scheme(did_config, field_name)?;
    let content: String = match scheme {
        "did" => path.to_string(),
        PARAMETER_STORE_SCHEME => {
            #[cfg(feature = "aws")]
            {
                let cfg = require_aws_config(
                    aws_config,
                    &format!("{field_name} ({PARAMETER_STORE_SCHEME}://)"),
                )?;
                aws_parameter_store(did_config, cfg).await?
            }
            #[cfg(not(feature = "aws"))]
            {
                let _ = path;
                return Err(MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!(
                        "aws_parameter_store:// for {field_name} requires the 'aws' feature. Rebuild with: cargo build --features aws"
                    ),
                ));
            }
        }
        _ => {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                format!(
                    "Invalid {field_name} format! Expected did:// or aws_parameter_store:// (got '{did_config}')"
                ),
            ));
        }
    };

    // A DID is a single token, and a parameter set by hand via the console or
    // CLI often carries a trailing newline. Trim rather than hand a stray
    // "\n" to the DID resolver, which fails far from the cause.
    Ok(content.trim().to_string())
}

pub(crate) fn get_hostname(host_name: &str) -> Result<String, MediatorError> {
    if host_name.starts_with("hostname://") {
        Ok(hostname::get()
            .map_err(|e| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Couldn't get hostname. Reason: {e}"),
                )
            })?
            .into_string()
            .map_err(|e| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Couldn't get hostname. Reason: {e:?}"),
                )
            })?)
    } else if host_name.starts_with("string://") {
        Ok(host_name.split_at(9).1.to_string())
    } else {
        Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid hostname format!".into(),
        ))
    }
}

/// Fetch a parameter named by a full `aws_parameter_store://…` target.
///
/// `target` is parsed by the shared grammar, so the name keeps its leading
/// slash and an optional `?region=` overrides the ambient region for this
/// call only — the rest of the process keeps using the shared `SdkConfig`.
#[cfg(feature = "aws")]
pub(crate) async fn aws_parameter_store(
    target: &str,
    aws_config: &SdkConfig,
) -> Result<String, MediatorError> {
    let parsed = parse_parameter_store_target(target)
        .map_err(|e| MediatorError::ConfigError(12, "NA".into(), e.to_string()))?;
    let parameter_name = parsed.name;

    // Region in the target wins, so a parameter can live somewhere other
    // than the region the rest of the SDK defaulted to.
    let regional_config;
    let aws_config = match parsed.region {
        Some(region) => {
            regional_config = aws_config.to_builder().region(Region::new(region)).build();
            &regional_config
        }
        None => aws_config,
    };
    let ssm = aws_sdk_ssm::Client::new(aws_config);

    let response = ssm
        .get_parameter()
        .set_name(Some(parameter_name.clone()))
        .send()
        .await
        .map_err(|e| {
            error!("Could not get ({parameter_name:?}) parameter. {e:?}");
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Could not get ({parameter_name:?}) parameter. {e:?}"),
            )
        })?;
    let parameter = response.parameter.ok_or_else(|| {
        error!("No parameter string found in response");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            "No parameter string found in response".into(),
        )
    })?;

    if let Some(_type) = parameter.r#type {
        if _type != ParameterType::String {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                "Expected String parameter type".into(),
            ));
        }
    } else {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Unknown parameter type".into(),
        ));
    }

    parameter.value.ok_or_else(|| {
        error!(
            "Parameter ({:?}) found, but no parameter value found in response",
            parameter.name
        );
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!(
                "Parameter ({:?}) found, but no parameter value found in response",
                parameter.name
            ),
        )
    })
}

/// Fetch an object body named by a full `s3://…` target, decoded as UTF-8.
///
/// `target` is parsed by the shared grammar. An optional `?region=` overrides
/// the ambient region for this call only — the rest of the process keeps
/// using the shared `SdkConfig`.
#[cfg(feature = "aws")]
pub(crate) async fn aws_s3(
    target: &str,
    aws_config: &SdkConfig,
) -> Result<String, MediatorError> {
    let parsed = parse_s3_target(target)
        .map_err(|e| MediatorError::ConfigError(12, "NA".into(), e.to_string()))?;

    // Region in the target wins, so the object can live somewhere other than
    // the region the rest of the SDK defaulted to.
    let regional_config;
    let aws_config = match parsed.region {
        Some(region) => {
            regional_config = aws_config.to_builder().region(Region::new(region)).build();
            &regional_config
        }
        None => aws_config,
    };
    let s3 = aws_sdk_s3::Client::new(aws_config);

    let response = s3
        .get_object()
        .bucket(&parsed.bucket)
        .key(&parsed.key)
        .send()
        .await
        .map_err(|e| {
            error!(
                "Could not get s3 object (bucket={:?} key={:?}). {e:?}",
                parsed.bucket, parsed.key
            );
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!(
                    "Could not get s3 object (bucket={:?} key={:?}). {e:?}",
                    parsed.bucket, parsed.key
                ),
            )
        })?;

    let bytes = response.body.collect().await.map_err(|e| {
        error!("Could not read s3 object body. {e:?}");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Could not read s3 object body. {e:?}"),
        )
    })?;

    String::from_utf8(bytes.to_vec()).map_err(|e| {
        error!("s3 object is not valid UTF-8. {e}");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("s3 object is not valid UTF-8. {e}"),
        )
    })
}

/// Reads a file and returns a vector of strings, one for each line in the file.
/// Strips lines starting with `#` (comments). Used by the runtime document /
/// DID-resolution helpers below; the config-loading copy lives in the
/// `affinidi-messaging-mediator-config` crate.
fn read_file_lines<P>(file_name: P) -> Result<Vec<String>, MediatorError>
where
    P: AsRef<Path>,
{
    let file = File::open(file_name.as_ref()).map_err(|err| {
        error!(
            "Could not open file({}). {}",
            file_name.as_ref().display(),
            err
        );
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!(
                "Could not open file({}). {}",
                file_name.as_ref().display(),
                err
            ),
        )
    })?;

    let mut lines = Vec::new();
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
        if !line.starts_with('#') {
            lines.push(line);
        }
    }

    Ok(lines)
}

/// Reads document from `file://`, `aws_parameter_store://`, or `s3://`.
pub(crate) async fn read_document(
    document_path: &str,
    #[cfg_attr(not(feature = "aws"), allow(unused_variables))] aws_config: &Option<AwsConfig>,
) -> Result<String, MediatorError> {
    let (scheme, path) = parse_scheme(document_path, "document_path")?;
    let content: String = match scheme {
        "file" => read_file_lines(path)?.concat(),
        PARAMETER_STORE_SCHEME => {
            #[cfg(feature = "aws")]
            {
                let cfg = require_aws_config(aws_config, "document_path (aws_parameter_store://)")?;
                aws_parameter_store(document_path, cfg).await?
            }
            #[cfg(not(feature = "aws"))]
            {
                let _ = path;
                return Err(MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "aws_parameter_store:// requires the 'aws' feature. Rebuild with: cargo build --features aws".into(),
                ));
            }
        }
        S3_SCHEME => {
            #[cfg(feature = "aws")]
            {
                let cfg = require_aws_config(aws_config, "document_path (s3://)")?;
                aws_s3(document_path, cfg).await?
            }
            #[cfg(not(feature = "aws"))]
            {
                let _ = path;
                return Err(MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "s3:// requires the 'aws' feature. Rebuild with: cargo build --features aws".into(),
                ));
            }
        }
        _ => {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                "Invalid document_path format! Expecting file://, aws_parameter_store://, or s3:// ..."
                    .into(),
            ));
        }
    };

    Ok(content)
}

/// Normalise an operator-supplied `api_prefix` to a canonical form.
///
/// Returns either the empty string (mount at root) or `"/<segment>"` with
/// exactly one leading `/` and no trailing `/`. This is the form axum's
/// [`Router::nest`](axum::Router::nest) accepts and the form the path-join
/// helper in this module assumes.
///
/// All of the following normalise to `""`:
/// `""`, `"/"`, `"//"`, whitespace-only.
///
/// All of the following normalise to `"/mediator/v1"`:
/// `"/mediator/v1"`, `"/mediator/v1/"`, `"mediator/v1"`, `"mediator/v1/"`,
/// `"//mediator/v1//"`.
pub fn normalize_api_prefix(input: &str) -> String {
    let bare = input.trim().trim_matches('/');
    if bare.is_empty() {
        String::new()
    } else {
        format!("/{bare}")
    }
}

/// Join a normalised `api_prefix` and a route suffix into a single
/// well-formed axum path. The prefix is expected to already be in the
/// form returned by [`normalize_api_prefix`] (`""` or `"/foo"`). The
/// suffix may or may not have a leading `/`.
///
/// The result always starts with exactly one `/`:
///
/// ```ignore
/// assert_eq!(join_api_path("",         "readyz"),  "/readyz");
/// assert_eq!(join_api_path("",         "/readyz"), "/readyz");
/// assert_eq!(join_api_path("/foo",     "readyz"),  "/foo/readyz");
/// assert_eq!(join_api_path("/foo",     "/readyz"), "/foo/readyz");
/// assert_eq!(join_api_path("/mediator/v1", "admin/status"), "/mediator/v1/admin/status");
/// ```
pub fn join_api_path(prefix: &str, suffix: &str) -> String {
    let suffix = suffix.trim_start_matches('/');
    if prefix.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{prefix}/{suffix}")
    }
}

/// Preload the mediator's own DID document into `resolver` so it can pack
/// and unpack DIDComm messages addressed to or from itself without
/// resolving its own DID over the network.
///
/// `did:web`/`did:webvh` self-resolution issues an HTTPS request to the
/// mediator's own `/.well-known/did.json{,l}`, which is frequently not
/// reachable from inside the mediator's own container or network. Seeding
/// the cache with the document the mediator already holds sidesteps that.
/// `did:peer` resolves locally and never reaches this path, so preloading
/// it is a harmless no-op from the caller's perspective.
///
/// This is the single seam both the config-validation resolver and the
/// request-time server resolver use, so the invariant "the resolver knows
/// its own DID" is established in exactly one place.
pub(crate) async fn preload_self_did(
    resolver: &mut DIDCacheClient,
    mediator_did: &str,
    doc: &Document,
) {
    resolver.add_did_document(mediator_did, doc.clone()).await;
    info!("Preloaded mediator DID into resolver cache: {mediator_did}");
}

/// Boot guard: the loaded operating secrets must be able to decrypt this
/// mediator's own inbound DIDComm.
///
/// A peer encrypts inbound DIDComm to the `keyAgreement` verification-method
/// id(s) published in *our* DID document, and the unpack path
/// ([`crate::didcomm_compat`]) does an exact-match lookup of that kid against
/// the loaded operating secrets. If no loaded secret carries a matching id,
/// every inbound message — including the `/authenticate` handshake — fails at
/// runtime with `No local secret matches any JWE recipient`: the mediator boots
/// clean but can never read a single message.
///
/// A common cause is a VTA context whose key *labels* don't equal the DID-doc VM
/// ids — `vta-sdk` < 0.11.1 used a key's free-text/`did:key` label as its kid,
/// so the bundle was keyed by the wrong ids instead of `…#key-N`. Catch that at
/// boot with an actionable error rather than as a silent per-request outage.
///
/// Vacuously OK when the document publishes no `keyAgreement` key (nothing to
/// match against).
pub(crate) async fn assert_operating_secrets_cover_key_agreement(
    mediator_doc: &Document,
    mediator_secrets: &impl SecretsResolver,
) -> Result<(), MediatorError> {
    let ka_kids: Vec<String> = mediator_doc
        .find_key_agreement(None)
        .into_iter()
        .map(str::to_string)
        .collect();
    if ka_kids.is_empty() {
        return Ok(());
    }
    if !mediator_secrets.find_secrets(&ka_kids).await.is_empty() {
        return Ok(());
    }
    let loaded = mediator_secrets.len().await;
    error!(
        "Operating secrets do not cover any published keyAgreement key. \
         Loaded {loaded} secret(s); DID document keyAgreement id(s): {ka_kids:?}"
    );
    Err(MediatorError::ConfigError(
        12,
        "NA".into(),
        format!(
            "Mediator cannot decrypt inbound DIDComm: {loaded} operating secret(s) loaded, but \
             none match this mediator's published keyAgreement key(s) {ka_kids:?}. Every inbound \
             message (including /authenticate) would fail with \"No local secret matches any JWE \
             recipient\". If this mediator is VTA-managed, ensure the VTA context's key labels \
             equal the DID document verification-method ids and re-provision (vta-sdk >= 0.11.1 \
             fixes the label-as-kid bug); for self-hosted setups re-run mediator-setup so the \
             operating secrets match the published DID document."
        ),
    ))
}

/// Creates a set of URI's that can be used to detect if forwarding loopbacks to the mediator could occur
pub(crate) async fn load_forwarding_protection_blocks(
    did_resolver: &DIDCacheClient,
    forwarding_config: &mut ForwardingConfig,
    mediator_did: &str,
    blocked_dids: &str,
) -> Result<(), MediatorError> {
    let mut blocked_dids: Vec<String> = match serde_json::from_str(blocked_dids) {
        Ok(dids) => dids,
        Err(err) => {
            error!("Could not parse blocked_forwarding_dids. Reason: {err}");
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Could not parse blocked_forwarding_dids. Reason: {err}"),
            ));
        }
    };

    blocked_dids.push(mediator_did.into());

    for did in blocked_dids {
        let doc = did_resolver.resolve(&did).await.map_err(|err| {
            MediatorError::DIDError(
                12,
                "NA".into(),
                did.clone(),
                format!("Couldn't resolve DID. Reason: {err}"),
            )
        })?;

        forwarding_config.blocked_forwarding.insert(did.clone());

        for service in doc.doc.service.iter() {
            match &service.service_endpoint {
                Endpoint::Url(uri) => {
                    forwarding_config.blocked_forwarding.insert(uri.to_string());
                }
                Endpoint::Map(map) => {
                    if let Some(endpoints) = map.as_array() {
                        for endpoint in endpoints {
                            if let Some(uri) = endpoint.get("uri") {
                                if let Some(uri) = uri.as_str() {
                                    forwarding_config.blocked_forwarding.insert(uri.into());
                                } else {
                                    warn!("Couldn't parse URI as a string: {uri:#?}");
                                }
                            } else {
                                warn!(
                                    "Service endpoint map does not contain a URI. DID ({did}), Service ({service:#?}), Endpoint ({endpoint:#?})"
                                );
                            }
                        }
                    } else if let Some(uri) = map.get("uri") {
                        if let Some(uri) = uri.as_str() {
                            forwarding_config.blocked_forwarding.insert(uri.into());
                        } else {
                            warn!("Couldn't parse URI as a string: {uri:#?}");
                        }
                    } else {
                        warn!(
                            "Service endpoint map does not contain a URI. DID ({did}), Service ({service:#?}), Endpoint ({map:#?})"
                        );
                    }
                }
                // `Endpoint` is `#[non_exhaustive]`; ignore unknown shapes.
                _ => {}
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{join_api_path, normalize_api_prefix, read_did_config, read_document};

    /// The runtime document reader accepts `file://`, `aws_parameter_store://`,
    /// and `s3://`. An unknown scheme must fail with a message that names all
    /// three, so an operator's typo is self-diagnosing.
    #[tokio::test]
    async fn read_document_rejects_unknown_scheme() {
        let err = read_document("gs://bucket/obj", &None)
            .await
            .expect_err("unknown scheme is not a document source");
        let msg = err.to_string();
        assert!(
            msg.contains("file://")
                && msg.contains("aws_parameter_store://")
                && msg.contains("s3://"),
            "error should name the accepted schemes, got: {msg}"
        );
    }

    /// `mediator-setup` documents that a `file://` DID target does not
    /// round-trip into `mediator_did`. Pin the runtime half of that claim so
    /// the docs and the code cannot drift apart.
    #[tokio::test]
    async fn read_did_config_rejects_a_file_target() {
        let err = read_did_config("file:///run/mediator/did.txt", &None, "mediator_did")
            .await
            .expect_err("file:// is not a DID source");
        let msg = err.to_string();
        assert!(
            msg.contains("did://") && msg.contains("aws_parameter_store://"),
            "error should name the two accepted schemes, got: {msg}"
        );
    }

    #[tokio::test]
    async fn read_did_config_trims_surrounding_whitespace() {
        // A DID is a single token. The trim exists for parameter-store values
        // set by hand (a trailing newline is easy to leave behind); assert it
        // through the one scheme reachable without an AWS client.
        let did = read_did_config("did://  did:peer:2.Vz6Mk\n", &None, "mediator_did")
            .await
            .expect("literal DID resolves");
        assert_eq!(did, "did:peer:2.Vz6Mk");
    }

    #[test]
    fn normalize_empty_forms_collapse_to_root() {
        assert_eq!(normalize_api_prefix(""), "");
        assert_eq!(normalize_api_prefix("/"), "");
        assert_eq!(normalize_api_prefix("//"), "");
        assert_eq!(normalize_api_prefix("///"), "");
        assert_eq!(normalize_api_prefix("   "), "");
        assert_eq!(normalize_api_prefix(" / "), "");
    }

    #[test]
    fn normalize_strips_wrapping_slashes_and_whitespace() {
        assert_eq!(normalize_api_prefix("foo"), "/foo");
        assert_eq!(normalize_api_prefix("/foo"), "/foo");
        assert_eq!(normalize_api_prefix("foo/"), "/foo");
        assert_eq!(normalize_api_prefix("/foo/"), "/foo");
        assert_eq!(normalize_api_prefix("//foo//"), "/foo");
        assert_eq!(normalize_api_prefix("  /foo/  "), "/foo");
    }

    #[test]
    fn normalize_preserves_internal_segments() {
        assert_eq!(normalize_api_prefix("/mediator/v1/"), "/mediator/v1");
        assert_eq!(normalize_api_prefix("mediator/v1"), "/mediator/v1");
        assert_eq!(normalize_api_prefix("/a/b/c"), "/a/b/c");
    }

    #[test]
    fn normalize_is_idempotent() {
        for input in ["", "/", "/foo", "/foo/bar", "foo/", "  /foo/bar/  "] {
            let once = normalize_api_prefix(input);
            let twice = normalize_api_prefix(&once);
            assert_eq!(once, twice, "not idempotent for {input:?}");
        }
    }

    #[test]
    fn join_api_path_handles_empty_prefix() {
        assert_eq!(join_api_path("", "readyz"), "/readyz");
        assert_eq!(join_api_path("", "/readyz"), "/readyz");
        assert_eq!(join_api_path("", "admin/status"), "/admin/status");
    }

    #[test]
    fn join_api_path_handles_non_empty_prefix() {
        assert_eq!(join_api_path("/foo", "readyz"), "/foo/readyz");
        assert_eq!(join_api_path("/foo", "/readyz"), "/foo/readyz");
        assert_eq!(
            join_api_path("/mediator/v1", "admin/status"),
            "/mediator/v1/admin/status"
        );
    }

    #[test]
    fn join_api_path_always_returns_leading_slash() {
        for prefix in ["", "/foo", "/mediator/v1"] {
            for suffix in ["readyz", "/readyz", "admin/status"] {
                let joined = join_api_path(prefix, suffix);
                assert!(
                    joined.starts_with('/'),
                    "join_api_path({prefix:?}, {suffix:?}) = {joined:?} did not start with /"
                );
            }
        }
    }

    /// `preload_self_did` must leave the mediator's own DID resolvable
    /// straight from the cache — the whole point is that the request-time
    /// resolver answers self-resolution without a network round-trip.
    #[tokio::test]
    async fn preload_self_did_makes_doc_resolvable_from_cache() {
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

        const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";

        let mut resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();

        // Obtain a real Document, then evict it so the cache is cold.
        let doc = resolver.resolve(DID_KEY).await.unwrap().doc;
        resolver.remove(DID_KEY).await;

        super::preload_self_did(&mut resolver, DID_KEY, &doc).await;

        // The next resolve must be served from cache (no network), proving
        // the preload seeded the document the server resolver will use.
        let cached = resolver.resolve(DID_KEY).await.unwrap();
        assert!(cached.cache_hit, "preloaded DID was not served from cache");
        assert_eq!(cached.doc, doc);
    }

    /// The boot guard passes when a loaded operating secret matches a published
    /// `keyAgreement` verification-method id — the mediator can decrypt inbound
    /// DIDComm.
    #[tokio::test]
    async fn coverage_guard_passes_when_secret_matches_key_agreement() {
        use affinidi_did_common::DocumentExt;
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        use affinidi_secrets_resolver::{
            SecretsResolver, ThreadedSecretsResolver, secrets::Secret,
        };

        const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let doc = resolver.resolve(DID_KEY).await.unwrap().doc;
        let ka_kid = doc
            .find_key_agreement(None)
            .first()
            .copied()
            .expect("did:key publishes a keyAgreement key")
            .to_string();

        // A secret keyed under the *correct* published kid. `find_secrets`
        // matches on id, which is exactly what the unpack path looks up.
        let (secrets, _h) = ThreadedSecretsResolver::new(None).await;
        secrets
            .insert_vec(&[Secret::generate_ed25519(Some(&ka_kid), Some(&[7u8; 32]))])
            .await;

        super::assert_operating_secrets_cover_key_agreement(&doc, &secrets)
            .await
            .expect("guard must pass when a secret covers the keyAgreement kid");
    }

    /// Regression for the storm.ws label-as-kid outage: the document publishes a
    /// `keyAgreement` kid, but the loaded secret is keyed under the *wrong* id (a
    /// decorative `did:key` label, as `vta-sdk` < 0.11.1 produced). The guard
    /// must abort boot rather than let the mediator fail every `/authenticate` at
    /// runtime with "No local secret matches any JWE recipient".
    #[tokio::test]
    async fn coverage_guard_fails_when_no_secret_matches_key_agreement() {
        use affinidi_did_common::DocumentExt;
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        use affinidi_secrets_resolver::{
            SecretsResolver, ThreadedSecretsResolver, secrets::Secret,
        };

        const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let doc = resolver.resolve(DID_KEY).await.unwrap().doc;
        let ka_kid = doc
            .find_key_agreement(None)
            .first()
            .copied()
            .expect("did:key publishes a keyAgreement key")
            .to_string();

        // Loaded under a decorative free-text label, NOT the published VM id.
        let (secrets, _h) = ThreadedSecretsResolver::new(None).await;
        secrets
            .insert_vec(&[Secret::generate_ed25519(
                Some("did:key:z6MkDecorative key-agreement key"),
                Some(&[9u8; 32]),
            )])
            .await;

        let err = super::assert_operating_secrets_cover_key_agreement(&doc, &secrets)
            .await
            .expect_err("guard must fail when no secret covers the keyAgreement kid");
        let msg = err.to_string();
        assert!(
            msg.contains("No local secret matches any JWE recipient"),
            "error must name the runtime failure mode, got: {msg}"
        );
        assert!(
            msg.contains(&ka_kid),
            "error must name the uncovered kid, got: {msg}"
        );
    }

    /// A document publishing no `keyAgreement` key has nothing to match, so the
    /// guard is vacuously satisfied even with an empty secret set.
    #[tokio::test]
    async fn coverage_guard_vacuous_when_no_key_agreement() {
        use affinidi_did_common::Document;
        use affinidi_secrets_resolver::ThreadedSecretsResolver;

        let doc: Document = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:example:no-key-agreement",
        }))
        .expect("minimal DID document parses");

        let (secrets, _h) = ThreadedSecretsResolver::new(None).await;
        super::assert_operating_secrets_cover_key_agreement(&doc, &secrets)
            .await
            .expect("guard is vacuous when the doc publishes no keyAgreement key");
    }
}
