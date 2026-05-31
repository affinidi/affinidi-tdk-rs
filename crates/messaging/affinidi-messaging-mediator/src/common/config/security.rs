use affinidi_messaging_mediator_common::{MediatorSecrets, errors::MediatorError};
use affinidi_messaging_sdk::protocols::mediator::acls::{AccessListModeType, MediatorACLSet};
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};
use http::{
    HeaderValue, Method,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Debug},
    sync::Arc,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use vta_sdk::did_secrets::DidSecretsBundle;

/// Resolved cross-origin policy for browser clients.
///
/// Built from the `security.cors_allow_origin` config value. Held
/// alongside the pre-built [`CorsLayer`] so the WebSocket handler can
/// apply the *same* allowlist as a defence-in-depth `Origin` check
/// (WebSocket upgrades aren't subject to CORS, but browsers still send
/// an `Origin` header on them).
#[derive(Clone, Debug)]
pub enum CorsOriginPolicy {
    /// No cross-origin browser access (the default — `cors_allow_origin`
    /// unset). Browser requests/upgrades carrying an `Origin` are
    /// refused; header-less native clients are unaffected.
    None,
    /// Any origin (`cors_allow_origin = "*"`). Defensible here because
    /// these endpoints authenticate with a bearer token in the
    /// `Authorization` header, not an ambient cookie — a wildcard does
    /// not expose them to CSRF, since a cross-origin page would still
    /// need a valid token to do anything. Emits `Access-Control-Allow-
    /// Origin: *` and never sets `allow_credentials`.
    Any,
    /// An explicit allowlist of origin matchers. Each entry is either an
    /// exact, scheme-qualified origin or a `scheme://*.suffix` wildcard
    /// (see [`OriginMatcher`]). A request `Origin` is permitted iff it
    /// matches at least one entry; the matched origin is echoed back, so
    /// the response stays CORS-spec compliant (one exact origin, never a
    /// literal `*.…`).
    List(Vec<OriginMatcher>),
}

/// A single entry in a [`CorsOriginPolicy::List`] allowlist.
///
/// The CORS spec's `Access-Control-Allow-Origin` header only carries a
/// bare `*`, a single exact origin, or `null` — there is no
/// wildcard-subdomain token. We support `*.suffix` patterns by matching
/// the *request* `Origin` against the pattern and echoing back the exact
/// origin that matched (which is what [`AllowOrigin::predicate`] does).
#[derive(Clone, Debug)]
pub enum OriginMatcher {
    /// An exact, scheme-qualified origin, compared byte-for-byte against
    /// the request `Origin` (e.g. `https://app.affinidi.com`).
    Exact(HeaderValue),
    /// A `scheme://*.suffix[:port]` wildcard (e.g. `https://*.affinidi.com`).
    ///
    /// Matches a request origin iff the scheme and port match exactly and
    /// the request host is a sub-domain of `suffix` — i.e. it ends with
    /// `.suffix` and has at least one label in front of that boundary
    /// dot. The boundary dot is mandatory, so `https://*.affinidi.com`
    /// matches `https://app.affinidi.com` and `https://a.b.affinidi.com`
    /// but NOT the apex `https://affinidi.com` (add it explicitly) nor a
    /// look-alike like `https://evilaffinidi.com`.
    WildcardSubdomain {
        /// Lower-cased scheme, e.g. `https`.
        scheme: String,
        /// Lower-cased registrable suffix the sub-domain must sit under,
        /// e.g. `affinidi.com`.
        suffix: String,
        /// Explicit port the request origin must carry, if the pattern
        /// pinned one (`https://*.x.com:8443`). `None` means the origin
        /// must carry no port either.
        port: Option<u16>,
    },
}

/// A request `Origin` decomposed into the three parts that matter for
/// matching: scheme (lower-cased), host (lower-cased), optional port.
/// Origins are serialised without a path/query, so this is a total parse
/// of a well-formed `Origin` header; anything that doesn't fit the
/// `scheme://host[:port]` shape returns `None` and never matches.
struct ParsedOrigin<'a> {
    scheme: String,
    host: String,
    port: Option<&'a str>,
}

impl<'a> ParsedOrigin<'a> {
    fn parse(origin: &'a str) -> Option<Self> {
        let (scheme, rest) = origin.split_once("://")?;
        if scheme.is_empty() || rest.is_empty() {
            return None;
        }
        // An Origin carries no path/userinfo/query. Reject anything that
        // smuggles one in rather than silently matching on a prefix.
        if rest.contains(['/', '?', '#', '@', '\\']) {
            return None;
        }
        let (host, port) = match rest.rsplit_once(':') {
            // A ':' that isn't followed by an all-digit port isn't a port
            // separator (defensive — Origin hosts are never IPv6-bracketed
            // here, but treat a non-numeric tail as "no port" so it can't
            // masquerade as one).
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (h, Some(p)),
            _ => (rest, None),
        };
        if host.is_empty() {
            return None;
        }
        Some(ParsedOrigin {
            scheme: scheme.to_ascii_lowercase(),
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

impl OriginMatcher {
    /// Whether this matcher admits the given request `Origin` header.
    fn matches(&self, origin: &HeaderValue) -> bool {
        match self {
            // Exact origins are compared byte-for-byte, exactly as the
            // previous `AllowOrigin::list` did — no normalisation.
            OriginMatcher::Exact(expected) => expected == origin,
            OriginMatcher::WildcardSubdomain {
                scheme,
                suffix,
                port,
            } => {
                let Ok(origin) = origin.to_str() else {
                    return false;
                };
                let Some(parsed) = ParsedOrigin::parse(origin) else {
                    return false;
                };
                // Scheme and port must match exactly — a wildcard widens
                // only the host, never the scheme/port. Compare ports by
                // their string form so `:08443` can't slip past `:8443`.
                if &parsed.scheme != scheme
                    || parsed.port.map(str::to_string) != port.as_ref().map(u16::to_string)
                {
                    return false;
                }
                // Sub-domain check with a mandatory boundary dot: the host
                // must end with ".<suffix>" and have ≥1 label in front, so
                // neither the apex (`suffix`) nor a look-alike
                // (`evil<suffix>`) can match.
                parsed
                    .host
                    .strip_suffix(suffix)
                    .and_then(|head| head.strip_suffix('.'))
                    .is_some_and(|label| !label.is_empty())
            }
        }
    }
}

/// Whether `origin` is admitted by any matcher in `matchers`.
///
/// Shared by the REST [`CorsLayer`] predicate and the WebSocket
/// defence-in-depth `Origin` check so the two enforcement points can
/// never drift apart.
pub fn origin_matches(matchers: &[OriginMatcher], origin: &HeaderValue) -> bool {
    matchers.iter().any(|m| m.matches(origin))
}

/// Build the mediator's [`CorsLayer`] for the given origin policy. The
/// allowed methods/headers are fixed; only the origin matching varies.
fn build_cors_layer(policy: &CorsOriginPolicy) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::OPTIONS,
            Method::DELETE,
            Method::PATCH,
            Method::PUT,
        ]);

    match policy {
        // Default-closed: an empty allowlist never echoes an origin.
        CorsOriginPolicy::None => base,
        CorsOriginPolicy::Any => base.allow_origin(AllowOrigin::any()),
        // A predicate (rather than `AllowOrigin::list`) so `*.suffix`
        // wildcards can match; `AllowOrigin::predicate` echoes back the
        // exact request origin on a match and sets `Vary: Origin`.
        CorsOriginPolicy::List(matchers) => {
            let matchers = matchers.clone();
            base.allow_origin(AllowOrigin::predicate(move |origin, _parts| {
                origin_matches(&matchers, origin)
            }))
        }
    }
}

/// Security configuration for the mediator.
///
/// JWT signing secret + operating keys are no longer in this struct — they
/// live in the unified secret backend (`[secrets] backend = "..."` in
/// `mediator.toml`) and are loaded during [`SecurityConfigRaw::convert`].
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfigRaw {
    pub mediator_acl_mode: String,
    pub global_acl_default: String,
    pub local_direct_delivery_allowed: String,
    pub local_direct_delivery_allow_anon: String,
    pub use_ssl: String,
    pub ssl_certificate_file: Option<String>,
    pub ssl_key_file: Option<String>,
    pub jwt_access_expiry: String,
    pub jwt_refresh_expiry: String,
    pub cors_allow_origin: Option<String>,
    pub block_anonymous_outer_envelope: String,
    pub block_remote_admin_msgs: String,
    pub force_session_did_match: String,
    pub admin_messages_expiry: String,
}

#[derive(Clone, Serialize)]
pub struct SecurityConfig {
    pub mediator_acl_mode: AccessListModeType,
    pub global_acl_default: MediatorACLSet,
    pub local_direct_delivery_allowed: bool,
    pub local_direct_delivery_allow_anon: bool,
    #[serde(skip_serializing)]
    pub mediator_secrets: Arc<ThreadedSecretsResolver>,
    pub use_ssl: bool,
    pub ssl_certificate_file: Option<String>,
    #[serde(skip_serializing)]
    pub ssl_key_file: Option<String>,
    #[serde(skip_serializing)]
    pub jwt_encoding_key: EncodingKey,
    #[serde(skip_serializing)]
    pub jwt_decoding_key: DecodingKey,
    pub jwt_access_expiry: u64,
    pub jwt_refresh_expiry: u64,
    #[serde(skip_serializing)]
    pub cors_allow_origin: CorsLayer,
    /// The same origin policy the `cors_allow_origin` layer enforces,
    /// kept in an inspectable form for the WebSocket `Origin` check.
    #[serde(skip_serializing)]
    pub cors_origins: CorsOriginPolicy,
    pub block_anonymous_outer_envelope: bool,
    pub force_session_did_match: bool,
    pub block_remote_admin_msgs: bool,
    pub admin_messages_expiry: u64,
}

impl Debug for SecurityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityConfig")
            .field("mediator_acl_mode", &self.mediator_acl_mode)
            .field("global_acl_default", &self.global_acl_default)
            .field(
                "local_direct_delivery_allowed",
                &self.local_direct_delivery_allowed,
            )
            .field(
                "local_direct_delivery_allow_anon",
                &self.local_direct_delivery_allow_anon,
            )
            .field("use_ssl", &self.use_ssl)
            .field("ssl_certificate_file", &self.ssl_certificate_file)
            .field("ssl_key_file", &self.ssl_key_file)
            .field("jwt_encoding_key?", &"<hidden>".to_string())
            .field("jwt_decoding_key?", &"<hidden>".to_string())
            .field("jwt_access_expiry", &self.jwt_access_expiry)
            .field("jwt_refresh_expiry", &self.jwt_refresh_expiry)
            .field("cors_allow_origin", &self.cors_allow_origin)
            .field("cors_origins", &self.cors_origins)
            .field(
                "block_anonymous_outer_envelope",
                &self.block_anonymous_outer_envelope,
            )
            .field("force_session_did_match", &self.force_session_did_match)
            .field("block_remote_admin_msgs", &self.block_remote_admin_msgs)
            .field("admin_messages_expiry", &self.admin_messages_expiry)
            .finish()
    }
}

impl SecurityConfig {
    /// Construct a baseline `SecurityConfig` with conservative defaults
    /// and zero-byte JWT keys. Used by [`Config::headless`] and the
    /// `MediatorBuilder` as a starting point — embedded callers MUST
    /// overwrite `jwt_encoding_key` / `jwt_decoding_key` with real
    /// material before starting the mediator.
    ///
    /// [`Config::headless`]: crate::common::config::Config::headless
    pub fn headless(secrets_resolver: Arc<ThreadedSecretsResolver>) -> Self {
        Self::default(secrets_resolver)
    }

    pub(crate) fn default(secrets_resolver: Arc<ThreadedSecretsResolver>) -> Self {
        SecurityConfig {
            mediator_acl_mode: AccessListModeType::ExplicitDeny,
            global_acl_default: MediatorACLSet::default(),
            local_direct_delivery_allowed: false,
            local_direct_delivery_allow_anon: false,
            mediator_secrets: secrets_resolver,
            use_ssl: true,
            ssl_certificate_file: None,
            ssl_key_file: None,
            jwt_encoding_key: EncodingKey::from_ed_der(&[0; 32]),
            jwt_decoding_key: DecodingKey::from_ed_der(&[0; 32]),
            jwt_access_expiry: 900,
            jwt_refresh_expiry: 86_400,
            cors_allow_origin: build_cors_layer(&CorsOriginPolicy::None),
            cors_origins: CorsOriginPolicy::None,
            block_anonymous_outer_envelope: true,
            force_session_did_match: true,
            block_remote_admin_msgs: true,
            admin_messages_expiry: 3,
        }
    }
}

impl SecurityConfigRaw {
    /// Parse the raw `cors_allow_origin` config value into a
    /// [`CorsOriginPolicy`].
    ///
    /// - empty / whitespace-only ⇒ [`CorsOriginPolicy::None`]
    /// - a bare `*` token ⇒ [`CorsOriginPolicy::Any`] (`tower_http`'s
    ///   origin list would otherwise *panic* on `*`). If `*` is mixed
    ///   with explicit origins the explicit entries are redundant and a
    ///   warning is logged.
    /// - otherwise ⇒ [`CorsOriginPolicy::List`] of matchers, each an
    ///   exact origin or a `scheme://*.suffix[:port]` wildcard.
    fn parse_cors_origins(cors_allow_origin: &str) -> Result<CorsOriginPolicy, MediatorError> {
        let tokens: Vec<&str> = cors_allow_origin
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        if tokens.is_empty() {
            return Ok(CorsOriginPolicy::None);
        }

        if tokens.contains(&"*") {
            if tokens.len() > 1 {
                tracing::warn!(
                    "security.cors_allow_origin contains '*' alongside explicit origins; \
                     treating as allow-any (the explicit entries are redundant)"
                );
            }
            return Ok(CorsOriginPolicy::Any);
        }

        let matchers = tokens
            .iter()
            .map(|o| Self::parse_origin_matcher(o))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CorsOriginPolicy::List(matchers))
    }

    /// Parse a single allowlist entry into an [`OriginMatcher`].
    ///
    /// Wildcard entries have the shape `scheme://*.suffix[:port]` — the
    /// `*` must be the entire leftmost host label (i.e. immediately
    /// followed by `.`) and is the only `*` allowed. Everything *without*
    /// a `*` is treated as an exact origin and parsed as a [`HeaderValue`]
    /// exactly as before this matcher existed (so existing exact-origin
    /// configs are unaffected).
    fn parse_origin_matcher(token: &str) -> Result<OriginMatcher, MediatorError> {
        let config_err = |msg: String| MediatorError::ConfigError(12, "NA".into(), msg);

        // Fast path: no '*' ⇒ exact origin, parsed verbatim (unchanged
        // legacy behaviour — scheme requirement is enforced by the
        // wizard, not here, so we don't reject pre-existing configs).
        if !token.contains('*') {
            let value = token
                .parse::<HeaderValue>()
                .map_err(|err| config_err(format!("Invalid CORS origin '{token}': {err}")))?;
            return Ok(OriginMatcher::Exact(value));
        }

        // Wildcard form: must be exactly `scheme://*.suffix[:port]`.
        let Some((scheme, rest)) = token.split_once("://") else {
            return Err(config_err(format!(
                "Invalid CORS origin '{token}': '*' is only supported as a leftmost \
                 sub-domain wildcard, e.g. 'https://*.example.com'"
            )));
        };
        let Some(suffix) = rest.strip_prefix("*.") else {
            return Err(config_err(format!(
                "Invalid CORS origin '{token}': '*' is only allowed as the leftmost host \
                 label, written as '{scheme}://*.suffix'"
            )));
        };
        if scheme.is_empty() {
            return Err(config_err(format!(
                "Invalid CORS origin '{token}': missing scheme before '://'"
            )));
        }
        // Only the single leftmost `*` is permitted.
        if suffix.contains('*') {
            return Err(config_err(format!(
                "Invalid CORS origin '{token}': only one leftmost '*' wildcard is allowed"
            )));
        }
        // Split an optional :port off the suffix.
        let (host_suffix, port) = match suffix.rsplit_once(':') {
            Some((h, p)) => {
                let port: u16 = p.parse().map_err(|_| {
                    config_err(format!("Invalid CORS origin '{token}': bad port '{p}'"))
                })?;
                (h, Some(port))
            }
            None => (suffix, None),
        };
        if host_suffix.is_empty()
            || host_suffix.starts_with('.')
            || host_suffix.contains(['/', '?', '#', '@', '\\'])
        {
            return Err(config_err(format!(
                "Invalid CORS origin '{token}': '{host_suffix}' is not a valid wildcard \
                 suffix (expected e.g. 'https://*.example.com')"
            )));
        }
        Ok(OriginMatcher::WildcardSubdomain {
            scheme: scheme.to_ascii_lowercase(),
            suffix: host_suffix.to_ascii_lowercase(),
            port,
        })
    }

    /// Build the runtime `SecurityConfig` from the raw TOML values.
    ///
    /// Operating keys and the JWT signing secret are loaded from the
    /// unified secret backend:
    /// - **VTA mode** (admin credential present in the backend):
    ///   `vta_bundle` is the freshly-fetched [`DidSecretsBundle`] (or the
    ///   cached copy if the VTA was unreachable). Secrets are inserted
    ///   into the resolver directly.
    /// - **Self-hosted mode** (no admin credential, no VTA bundle):
    ///   operating secrets come from the well-known
    ///   [`OPERATING_SECRETS`](affinidi_messaging_mediator_common::OPERATING_SECRETS)
    ///   key in the backend.
    ///
    /// The JWT secret is always loaded from the backend's `JWT_SECRET`
    /// well-known entry — no inline `string://` path.
    pub(crate) async fn convert(
        &self,
        secrets_resolver: Arc<ThreadedSecretsResolver>,
        secrets: &MediatorSecrets,
        vta_bundle: Option<&DidSecretsBundle>,
    ) -> Result<SecurityConfig, MediatorError> {
        let warn_default = |field: &str, value: &str, default: &str| {
            tracing::warn!(
                "Could not parse security.{field} value '{value}', using default: {default}"
            );
        };

        let mut config = SecurityConfig {
            mediator_acl_mode: match self.mediator_acl_mode.as_str() {
                "explicit_allow" => AccessListModeType::ExplicitAllow,
                "explicit_deny" => AccessListModeType::ExplicitDeny,
                _ => AccessListModeType::ExplicitDeny,
            },
            local_direct_delivery_allowed: self
                .local_direct_delivery_allowed
                .parse()
                .unwrap_or_else(|_| {
                    warn_default(
                        "local_direct_delivery_allowed",
                        &self.local_direct_delivery_allowed,
                        "false",
                    );
                    false
                }),
            local_direct_delivery_allow_anon: self
                .local_direct_delivery_allow_anon
                .parse()
                .unwrap_or_else(|_| {
                    warn_default(
                        "local_direct_delivery_allow_anon",
                        &self.local_direct_delivery_allow_anon,
                        "false",
                    );
                    false
                }),
            use_ssl: self.use_ssl.parse().unwrap_or_else(|_| {
                warn_default("use_ssl", &self.use_ssl, "true");
                true
            }),
            ssl_certificate_file: self.ssl_certificate_file.clone(),
            ssl_key_file: self.ssl_key_file.clone(),
            jwt_access_expiry: self.jwt_access_expiry.parse().unwrap_or_else(|_| {
                warn_default("jwt_access_expiry", &self.jwt_access_expiry, "900");
                900
            }),
            jwt_refresh_expiry: self.jwt_refresh_expiry.parse().unwrap_or_else(|_| {
                warn_default("jwt_refresh_expiry", &self.jwt_refresh_expiry, "86400");
                86_400
            }),
            block_anonymous_outer_envelope: self
                .block_anonymous_outer_envelope
                .parse()
                .unwrap_or_else(|_| {
                    warn_default(
                        "block_anonymous_outer_envelope",
                        &self.block_anonymous_outer_envelope,
                        "true",
                    );
                    true
                }),
            force_session_did_match: self.force_session_did_match.parse().unwrap_or_else(|_| {
                warn_default(
                    "force_session_did_match",
                    &self.force_session_did_match,
                    "true",
                );
                true
            }),
            block_remote_admin_msgs: self.block_remote_admin_msgs.parse().unwrap_or_else(|_| {
                warn_default(
                    "block_remote_admin_msgs",
                    &self.block_remote_admin_msgs,
                    "true",
                );
                true
            }),
            admin_messages_expiry: self.admin_messages_expiry.parse().unwrap_or_else(|_| {
                warn_default("admin_messages_expiry", &self.admin_messages_expiry, "3");
                3
            }),
            ..SecurityConfig::default(secrets_resolver)
        };

        if !config.block_anonymous_outer_envelope && config.force_session_did_match {
            tracing::error!(
                "Conflicting configuration: security.force_session_did_match can not be true when security.block_anonymous_outer_envelope is false"
            );
            return Err(MediatorError::ConfigError(12,
                "NA".into(),
                "Conflicting configuration: security.force_session_did_match can not be true when security.block_anonymous_outer_envelope is false".into(),
            ));
        }

        config.global_acl_default = MediatorACLSet::from_string_ruleset(&self.global_acl_default)
            .map_err(|err| {
            tracing::error!("Couldn't parse global_acl_default config parameter. Reason: {err}");
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Couldn't parse global_acl_default config parameter. Reason: {err}"),
            )
        })?;

        if let Some(cors_allow_origin) = &self.cors_allow_origin {
            let policy = Self::parse_cors_origins(cors_allow_origin)?;
            config.cors_allow_origin = build_cors_layer(&policy);
            config.cors_origins = policy;
        }

        // ── Populate the DIDComm secrets resolver ────────────────────────
        if let Some(bundle) = vta_bundle {
            // VTA mode: operating keys arrived via integration::startup.
            tracing::info!(
                "Loading {} operating secret(s) from VTA DidSecretsBundle",
                bundle.secrets.len()
            );
            let converted = bundle
                .secrets
                .iter()
                .map(|entry| {
                    Secret::from_multibase(&entry.private_key_multibase, Some(&entry.key_id))
                        .map_err(|e| {
                            MediatorError::ConfigError(
                                12,
                                "NA".into(),
                                format!(
                                    "Could not decode VTA operating secret '{}': {e}",
                                    entry.key_id
                                ),
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            config.mediator_secrets.insert_vec(&converted).await;
        } else {
            // Self-hosted mode: operating keys come from the well-known
            // OPERATING_SECRETS entry in the backend.
            match secrets
                .load_entry::<Vec<Secret>>(
                    affinidi_messaging_mediator_common::OPERATING_SECRETS,
                    "operating-secrets",
                )
                .await
            {
                Ok(Some(secrets_vec)) => {
                    tracing::info!(
                        "Loading {} operating secret(s) from unified secret backend",
                        secrets_vec.len()
                    );
                    config.mediator_secrets.insert_vec(&secrets_vec).await;
                }
                Ok(None) => {
                    return Err(MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        "No operating secrets found. In self-hosted mode, the backend must \
                         contain an entry at 'mediator/operating/secrets'. Run \
                         `mediator-setup` to provision, or enable VTA integration."
                            .into(),
                    ));
                }
                Err(err) => {
                    tracing::error!("Could not load operating secrets: {err}");
                    return Err(MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!("Could not load operating secrets: {err}"),
                    ));
                }
            }
        }

        // ── JWT signing secret ───────────────────────────────────────────
        let jwt_bytes = match secrets.load_jwt_secret().await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return Err(MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "JWT signing secret is missing from the backend (well-known key \
                     'mediator/jwt/secret'). Re-run `mediator-setup` to provision."
                        .into(),
                ));
            }
            Err(err) => {
                return Err(MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Could not load JWT signing secret: {err}"),
                ));
            }
        };

        config.jwt_encoding_key = EncodingKey::from_ed_der(&jwt_bytes);

        let pair = Ed25519KeyPair::from_pkcs8(&jwt_bytes).map_err(|err| {
            tracing::error!("Could not create JWT key pair. {err}");
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Could not create JWT key pair. {err}"),
            )
        })?;
        config.jwt_decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::{CorsOriginPolicy, OriginMatcher, SecurityConfigRaw, origin_matches};
    use http::HeaderValue;

    /// Parse `spec` into a `List` policy and return its matchers, or panic
    /// with the actual variant for a clearer failure than `unwrap`.
    fn matchers(spec: &str) -> Vec<OriginMatcher> {
        match SecurityConfigRaw::parse_cors_origins(spec).unwrap() {
            CorsOriginPolicy::List(m) => m,
            other => panic!("expected List for {spec:?}, got {other:?}"),
        }
    }

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    /// Does `spec`'s allowlist admit request origin `origin`?
    fn allows(spec: &str, origin: &str) -> bool {
        origin_matches(&matchers(spec), &hv(origin))
    }

    #[test]
    fn empty_origins_parse_to_none() {
        assert!(matches!(
            SecurityConfigRaw::parse_cors_origins("").unwrap(),
            CorsOriginPolicy::None
        ));
        // Whitespace / stray commas collapse to nothing.
        assert!(matches!(
            SecurityConfigRaw::parse_cors_origins("  ,  ").unwrap(),
            CorsOriginPolicy::None
        ));
    }

    #[test]
    fn bare_wildcard_parses_to_any() {
        // A literal "*" must NOT reach tower_http's origin list (which
        // panics on it) — it maps to the allow-any policy instead.
        assert!(matches!(
            SecurityConfigRaw::parse_cors_origins("*").unwrap(),
            CorsOriginPolicy::Any
        ));
    }

    #[test]
    fn wildcard_mixed_with_origins_is_any() {
        assert!(matches!(
            SecurityConfigRaw::parse_cors_origins("https://a.example,*").unwrap(),
            CorsOriginPolicy::Any
        ));
    }

    #[test]
    fn explicit_origins_parse_to_list() {
        let origins = matchers("https://a.example, https://b.example");
        assert_eq!(origins.len(), 2);
        assert!(matches!(&origins[0], OriginMatcher::Exact(v) if v == "https://a.example"));
        assert!(matches!(&origins[1], OriginMatcher::Exact(v) if v == "https://b.example"));
    }

    #[test]
    fn exact_origin_matches_byte_for_byte() {
        assert!(allows("https://a.example", "https://a.example"));
        // No normalisation — a trailing slash, differing case in the
        // host, or an extra port are all distinct origins.
        assert!(!allows("https://a.example", "https://a.example/"));
        assert!(!allows("https://a.example", "https://a.example:443"));
        assert!(!allows("https://a.example", "http://a.example"));
    }

    #[test]
    fn wildcard_parses_and_lowercases() {
        let m = matchers("HTTPS://*.Affinidi.COM");
        assert_eq!(m.len(), 1);
        match &m[0] {
            OriginMatcher::WildcardSubdomain {
                scheme,
                suffix,
                port,
            } => {
                assert_eq!(scheme, "https");
                assert_eq!(suffix, "affinidi.com");
                assert_eq!(*port, None);
            }
            other => panic!("expected WildcardSubdomain, got {other:?}"),
        }
    }

    #[test]
    fn wildcard_matches_subdomains_at_any_depth() {
        assert!(allows("https://*.affinidi.com", "https://app.affinidi.com"));
        assert!(allows("https://*.affinidi.com", "https://a.b.affinidi.com"));
        // Case-insensitive host comparison.
        assert!(allows("https://*.affinidi.com", "https://App.Affinidi.Com"));
    }

    #[test]
    fn wildcard_rejects_apex_and_lookalikes() {
        // The boundary dot is mandatory: the apex needs an explicit entry.
        assert!(!allows("https://*.affinidi.com", "https://affinidi.com"));
        // A look-alike registrable domain must not slip through.
        assert!(!allows(
            "https://*.affinidi.com",
            "https://evilaffinidi.com"
        ));
        assert!(!allows(
            "https://*.affinidi.com",
            "https://affinidi.com.evil.com"
        ));
        // An empty leftmost label ("https://.affinidi.com") isn't a
        // sub-domain.
        assert!(!allows("https://*.affinidi.com", "https://.affinidi.com"));
    }

    #[test]
    fn wildcard_requires_exact_scheme_and_port() {
        assert!(!allows("https://*.affinidi.com", "http://app.affinidi.com"));
        // Pattern pins no port → an origin carrying one is rejected.
        assert!(!allows(
            "https://*.affinidi.com",
            "https://app.affinidi.com:8443"
        ));
        // Pattern pins a port → it must match exactly.
        assert!(allows(
            "https://*.affinidi.com:8443",
            "https://app.affinidi.com:8443"
        ));
        assert!(!allows(
            "https://*.affinidi.com:8443",
            "https://app.affinidi.com:8444"
        ));
        assert!(!allows(
            "https://*.affinidi.com:8443",
            "https://app.affinidi.com"
        ));
    }

    #[test]
    fn wildcard_rejects_path_smuggling_in_request_origin() {
        // A malformed Origin that smuggles a path/userinfo must never
        // match — these aren't valid serialised origins.
        assert!(!allows(
            "https://*.affinidi.com",
            "https://app.affinidi.com/../evil.com"
        ));
        assert!(!allows(
            "https://*.affinidi.com",
            "https://evil.com@app.affinidi.com"
        ));
    }

    #[test]
    fn exact_and_wildcard_entries_coexist() {
        let spec = "https://*.affinidi.com, https://affinidi.com";
        assert!(allows(spec, "https://app.affinidi.com")); // wildcard
        assert!(allows(spec, "https://affinidi.com")); // exact apex
        assert!(!allows(spec, "https://other.com"));
    }

    #[test]
    fn invalid_entries_are_rejected_at_parse_time() {
        // Wildcard not in the leftmost-label position.
        assert!(SecurityConfigRaw::parse_cors_origins("https://app.*.com").is_err());
        // More than one wildcard.
        assert!(SecurityConfigRaw::parse_cors_origins("https://*.*.com").is_err());
        // Bad port on a wildcard.
        assert!(SecurityConfigRaw::parse_cors_origins("https://*.affinidi.com:notaport").is_err());
        // Empty suffix.
        assert!(SecurityConfigRaw::parse_cors_origins("https://*.").is_err());
    }
}
