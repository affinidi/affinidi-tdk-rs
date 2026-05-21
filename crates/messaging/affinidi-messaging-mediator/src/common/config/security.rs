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
    /// An explicit allowlist of scheme-qualified origins.
    List(Vec<HeaderValue>),
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
        CorsOriginPolicy::List(origins) => base.allow_origin(origins.clone()),
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
    /// - a `*` token ⇒ [`CorsOriginPolicy::Any`] (a bare wildcard;
    ///   `tower_http`'s origin list would otherwise *panic* on `*`).
    ///   If `*` is mixed with explicit origins the explicit entries are
    ///   redundant and a warning is logged.
    /// - otherwise ⇒ [`CorsOriginPolicy::List`] of the explicit origins.
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

        let origins = tokens
            .iter()
            .map(|o| {
                o.parse::<HeaderValue>().map_err(|err| {
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!("Invalid CORS origin '{o}': {err}"),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CorsOriginPolicy::List(origins))
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
    use super::{CorsOriginPolicy, SecurityConfigRaw};

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
        let policy =
            SecurityConfigRaw::parse_cors_origins("https://a.example, https://b.example").unwrap();
        match policy {
            CorsOriginPolicy::List(origins) => {
                assert_eq!(origins.len(), 2);
                assert_eq!(origins[0], "https://a.example");
                assert_eq!(origins[1], "https://b.example");
            }
            other => panic!("expected List, got {other:?}"),
        }
    }
}
