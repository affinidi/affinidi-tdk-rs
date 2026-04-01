use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::acls::{AccessListModeType, MediatorACLSet};
use affinidi_secrets_resolver::ThreadedSecretsResolver;
use vta_sdk::did_secrets::DidSecretsBundle;
use aws_config::SdkConfig;
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
use tower_http::cors::CorsLayer;

use super::helpers::{config_jwt_secret, load_secrets};

/// Security configuration for the mediator
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfigRaw {
    pub mediator_acl_mode: String,
    pub global_acl_default: String,
    pub local_direct_delivery_allowed: String,
    pub local_direct_delivery_allow_anon: String,
    pub mediator_secrets: String,
    pub use_ssl: String,
    pub ssl_certificate_file: Option<String>,
    pub ssl_key_file: Option<String>,
    pub jwt_authorization_secret: String,
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
            cors_allow_origin: CorsLayer::new()
                .allow_headers([AUTHORIZATION, CONTENT_TYPE])
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::OPTIONS,
                    Method::DELETE,
                    Method::PATCH,
                    Method::PUT,
                ]),
            block_anonymous_outer_envelope: true,
            force_session_did_match: true,
            block_remote_admin_msgs: true,
            admin_messages_expiry: 3,
        }
    }
}

impl SecurityConfigRaw {
    fn parse_cors_allow_origin(
        &self,
        cors_allow_origin: &str,
    ) -> Result<Vec<HeaderValue>, MediatorError> {
        cors_allow_origin
            .split(',')
            .map(|o| {
                o.trim().parse::<HeaderValue>().map_err(|err| {
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!("Invalid CORS origin '{}': {}", o.trim(), err),
                    )
                })
            })
            .collect()
    }

    pub(crate) async fn convert(
        &self,
        secrets_resolver: Arc<ThreadedSecretsResolver>,
        aws_config: &SdkConfig,
        vta_bundle: Option<&DidSecretsBundle>,
    ) -> Result<SecurityConfig, MediatorError> {
        let warn_default = |field: &str, value: &str, default: &str| {
            eprintln!(
                "WARN: Could not parse security.{field} value '{value}', using default: {default}"
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

        // Check if conflicting config on anonymous and force session_match
        if !config.block_anonymous_outer_envelope && config.force_session_did_match {
            eprintln!(
                "Conflicting configuration: security.force_session_did_match can not be true when security.block_anonymous_outer_envelope is false"
            );
            return Err(MediatorError::ConfigError(12,
                "NA".into(),
                "Conflicting configuration: security.force_session_did_match can not be true when security.block_anonymous_outer_envelope is false".into(),
            ));
        }

        // Convert the default ACL Set into a GlobalACLSet
        config.global_acl_default = MediatorACLSet::from_string_ruleset(&self.global_acl_default)
            .map_err(|err| {
            eprintln!("Couldn't parse global_acl_default config parameter. Reason: {err}");
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Couldn't parse global_acl_default config parameter. Reason: {err}"),
            )
        })?;

        if let Some(cors_allow_origin) = &self.cors_allow_origin {
            config.cors_allow_origin =
                CorsLayer::new().allow_origin(self.parse_cors_allow_origin(cors_allow_origin)?);
        }

        // Load mediator secrets
        load_secrets(&config.mediator_secrets, &self.mediator_secrets, aws_config, vta_bundle).await?;

        // Create the JWT encoding and decoding keys
        let jwt_secret = config_jwt_secret(&self.jwt_authorization_secret, aws_config).await?;

        config.jwt_encoding_key = EncodingKey::from_ed_der(&jwt_secret);

        let pair = Ed25519KeyPair::from_pkcs8(&jwt_secret).map_err(|err| {
            eprintln!("Could not create JWT key pair. {err}");
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
