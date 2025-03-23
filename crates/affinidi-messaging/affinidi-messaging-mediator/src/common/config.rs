use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient,
    config::{DIDCacheConfig, DIDCacheConfigBuilder},
};
use affinidi_messaging_mediator_common::{
    database::config::{DatabaseConfig, DatabaseConfigRaw},
    errors::MediatorError,
};
use affinidi_messaging_mediator_processors::message_expiry_cleanup::config::{
    MessageExpiryCleanupConfig, MessageExpiryCleanupConfigRaw,
};
use affinidi_messaging_sdk::protocols::mediator::acls::{AccessListModeType, MediatorACLSet};
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};
use ahash::AHashSet as HashSet;
use async_convert::{TryFrom, async_trait};
use aws_config::{self, BehaviorVersion, Region, SdkConfig};
use aws_sdk_secretsmanager;
use aws_sdk_ssm::types::ParameterType;
use base64::prelude::*;
use http::{
    HeaderValue, Method,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use regex::{Captures, Regex};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sha256::digest;
use ssi::dids::{Document, document::service::Endpoint};
use std::{
    collections::HashMap,
    env,
    fmt::{self, Debug},
    fs::File,
    io::{self, BufRead},
    path::Path,
    sync::Arc,
};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use tracing_subscriber::{EnvFilter, filter::LevelFilter};
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_address: String,
    pub api_prefix: String,
    pub admin_did: String,
    pub did_web_self_hosted: Option<String>,
}

/// SecurityConfig Struct contains security related configuration details
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfigRaw {
    pub mediator_acl_mode: String,
    pub global_acl_default: String,
    pub local_direct_delivery_allowed: String,
    pub mediator_secrets: String,
    pub use_ssl: String,
    pub ssl_certificate_file: String,
    pub ssl_key_file: String,
    pub jwt_authorization_secret: String,
    pub jwt_access_expiry: String,
    pub jwt_refresh_expiry: String,
    pub cors_allow_origin: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct SecurityConfig {
    pub mediator_acl_mode: AccessListModeType,
    pub global_acl_default: MediatorACLSet,
    pub local_direct_delivery_allowed: bool,
    #[serde(skip_serializing)]
    pub mediator_secrets: Arc<ThreadedSecretsResolver>,
    pub use_ssl: bool,
    pub ssl_certificate_file: String,
    #[serde(skip_serializing)]
    pub ssl_key_file: String,
    #[serde(skip_serializing)]
    pub jwt_encoding_key: EncodingKey,
    #[serde(skip_serializing)]
    pub jwt_decoding_key: DecodingKey,
    pub jwt_access_expiry: u64,
    pub jwt_refresh_expiry: u64,
    #[serde(skip_serializing)]
    pub cors_allow_origin: CorsLayer,
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
            .field("use_ssl", &self.use_ssl)
            .field("ssl_certificate_file", &self.ssl_certificate_file)
            .field("ssl_key_file", &self.ssl_key_file)
            .field("jwt_encoding_key?", &"<hidden>".to_string())
            .field("jwt_decoding_key?", &"<hidden>".to_string())
            .field("jwt_access_expiry", &self.jwt_access_expiry)
            .field("jwt_refresh_expiry", &self.jwt_refresh_expiry)
            .field("cors_allow_origin", &self.cors_allow_origin)
            .finish()
    }
}

impl SecurityConfig {
    async fn default() -> Self {
        SecurityConfig {
            mediator_acl_mode: AccessListModeType::ExplicitDeny,
            global_acl_default: MediatorACLSet::default(),
            local_direct_delivery_allowed: false,
            mediator_secrets: Arc::new(ThreadedSecretsResolver::new(None).await.0),
            use_ssl: true,
            ssl_certificate_file: "".into(),
            ssl_key_file: "".into(),
            jwt_encoding_key: EncodingKey::from_ed_der(&[0; 32]),
            jwt_decoding_key: DecodingKey::from_ed_der(&[0; 32]),
            jwt_access_expiry: 900,
            jwt_refresh_expiry: 86_400,
            cors_allow_origin: CorsLayer::new()
                .allow_origin(Any)
                .allow_headers([AUTHORIZATION, CONTENT_TYPE])
                //.allow_credentials(true)
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::OPTIONS,
                    Method::DELETE,
                    Method::PATCH,
                    Method::PUT,
                ]),
        }
    }
}

impl SecurityConfigRaw {
    fn parse_cors_allow_origin(
        &self,
        cors_allow_origin: &str,
    ) -> Result<Vec<HeaderValue>, MediatorError> {
        let origins: Vec<HeaderValue> = cors_allow_origin
            .split(',')
            .map(|o| o.parse::<HeaderValue>().unwrap())
            .collect();

        Ok(origins)
    }

    async fn convert(&self, aws_config: &SdkConfig) -> Result<SecurityConfig, MediatorError> {
        let mut config = SecurityConfig {
            mediator_acl_mode: match self.mediator_acl_mode.as_str() {
                "explicit_allow" => AccessListModeType::ExplicitAllow,
                "explicit_deny" => AccessListModeType::ExplicitDeny,
                _ => AccessListModeType::ExplicitDeny,
            },
            local_direct_delivery_allowed: self
                .local_direct_delivery_allowed
                .parse()
                .unwrap_or(false),
            use_ssl: self.use_ssl.parse().unwrap_or(true),
            ssl_certificate_file: self.ssl_certificate_file.clone(),
            ssl_key_file: self.ssl_key_file.clone(),
            jwt_access_expiry: self.jwt_access_expiry.parse().unwrap_or(900),
            jwt_refresh_expiry: self.jwt_refresh_expiry.parse().unwrap_or(86_400),
            ..SecurityConfig::default().await
        };

        // Convert the default ACL Set into a GlobalACLSet
        config.global_acl_default = MediatorACLSet::from_string_ruleset(&self.global_acl_default)
            .map_err(|err| {
            eprintln!(
                "Couldn't parse global_acl_default config parameter. Reason: {}",
                err
            );
            MediatorError::ConfigError(
                "NA".into(),
                format!(
                    "Couldn't parse global_acl_default config parameter. Reason: {}",
                    err
                ),
            )
        })?;

        if let Some(cors_allow_origin) = &self.cors_allow_origin {
            config.cors_allow_origin =
                CorsLayer::new().allow_origin(self.parse_cors_allow_origin(cors_allow_origin)?);
        }

        // Load mediator secrets
        config.mediator_secrets = Arc::new(load_secrets(&self.mediator_secrets, aws_config).await?);

        // Create the JWT encoding and decoding keys
        let jwt_secret = config_jwt_secret(&self.jwt_authorization_secret, aws_config).await?;

        config.jwt_encoding_key = EncodingKey::from_ed_der(&jwt_secret);

        let pair = Ed25519KeyPair::from_pkcs8(&jwt_secret).map_err(|err| {
            eprintln!("Could not create JWT key pair. {}", err);
            MediatorError::ConfigError(
                "NA".into(),
                format!("Could not create JWT key pair. {}", err),
            )
        })?;
        config.jwt_decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());

        Ok(config)
    }
}

/// StreamingConfig Struct contains live streaming related configuration details
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamingConfig {
    pub enabled: String,
    pub uuid: String,
}

/// DIDResolverConfig Struct contains live streaming related configuration details
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DIDResolverConfig {
    pub address: Option<String>,
    pub cache_capacity: String,
    pub cache_ttl: String,
    pub network_timeout: String,
    pub network_limit: String,
}

/// LimitsConfig Struct contains limits used by Affinidi Messenger
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimitsConfig {
    pub attachments_max_count: usize,
    pub crypto_operations_per_message: usize,
    pub deleted_messages: usize,
    pub forward_task_queue: usize,
    pub http_size: usize,
    pub listed_messages: usize,
    pub local_max_acl: usize,
    pub message_expiry_seconds: u64,
    pub message_size: usize,
    pub queued_send_messages_soft: i32,
    pub queued_send_messages_hard: i32,
    pub queued_receive_messages_soft: i32,
    pub queued_receive_messages_hard: i32,
    pub to_keys_per_recipient: usize,
    pub to_recipients: usize,
    pub ws_size: usize,
    pub access_list_limit: usize,
    pub oob_invite_ttl: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            attachments_max_count: 20,
            crypto_operations_per_message: 1000,
            deleted_messages: 100,
            forward_task_queue: 50_000,
            http_size: 10_485_760,
            listed_messages: 100,
            local_max_acl: 1_000,
            message_expiry_seconds: 604_800,
            message_size: 1_048_576,
            queued_send_messages_soft: 200,
            queued_send_messages_hard: 1_000,
            queued_receive_messages_soft: 200,
            queued_receive_messages_hard: 1_000,
            to_keys_per_recipient: 100,
            to_recipients: 100,
            ws_size: 10_485_760,
            access_list_limit: 1_000,
            oob_invite_ttl: 86_400,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LimitsConfigRaw {
    pub attachments_max_count: String,
    pub crypto_operations_per_message: String,
    pub deleted_messages: String,
    pub forward_task_queue: String,
    pub http_size: String,
    pub listed_messages: String,
    pub local_max_acl: String,
    pub message_expiry_seconds: String,
    pub message_size: String,
    pub queued_send_messages_soft: String,
    pub queued_send_messages_hard: String,
    pub queued_receive_messages_soft: String,
    pub queued_receive_messages_hard: String,
    pub to_keys_per_recipient: String,
    pub to_recipients: String,
    pub ws_size: String,
    pub access_list_limit: String,
    pub oob_invite_ttl: String,
}

impl std::convert::TryFrom<LimitsConfigRaw> for LimitsConfig {
    type Error = MediatorError;

    fn try_from(raw: LimitsConfigRaw) -> Result<Self, Self::Error> {
        Ok(LimitsConfig {
            attachments_max_count: raw.attachments_max_count.parse().unwrap_or(20),
            crypto_operations_per_message: raw
                .crypto_operations_per_message
                .parse()
                .unwrap_or(1000),
            deleted_messages: raw.deleted_messages.parse().unwrap_or(100),
            forward_task_queue: raw.forward_task_queue.parse().unwrap_or(50_000),
            http_size: raw.http_size.parse().unwrap_or(10_485_760),
            listed_messages: raw.listed_messages.parse().unwrap_or(100),
            local_max_acl: raw.local_max_acl.parse().unwrap_or(1_000),
            message_expiry_seconds: raw.message_expiry_seconds.parse().unwrap_or(10_080),
            message_size: raw.message_size.parse().unwrap_or(1_048_576),
            queued_send_messages_soft: raw.queued_send_messages_soft.parse().unwrap_or(100),
            queued_send_messages_hard: raw.queued_send_messages_hard.parse().unwrap_or(1_000),
            queued_receive_messages_soft: raw.queued_receive_messages_soft.parse().unwrap_or(100),
            queued_receive_messages_hard: raw.queued_receive_messages_hard.parse().unwrap_or(1_000),
            to_keys_per_recipient: raw.to_keys_per_recipient.parse().unwrap_or(100),
            to_recipients: raw.to_recipients.parse().unwrap_or(100),
            ws_size: raw.ws_size.parse().unwrap_or(10_485_760),
            access_list_limit: raw.access_list_limit.parse().unwrap_or(1_000),
            oob_invite_ttl: raw.oob_invite_ttl.parse().unwrap_or(86_400),
        })
    }
}

/// ProcessorsConfig Struct contains configuration specific to different processors
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessorsConfig {
    pub forwarding: ForwardingConfig,
    pub message_expiry_cleanup: MessageExpiryCleanupConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProcessorsConfigRaw {
    pub forwarding: ForwardingConfigRaw,
    pub message_expiry_cleanup: MessageExpiryCleanupConfigRaw,
}

/// ForwardingConfig Struct contains configuration specific to DIDComm Routing/Forwarding
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardingConfig {
    pub enabled: bool,
    pub future_time_limit: u64,
    pub external_forwarding: bool,
    pub report_errors: bool,
    pub blocked_forwarding: HashSet<String>,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        ForwardingConfig {
            enabled: true,
            future_time_limit: 86400,
            external_forwarding: true,
            report_errors: true,
            blocked_forwarding: HashSet::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ForwardingConfigRaw {
    pub enabled: String,
    pub future_time_limit: String,
    pub external_forwarding: String,
    pub report_errors: String,
    pub blocked_forwarding_dids: String,
}

impl std::convert::TryFrom<ForwardingConfigRaw> for ForwardingConfig {
    type Error = MediatorError;

    fn try_from(raw: ForwardingConfigRaw) -> Result<Self, Self::Error> {
        Ok(ForwardingConfig {
            enabled: raw.enabled.parse().unwrap_or(true),
            future_time_limit: raw.future_time_limit.parse().unwrap_or(86400),
            external_forwarding: raw.external_forwarding.parse().unwrap_or(true),
            report_errors: raw.report_errors.parse().unwrap_or(true),
            blocked_forwarding: HashSet::new(),
        })
    }
}

impl DIDResolverConfig {
    pub fn convert(&self) -> DIDCacheConfig {
        let mut config = DIDCacheConfigBuilder::default()
            .with_cache_capacity(self.cache_capacity.parse().unwrap_or(1000))
            .with_cache_ttl(self.cache_ttl.parse().unwrap_or(300))
            .with_network_timeout(self.network_timeout.parse().unwrap_or(5))
            .with_network_cache_limit_count(self.network_limit.parse().unwrap_or(100));

        if let Some(address) = &self.address {
            config = config.with_network_mode(address);
        }

        config.build()
    }
}

/// ConfigRaw Struct is used to deserialize the configuration file
/// We then convert this to the Config Struct
#[derive(Debug, Serialize, Deserialize)]
struct ConfigRaw {
    pub log_level: String,
    pub log_json: String,
    pub mediator_did: String,
    pub server: ServerConfig,
    pub database: DatabaseConfigRaw,
    pub security: SecurityConfigRaw,
    pub streaming: StreamingConfig,
    pub did_resolver: DIDResolverConfig,
    pub limits: LimitsConfigRaw,
    pub processors: ProcessorsConfigRaw,
}

#[derive(Clone, Serialize)]
pub struct Config {
    #[serde(skip_serializing)]
    pub log_level: LevelFilter,
    #[serde(skip_serializing)]
    pub log_json: bool,
    pub listen_address: String,
    pub mediator_did: String,
    pub mediator_did_hash: String,
    pub mediator_did_doc: Option<Document>,
    pub admin_did: String,
    pub api_prefix: String,
    pub streaming_enabled: bool,
    pub streaming_uuid: String,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    #[serde(skip_serializing)]
    pub did_resolver_config: DIDCacheConfig,
    pub processors: ProcessorsConfig,
    pub limits: LimitsConfig,
    pub tags: HashMap<String, String>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("log_level", &self.log_level)
            .field("log_json", &self.log_json)
            .field("listen_address", &self.listen_address)
            .field("mediator_did", &self.mediator_did)
            .field("mediator_did_hash", &self.mediator_did_hash)
            .field("admin_did", &self.admin_did)
            .field("mediator_did_doc", &"Hidden")
            .field("database", &self.database)
            .field("streaming_enabled?", &self.streaming_enabled)
            .field("streaming_uuid", &self.streaming_uuid)
            .field("DID Resolver config", &self.did_resolver_config)
            .field("api_prefix", &self.api_prefix)
            .field("security", &self.security)
            .field("processors", &self.processors)
            .field("Limits", &self.limits)
            .field("tags", &self.tags)
            .finish()
    }
}

impl Config {
    async fn default() -> Self {
        let did_resolver_config = DIDCacheConfigBuilder::default()
            .with_cache_capacity(1000)
            .with_cache_ttl(300)
            .with_network_timeout(5)
            .with_network_cache_limit_count(100)
            .build();

        Config {
            log_level: LevelFilter::INFO,
            log_json: true,
            listen_address: "".into(),
            mediator_did: "".into(),
            mediator_did_hash: "".into(),
            mediator_did_doc: None,
            admin_did: "".into(),
            database: DatabaseConfig::default(),
            streaming_enabled: true,
            streaming_uuid: "".into(),
            did_resolver_config,
            api_prefix: "/mediator/v1/".into(),
            security: SecurityConfig::default().await,
            processors: ProcessorsConfig {
                forwarding: ForwardingConfig::default(),
                message_expiry_cleanup: MessageExpiryCleanupConfig::default(),
            },
            limits: LimitsConfig::default(),
            tags: HashMap::from([("app".to_string(), "mediator".to_string())]),
        }
    }
}

#[async_trait]
impl TryFrom<ConfigRaw> for Config {
    type Error = MediatorError;

    async fn try_from(raw: ConfigRaw) -> Result<Self, Self::Error> {
        // Set up AWS Configuration
        let region = match env::var("AWS_REGION") {
            Ok(region) => Region::new(region),
            Err(_) => Region::new("ap-southeast-1"),
        };
        let aws_config = aws_config::defaults(BehaviorVersion::v2025_01_17())
            .region(region)
            .load()
            .await;
        let mut tags = HashMap::from([("app".to_string(), "mediator".to_string())]);
        for (key, value) in env::vars() {
            if key.get(..13) == Some("MEDIATOR_TAG_") {
                tags.insert(key.get(13..).unwrap().to_lowercase(), value);
            }
        }

        let mut config = Config {
            log_level: match raw.log_level.as_str() {
                "trace" => LevelFilter::TRACE,
                "debug" => LevelFilter::DEBUG,
                "info" => LevelFilter::INFO,
                "warn" => LevelFilter::WARN,
                "error" => LevelFilter::ERROR,
                _ => LevelFilter::INFO,
            },
            log_json: raw.log_json.parse().unwrap_or(true),
            listen_address: raw.server.listen_address,
            mediator_did: read_did_config(&raw.mediator_did, &aws_config, "mediator_did").await?,
            admin_did: read_did_config(&raw.server.admin_did, &aws_config, "admin_did").await?,
            database: raw.database.try_into()?,
            streaming_enabled: raw.streaming.enabled.parse().unwrap_or(true),
            did_resolver_config: raw.did_resolver.convert(),
            api_prefix: raw.server.api_prefix,
            security: raw.security.convert(&aws_config).await?,
            processors: ProcessorsConfig {
                forwarding: raw.processors.forwarding.clone().try_into()?,
                message_expiry_cleanup: raw.processors.message_expiry_cleanup.clone().try_into()?,
            },
            limits: raw.limits.try_into()?,
            tags,
            ..Config::default().await
        };

        config.mediator_did_hash = digest(&config.mediator_did);

        // Are we self-hosting our own did:web Document?
        if let Some(path) = raw.server.did_web_self_hosted {
            let content = read_document(&path, &aws_config).await?;
            let doc: Document = serde_json::from_str(&content).map_err(|err| {
                eprintln!("Could not parse DID Document. Reason: {}", err);
                MediatorError::ConfigError(
                    "NA".into(),
                    format!("Could not parse DID Document. Reason: {}", err),
                )
            })?;
            config.mediator_did_doc = Some(doc);
        }

        // Ensure that the security JWT expiry times are valid
        if config.security.jwt_access_expiry >= config.security.jwt_refresh_expiry {
            eprintln!(
                "JWT Access expiry ({}) must be less than JWT Refresh expiry ({})",
                config.security.jwt_access_expiry, config.security.jwt_refresh_expiry
            );
            return Err(MediatorError::ConfigError(
                "NA".into(),
                "JWT Access expiry must be less than JWT Refresh expiry".into(),
            ));
        }

        // Get Subscriber unique hostname
        if config.streaming_enabled {
            config.streaming_uuid = get_hostname(&raw.streaming.uuid)?;
        }

        // Fill out the forwarding protection for DIDs and associated service endpoints
        // This protects against the mediator forwarding messages to itself.
        let mut did_resolver = DIDCacheClient::new(config.did_resolver_config.clone())
            .await
            .map_err(|err| {
                MediatorError::DIDError(
                    "NA".into(),
                    "NA".into(),
                    format!("Couldn't start DID Resolver: {}", err),
                )
            })?;

        // Load the Local DID Document if self hosted
        if let Some(mediator_doc) = &config.mediator_did_doc {
            did_resolver
                .add_did_document(&config.mediator_did, mediator_doc.clone())
                .await;
        }

        load_forwarding_protection_blocks(
            &did_resolver,
            &mut config.processors.forwarding,
            &config.mediator_did,
            &raw.processors.forwarding.blocked_forwarding_dids,
        )
        .await?;

        Ok(config)
    }
}

/// Loads the secret data into the Config file.
async fn load_secrets(
    secrets: &str,
    aws_config: &SdkConfig,
) -> Result<ThreadedSecretsResolver, MediatorError> {
    let parts: Vec<&str> = secrets.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            "NA".into(),
            "Invalid `mediator_secrets` format".into(),
        ));
    }
    println!("Loading secrets method({}) path({})", parts[0], parts[1]);
    let content: String = match parts[0] {
        "file" => read_file_lines(parts[1])?.concat(),
        "aws_secrets" => {
            let asm = aws_sdk_secretsmanager::Client::new(aws_config);

            let response = asm
                .get_secret_value()
                .secret_id(parts[1])
                .send()
                .await
                .map_err(|e| {
                    eprintln!("Could not get secret value. {}", e);
                    MediatorError::ConfigError(
                        "NA".into(),
                        format!("Could not get secret value. {}", e),
                    )
                })?;
            response.secret_string.ok_or_else(|| {
                eprintln!("No secret string found in response");
                MediatorError::ConfigError("NA".into(), "No secret string found in response".into())
            })?
        }
        _ => {
            return Err(MediatorError::ConfigError(
                "NA".into(),
                "Invalid `mediator_secrets` format! Expecting file:// or aws_secrets:// ...".into(),
            ));
        }
    };

    let (secrets_resolver, _) = ThreadedSecretsResolver::new(None).await;
    let secrets: Vec<Secret> = serde_json::from_str(&content).map_err(|err| {
        eprintln!("Could not parse `mediator_secrets` JSON content. {}", err);
        MediatorError::ConfigError(
            "NA".into(),
            format!("Could not parse `mediator_secrets` JSON content. {}", err),
        )
    })?;

    info!(
        "Loading {} mediatior Secret{}",
        secrets.len(),
        if secrets.is_empty() { "" } else { "s" }
    );
    secrets_resolver.insert_vec(&secrets).await;

    Ok(secrets_resolver)
}

/// Read the primary configuration file for the mediator
/// Returns a ConfigRaw struct, that still needs to be processed for additional information
/// and conversion to Config struct
fn read_config_file(file_name: &str) -> Result<ConfigRaw, MediatorError> {
    // Read configuration file parameters
    println!("Config file({})", file_name);
    let raw_config = read_file_lines(file_name)?;

    let config_with_vars = expand_env_vars(&raw_config)?;
    match toml::from_str(&config_with_vars.join("\n")) {
        Ok(config) => Ok(config),
        Err(err) => {
            eprintln!("Could not parse configuration settings. {:?}", err);
            Err(MediatorError::ConfigError(
                "NA".into(),
                format!("Could not parse configuration settings. Reason: {:?}", err),
            ))
        }
    }
}

/// Reads a file and returns a vector of strings, one for each line in the file.
/// It also strips any lines starting with a # (comments)
/// You can join the Vec back into a single string with `.join("\n")`
/// ```ignore
/// let lines = read_file_lines("file.txt")?;
/// let file_contents = lines.join("\n");
/// ```
fn read_file_lines<P>(file_name: P) -> Result<Vec<String>, MediatorError>
where
    P: AsRef<Path>,
{
    let file = File::open(file_name.as_ref()).map_err(|err| {
        eprintln!(
            "Could not open file({}). {}",
            file_name.as_ref().display(),
            err
        );
        MediatorError::ConfigError(
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
        // Strip comments out
        if !line.starts_with('#') {
            lines.push(line);
        }
    }

    Ok(lines)
}

/// Replaces all strings ${VAR_NAME:default_value}
/// with the corresponding environment variables (e.g. value of ${VAR_NAME})
/// or with `default_value` if the variable is not defined.
fn expand_env_vars(raw_config: &Vec<String>) -> Result<Vec<String>, MediatorError> {
    let re = Regex::new(r"\$\{(?P<env_var>[A-Z_]{1,}[0-9A-Z_]*):(?P<default_value>.*)\}").map_err(
        |e| {
            MediatorError::ConfigError(
                "NA".into(),
                format!("Couldn't create ENV Regex. Reason: {}", e),
            )
        },
    )?;
    let mut result: Vec<String> = Vec::new();
    for line in raw_config {
        result.push(
            re.replace_all(line, |caps: &Captures| match env::var(&caps["env_var"]) {
                Ok(val) => val,
                Err(_) => (caps["default_value"]).into(),
            })
            .into_owned(),
        );
    }
    Ok(result)
}

/// Converts the mediator_did config to a valid DID depending on source
async fn read_did_config(
    did_config: &str,
    aws_config: &SdkConfig,
    field_name: &str,
) -> Result<String, MediatorError> {
    let parts: Vec<&str> = did_config.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            "NA".into(),
            format!("Invalid `{}` format", field_name),
        ));
    }
    let content: String = match parts[0] {
        "did" => parts[1].to_string(),
        "aws_parameter_store" => aws_parameter_store(parts[1], aws_config).await?,
        _ => {
            return Err(MediatorError::ConfigError(
                "NA".into(),
                "Invalid mediator_did format! Expecting file:// or aws_parameter_store:// ..."
                    .into(),
            ));
        }
    };

    Ok(content)
}

/// Converts the jwt_authorization_secret config to a valid JWT secret
/// Can take a basic string, or fetch from AWS Secrets Manager
async fn config_jwt_secret(
    jwt_secret: &str,
    aws_config: &SdkConfig,
) -> Result<Vec<u8>, MediatorError> {
    let parts: Vec<&str> = jwt_secret.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            "NA".into(),
            "Invalid `jwt_authorization_secret` format".into(),
        ));
    }
    let content: String = match parts[0] {
        "string" => parts[1].to_string(),
        "aws_secrets" => {
            println!("Loading JWT secret from AWS Secrets Manager");
            let asm = aws_sdk_secretsmanager::Client::new(aws_config);

            let response = asm
                .get_secret_value()
                .secret_id(parts[1])
                .send()
                .await
                .map_err(|e| {
                    eprintln!("Could not get secret value. {}", e);
                    MediatorError::ConfigError(
                        "NA".into(),
                        format!("Could not get secret value. {}", e),
                    )
                })?;
            response.secret_string.ok_or_else(|| {
                eprintln!("No secret string found in response");
                MediatorError::ConfigError("NA".into(), "No secret string found in response".into())
            })?
        }
        _ => return Err(MediatorError::ConfigError(
            "NA".into(),
            "Invalid `jwt_authorization_secret` format! Expecting string:// or aws_secrets:// ..."
                .into(),
        )),
    };

    BASE64_URL_SAFE_NO_PAD.decode(content).map_err(|err| {
        eprintln!("Could not create JWT key pair. {}", err);
        MediatorError::ConfigError(
            "NA".into(),
            format!("Could not create JWT key pair. {}", err),
        )
    })
}

fn get_hostname(host_name: &str) -> Result<String, MediatorError> {
    if host_name.starts_with("hostname://") {
        Ok(hostname::get()
            .map_err(|e| {
                MediatorError::ConfigError(
                    "NA".into(),
                    format!("Couldn't get hostname. Reason: {}", e),
                )
            })?
            .into_string()
            .map_err(|e| {
                MediatorError::ConfigError(
                    "NA".into(),
                    format!("Couldn't get hostname. Reason: {:?}", e),
                )
            })?)
    } else if host_name.starts_with("string://") {
        Ok(host_name.split_at(9).1.to_string())
    } else {
        Err(MediatorError::ConfigError(
            "NA".into(),
            "Invalid hostname format!".into(),
        ))
    }
}

async fn aws_parameter_store(
    parameter_name: &str,
    aws_config: &SdkConfig,
) -> Result<String, MediatorError> {
    let ssm = aws_sdk_ssm::Client::new(aws_config);

    let response = ssm
        .get_parameter()
        // .set_name(Some(parts[1].to_string()))
        .set_name(Some(parameter_name.to_string()))
        .send()
        .await
        .map_err(|e| {
            eprintln!("Could not get ({:?}) parameter. {}", parameter_name, e);
            MediatorError::ConfigError(
                "NA".into(),
                format!("Could not get ({:?}) parameter. {}", parameter_name, e),
            )
        })?;
    let parameter = response.parameter.ok_or_else(|| {
        eprintln!("No parameter string found in response");
        MediatorError::ConfigError("NA".into(), "No parameter string found in response".into())
    })?;

    if let Some(_type) = parameter.r#type {
        if _type != ParameterType::String {
            return Err(MediatorError::ConfigError(
                "NA".into(),
                "Expected String parameter type".into(),
            ));
        }
    } else {
        return Err(MediatorError::ConfigError(
            "NA".into(),
            "Unknown parameter type".into(),
        ));
    }

    parameter.value.ok_or_else(|| {
        eprintln!(
            "Parameter ({:?}) found, but no parameter value found in response",
            parameter.name
        );
        MediatorError::ConfigError(
            "NA".into(),
            format!(
                "Parameter ({:?}) found, but no parameter value found in response",
                parameter.name
            ),
        )
    })
}

/// Reads document from file or aws_parameter_store
async fn read_document(
    document_path: &str,
    aws_config: &SdkConfig,
) -> Result<String, MediatorError> {
    let parts: Vec<&str> = document_path.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            "NA".into(),
            "Invalid `document_path` format".into(),
        ));
    }
    let content: String = match parts[0] {
        "file" => read_file_lines(parts[1])?.concat(),
        "aws_parameter_store" => aws_parameter_store(parts[1], aws_config).await?,
        _ => {
            return Err(MediatorError::ConfigError(
                "NA".into(),
                "Invalid document_path format! Expecting file:// or aws_parameter_store:// ..."
                    .into(),
            ));
        }
    };

    Ok(content)
}

/// Creates a set of URI's that can be used to detect if forwarding loopbacks to the mediator could occur
async fn load_forwarding_protection_blocks(
    did_resolver: &DIDCacheClient,
    forwarding_config: &mut ForwardingConfig,
    mediator_did: &str,
    blocked_dids: &str,
) -> Result<(), MediatorError> {
    let mut blocked_dids: Vec<String> = match serde_json::from_str(blocked_dids) {
        Ok(dids) => dids,
        Err(err) => {
            eprintln!("Could not parse blocked_forwarding_dids. Reason: {}", err);
            return Err(MediatorError::ConfigError(
                "NA".into(),
                format!("Could not parse blocked_forwarding_dids. Reason: {}", err),
            ));
        }
    };

    // Add the mediator DID to the blocked list
    blocked_dids.push(mediator_did.into());

    // Iterate through each DID that we need to block
    for did in blocked_dids {
        let doc = did_resolver.resolve(&did).await.map_err(|err| {
            MediatorError::DIDError(
                "NA".into(),
                did.clone(),
                format!("Couldn't resolve DID. Reason: {}", err),
            )
        })?;

        forwarding_config.blocked_forwarding.insert(did.clone());

        // Add the service endpoints to the forwarding protection list
        for service in doc.doc.service.iter() {
            if let Some(endpoints) = &service.service_endpoint {
                for endpoint in endpoints {
                    match endpoint {
                        Endpoint::Uri(uri) => {
                            forwarding_config.blocked_forwarding.insert(uri.to_string());
                        }
                        Endpoint::Map(map) => {
                            if let Some(uri) = map.get("uri") {
                                if let Some(uri) = uri.as_str() {
                                    forwarding_config.blocked_forwarding.insert(uri.into());
                                } else {
                                    eprintln!("WARN: Couldn't parse URI as a string: {:#?}", uri);
                                }
                            } else {
                                eprintln!(
                                    "WARN: Service endpoint map does not contain a URI. DID ({}), Service ({:#?}), Endpoint ({:#?})",
                                    did, service, map
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn init(config_file: &str, with_ansi: bool) -> Result<Config, MediatorError> {
    // Read configuration file parameters
    let config = read_config_file(config_file)?;

    // setup logging/tracing framework
    let filter = if env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(config.log_level.as_str())
    };

    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .compact()
        // Display source code file paths
        .with_file(false)
        // Display source code line numbers
        .with_line_number(false)
        // Display the thread ID an event was recorded on
        .with_thread_ids(false)
        // Don't display the event's target (module path)
        .with_target(true)
        .with_ansi(with_ansi)
        .with_env_filter(filter);

    println!("Switching to tracing subscriber for all logging...");
    if config.log_json.parse().unwrap_or(true) {
        let subscriber = subscriber
            .json()
            // Build the subscriber
            .finish();
        tracing::subscriber::set_global_default(subscriber).map_err(|e| {
            MediatorError::ConfigError("NA".into(), format!("Couldn't setup logging: {}", e))
        })?;
    } else {
        let subscriber = subscriber.finish();
        tracing::subscriber::set_global_default(subscriber).map_err(|e| {
            MediatorError::ConfigError("NA".into(), format!("Couldn't setup logging: {}", e))
        })?;
    }

    match <Config as async_convert::TryFrom<ConfigRaw>>::try_from(config).await {
        Ok(config) => {
            info!("Configuration settings parsed successfully.\n{:#?}", config);
            Ok(config)
        }
        Err(err) => Err(err),
    }
}
