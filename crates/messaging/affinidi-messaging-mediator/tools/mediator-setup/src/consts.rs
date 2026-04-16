/// Deployment type display strings
pub const DEPLOYMENT_LOCAL: &str = "Local development";
pub const DEPLOYMENT_SERVER: &str = "Headless server";
pub const DEPLOYMENT_CONTAINER: &str = "Container";

/// DID method display strings
pub const DID_VTA: &str = "VTA managed";
pub const DID_WEBVH: &str = "did:webvh";
pub const DID_PEER: &str = "did:peer";
pub const DID_IMPORT: &str = "Import existing";

/// Secret storage schemes
pub const STORAGE_STRING: &str = "string://";
pub const STORAGE_FILE: &str = "file://";
pub const STORAGE_KEYRING: &str = "keyring://";
pub const STORAGE_AWS: &str = "aws_secrets://";
pub const STORAGE_GCP: &str = "gcp_secrets://";
pub const STORAGE_AZURE: &str = "azure_keyvault://";
pub const STORAGE_VAULT: &str = "vault://";
pub const STORAGE_VTA: &str = "vta://";

/// SSL mode display strings
pub const SSL_NONE: &str = "No SSL (TLS proxy)";
pub const SSL_EXISTING: &str = "Existing certificates";
pub const SSL_SELF_SIGNED: &str = "Self-signed";

/// Admin DID mode display strings
pub const ADMIN_GENERATE: &str = "Generate did:key";
pub const ADMIN_PASTE: &str = "Paste existing";
pub const ADMIN_VTA: &str = "Copy from VTA";
pub const ADMIN_SKIP: &str = "Skip";

/// VTA connectivity modes
pub const VTA_MODE_ONLINE: &str = "online";
pub const VTA_MODE_COLD_START: &str = "cold-start";

/// Default values
pub const DEFAULT_CONFIG_PATH: &str = "conf/mediator.toml";
pub const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1/";
pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:7037";
