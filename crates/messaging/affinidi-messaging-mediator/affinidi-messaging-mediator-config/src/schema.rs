//! Top-level raw config schema (`[server]`, `[streaming]`, `[did_resolver]`,
//! `[secrets]`, `[storage]`, and the `ConfigRaw` root).

use serde::{Deserialize, Serialize};

use crate::{LimitsConfigRaw, ProcessorsConfigRaw, SecurityConfigRaw};

/// `[database]` section schema (raw, all-strings TOML form).
///
/// Defined here rather than imported from mediator-common: that crate gates its
/// `database` module behind the `server` feature, so importing `DatabaseConfigRaw`
/// would force this lean schema crate to depend on a build of mediator-common
/// that exposes `database` without `server` — a publish-ordering hazard (the
/// published mediator-common keeps `database` gated). The raw DB config is config
/// schema, so it lives here; the resolved `DatabaseConfig` (with circuit-breaker
/// tuning, used by the runtime `DatabaseHandler`) stays in mediator-common, and
/// the mediator converts between them.
#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseConfigRaw {
    pub functions_file: String,
    pub database_url: String,
    pub database_timeout: String,
    pub scripts_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_address: String,
    pub api_prefix: String,
    pub admin_did: String,
    pub did_web_self_hosted: Option<String>,
    /// Additional URL aliases the mediator should treat as
    /// pointing at *itself* when resolving a routing-2.0 next-hop.
    /// Each entry is a full URL (e.g. `"https://mediator.example.com"`);
    /// host + port are extracted and compared against the next-hop's
    /// service endpoint. `listen_address` is automatically included,
    /// so this is only needed when the mediator is reachable via
    /// hostnames or ports that differ from its bind address (e.g.,
    /// behind a load balancer or reverse proxy).
    #[serde(default)]
    pub local_endpoints: Vec<String>,
}

/// Live streaming configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamingConfig {
    pub enabled: String,
    pub uuid: String,
}

/// DID resolver configuration.
///
/// The conversion to the runtime `DIDCacheConfig` lives in the mediator
/// (`crate::common::config::did_resolver_cache_config`) so this crate stays
/// free of the DID-resolver SDK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DIDResolverConfig {
    pub address: Option<String>,
    pub cache_capacity: String,
    pub cache_ttl: String,
    pub network_timeout: String,
    pub network_limit: String,
}

/// `[secrets]` config section — the unified secret-storage backend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretsConfigRaw {
    /// Backend URL. Examples: `keyring://affinidi-mediator`,
    /// `file:///var/lib/mediator/secrets.json`,
    /// `aws_secrets://us-east-1/prod/mediator/`.
    pub backend: String,
    /// Maximum age for the cached VTA bundle (humantime format, e.g.
    /// `"30d"` or `"12h"`). `None` or `"0"` means no expiry. Defaults to
    /// 30 days when unset.
    #[serde(default)]
    pub cache_ttl: Option<String>,
}

/// Raw configuration deserialized from the TOML file, converted to the runtime
/// `Config` in the mediator binary.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigRaw {
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
    /// Unified secret backend — required whenever the mediator has any
    /// persistent identity (which is effectively always).
    pub secrets: SecretsConfigRaw,
    /// Optional storage backend selector. Absent → Redis (legacy
    /// behaviour, uses `[database]`). Present with `backend = "fjall"`
    /// → embedded Fjall at `data_dir`, `[database]` is ignored.
    #[serde(default)]
    pub storage: Option<StorageConfig>,
}

/// `[storage]` section — selects the mediator's storage backend.
/// Mirrors the wizard recipe shape so a `mediator.toml` produced by
/// the wizard parses unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    /// `"redis"` (default) or `"fjall"`. Memory backend is not
    /// exposed here — it's a tests-only backend.
    pub backend: String,
    /// On-disk path for the Fjall data directory. Required when
    /// `backend = "fjall"`. The mediator creates this directory if
    /// it doesn't exist.
    #[serde(default)]
    pub data_dir: Option<String>,
    /// `[storage.fjall]` — memory tuning for the embedded Fjall backend.
    /// Ignored when `backend = "redis"`: Redis holds its data in the Redis
    /// *server*, so its memory is governed by `maxmemory` in `redis.conf`,
    /// not by anything the mediator can set. See the memory-tuning guide.
    #[serde(default)]
    pub fjall: Option<FjallConfig>,
}

/// `[storage.fjall]` — memory knobs for the embedded Fjall backend.
///
/// Fjall ships with defaults sized for a general-purpose embedded database
/// (32 MiB block cache, 64 MiB of memtable *per keyspace*, 512 MiB of journal).
/// The mediator opens 14 keyspaces, so the stock per-keyspace memtable default
/// alone allows ~896 MiB of write buffer. These knobs bring that down to a
/// budget the operator chooses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FjallConfig {
    /// Block cache, in bytes. Caches decompressed data blocks read from disk;
    /// this is the read-side memory and the first thing to raise for read
    /// throughput. Default 16 MiB (Fjall's own default is 32 MiB).
    #[serde(default = "default_fjall_block_cache")]
    pub block_cache: String,
    /// Total write-buffer (memtable) budget in bytes, divided across the
    /// mediator's keyspaces by write weight. Default 32 MiB.
    ///
    /// **Applies at data-directory creation only.** Fjall persists each
    /// keyspace's memtable size when the keyspace is first created and has no
    /// runtime setter, so changing this against an existing `data_dir` has no
    /// effect on already-created keyspaces. `max_journal` (below) bounds
    /// unflushed memory on existing directories.
    #[serde(default = "default_fjall_write_buffer")]
    pub write_buffer: String,
    /// Journal size ceiling in bytes. Default 128 MiB (Fjall's default is
    /// 512 MiB).
    ///
    /// This is the load-bearing global bound. Fjall's own global write-buffer
    /// cap (`max_write_buffer_size`) is a dead field in 3.1.x — declared, with a
    /// setter, but never read — so there is *no* global memtable ceiling. What
    /// does exist: when the journal exceeds this size, Fjall force-rotates the
    /// keyspaces pinning the oldest journal, which flushes their memtables. So
    /// this indirectly caps total unflushed memory, and unlike `write_buffer` it
    /// takes effect on every open, including existing data directories.
    ///
    /// Lower = tighter memory, more frequent flushes (more write amplification).
    #[serde(default = "default_fjall_max_journal")]
    pub max_journal: String,
}

/// 16 MiB.
fn default_fjall_block_cache() -> String {
    "16777216".to_string()
}

/// 32 MiB, split across keyspaces by write weight.
fn default_fjall_write_buffer() -> String {
    "33554432".to_string()
}

/// 128 MiB.
fn default_fjall_max_journal() -> String {
    "134217728".to_string()
}

impl Default for FjallConfig {
    fn default() -> Self {
        Self {
            block_cache: default_fjall_block_cache(),
            write_buffer: default_fjall_write_buffer(),
            max_journal: default_fjall_max_journal(),
        }
    }
}
