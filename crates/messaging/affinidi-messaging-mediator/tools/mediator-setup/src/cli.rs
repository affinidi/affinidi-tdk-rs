use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(
    name = "mediator-setup",
    about = "Interactive setup wizard for Affinidi Messaging Mediator"
)]
pub struct Args {
    /// Path to mediator configuration file
    #[arg(long, short = 'c', default_value = "conf/mediator.toml")]
    pub config: String,

    /// Deployment type
    #[arg(long, value_enum)]
    pub deployment: Option<DeploymentType>,

    /// Messaging protocol
    #[arg(long, value_enum)]
    pub protocol: Option<Protocol>,

    /// DID method for the mediator
    #[arg(long, value_enum)]
    pub did_method: Option<DidMethod>,

    /// Public URL for the mediator (required for did:webvh)
    #[arg(long)]
    pub public_url: Option<String>,

    /// Secret storage backend
    #[arg(long, value_enum)]
    pub secret_storage: Option<SecretStorage>,

    /// SSL/TLS mode
    #[arg(long, value_enum)]
    pub ssl: Option<SslMode>,

    /// Redis database URL
    #[arg(long)]
    pub database_url: Option<String>,

    /// Admin DID configuration
    #[arg(long, value_enum)]
    pub admin: Option<AdminMode>,

    /// Listen address (ip:port)
    #[arg(long)]
    pub listen_address: Option<String>,

    /// Run without interactive TUI — uses CLI args and deployment defaults
    #[arg(long)]
    pub non_interactive: bool,

    /// Load a build recipe TOML file (non-interactive, fully declarative)
    #[arg(long, value_name = "FILE")]
    pub from: Option<String>,

    /// Phase 2 of a sealed-handoff setup: path to the armored
    /// `bundle.armor` returned by the VTA operator. When present,
    /// `--from` switches from phase 1 (emit request) to phase 2
    /// (open bundle, write mediator config). Requires `--from`.
    #[arg(long, value_name = "PATH")]
    pub bundle: Option<PathBuf>,

    /// Phase 2 only: optional SHA-256 digest the VTA admin printed
    /// out-of-band. When present, the wizard verifies the bundle's
    /// canonical digest matches before unsealing and refuses on
    /// mismatch. Omit to skip the OOB check (the bundle's internal
    /// AEAD still authenticates the payload).
    #[arg(long, value_name = "HEX")]
    pub digest: Option<String>,

    // ── Online-VTA connection flags ────────────────────────────────────
    /// VTA DID (e.g. did:webvh:vta.example.com). Pre-fills the TUI; required
    /// for non-interactive / --setup-key-{out,file} flows.
    #[arg(long, value_name = "DID")]
    pub vta_did: Option<String>,

    /// VTA context id the mediator will live in (default: `mediator`).
    #[arg(long, value_name = "ID")]
    pub vta_context: Option<String>,

    /// Public URL the mediator will serve at (e.g.
    /// https://mediator.example.com). Passed to the VTA's
    /// `didcomm-mediator` template as the `URL` variable during
    /// provisioning. Required for Phase 2 (`--setup-key-file`).
    #[arg(long, value_name = "URL")]
    pub mediator_url: Option<String>,

    /// Phase 1: generate an ephemeral did:key, write it to the given file,
    /// print the `pnm acl create` command, and exit. The operator registers
    /// the ACL, then re-runs with `--setup-key-file` to finalise.
    #[arg(long, value_name = "PATH")]
    pub setup_key_out: Option<PathBuf>,

    /// Phase 2: read an ephemeral did:key from the given file and use it to
    /// authenticate against the VTA. Requires `--vta-did`.
    ///
    /// Auto-falls between DIDComm and REST when both transports are
    /// advertised — pre-auth failures on one wire trigger a retry on
    /// the other without prompting. Post-auth failures (VTA accepted
    /// the handshake then rejected the request body) terminate
    /// immediately — a different wire reproduces the rejection.
    ///
    /// Exit codes:
    ///   0  — success
    ///   2  — no transport worked (neither advertised, or every
    ///        advertised transport failed pre-auth)
    ///   3  — VTA accepted the auth handshake but rejected the
    ///        request body afterwards
    #[arg(long, value_name = "PATH")]
    pub setup_key_file: Option<PathBuf>,

    /// Phase 2 only: retry the authentication loop for up to this many
    /// seconds while waiting for the ACL entry to appear on the VTA. Useful
    /// when ACL provisioning is orchestrated in parallel.
    #[arg(long, value_name = "SECS")]
    pub wait_for_acl: Option<u64>,

    // ── Re-run safety ─────────────────────────────────────────────────
    /// Allow the wizard to run when an existing `mediator.toml` and a
    /// provisioned backend are detected. Without this flag the wizard
    /// refuses to overwrite secrets that are already in production —
    /// rotating them silently can lock the mediator out of the VTA, and
    /// previously-issued JWTs would stop verifying.
    #[arg(long)]
    pub force_reprovision: bool,

    /// Tear down a previous setup: load the configured backend, list the
    /// well-known mediator keys it holds, prompt for confirmation, then
    /// delete each entry and remove the local config + secrets files.
    /// Combine with `--yes` (planned) to skip the prompt in CI.
    #[arg(long)]
    pub uninstall: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DeploymentType {
    /// Local development (desktop, quick start)
    Local,
    /// Headless server (production, cloud/bare metal)
    Server,
    /// Container (Docker image)
    Container,
}

impl std::fmt::Display for DeploymentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "Local development"),
            Self::Server => write!(f, "Headless server"),
            Self::Container => write!(f, "Container"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Protocol {
    /// DIDComm v2 (recommended)
    Didcomm,
    /// TSP — Trust Spanning Protocol (experimental)
    Tsp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Didcomm => write!(f, "DIDComm v2"),
            Self::Tsp => write!(f, "TSP"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DidMethod {
    /// Generate a did:peer (simplest, no hosting)
    Peer,
    /// Generate a did:webvh (production, requires webvh server)
    Webvh,
    /// Configure via VTA
    Vta,
}

impl std::fmt::Display for DidMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Peer => write!(f, "did:peer"),
            Self::Webvh => write!(f, "did:webvh"),
            Self::Vta => write!(f, "VTA managed"),
        }
    }
}

/// Secret-store backends accepted on the CLI. `string://` (inline) was
/// removed in the unified-secrets refactor — inline private keys in TOML
/// are unsafe even for CI. `vta://` was never a backend (the VTA is a
/// *source* of keys); pick whichever real store will hold them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SecretStorage {
    /// Local file (file://) — dev only, requires explicit confirmation
    /// in interactive mode.
    File,
    /// OS Keyring (keyring://)
    Keyring,
    /// AWS Secrets Manager (aws_secrets://)
    Aws,
}

impl std::fmt::Display for SecretStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File => write!(f, "file://"),
            Self::Keyring => write!(f, "keyring://"),
            Self::Aws => write!(f, "aws_secrets://"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SslMode {
    /// No SSL — use a TLS-terminating proxy
    None,
    /// Generate self-signed certificates (local dev only)
    SelfSigned,
}

impl std::fmt::Display for SslMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "No SSL (TLS proxy)"),
            Self::SelfSigned => write!(f, "Self-signed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AdminMode {
    /// Generate a new admin did:key
    Generate,
    /// Skip admin DID configuration
    Skip,
}

impl std::fmt::Display for AdminMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generate => write!(f, "Generate did:key"),
            Self::Skip => write!(f, "Skip"),
        }
    }
}
