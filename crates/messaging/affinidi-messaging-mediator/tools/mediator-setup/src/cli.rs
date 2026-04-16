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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SecretStorage {
    /// Inline in config (string://)
    Inline,
    /// Local file (file://)
    File,
    /// OS Keyring (keyring://)
    Keyring,
    /// AWS Secrets Manager (aws_secrets://)
    Aws,
    /// VTA managed (vta://)
    Vta,
}

impl std::fmt::Display for SecretStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inline => write!(f, "string://"),
            Self::File => write!(f, "file://"),
            Self::Keyring => write!(f, "keyring://"),
            Self::Aws => write!(f, "aws_secrets://"),
            Self::Vta => write!(f, "vta://"),
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
