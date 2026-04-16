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

    /// Deployment type (skips step 1 if provided)
    #[arg(long, value_enum)]
    pub deployment: Option<DeploymentType>,

    /// Run without interactive TUI (requires all options via CLI)
    #[arg(long)]
    pub non_interactive: bool,
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
