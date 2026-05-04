// Standalone forwarding processor configuration

use affinidi_messaging_mediator_common::{
    database::config::DatabaseConfig, tasks::forwarding::ForwardingConfig,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Config {
    pub database: DatabaseConfig,
    pub processors: ProcessorConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessorConfig {
    pub forwarding: ForwardingConfig,
}
