use super::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;
use std::fs::read_to_string;
use tracing::{Level, event};

impl Database {
    // Load Redis scripts into the database
    pub async fn load_scripts(&self, scripts_path: &str) -> Result<(), MediatorError> {
        // Load the file contents into a string
        let lua_scripts = read_to_string(scripts_path).map_err(|err| {
            MediatorError::ConfigError(
                2,
                "Initialization".into(),
                format!(
                    "Couldn't ready database functions_file ({scripts_path}). Reason: {err}"
                ),
            )
        })?;

        let mut conn = self.0.get_async_connection().await?;
        match deadpool_redis::redis::cmd("FUNCTION")
            .arg("LOAD")
            .arg("REPLACE")
            .arg(lua_scripts)
            .exec_async(&mut conn)
            .await
        {
            Ok(_) => {
                event!(
                    Level::INFO,
                    "Loaded LUA scripts into the database from file: {}",
                    scripts_path
                );
                Ok(())
            }
            Err(err) => {
                event!(
                    Level::WARN,
                    "database response for FUNCTION LOAD: ({})",
                    err
                );
                Err(MediatorError::DatabaseError(
                    14,
                    "Initialization".into(),
                    format!("Loading LUA scripts, received database error: {err}"),
                ))
            }
        }
    }
}
