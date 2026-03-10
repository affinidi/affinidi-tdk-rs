//! All Redis related database methods are handled by `DatabaseHandler` module

use crate::common::circuit_breaker::CircuitBreaker;
use affinidi_messaging_mediator_common::{database::DatabaseHandler, errors::MediatorError};
use deadpool_redis::Connection;
use std::sync::Arc;

pub mod accounts;
pub(crate) mod acls;
pub mod admin_accounts;
pub mod fetch;
pub mod forwarding;
pub mod get;
pub mod handlers;
pub(crate) mod initialization;
pub mod list;
pub(crate) mod messages;
#[cfg(feature = "didcomm")]
pub(crate) mod oob_discovery;
pub mod session;
pub mod stats;
pub mod store;
pub mod streaming;
pub(crate) mod upgrades;

/// Mediator-specific database wrapper around [`DatabaseHandler`].
///
/// Provides mediator-level operations (sessions, accounts, forwarding, etc.)
/// while delegating low-level Redis access through `Deref` to `DatabaseHandler`.
/// Includes a circuit breaker for Redis connection resilience.
#[derive(Clone)]
pub struct Database {
    handler: DatabaseHandler,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl Database {
    /// Create a new Database with a circuit breaker.
    /// Opens the circuit after 5 consecutive failures, recovers after 10 seconds.
    pub fn new(handler: DatabaseHandler) -> Self {
        Self {
            handler,
            circuit_breaker: Arc::new(CircuitBreaker::new(5, 10)),
        }
    }

    /// Get a Redis connection with circuit breaker protection.
    /// If the circuit is open, returns an error immediately without trying Redis.
    pub async fn get_connection(&self) -> Result<Connection, MediatorError> {
        if !self.circuit_breaker.allow_request() {
            return Err(MediatorError::DatabaseError(
                14,
                "circuit_breaker".into(),
                "Redis circuit breaker is open — failing fast. Redis may be unavailable.".into(),
            ));
        }

        match self.handler.get_async_connection().await {
            Ok(conn) => {
                self.circuit_breaker.record_success();
                Ok(conn)
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                Err(e)
            }
        }
    }

    /// Get the circuit breaker state for health checks
    pub fn circuit_breaker_state(&self) -> &'static str {
        self.circuit_breaker.state_str()
    }
}

impl std::ops::Deref for Database {
    type Target = DatabaseHandler;

    fn deref(&self) -> &DatabaseHandler {
        &self.handler
    }
}
