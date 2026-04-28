//! GET /admin/status — real-time operational status for monitoring.
//!
//! Returns a JSON payload with current mediator state including:
//! connections, throughput, queue depths, circuit breaker state, uptime, etc.
//!
//! Designed to be polled by the mediator-monitor TUI or any monitoring tool.

use crate::SharedData;
use axum::{Json, extract::State};
use chrono::Utc;
use http::StatusCode;
use serde::Serialize;

#[derive(Serialize)]
pub struct AdminStatus {
    /// Mediator version
    pub version: &'static str,
    /// Uptime in seconds
    pub uptime_seconds: i64,
    /// Current UTC timestamp
    pub timestamp: String,

    /// Connection metrics
    pub connections: ConnectionStatus,
    /// Message throughput (from Redis GLOBAL hash)
    pub messages: MessageStatus,
    /// Forwarding queue status
    pub forwarding: ForwardingStatus,
    /// Circuit breaker state
    pub circuit_breaker: &'static str,
    /// Database configuration
    pub database: DatabaseStatus,
}

#[derive(Serialize)]
pub struct ConnectionStatus {
    /// Active WebSocket connections
    pub websocket_active: usize,
    /// Max configured WebSocket connections
    pub websocket_max: usize,
}

#[derive(Serialize)]
pub struct MessageStatus {
    /// Total messages received (lifetime)
    pub received_count: i64,
    /// Total bytes received (lifetime)
    pub received_bytes: i64,
    /// Total messages sent/delivered (lifetime)
    pub sent_count: i64,
    /// Total bytes sent (lifetime)
    pub sent_bytes: i64,
    /// Total messages deleted (lifetime)
    pub deleted_count: i64,
}

#[derive(Serialize)]
pub struct ForwardingStatus {
    /// Current queue depth
    pub queue_length: usize,
    /// Max configured queue length
    pub queue_limit: usize,
}

#[derive(Serialize)]
pub struct DatabaseStatus {
    /// Redis connection URL (password masked)
    pub url: String,
    /// Connection timeout in seconds
    pub timeout: u32,
}

/// Mask password in Redis URL for display.
fn mask_redis_url(url: &str) -> String {
    // redis://:password@host → redis://:***@host
    if let Some(at_pos) = url.find('@') {
        if let Some(colon_pos) = url[..at_pos].rfind(':') {
            let scheme_end = url.find("://").map(|p| p + 3).unwrap_or(0);
            if colon_pos >= scheme_end {
                return format!("{}***{}", &url[..colon_pos + 1], &url[at_pos..]);
            }
        }
    }
    url.to_string()
}

pub async fn admin_status_handler(
    State(state): State<SharedData>,
) -> Result<(StatusCode, Json<AdminStatus>), StatusCode> {
    let now = Utc::now();
    let uptime = now
        .signed_duration_since(state.service_start_timestamp)
        .num_seconds();

    // Get message stats from Redis GLOBAL hash
    let (received_count, received_bytes, sent_count, sent_bytes, deleted_count) =
        match state.database.get_db_metadata().await {
            Ok(stats) => (
                stats.received_count,
                stats.received_bytes,
                stats.sent_count,
                stats.sent_bytes,
                stats.deleted_count,
            ),
            Err(_) => (0, 0, 0, 0, 0),
        };

    // Get forward queue length
    let queue_length = state.database.get_forward_tasks_len().await.unwrap_or(0);

    let status = AdminStatus {
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: uptime,
        timestamp: now.to_rfc3339(),
        connections: ConnectionStatus {
            websocket_active: state
                .active_websocket_count
                .load(std::sync::atomic::Ordering::Relaxed),
            websocket_max: state.config.limits.max_websocket_connections,
        },
        messages: MessageStatus {
            received_count,
            received_bytes,
            sent_count,
            sent_bytes,
            deleted_count,
        },
        forwarding: ForwardingStatus {
            queue_length,
            queue_limit: state.config.limits.forward_task_queue,
        },
        circuit_breaker: state.database.circuit_breaker_state(),
        database: DatabaseStatus {
            url: mask_redis_url(&state.config.database.database_url),
            timeout: state.config.database.database_timeout,
        },
    };

    Ok((StatusCode::OK, Json(status)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_redis_url_with_password() {
        assert_eq!(
            mask_redis_url("redis://:mypassword@host:6379/"),
            "redis://:***@host:6379/"
        );
    }

    #[test]
    fn test_mask_redis_url_with_user_password() {
        assert_eq!(
            mask_redis_url("redis://user:pass@host:6379/"),
            "redis://user:***@host:6379/"
        );
    }

    #[test]
    fn test_mask_redis_url_no_password() {
        assert_eq!(mask_redis_url("redis://127.0.0.1/"), "redis://127.0.0.1/");
    }

    #[test]
    fn test_mask_redis_url_tls() {
        assert_eq!(
            mask_redis_url("rediss://:secret@host/"),
            "rediss://:***@host/"
        );
    }
}
