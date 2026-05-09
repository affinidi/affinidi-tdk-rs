//! Polls the mediator's /admin/status endpoint and maintains history for rate calculations.

use crate::auth::AdminAuth;
use reqwest::Client;
use serde::Deserialize;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

/// Mirrors the JSON structure from the mediator's /admin/status endpoint.
#[derive(Deserialize, Clone, Debug, Default)]
pub struct AdminStatus {
    pub version: String,
    pub uptime_seconds: i64,
    pub timestamp: String,
    pub connections: ConnectionStatus,
    pub messages: MessageStatus,
    pub forwarding: ForwardingStatus,
    pub circuit_breaker: String,
    pub database: DatabaseStatus,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct ConnectionStatus {
    pub websocket_active: usize,
    pub websocket_max: usize,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct MessageStatus {
    pub received_count: i64,
    pub received_bytes: i64,
    pub sent_count: i64,
    /// Mirror of the `/admin/status` JSON schema. Not currently
    /// rendered in the UI, but kept on the wire-shape struct so
    /// `serde_json` doesn't drop it during round-trip.
    #[allow(dead_code)]
    pub sent_bytes: i64,
    pub deleted_count: i64,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct ForwardingStatus {
    pub queue_length: usize,
    pub queue_limit: usize,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct DatabaseStatus {
    pub url: String,
    pub timeout: u32,
}

/// A snapshot with timing for rate calculations.
#[derive(Clone)]
struct Snapshot {
    status: AdminStatus,
    taken_at: Instant,
}

/// Polls the mediator and maintains a history window for calculating rates.
pub struct StatusPoller {
    client: Client,
    status_url: String,
    /// Admin auth handle. Required — `/admin/status` is auth-gated.
    /// Held as `Arc` so the poller is cheap to clone if we ever need to
    /// hand it across tasks; today it lives on the main task.
    auth: Arc<AdminAuth>,
    pub current: AdminStatus,
    pub error: Option<String>,
    pub connected: bool,
    history: VecDeque<Snapshot>,
    /// Messages per second (calculated from history)
    pub msg_per_sec: f64,
    /// Bytes per second inbound
    pub bytes_per_sec: f64,
}

impl StatusPoller {
    pub fn new(base_url: &str, auth: Arc<AdminAuth>) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            status_url: format!("{base_url}/admin/status"),
            auth,
            current: AdminStatus::default(),
            error: None,
            connected: false,
            history: VecDeque::with_capacity(32),
            msg_per_sec: 0.0,
            bytes_per_sec: 0.0,
        }
    }

    pub async fn poll(&mut self) {
        let token = match self.auth.bearer_token().await {
            Ok(t) => t,
            Err(e) => {
                // Auth failure is distinct from a transport / parse error —
                // surface it as such so the operator knows the credential
                // path is wrong, not the URL.
                self.error = Some(format!("Auth error: {e}"));
                self.connected = false;
                return;
            }
        };

        let request = self
            .client
            .get(&self.status_url)
            .header("Authorization", format!("Bearer {token}"));

        match request.send().await {
            Ok(response) => {
                let status_code = response.status();
                if status_code == reqwest::StatusCode::UNAUTHORIZED {
                    self.error = Some(
                        "Unauthorized (401) — admin JWT was rejected by the mediator. Check that \
                         the admin profile's `did` and `mediator` match the mediator's config and \
                         that the secrets are current."
                            .into(),
                    );
                    self.connected = false;
                    return;
                }
                if status_code == reqwest::StatusCode::FORBIDDEN {
                    self.error = Some(
                        "Forbidden (403) — DID authenticated but is not admin-tier. \
                         /admin/status requires Admin, RootAdmin, or Mediator account_type."
                            .into(),
                    );
                    self.connected = false;
                    return;
                }
                if !status_code.is_success() {
                    self.error = Some(format!("Mediator returned {status_code}"));
                    self.connected = false;
                    return;
                }
                match response.json::<AdminStatus>().await {
                    Ok(status) => {
                        let now = Instant::now();

                        // Calculate rates from oldest snapshot in window
                        if let Some(oldest) = self.history.front() {
                            let elapsed = now.duration_since(oldest.taken_at).as_secs_f64();
                            if elapsed > 0.5 {
                                let msg_delta = (status.messages.received_count
                                    - oldest.status.messages.received_count)
                                    as f64;
                                let bytes_delta = (status.messages.received_bytes
                                    - oldest.status.messages.received_bytes)
                                    as f64;
                                self.msg_per_sec = msg_delta / elapsed;
                                self.bytes_per_sec = bytes_delta / elapsed;
                            }
                        }

                        // Keep last 30 snapshots (~60 seconds at 2s interval)
                        if self.history.len() >= 30 {
                            self.history.pop_front();
                        }
                        self.history.push_back(Snapshot {
                            status: status.clone(),
                            taken_at: now,
                        });

                        self.current = status;
                        self.connected = true;
                        self.error = None;
                    }
                    Err(e) => {
                        self.error = Some(format!("Parse error: {e}"));
                        self.connected = false;
                    }
                }
            }
            Err(e) => {
                self.error = Some(format!("Connection error: {e}"));
                self.connected = false;
            }
        }
    }

    /// Format uptime as human-readable string.
    pub fn uptime_display(&self) -> String {
        let secs = self.current.uptime_seconds;
        if secs < 0 {
            return "N/A".into();
        }
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let mins = (secs % 3600) / 60;
        let s = secs % 60;
        if days > 0 {
            format!("{days}d {hours}h {mins}m")
        } else if hours > 0 {
            format!("{hours}h {mins}m {s}s")
        } else if mins > 0 {
            format!("{mins}m {s}s")
        } else {
            format!("{s}s")
        }
    }
}
