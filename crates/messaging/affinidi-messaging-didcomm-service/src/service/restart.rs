use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::config::{RestartPolicy, RetryConfig};

use super::ListenerEvent;
use super::listener::Listener;

enum ShouldRestart {
    Yes(Duration),
    Stop,
}

fn should_restart(policy: &RestartPolicy, count: u32, was_success: bool) -> ShouldRestart {
    match policy {
        RestartPolicy::Never => ShouldRestart::Stop,
        RestartPolicy::OnFailure {
            max_retries,
            backoff,
        } => {
            if was_success {
                return ShouldRestart::Stop;
            }
            if let Some(max) = max_retries
                && count > *max
            {
                return ShouldRestart::Stop;
            }
            ShouldRestart::Yes(calculate_backoff(count, backoff))
        }
        RestartPolicy::Always { backoff } => ShouldRestart::Yes(calculate_backoff(count, backoff)),
    }
}

impl Listener {
    pub(crate) async fn run_with_restart(
        &mut self,
        restart_count: Arc<std::sync::atomic::AtomicU32>,
    ) {
        let alias = self.config.profile.alias.clone();
        let restart_policy = self.config.restart_policy.clone();

        let listener_id = self.config.id.clone();
        let shutdown = self.shutdown.clone();

        loop {
            if shutdown.is_cancelled() {
                debug!(profile = %alias, "Listener shutting down before connect attempt");
                let _ = self.events_tx.send(ListenerEvent::Disconnected {
                    listener_id: listener_id.clone(),
                    error: None,
                });
                break;
            }

            let connect_res = tokio::select! {
                res = self.connect() => res,
                _ = shutdown.cancelled() => {
                    debug!(profile = %alias, "Connect aborted by shutdown");
                    let _ = self.events_tx.send(ListenerEvent::Disconnected {
                        listener_id: listener_id.clone(),
                        error: None,
                    });
                    break;
                }
            };

            let was_success = match connect_res {
                Err(e) => {
                    warn!(profile = %alias, error = %e, "Failed to connect");
                    let _ = self.events_tx.send(ListenerEvent::Disconnected {
                        listener_id: listener_id.clone(),
                        error: Some(e.to_string()),
                    });
                    false
                }
                Ok(()) => {
                    let result = self.listen().await;

                    if self.shutdown.is_cancelled() {
                        debug!(profile = %alias, "Listener shutting down");
                        let _ = self.events_tx.send(ListenerEvent::Disconnected {
                            listener_id: listener_id.clone(),
                            error: None,
                        });
                        break;
                    }

                    if let Err(ref e) = result {
                        warn!(profile = %alias, error = %e, "Listener failed");
                        let _ = self.events_tx.send(ListenerEvent::Disconnected {
                            listener_id: listener_id.clone(),
                            error: Some(e.to_string()),
                        });
                    }

                    result.is_ok()
                }
            };

            let count = restart_count.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1;

            match should_restart(&restart_policy, count, was_success) {
                ShouldRestart::Yes(delay) => {
                    info!(profile = %alias, attempt = count, backoff = ?delay, "Restarting");
                    let _ = self.events_tx.send(ListenerEvent::Restarting {
                        listener_id: listener_id.clone(),
                        attempt: count,
                        delay,
                    });
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = shutdown.cancelled() => {
                            debug!(profile = %alias, "Restart backoff aborted by shutdown");
                            break;
                        }
                    }
                }
                ShouldRestart::Stop => {
                    if !was_success
                        && let RestartPolicy::OnFailure {
                            max_retries: Some(max),
                            ..
                        } = &restart_policy
                    {
                        error!(profile = %alias, max_retries = max, "Exceeded max retries, stopping");
                    }
                    break;
                }
            }
        }
    }
}

fn calculate_backoff(attempt: u32, config: &RetryConfig) -> Duration {
    let delay_secs = config
        .initial_delay_secs
        .saturating_mul(2u64.saturating_pow(attempt.saturating_sub(1)))
        .min(config.max_delay_secs);
    Duration::from_secs(delay_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(initial: u64, max: u64) -> RetryConfig {
        RetryConfig {
            initial_delay_secs: initial,
            max_delay_secs: max,
        }
    }

    #[test]
    fn first_attempt_uses_initial_delay() {
        let d = calculate_backoff(1, &cfg(2, 60));
        assert_eq!(d, Duration::from_secs(2));
    }

    #[test]
    fn second_attempt_doubles() {
        let d = calculate_backoff(2, &cfg(2, 60));
        assert_eq!(d, Duration::from_secs(4));
    }

    #[test]
    fn third_attempt_quadruples() {
        let d = calculate_backoff(3, &cfg(2, 60));
        assert_eq!(d, Duration::from_secs(8));
    }

    #[test]
    fn capped_at_max_delay() {
        let d = calculate_backoff(10, &cfg(2, 30));
        assert_eq!(d, Duration::from_secs(30));
    }

    #[test]
    fn attempt_zero_same_as_first() {
        let d = calculate_backoff(0, &cfg(5, 120));
        assert_eq!(d, Duration::from_secs(5));
    }

    #[test]
    fn large_attempt_saturates_not_panics() {
        let d = calculate_backoff(u32::MAX, &cfg(2, 60));
        assert_eq!(d, Duration::from_secs(60));
    }

    #[test]
    fn default_retry_config_values() {
        let c = RetryConfig::default();
        assert_eq!(c.initial_delay_secs, 2);
        assert_eq!(c.max_delay_secs, 60);
    }
}
