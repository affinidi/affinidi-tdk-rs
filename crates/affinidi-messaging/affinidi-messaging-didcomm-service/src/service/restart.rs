use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error};

use crate::config::RetryConfig;

use super::listener::Listener;

impl Listener {
    pub(crate) async fn run_with_restart(
        &mut self,
        restart_count: Arc<std::sync::atomic::AtomicU32>,
    ) {
        let alias = self.config.profile.alias.clone();
        let restart_policy = self.config.restart_policy.clone();

        loop {
            if let Err(e) = self.connect().await {
                debug!("[profile = {}] Failed to connect: {}", alias, e);
            } else {
                let result = self.listen().await;

                if self.shutdown.is_cancelled() {
                    debug!("[profile = {}] Listener shutting down", alias);
                    break;
                }

                if let Err(ref e) = result {
                    debug!("[profile = {}] Listener failed: {}", alias, e);
                }

                let count = restart_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;

                match &restart_policy {
                    crate::config::RestartPolicy::Never => {
                        break;
                    }
                    crate::config::RestartPolicy::OnFailure {
                        max_retries,
                        backoff,
                    } => {
                        if result.is_ok() {
                            break;
                        }
                        if let Some(max) = max_retries
                            && count > *max
                        {
                            error!(
                                "[profile = {}] Listener exceeded max retries ({}), stopping",
                                alias, max
                            );
                            break;
                        }
                        let delay = calculate_backoff(count, backoff);
                        debug!(
                            "[profile = {}] Listener failed (attempt {}), restarting in {:?}",
                            alias, count, delay
                        );
                        tokio::time::sleep(delay).await;
                    }
                    crate::config::RestartPolicy::Always { backoff } => {
                        let delay = calculate_backoff(count, backoff);
                        debug!(
                            "[profile = {}] Listener stopped (attempt {}), restarting in {:?}",
                            alias, count, delay
                        );
                        tokio::time::sleep(delay).await;
                    }
                }

                continue;
            }

            let count = restart_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;

            match &restart_policy {
                crate::config::RestartPolicy::Never => {
                    break;
                }
                crate::config::RestartPolicy::OnFailure {
                    max_retries,
                    backoff,
                } => {
                    if let Some(max) = max_retries
                        && count > *max
                    {
                        debug!(
                            "[profile = {}] Listener exceeded max retries ({}), stopping",
                            alias, max
                        );
                        break;
                    }
                    let delay = calculate_backoff(count, backoff);
                    debug!(
                        "[profile = {}] Connect failed (attempt {}), retrying in {:?}",
                        alias, count, delay
                    );
                    tokio::time::sleep(delay).await;
                }
                crate::config::RestartPolicy::Always { backoff } => {
                    let delay = calculate_backoff(count, backoff);
                    debug!(
                        "[profile = {}] Connect failed (attempt {}), retrying in {:?}",
                        alias, count, delay
                    );
                    tokio::time::sleep(delay).await;
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
            max_attempts: 10,
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
        assert_eq!(c.max_attempts, 5);
        assert_eq!(c.initial_delay_secs, 2);
        assert_eq!(c.max_delay_secs, 60);
    }
}
