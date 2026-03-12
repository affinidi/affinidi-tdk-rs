use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

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
                error!("[profile = {}] Failed to connect: {}", alias, e);
            } else {
                let result = self.listen().await;

                if self.shutdown.is_cancelled() {
                    info!("[profile = {}] Listener shutting down", alias);
                    break;
                }

                if let Err(ref e) = result {
                    error!("[profile = {}] Listener failed: {}", alias, e);
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
                        warn!(
                            "[profile = {}] Listener failed (attempt {}), restarting in {:?}",
                            alias, count, delay
                        );
                        tokio::time::sleep(delay).await;
                    }
                    crate::config::RestartPolicy::Always { backoff } => {
                        let delay = calculate_backoff(count, backoff);
                        warn!(
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
                        error!(
                            "[profile = {}] Listener exceeded max retries ({}), stopping",
                            alias, max
                        );
                        break;
                    }
                    let delay = calculate_backoff(count, backoff);
                    warn!(
                        "[profile = {}] Connect failed (attempt {}), retrying in {:?}",
                        alias, count, delay
                    );
                    tokio::time::sleep(delay).await;
                }
                crate::config::RestartPolicy::Always { backoff } => {
                    let delay = calculate_backoff(count, backoff);
                    warn!(
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
