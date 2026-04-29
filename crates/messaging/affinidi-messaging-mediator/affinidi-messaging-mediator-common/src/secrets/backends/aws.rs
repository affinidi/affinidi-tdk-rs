//! AWS Secrets Manager backend (feature `secrets-aws`).
//!
//! Every secret `key` is stored as an AWS secret named
//! `<namespace><key>`. Both binary and string-form secrets live in the
//! `SecretString` field (base64url encoded) so everything round-trips
//! identically across backends.
//!
//! Calls go through [`super::super::retry::with_retry`] with
//! [`AwsRetryPolicy`]: ThrottlingException / TooManyRequestsException /
//! InternalServiceError / RequestTimeout / connection-level failures
//! retry; ResourceNotFoundException, validation, and access-denied
//! errors short-circuit so the caller's error path runs unchanged.

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::DynSecretStore;
use crate::secrets::url::BackendUrl;

#[cfg(feature = "secrets-aws")]
use crate::secrets::retry::{RetryPolicy, Retryable, with_retry};
#[cfg(feature = "secrets-aws")]
use crate::secrets::store::SecretStore;
#[cfg(feature = "secrets-aws")]
use async_trait::async_trait;

const BACKEND_LABEL: &str = "aws_secrets";

#[cfg(feature = "secrets-aws")]
pub(crate) fn open(url: BackendUrl) -> Result<DynSecretStore> {
    let BackendUrl::Aws { region, namespace } = url else {
        return Err(SecretStoreError::Other(
            "internal error: aws backend received non-aws URL".into(),
        ));
    };
    Ok(std::sync::Arc::new(AwsStore { region, namespace }))
}

#[cfg(not(feature = "secrets-aws"))]
pub(crate) fn open(_url: BackendUrl) -> Result<DynSecretStore> {
    Err(SecretStoreError::BackendUnavailable {
        backend: BACKEND_LABEL,
        reason: "compiled without the 'secrets-aws' feature; rebuild with \
                 `cargo build --features secrets-aws` to enable"
            .into(),
    })
}

#[cfg(feature = "secrets-aws")]
pub struct AwsStore {
    region: String,
    namespace: String,
}

#[cfg(feature = "secrets-aws")]
impl AwsStore {
    fn secret_name(&self, key: &str) -> String {
        format!("{}{}", self.namespace, key)
    }

    async fn client(&self) -> aws_sdk_secretsmanager::Client {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_secretsmanager::config::Region::new(
                self.region.clone(),
            ))
            .load()
            .await;
        aws_sdk_secretsmanager::Client::new(&config)
    }
}

/// `RetryPolicy` for AWS Secrets Manager. Pure string match on the
/// SDK error display because the typed `*Error` enums sit behind
/// `#[non_exhaustive]` wrappers; touching specific variants ties
/// us to a specific SDK minor.
#[cfg(feature = "secrets-aws")]
pub(crate) struct AwsRetryPolicy;

/// Join the `Display` form of `err` with every `source()` in its chain.
/// `SdkError::Display` only emits the kind ("service error"); the actual
/// AWS reason (`ResourceNotFoundException: ...`, `AccessDeniedException:
/// User ... is not authorized`, etc.) lives inside `source()`. Without
/// this both the retry classifier and the surfaced error message are
/// blind to anything past the wrapper.
#[cfg(feature = "secrets-aws")]
fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![err.to_string()];
    let mut cur = err.source();
    while let Some(src) = cur {
        parts.push(src.to_string());
        cur = src.source();
    }
    parts.join(" | ")
}

#[cfg(feature = "secrets-aws")]
impl<E: std::error::Error + 'static> RetryPolicy<E> for AwsRetryPolicy {
    fn classify(&self, err: &E) -> Retryable {
        let msg = format_error_chain(err);
        // Hard "do not retry" cases first — these are deterministic
        // misconfigurations, not transient failures. Retrying them
        // wastes time and clutters the audit log with bogus retries.
        const TERMINAL: &[&str] = &[
            "ResourceNotFoundException",
            "AccessDeniedException",
            "ValidationException",
            "InvalidParameterException",
            "InvalidRequestException",
            "DecryptionFailure",
            "EncryptionFailure",
        ];
        if TERMINAL.iter().any(|t| msg.contains(t)) {
            return Retryable::No;
        }
        // Transient failures we should retry. Throttling, internal,
        // request-timeout, dns / TCP errors all fall through here.
        const TRANSIENT: &[&str] = &[
            "ThrottlingException",
            "TooManyRequestsException",
            "InternalServiceError",
            "InternalServerError",
            "ServiceUnavailable",
            "RequestTimeout",
            "RequestTimeoutException",
            "dispatch failure",
            "io error",
            "timeout",
            "connection reset",
            "connection closed",
        ];
        if TRANSIENT.iter().any(|t| msg.contains(t)) {
            return Retryable::Yes { retry_after: None };
        }
        // Default: don't retry. Better to surface an unknown error
        // immediately than to mask a real bug under three identical
        // SDK calls.
        Retryable::No
    }
}

#[cfg(feature = "secrets-aws")]
#[async_trait]
impl SecretStore for AwsStore {
    fn backend(&self) -> &'static str {
        BACKEND_LABEL
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

        let name = self.secret_name(key);
        let client = self.client().await;
        let label = format!("GetSecretValue({name})");
        // The retry helper takes a closure returning a fresh future
        // each attempt; we re-issue the SDK call (the cloned client
        // is cheap — internally `Arc`-wrapped) and translate the
        // outcome at the call site.
        let response = with_retry(&label, &AwsRetryPolicy, || {
            let client = client.clone();
            let name = name.clone();
            async move { client.get_secret_value().secret_id(&name).send().await }
        })
        .await;
        let response = match response {
            Ok(r) => r,
            Err(sdk_err) => {
                let msg = format_error_chain(&sdk_err);
                if msg.contains("ResourceNotFoundException") {
                    return Ok(None);
                }
                return Err(SecretStoreError::Unreachable {
                    backend: BACKEND_LABEL,
                    reason: format!("GetSecretValue({name}) failed: {msg}"),
                });
            }
        };
        let Some(encoded) = response.secret_string else {
            return Err(SecretStoreError::InvalidShape {
                key: key.to_string(),
                reason: "AWS secret has no SecretString (binary-only secrets not supported)".into(),
            });
        };
        let bytes =
            B64URL
                .decode(encoded.as_bytes())
                .map_err(|e| SecretStoreError::InvalidShape {
                    key: key.to_string(),
                    reason: format!("AWS SecretString is not valid base64: {e}"),
                })?;
        Ok(Some(bytes))
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

        let name = self.secret_name(key);
        let client = self.client().await;
        let encoded = B64URL.encode(value);

        // PutSecretValue → CreateSecret on first write. Each SDK call
        // is wrapped independently because they have distinct
        // throttling buckets in AWS.
        let put_label = format!("PutSecretValue({name})");
        let put_result = with_retry(&put_label, &AwsRetryPolicy, || {
            let client = client.clone();
            let name = name.clone();
            let encoded = encoded.clone();
            async move {
                client
                    .put_secret_value()
                    .secret_id(&name)
                    .secret_string(&encoded)
                    .send()
                    .await
            }
        })
        .await;
        match put_result {
            Ok(_) => Ok(()),
            Err(err) if format_error_chain(&err).contains("ResourceNotFoundException") => {
                let create_label = format!("CreateSecret({name})");
                with_retry(&create_label, &AwsRetryPolicy, || {
                    let client = client.clone();
                    let name = name.clone();
                    let encoded = encoded.clone();
                    async move {
                        client
                            .create_secret()
                            .name(&name)
                            .secret_string(&encoded)
                            .send()
                            .await
                    }
                })
                .await
                .map_err(|e| SecretStoreError::Unreachable {
                    backend: BACKEND_LABEL,
                    reason: format!("CreateSecret({name}) failed: {}", format_error_chain(&e)),
                })?;
                Ok(())
            }
            Err(err) => Err(SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!(
                    "PutSecretValue({name}) failed: {}",
                    format_error_chain(&err)
                ),
            }),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let name = self.secret_name(key);
        let client = self.client().await;
        let label = format!("DeleteSecret({name})");
        let result = with_retry(&label, &AwsRetryPolicy, || {
            let client = client.clone();
            let name = name.clone();
            async move {
                client
                    .delete_secret()
                    .secret_id(&name)
                    .force_delete_without_recovery(true)
                    .send()
                    .await
            }
        })
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(err) if format_error_chain(&err).contains("ResourceNotFoundException") => Ok(()),
            Err(err) => Err(SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("DeleteSecret({name}) failed: {}", format_error_chain(&err)),
            }),
        }
    }

    /// Walks `ListSecrets` pages until exhausted and returns the full
    /// secret names (region-wide — the configured `namespace` is *not*
    /// applied as a server-side filter, because the wizard's discovery
    /// flow wants to surface every name already in use, not just the
    /// ones inside the operator's chosen namespace). Each retry batch
    /// is its own `with_retry` invocation so a transient throttle on
    /// page N doesn't lose pages 1..N-1.
    async fn list_namespace(&self) -> Result<Vec<String>> {
        let client = self.client().await;
        let mut names: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let token_for_label = next_token
                .as_deref()
                .map(|t| format!("...{}", &t[t.len().saturating_sub(8)..]))
                .unwrap_or_else(|| "first".into());
            let label = format!("ListSecrets({token_for_label})");
            let response = with_retry(&label, &AwsRetryPolicy, || {
                let client = client.clone();
                let token = next_token.clone();
                async move {
                    let mut req = client.list_secrets();
                    if let Some(t) = token {
                        req = req.next_token(t);
                    }
                    req.send().await
                }
            })
            .await
            .map_err(|err| SecretStoreError::Unreachable {
                backend: BACKEND_LABEL,
                reason: format!("ListSecrets failed: {}", format_error_chain(&err)),
            })?;

            if let Some(entries) = response.secret_list {
                for entry in entries {
                    if let Some(name) = entry.name {
                        names.push(name);
                    }
                }
            }
            match response.next_token {
                Some(t) if !t.is_empty() => next_token = Some(t),
                _ => break,
            }
        }
        Ok(names)
    }
}

#[cfg(test)]
#[cfg(feature = "secrets-aws")]
mod policy_tests {
    use super::*;

    /// Minimal stand-in error type for testing the policy's classifier
    /// without a live AWS SDK error to construct. Optionally chains a
    /// `source` so we can exercise the `format_error_chain` walker that
    /// the classifier and surfaced error messages now rely on.
    #[derive(Debug)]
    struct StubErr {
        msg: &'static str,
        source: Option<Box<StubErr>>,
    }
    impl StubErr {
        fn new(msg: &'static str) -> Self {
            Self { msg, source: None }
        }
        fn with_source(msg: &'static str, source: StubErr) -> Self {
            Self {
                msg,
                source: Some(Box::new(source)),
            }
        }
    }
    impl std::fmt::Display for StubErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.msg)
        }
    }
    impl std::error::Error for StubErr {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.source
                .as_deref()
                .map(|s| s as &(dyn std::error::Error + 'static))
        }
    }

    fn classify(msg: &'static str) -> Retryable {
        AwsRetryPolicy.classify(&StubErr::new(msg))
    }

    #[test]
    fn not_found_is_terminal() {
        assert!(matches!(
            classify("service error: ResourceNotFoundException: secret does not exist"),
            Retryable::No
        ));
    }

    #[test]
    fn access_denied_is_terminal() {
        assert!(matches!(
            classify("AccessDeniedException: User is not authorized"),
            Retryable::No
        ));
    }

    #[test]
    fn throttling_is_retryable() {
        match classify("ThrottlingException: Rate exceeded") {
            Retryable::Yes { retry_after: None } => {}
            other => panic!(
                "expected retryable without retry_after, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn dispatch_failure_is_retryable() {
        // Network-level error — the SDK wraps these as "dispatch
        // failure" with the underlying I/O error inside.
        assert!(matches!(
            classify("dispatch failure: io error: connection reset"),
            Retryable::Yes { .. }
        ));
    }

    #[test]
    fn unknown_error_is_terminal_by_default() {
        // Conservative default — surfacing an unknown error
        // immediately beats hiding a real bug under three identical
        // failures.
        assert!(matches!(
            classify("some new error variant we have not seen before"),
            Retryable::No
        ));
    }

    #[test]
    fn classifier_sees_inner_source_message() {
        // The aws-sdk-rust SdkError::Display only emits "service error"
        // — the actual exception name (e.g. AccessDeniedException) lives
        // in the source chain. The classifier must walk it or every
        // terminal/transient case looks the same.
        let inner = StubErr::new("AccessDeniedException: User is not authorized");
        let outer = StubErr::with_source("service error", inner);
        assert!(matches!(AwsRetryPolicy.classify(&outer), Retryable::No));
    }

    #[test]
    fn chain_walker_concatenates_with_pipe_separator() {
        let inner = StubErr::new("InvalidParameterException: bad name");
        let outer = StubErr::with_source("service error", inner);
        let formatted = format_error_chain(&outer);
        assert!(
            formatted.contains("service error"),
            "outer message must be present: {formatted}"
        );
        assert!(
            formatted.contains("InvalidParameterException"),
            "inner message must be present: {formatted}"
        );
        assert!(
            formatted.contains(" | "),
            "expected ' | ' separator: {formatted}"
        );
    }
}
