//! Errors from the console.

use affinidi_messaging_sdk::errors::ATMError;

/// Why a console operation failed.
///
/// The variants separate what a caller does next: an identity that cannot be
/// used is fixed by choosing another; a refusal is the mediator's answer and is
/// shown as such; a transport failure is retried; `NotPermitted` means the
/// console knows in advance the mediator would refuse, so no request was sent.
#[derive(Debug, thiserror::Error)]
pub enum ConsoleError {
    /// The identity could not be loaded or has nothing to connect with.
    #[error("identity: {0}")]
    Identity(String),
    /// No mediator was given and none could be found from the DID document.
    #[error("no mediator for {0}: pass one explicitly or publish a DIDCommMessaging service")]
    NoMediator(String),
    /// The connection to the mediator could not be established.
    #[error("connecting to the mediator: {0}")]
    Connect(String),
    /// The mediator answered with a problem report: a refusal, with the stable
    /// code a caller can act on and the mediator's explanation.
    #[error("the mediator refused ({code}): {comment}")]
    Refused { code: String, comment: String },
    /// The console's session cannot do this, so nothing was sent.
    #[error("not permitted for this session: {0}")]
    NotPermitted(&'static str),
    /// A purge plan was confirmed against a queue that has since changed.
    #[error("the queue changed since the purge was previewed ({previewed} then, {now} now)")]
    PlanStale { previewed: u64, now: u64 },
    /// Anything else the SDK reported.
    #[error(transparent)]
    Sdk(#[from] ATMError),
}

impl ConsoleError {
    /// Classify an SDK error: a problem report from the mediator is a
    /// [`ConsoleError::Refused`], everything else stays an SDK error.
    pub(crate) fn from_call(e: ATMError) -> Self {
        match e {
            ATMError::ProblemReport(code, comment, _) => ConsoleError::Refused { code, comment },
            other => ConsoleError::Sdk(other),
        }
    }

    /// The mediator's problem code, when this is a refusal.
    pub fn refusal_code(&self) -> Option<&str> {
        match self {
            ConsoleError::Refused { code, .. } => Some(code),
            _ => None,
        }
    }
}

/// Shorthand for console results.
pub type Result<T> = std::result::Result<T, ConsoleError>;
