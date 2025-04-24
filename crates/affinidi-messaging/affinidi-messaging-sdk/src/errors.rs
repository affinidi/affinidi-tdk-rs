use affinidi_did_authentication::errors::DIDAuthError;
use affinidi_messaging_didcomm::Message;
use affinidi_tdk_common::errors::TDKError;
use thiserror::Error;

use crate::messages::{known::MessageType, problem_report::ProblemReport};

/// ATMError
#[derive(Error, Debug)]
pub enum ATMError {
    #[error("DID error: {0}")]
    DIDError(String),
    #[error("Secrets error: {0}")]
    SecretsError(String),
    #[error("SSL error: {0}")]
    SSLError(String),
    #[error("Transport (HTTP(S)) error: {0}")]
    TransportError(String),
    #[error("Message sending error: {0}")]
    MsgSendError(String),
    #[error("Message receive error: {0}")]
    MsgReceiveError(String),
    #[error("Config error: {0}")]
    ConfigError(String),
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    #[error("ACL Denied error: {0}")]
    ACLDenied(String),
    #[error("ACL config error: {0}")]
    ACLConfigError(String),
    #[error("DIDComm message error: {0}. Reason: {1}")]
    DidcommError(String, String),
    #[error("SDK Error: {0}")]
    SDKError(String),
    #[error("TDK Error: {0}")]
    TDKError(String),
    #[error("DIDComm Problem Report: code: ({0}), comment: ({1}), escalate?: ({2})")]
    ProblemReport(String, String, String),
    #[error("DIDComm Mediator error: code({0}), message: ({1})")]
    MediatorError(String, String),
    #[error("ATM DID Profile error: {0}")]
    ProfileError(String),
}

impl ATMError {
    /// Creates an ATM Error from a DIDComm Problem Report Error Message
    pub fn from_problem_report(message: &Message) -> Self {
        if let Ok(MessageType::ProblemReport) = message.type_.parse::<MessageType>() {
            let body: ProblemReport = match serde_json::from_value(message.body.clone()) {
                Ok(body) => body,
                Err(err) => {
                    return ATMError::SDKError(format!(
                        "Internal error handling error. Could not parse Problem Report message. Reason: {}",
                        err
                    ));
                }
            };

            let comment = body.interpolation();

            ATMError::ProblemReport(
                body.code,
                comment,
                body.escalate_to.unwrap_or("NONE".into()),
            )
        } else {
            // Handling for non-Problem Report messages
            ATMError::SDKError(format!(
                "Internal error handling error. Expecting a DIDComm Problem Report message. Received instead ({})",
                message.type_
            ))
        }
    }
}

impl From<ATMError> for TDKError {
    fn from(err: ATMError) -> Self {
        TDKError::ATM(err.to_string())
    }
}

impl From<TDKError> for ATMError {
    fn from(err: TDKError) -> Self {
        ATMError::TDKError(err.to_string())
    }
}

impl From<DIDAuthError> for ATMError {
    fn from(err: DIDAuthError) -> Self {
        ATMError::AuthenticationError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_problem_report_works() {
        let message = Message::build(
            "example-1".into(),
            "https://didcomm.org/report-problem/2.0/problem-report".into(),
            serde_json::json!({
                "code": "test-code",
                "comment": "Test one {1} two {2} three {3}",
                "escalate_to": "test-escalate",
                "args": ["1", "2", "3"]
            }),
        )
        .finalize();

        let error = ATMError::from_problem_report(&message);

        match error {
            ATMError::ProblemReport(code, comment, escalate) => {
                assert_eq!(code, "test-code");
                assert_eq!(comment, "Test one 1 two 2 three 3");
                assert_eq!(escalate, "test-escalate");
            }
            _ => panic!("Expected ProblemReport error"),
        }
    }

    #[test]
    fn test_from_problem_report_wrong_type() {
        let message = Message::build(
            "example-1".into(),
            "https://didcomm.org/NOT-A-PROBLEM/2.0/problem-report".into(),
            serde_json::json!({
                "code": "test-code",
                "comment": "Test one {1} two {2} three {3}",
                "escalate_to": "test-escalate",
                "args": ["1", "2", "3"]
            }),
        )
        .finalize();

        let error = ATMError::from_problem_report(&message);

        match error {
            ATMError::SDKError(_) => {}
            _ => panic!("Expected SDKError error"),
        }
    }

    #[test]
    fn test_from_problem_report_wrong_body() {
        let message = Message::build(
            "example-1".into(),
            "https://didcomm.org/NOT-A-PROBLEM/2.0/problem-report".into(),
            serde_json::json!({}),
        )
        .finalize();

        let error = ATMError::from_problem_report(&message);

        match error {
            ATMError::SDKError(_) => {}
            _ => panic!("Expected SDKError error"),
        }
    }
}
