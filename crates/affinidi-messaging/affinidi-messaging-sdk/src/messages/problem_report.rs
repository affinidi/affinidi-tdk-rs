//! DIDComm Problem Report handling
//! [https://identity.foundation/didcomm-messaging/spec/#problem-reports]
//!
use core::fmt;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Deserialize, PartialEq)]
pub struct ProblemReport {
    pub code: String,
    pub comment: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub args: Vec<String>,
    #[serde(rename = "escalate_to", skip_serializing_if = "Option::is_none")]
    pub escalate_to: Option<String>,
}

impl fmt::Display for ProblemReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Problem Report: code: {}, comment: {}, escalate_to: {:?}",
            self.code,
            self.interpolation(),
            self.escalate_to
        )
    }
}

/// DIDComm Problem Report Sorter Code
/// - `Error` - Error, a clear failure to achieve goal)
/// - `Warning` - Warning, may be a problem - up to the receiver to decide.
#[derive(Serialize, Deserialize)]
pub enum ProblemReportSorter {
    Error,
    Warning,
}

impl fmt::Display for ProblemReportSorter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ProblemReportSorter::Error => write!(f, "e"),
            ProblemReportSorter::Warning => write!(f, "w"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum ProblemReportScope {
    Protocol,
    Message,
    Other(String),
}

impl fmt::Display for ProblemReportScope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ProblemReportScope::Protocol => write!(f, "p"),
            ProblemReportScope::Message => write!(f, "m"),
            ProblemReportScope::Other(ref s) => write!(f, "{}", s),
        }
    }
}

impl ProblemReport {
    /// Create a new Problem Report
    /// - `sorter` - The sorter code (Problem or Warning?)
    /// - `scope` - The scope code (Protocol, Message, or Other)
    /// - `descriptor` - The descriptor code (e.g. `trust.crypto` = Cryptographic operation failed)
    /// - `comment` - A human-readable comment (arguments must be in {1} {2} {n} format)
    /// - `args` - Arguments to the comment
    ///
    /// Example:
    /// let comment = "authentication for {1} failed due to {2}";
    /// let args = vec!["Alice".to_string(), "invalid signature".to_string()];
    pub fn new(
        sorter: ProblemReportSorter,
        scope: ProblemReportScope,
        descriptor: String,
        comment: String,
        args: Vec<String>,
        escalate_to: Option<String>,
    ) -> Self {
        ProblemReport {
            code: format!("{}.{}.{}", sorter, scope, descriptor),
            comment,
            args,
            escalate_to,
        }
    }

    pub fn interpolation(&self) -> String {
        let mut output: Vec<String> = Vec::new();
        let re = Regex::new(r"^\{(\d*)\}$").unwrap();
        for part in self.comment.split(" ") {
            match re.captures(part) {
                Some(cap) => {
                    if let Some(num) = cap.get(1) {
                        if let Ok(idx) = num.as_str().parse::<usize>() {
                            if let Some(arg) = self.args.get(idx - 1) {
                                output.push(arg.to_string());
                            } else {
                                output.push("?".to_string());
                            }
                        } else {
                            output.push("?".to_string());
                        }
                    } else {
                        output.push("?".to_string())
                    }
                }
                _ => {
                    output.push(part.to_string());
                }
            }
        }

        output.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use crate::messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter};

    #[test]
    fn test_problem_report() {
        let comment = "authentication for {1} failed due to {2}";
        let args = vec!["Alice".to_string(), "invalid signature".to_string()];
        let problem_report = ProblemReport::new(
            ProblemReportSorter::Error,
            ProblemReportScope::Other("test".to_string()),
            "authentication".to_string(),
            comment.to_string(),
            args.clone(),
            None,
        );

        assert_eq!(problem_report.code, "e.test.authentication");
        assert_eq!(problem_report.comment, comment);
        assert_eq!(problem_report.args, args);
    }

    #[test]
    fn test_problem_report_interpolation_works() {
        let problem_report = ProblemReport {
            code: "e.test.authentication".to_string(),
            comment: "authentication for {1} failed due to {2} {3}".to_string(),
            args: vec!["Alice".to_string(), "invalid signature".to_string()],
            escalate_to: None,
        };
        assert_eq!(
            problem_report.interpolation(),
            "authentication for Alice failed due to invalid signature ?".to_string()
        );
    }

    #[test]
    fn test_problem_report_empty_args() {
        let comment = "test of no interpolation required";
        let args = vec![];
        let problem_report = ProblemReport::new(
            ProblemReportSorter::Error,
            ProblemReportScope::Other("test".to_string()),
            "authentication".to_string(),
            comment.to_string(),
            args.clone(),
            None,
        );

        assert_eq!(problem_report.code, "e.test.authentication");
        assert_eq!(problem_report.comment, comment);
        assert_eq!(problem_report.args, args);
    }

    #[test]
    fn test_problem_report_serialize_empty() {
        let comment = "test of no interpolation required";
        let args = vec![];
        let problem_report = ProblemReport::new(
            ProblemReportSorter::Error,
            ProblemReportScope::Other("test".to_string()),
            "authentication".to_string(),
            comment.to_string(),
            args.clone(),
            None,
        );

        let ser = match serde_json::to_string(&problem_report) {
            Ok(ser) => ser,
            Err(err) => panic!("Error serializing ProblemReport: {}", err),
        };

        let pr: ProblemReport = match serde_json::from_str(&ser) {
            Ok(pr) => pr,
            Err(err) => panic!("Error deserializing ProblemReport: {}", err),
        };

        assert_eq!(problem_report, pr);
    }
}
