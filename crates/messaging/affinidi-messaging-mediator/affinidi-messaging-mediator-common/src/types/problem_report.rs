//! DIDComm Problem Report handling
//! [https://identity.foundation/didcomm-messaging/spec/#problem-reports]
//!
use core::fmt;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ProblemReportScope::Protocol => write!(f, "p"),
            ProblemReportScope::Message => write!(f, "m"),
            ProblemReportScope::Other(ref s) => write!(f, "{s}"),
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
            code: format!("{sorter}.{scope}.{descriptor}"),
            comment,
            args,
            escalate_to,
        }
    }

    /// Render `comment` with its `{1}`, `{2}`, … placeholders replaced by the
    /// corresponding entry of `args` (1-based). A placeholder with no argument
    /// behind it renders as `?`.
    ///
    /// # Why this is a whole-string substitution
    ///
    /// It used to split the comment on spaces and replace a token only when the
    /// *entire* token was a placeholder (`^\{(\d*)\}$`). Any placeholder with
    /// punctuation attached therefore survived verbatim — and the codebase is
    /// full of those. `"Message ({1}) not found"` reached the logs of every
    /// service that failed a delete as literally `Message ({1}) not found`,
    /// naming no message; `"Invalid limit ({1}). Maximum of {2} messages"`
    /// interpolated the limit but not the value that broke it. A report that
    /// cannot name what it is about is the one thing a problem report exists to
    /// do.
    pub fn interpolation(&self) -> String {
        // `{}` with no digits is accepted (and renders `?`) to preserve the
        // previous behaviour for a malformed comment.
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| Regex::new(r"\{(\d*)\}").expect("static pattern is valid"));

        re.replace_all(&self.comment, |cap: &regex::Captures| {
            // 1-based, so `{0}` has no argument and is as malformed as `{}`.
            // `checked_sub` rather than `idx - 1`, which underflows on `{0}`.
            cap[1]
                .parse::<usize>()
                .ok()
                .and_then(|idx| idx.checked_sub(1))
                .and_then(|idx| self.args.get(idx))
                .map(String::as_str)
                .unwrap_or("?")
                .to_string()
        })
        .into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{ProblemReport, ProblemReportScope, ProblemReportSorter};

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

    /// The regression this file exists to prevent: a placeholder wrapped in
    /// punctuation. `"Message ({1}) not found"` is the mediator's own
    /// delete-not-found comment, and it reached service logs uninterpolated —
    /// naming no message — because the old token-wise match required the
    /// placeholder to be a whole space-delimited word.
    #[test]
    fn interpolates_a_placeholder_with_punctuation_around_it() {
        let report = ProblemReport {
            code: "w.m.database.message.delete.not_found".to_string(),
            comment: "Message ({1}) not found".to_string(),
            args: vec!["5c514fa1acd4ca01".to_string()],
            escalate_to: None,
        };
        assert_eq!(
            report.interpolation(),
            "Message (5c514fa1acd4ca01) not found"
        );
    }

    /// Several placeholders in one token, and one that trails punctuation —
    /// the shape of the mediator's limit messages.
    #[test]
    fn interpolates_every_placeholder_in_a_token() {
        let report = ProblemReport {
            code: "e.p.api.message_delete.limit".to_string(),
            comment: "Invalid limit ({1}). Maximum of {2} messages per transaction".to_string(),
            args: vec!["250".to_string(), "100".to_string()],
            escalate_to: None,
        };
        assert_eq!(
            report.interpolation(),
            "Invalid limit (250). Maximum of 100 messages per transaction"
        );
    }

    /// `{0}` is 1-based nonsense and used to underflow `idx - 1`; `{}` has no
    /// index at all. Both render `?` rather than panicking.
    #[test]
    fn malformed_placeholders_render_a_question_mark() {
        let report = ProblemReport {
            code: "e.test.x".to_string(),
            comment: "a {0} b {} c {9}".to_string(),
            args: vec!["only".to_string()],
            escalate_to: None,
        };
        assert_eq!(report.interpolation(), "a ? b ? c ?");
    }

    /// Whitespace is preserved exactly: the old implementation rebuilt the
    /// string by joining on a single space, so a tab or newline in a comment
    /// survived only by accident of being inside a token.
    #[test]
    fn preserves_whitespace_verbatim() {
        let report = ProblemReport {
            code: "e.test.x".to_string(),
            comment: "line one: {1}\n\tline two: {2}".to_string(),
            args: vec!["a".to_string(), "b".to_string()],
            escalate_to: None,
        };
        assert_eq!(report.interpolation(), "line one: a\n\tline two: b");
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
            Err(err) => panic!("Error serializing ProblemReport: {err}"),
        };

        let pr: ProblemReport = match serde_json::from_str(&ser) {
            Ok(pr) => pr,
            Err(err) => panic!("Error deserializing ProblemReport: {err}"),
        };

        assert_eq!(problem_report, pr);
    }
}
