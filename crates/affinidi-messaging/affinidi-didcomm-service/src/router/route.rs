use std::sync::Arc;

use regex::Regex;

use super::handler::MessageHandler;

pub(crate) struct Route {
    pub pattern: Regex,
    pub handler: Arc<dyn MessageHandler>,
}

impl Route {
    pub fn new(pattern: &str, handler: Arc<dyn MessageHandler>) -> Self {
        let anchored = if pattern.starts_with('^') {
            pattern.to_string()
        } else {
            format!("^{}$", regex::escape(pattern))
        };

        let regex = Regex::new(&anchored).unwrap_or_else(|e| {
            panic!("Invalid route pattern '{pattern}': {e}");
        });

        Self {
            pattern: regex,
            handler,
        }
    }

    pub fn regex(pattern: &str, handler: Arc<dyn MessageHandler>) -> Self {
        let anchored = if pattern.starts_with('^') && pattern.ends_with('$') {
            pattern.to_string()
        } else if pattern.starts_with('^') {
            format!("{pattern}$")
        } else if pattern.ends_with('$') {
            format!("^{pattern}")
        } else {
            format!("^{pattern}$")
        };

        let regex = Regex::new(&anchored).unwrap_or_else(|e| {
            panic!("Invalid route regex '{pattern}': {e}");
        });

        Self {
            pattern: regex,
            handler,
        }
    }

    pub fn matches(&self, message_type: &str) -> bool {
        self.pattern.is_match(message_type)
    }
}
