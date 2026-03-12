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

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_handler() -> Arc<dyn MessageHandler> {
        use crate::handler::HandlerContext;
        use crate::router::handler::{HandlerFn, handler_fn};

        async fn noop(
            _ctx: HandlerContext,
        ) -> Result<Option<crate::response::DIDCommResponse>, crate::error::DIDCommServiceError>
        {
            Ok(None)
        }

        Arc::new(handler_fn(noop))
    }

    #[test]
    fn new_exact_match() {
        let route = Route::new("https://example.com/protocols/ping/1.0", dummy_handler());
        assert!(route.matches("https://example.com/protocols/ping/1.0"));
    }

    #[test]
    fn new_does_not_match_substring() {
        let route = Route::new("https://example.com/protocols/ping/1.0", dummy_handler());
        assert!(!route.matches("https://example.com/protocols/ping/1.0/extra"));
        assert!(!route.matches("prefix/https://example.com/protocols/ping/1.0"));
    }

    #[test]
    fn new_escapes_special_chars() {
        let route = Route::new("type.with+special(chars)", dummy_handler());
        assert!(route.matches("type.with+special(chars)"));
        assert!(!route.matches("typeXwith+special(chars)"));
    }

    #[test]
    fn new_preserves_explicit_anchors() {
        let route = Route::new("^already-anchored$", dummy_handler());
        assert!(route.matches("already-anchored"));
    }

    #[test]
    fn regex_pattern_match() {
        let route = Route::regex("https://example.com/protocols/.*/1\\.0", dummy_handler());
        assert!(route.matches("https://example.com/protocols/ping/1.0"));
        assert!(route.matches("https://example.com/protocols/trust-ping/1.0"));
    }

    #[test]
    fn regex_no_match() {
        let route = Route::regex("https://example.com/protocols/.*/1\\.0", dummy_handler());
        assert!(!route.matches("https://example.com/protocols/ping/2.0"));
    }

    #[test]
    fn regex_auto_anchors_both() {
        let route = Route::regex("foo.*bar", dummy_handler());
        assert!(route.matches("fooXbar"));
        assert!(!route.matches("prefixfooXbar"));
        assert!(!route.matches("fooXbarsuffix"));
    }

    #[test]
    fn regex_preserves_existing_start_anchor() {
        let route = Route::regex("^foo.*", dummy_handler());
        assert!(route.matches("foobar"));
        assert!(!route.matches("Xfoo"));
    }

    #[test]
    fn regex_preserves_existing_end_anchor() {
        let route = Route::regex(".*bar$", dummy_handler());
        assert!(route.matches("foobar"));
        assert!(!route.matches("barX"));
    }

    #[test]
    fn regex_preserves_both_anchors() {
        let route = Route::regex("^exact$", dummy_handler());
        assert!(route.matches("exact"));
        assert!(!route.matches("notexact"));
    }
}
