use std::collections::HashMap;

/// Issues sequential canonical blank node identifiers: `_:c14n0`, `_:c14n1`, etc.
///
/// Implements the "Issue Identifier" algorithm from RDFC-1.0.
#[derive(Clone, Debug)]
pub struct IdentifierIssuer {
    prefix: String,
    counter: u64,
    issued: HashMap<String, String>,
    order: Vec<String>,
}

impl IdentifierIssuer {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            counter: 0,
            issued: HashMap::new(),
            order: Vec::new(),
        }
    }

    /// Issue a canonical identifier for the given existing blank node identifier.
    /// If already issued, returns the previously issued identifier.
    pub fn issue(&mut self, existing: &str) -> String {
        if let Some(canonical) = self.issued.get(existing) {
            return canonical.clone();
        }
        let canonical = format!("{}{}", self.prefix, self.counter);
        self.counter += 1;
        self.issued.insert(existing.to_string(), canonical.clone());
        self.order.push(existing.to_string());
        canonical
    }

    /// Check if an identifier has already been issued for the given existing ID.
    pub fn is_issued(&self, existing: &str) -> bool {
        self.issued.contains_key(existing)
    }

    /// Get the canonical identifier for the given existing ID, if already issued.
    pub fn get(&self, existing: &str) -> Option<&str> {
        self.issued.get(existing).map(|s| s.as_str())
    }

    /// Iterate over issued identifiers in order of issuance.
    pub fn issued_order(&self) -> &[String] {
        &self.order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_issuance() {
        let mut issuer = IdentifierIssuer::new("c14n");
        assert_eq!(issuer.issue("b0"), "c14n0");
        assert_eq!(issuer.issue("b1"), "c14n1");
        assert_eq!(issuer.issue("b2"), "c14n2");
    }

    #[test]
    fn idempotent() {
        let mut issuer = IdentifierIssuer::new("c14n");
        assert_eq!(issuer.issue("b0"), "c14n0");
        assert_eq!(issuer.issue("b0"), "c14n0");
        assert_eq!(issuer.issue("b1"), "c14n1");
    }

    #[test]
    fn order_preserved() {
        let mut issuer = IdentifierIssuer::new("c14n");
        issuer.issue("x");
        issuer.issue("y");
        issuer.issue("z");
        assert_eq!(issuer.issued_order(), &["x", "y", "z"]);
    }

    #[test]
    fn clone_independent() {
        let mut issuer = IdentifierIssuer::new("c14n");
        issuer.issue("b0");
        let mut cloned = issuer.clone();
        cloned.issue("b1");
        assert!(!issuer.is_issued("b1"));
        assert!(cloned.is_issued("b1"));
    }
}
