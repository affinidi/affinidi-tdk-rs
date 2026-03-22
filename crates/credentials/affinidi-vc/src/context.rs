/*!
 * JSON-LD context constants and validation for Verifiable Credentials.
 *
 * Per W3C VCDM, the first context MUST be the base credentials context.
 */

/// W3C Verifiable Credentials v1.1 context URI.
pub const CREDENTIALS_V1_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";

/// W3C Verifiable Credentials v2.0 context URI.
pub const CREDENTIALS_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

/// Detect the VCDM version from the `@context` array.
///
/// Returns `Some(1)` for VCDM 1.1, `Some(2)` for VCDM 2.0, or `None` if
/// neither base context is found in the first position.
pub fn detect_version(contexts: &[String]) -> Option<u8> {
    contexts.first().and_then(|first| {
        if first == CREDENTIALS_V1_CONTEXT {
            Some(1)
        } else if first == CREDENTIALS_V2_CONTEXT {
            Some(2)
        } else {
            None
        }
    })
}

/// Validate that the context array has a valid base context as the first entry.
pub fn validate_contexts(contexts: &[String]) -> crate::error::Result<u8> {
    detect_version(contexts).ok_or_else(|| {
        crate::error::VcError::MissingContext(
            "first @context must be the W3C Credentials v1 or v2 context URI".into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_v1() {
        let contexts = vec![CREDENTIALS_V1_CONTEXT.to_string()];
        assert_eq!(detect_version(&contexts), Some(1));
    }

    #[test]
    fn detect_v2() {
        let contexts = vec![CREDENTIALS_V2_CONTEXT.to_string()];
        assert_eq!(detect_version(&contexts), Some(2));
    }

    #[test]
    fn detect_unknown() {
        let contexts = vec!["https://example.com".to_string()];
        assert_eq!(detect_version(&contexts), None);
    }

    #[test]
    fn detect_empty() {
        let contexts: Vec<String> = vec![];
        assert_eq!(detect_version(&contexts), None);
    }

    #[test]
    fn validate_v1_succeeds() {
        let contexts = vec![
            CREDENTIALS_V1_CONTEXT.to_string(),
            "https://example.com/custom".to_string(),
        ];
        assert_eq!(validate_contexts(&contexts).unwrap(), 1);
    }

    #[test]
    fn validate_v2_succeeds() {
        let contexts = vec![CREDENTIALS_V2_CONTEXT.to_string()];
        assert_eq!(validate_contexts(&contexts).unwrap(), 2);
    }

    #[test]
    fn validate_missing_base_context_fails() {
        let contexts = vec!["https://example.com".to_string()];
        assert!(validate_contexts(&contexts).is_err());
    }
}
