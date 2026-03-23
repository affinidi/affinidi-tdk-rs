use crate::DIDError;

/// Check if a character is a valid `idchar` per W3C DID Core 1.0
/// `idchar = ALPHA / DIGIT / "." / "-" / "_"`
/// Note: pct-encoded and ":" are handled separately
fn is_idchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')
}

/// Validate basic identifier format per W3C DID Core 1.0
pub fn validate_identifier_format(s: &str) -> Result<(), DIDError> {
    if s.is_empty() {
        return Err(DIDError::InvalidMethodSpecificId("empty".into()));
    }

    if s.ends_with(':') {
        return Err(DIDError::InvalidMethodSpecificId(
            "cannot end with ':'".into(),
        ));
    }

    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if is_idchar(c) || c == ':' {
            continue;
        }
        if c == '%' {
            match (chars.next(), chars.next()) {
                (Some(h1), Some(h2)) if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() => {
                    continue;
                }
                _ => {
                    return Err(DIDError::InvalidMethodSpecificId(
                        "invalid percent-encoding".into(),
                    ));
                }
            }
        }
        return Err(DIDError::InvalidMethodSpecificId(format!(
            "invalid character '{c}'"
        )));
    }

    Ok(())
}
