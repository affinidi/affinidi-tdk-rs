/// Escape a string value for N-Quads serialization per W3C spec.
///
/// Escapes: `\t`, `\n`, `\r`, `\"`, `\\`.
/// Characters outside the basic printable range are escaped as `\uXXXX` or `\UXXXXXXXX`.
pub fn escape_nquads(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < '\u{0020}' => {
                // Control characters → \uXXXX
                let cp = c as u32;
                out.push_str(&format!("\\u{cp:04X}"));
            }
            c => out.push(c),
        }
    }
    out
}

/// Unescape an N-Quads string value.
///
/// Handles: `\t`, `\n`, `\r`, `\"`, `\\`, `\uXXXX`, `\UXXXXXXXX`.
pub fn unescape_nquads(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if hex.len() != 4 {
                        return Err(format!("incomplete \\u escape: \\u{hex}"));
                    }
                    let cp = u32::from_str_radix(&hex, 16)
                        .map_err(|_| format!("invalid \\u escape: \\u{hex}"))?;
                    // Handle surrogate pairs
                    if (0xD800..=0xDBFF).contains(&cp) {
                        // High surrogate — expect \uXXXX low surrogate
                        let low_chars = chars.by_ref();
                        match (low_chars.next(), low_chars.next()) {
                            (Some('\\'), Some('u')) => {}
                            _ => return Err(format!("expected low surrogate after \\u{hex}")),
                        }
                        let low_hex: String = low_chars.take(4).collect();
                        if low_hex.len() != 4 {
                            return Err(format!("incomplete low surrogate: \\u{low_hex}"));
                        }
                        let low_cp = u32::from_str_radix(&low_hex, 16)
                            .map_err(|_| format!("invalid low surrogate: \\u{low_hex}"))?;
                        if !(0xDC00..=0xDFFF).contains(&low_cp) {
                            return Err(format!("invalid low surrogate: \\u{low_hex}"));
                        }
                        let combined = 0x10000 + ((cp - 0xD800) << 10) + (low_cp - 0xDC00);
                        let c = char::from_u32(combined)
                            .ok_or_else(|| format!("invalid surrogate pair: \\u{hex}\\u{low_hex}"))?;
                        out.push(c);
                    } else {
                        let c = char::from_u32(cp)
                            .ok_or_else(|| format!("invalid unicode codepoint: \\u{hex}"))?;
                        out.push(c);
                    }
                }
                Some('U') => {
                    let hex: String = chars.by_ref().take(8).collect();
                    if hex.len() != 8 {
                        return Err(format!("incomplete \\U escape: \\U{hex}"));
                    }
                    let cp = u32::from_str_radix(&hex, 16)
                        .map_err(|_| format!("invalid \\U escape: \\U{hex}"))?;
                    let c = char::from_u32(cp)
                        .ok_or_else(|| format!("invalid unicode codepoint: \\U{hex}"))?;
                    out.push(c);
                }
                Some(other) => {
                    return Err(format!("unknown escape sequence: \\{other}"));
                }
                None => {
                    return Err("trailing backslash".to_string());
                }
            }
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_basic() {
        assert_eq!(
            escape_nquads("hello\tworld\n\"test\"\\end"),
            "hello\\tworld\\n\\\"test\\\"\\\\end"
        );
    }

    #[test]
    fn unescape_basic() {
        assert_eq!(
            unescape_nquads("hello\\tworld\\n\\\"test\\\"\\\\end").unwrap(),
            "hello\tworld\n\"test\"\\end"
        );
    }

    #[test]
    fn unescape_unicode_bmp() {
        assert_eq!(unescape_nquads("\\u00E9").unwrap(), "é");
    }

    #[test]
    fn unescape_unicode_supplementary() {
        assert_eq!(unescape_nquads("\\U0001F600").unwrap(), "\u{1F600}");
    }

    #[test]
    fn roundtrip() {
        let original = "line1\nline2\ttab\"quoted\"\\backslash";
        let escaped = escape_nquads(original);
        let unescaped = unescape_nquads(&escaped).unwrap();
        assert_eq!(original, unescaped);
    }

    #[test]
    fn unescape_error_trailing_backslash() {
        assert!(unescape_nquads("test\\").is_err());
    }

    #[test]
    fn unescape_error_unknown_escape() {
        assert!(unescape_nquads("\\x").is_err());
    }
}
