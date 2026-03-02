use crate::error::{RdfError, Result};
use crate::model::*;
use super::escape::unescape_nquads;

/// Parse an N-Quads document into a Dataset.
pub fn parse(input: &str) -> Result<Dataset> {
    let mut dataset = Dataset::new();
    for (line_num, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let quad = parse_line(trimmed, line_num + 1)?;
        dataset.add(quad);
    }
    Ok(dataset)
}

fn parse_line(line: &str, line_num: usize) -> Result<Quad> {
    let mut cursor = Cursor::new(line, line_num);

    let subject = cursor.parse_subject()?;
    cursor.skip_whitespace();
    let predicate = cursor.parse_iri()?;
    cursor.skip_whitespace();
    let object = cursor.parse_object()?;
    cursor.skip_whitespace();

    // Optional graph
    let graph = if cursor.peek() == Some('.') {
        GraphLabel::Default
    } else {
        let g = cursor.parse_graph()?;
        cursor.skip_whitespace();
        g
    };

    cursor.expect_char('.')?;
    // Allow trailing whitespace after the dot
    cursor.skip_whitespace();
    if cursor.peek().is_some() {
        return Err(RdfError::parse(format!(
            "line {line_num}: unexpected content after '.'"
        )));
    }

    Ok(Quad {
        subject,
        predicate,
        object,
        graph,
    })
}

struct Cursor<'a> {
    input: &'a str,
    pos: usize,
    line_num: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a str, line_num: usize) -> Self {
        Self {
            input,
            pos: 0,
            line_num,
        }
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek() {
            if ch == ' ' || ch == '\t' {
                self.advance(ch.len_utf8());
            } else {
                break;
            }
        }
    }

    fn expect_char(&mut self, expected: char) -> Result<()> {
        match self.peek() {
            Some(ch) if ch == expected => {
                self.advance(ch.len_utf8());
                Ok(())
            }
            Some(ch) => Err(RdfError::parse(format!(
                "line {}: expected '{}', found '{}'",
                self.line_num, expected, ch
            ))),
            None => Err(RdfError::parse(format!(
                "line {}: expected '{}', found end of input",
                self.line_num, expected
            ))),
        }
    }

    fn parse_iri(&mut self) -> Result<NamedNode> {
        self.expect_char('<')?;
        let start = self.pos;
        loop {
            match self.peek() {
                Some('>') => {
                    let iri = &self.input[start..self.pos];
                    self.advance(1); // skip '>'
                    return Ok(NamedNode::new(iri));
                }
                Some(_) => self.advance(1),
                None => {
                    return Err(RdfError::parse(format!(
                        "line {}: unterminated IRI",
                        self.line_num
                    )));
                }
            }
        }
    }

    fn parse_blank_node(&mut self) -> Result<BlankNode> {
        // Expect "_:"
        self.expect_char('_')?;
        self.expect_char(':')?;
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch == ' ' || ch == '\t' || ch == '.' || ch == '<' {
                break;
            }
            self.advance(ch.len_utf8());
        }
        let id = &self.input[start..self.pos];
        if id.is_empty() {
            return Err(RdfError::parse(format!(
                "line {}: empty blank node label",
                self.line_num
            )));
        }
        Ok(BlankNode::new(id))
    }

    fn parse_subject(&mut self) -> Result<Subject> {
        match self.peek() {
            Some('<') => Ok(Subject::Named(self.parse_iri()?)),
            Some('_') => Ok(Subject::Blank(self.parse_blank_node()?)),
            Some(ch) => Err(RdfError::parse(format!(
                "line {}: unexpected character '{}' in subject position",
                self.line_num, ch
            ))),
            None => Err(RdfError::parse(format!(
                "line {}: unexpected end of input in subject position",
                self.line_num
            ))),
        }
    }

    fn parse_object(&mut self) -> Result<Object> {
        match self.peek() {
            Some('<') => Ok(Object::Named(self.parse_iri()?)),
            Some('_') => Ok(Object::Blank(self.parse_blank_node()?)),
            Some('"') => Ok(Object::Literal(self.parse_literal()?)),
            Some(ch) => Err(RdfError::parse(format!(
                "line {}: unexpected character '{}' in object position",
                self.line_num, ch
            ))),
            None => Err(RdfError::parse(format!(
                "line {}: unexpected end of input in object position",
                self.line_num
            ))),
        }
    }

    fn parse_graph(&mut self) -> Result<GraphLabel> {
        match self.peek() {
            Some('<') => Ok(GraphLabel::Named(self.parse_iri()?)),
            Some('_') => Ok(GraphLabel::Blank(self.parse_blank_node()?)),
            _ => Ok(GraphLabel::Default),
        }
    }

    fn parse_literal(&mut self) -> Result<Literal> {
        self.expect_char('"')?;
        let mut raw = String::new();
        // Read until unescaped quote
        loop {
            match self.peek() {
                Some('\\') => {
                    raw.push('\\');
                    self.advance(1);
                    match self.peek() {
                        Some(ch) => {
                            raw.push(ch);
                            self.advance(ch.len_utf8());
                            // For \u and \U, also capture hex digits into raw
                            if ch == 'u' {
                                for _ in 0..4 {
                                    if let Some(h) = self.peek() {
                                        raw.push(h);
                                        self.advance(h.len_utf8());
                                    }
                                }
                            } else if ch == 'U' {
                                for _ in 0..8 {
                                    if let Some(h) = self.peek() {
                                        raw.push(h);
                                        self.advance(h.len_utf8());
                                    }
                                }
                            }
                        }
                        None => {
                            return Err(RdfError::parse(format!(
                                "line {}: trailing backslash in literal",
                                self.line_num
                            )));
                        }
                    }
                }
                Some('"') => {
                    self.advance(1);
                    break;
                }
                Some(ch) => {
                    raw.push(ch);
                    self.advance(ch.len_utf8());
                }
                None => {
                    return Err(RdfError::parse(format!(
                        "line {}: unterminated string literal",
                        self.line_num
                    )));
                }
            }
        }

        // Unescape the raw string
        let value = unescape_nquads(&raw).map_err(|e| {
            RdfError::parse(format!("line {}: {e}", self.line_num))
        })?;

        // Check for language tag or datatype
        match self.peek() {
            Some('@') => {
                self.advance(1);
                let start = self.pos;
                while let Some(ch) = self.peek() {
                    if ch == ' ' || ch == '\t' || ch == '.' {
                        break;
                    }
                    self.advance(ch.len_utf8());
                }
                let lang = &self.input[start..self.pos];
                Ok(Literal::lang(value, lang))
            }
            Some('^') => {
                self.advance(1);
                self.expect_char('^')?;
                let datatype = self.parse_iri()?;
                Ok(Literal::typed(value, datatype))
            }
            _ => Ok(Literal::new(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_triple() {
        let input = "<http://example.org/s> <http://example.org/p> <http://example.org/o> .\n";
        let ds = parse(input).unwrap();
        assert_eq!(ds.quads().len(), 1);
        let q = &ds.quads()[0];
        assert_eq!(
            q.subject,
            Subject::Named(NamedNode::new("http://example.org/s"))
        );
        assert_eq!(q.predicate, NamedNode::new("http://example.org/p"));
        assert_eq!(
            q.object,
            Object::Named(NamedNode::new("http://example.org/o"))
        );
        assert_eq!(q.graph, GraphLabel::Default);
    }

    #[test]
    fn parse_blank_nodes() {
        let input = "_:b0 <http://example.org/p> _:b1 .\n";
        let ds = parse(input).unwrap();
        assert_eq!(ds.quads().len(), 1);
        let q = &ds.quads()[0];
        assert_eq!(q.subject, Subject::Blank(BlankNode::new("b0")));
        assert_eq!(q.object, Object::Blank(BlankNode::new("b1")));
    }

    #[test]
    fn parse_typed_literal() {
        let input = "<http://example.org/s> <http://example.org/p> \"42\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n";
        let ds = parse(input).unwrap();
        let q = &ds.quads()[0];
        match &q.object {
            Object::Literal(lit) => {
                assert_eq!(lit.value, "42");
                assert_eq!(lit.datatype.iri, xsd::INTEGER);
                assert!(lit.language.is_none());
            }
            _ => panic!("expected literal"),
        }
    }

    #[test]
    fn parse_lang_literal() {
        let input = "<http://example.org/s> <http://example.org/p> \"bonjour\"@fr .\n";
        let ds = parse(input).unwrap();
        let q = &ds.quads()[0];
        match &q.object {
            Object::Literal(lit) => {
                assert_eq!(lit.value, "bonjour");
                assert_eq!(lit.language.as_deref(), Some("fr"));
            }
            _ => panic!("expected literal"),
        }
    }

    #[test]
    fn parse_named_graph() {
        let input = "<http://example.org/s> <http://example.org/p> <http://example.org/o> <http://example.org/g> .\n";
        let ds = parse(input).unwrap();
        let q = &ds.quads()[0];
        assert_eq!(
            q.graph,
            GraphLabel::Named(NamedNode::new("http://example.org/g"))
        );
    }

    #[test]
    fn parse_escaped_literal() {
        let input = r#"<http://example.org/s> <http://example.org/p> "line1\nline2\t\"quoted\"" ."#;
        let ds = parse(input).unwrap();
        let q = &ds.quads()[0];
        match &q.object {
            Object::Literal(lit) => {
                assert_eq!(lit.value, "line1\nline2\t\"quoted\"");
            }
            _ => panic!("expected literal"),
        }
    }

    #[test]
    fn parse_skip_comments_and_empty() {
        let input = "# comment\n\n<http://example.org/s> <http://example.org/p> <http://example.org/o> .\n\n";
        let ds = parse(input).unwrap();
        assert_eq!(ds.quads().len(), 1);
    }

    #[test]
    fn parse_multiple_quads() {
        let input = "\
<http://example.org/s1> <http://example.org/p> <http://example.org/o1> .
<http://example.org/s2> <http://example.org/p> <http://example.org/o2> .
";
        let ds = parse(input).unwrap();
        assert_eq!(ds.quads().len(), 2);
    }

    #[test]
    fn parse_error_malformed() {
        let result = parse("not valid nquads\n");
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_parse_serialize() {
        let input = "<http://example.org/s> <http://example.org/p> \"hello world\" .\n";
        let ds = parse(input).unwrap();
        let output = super::super::serializer::serialize_dataset(ds.quads());
        assert_eq!(input, output);
    }
}
