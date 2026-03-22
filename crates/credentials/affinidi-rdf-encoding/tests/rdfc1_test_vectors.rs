use affinidi_rdf_encoding::model::*;
use affinidi_rdf_encoding::rdfc1;

/// Test: dataset with no blank nodes should just sort the N-Quads lines.
#[test]
fn no_blank_nodes() {
    let mut ds = Dataset::new();
    // Add quads in reverse sort order
    ds.add(Quad::new(
        NamedNode::new("http://example.org/s2"),
        NamedNode::new("http://example.org/p"),
        Literal::new("value2"),
        GraphLabel::Default,
    ));
    ds.add(Quad::new(
        NamedNode::new("http://example.org/s1"),
        NamedNode::new("http://example.org/p"),
        Literal::new("value1"),
        GraphLabel::Default,
    ));

    let result = rdfc1::canonicalize(&ds).unwrap();
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 2);
    // Should be sorted
    assert!(lines[0].contains("s1"));
    assert!(lines[1].contains("s2"));
}

/// Test: single blank node gets renamed to _:c14n0.
#[test]
fn single_blank_node() {
    let mut ds = Dataset::new();
    ds.add(Quad::new(
        BlankNode::new("original"),
        NamedNode::new("http://example.org/p"),
        Literal::new("value"),
        GraphLabel::Default,
    ));

    let result = rdfc1::canonicalize(&ds).unwrap();
    assert!(result.contains("_:c14n0"));
    assert!(!result.contains("_:original"));
}

/// Test: multiple blank nodes with unique first-degree hashes.
#[test]
fn unique_first_degree_hashes() {
    let mut ds = Dataset::new();
    // Two blank nodes with different properties → unique first-degree hashes
    ds.add(Quad::new(
        BlankNode::new("b0"),
        NamedNode::new("http://example.org/name"),
        Literal::new("Alice"),
        GraphLabel::Default,
    ));
    ds.add(Quad::new(
        BlankNode::new("b1"),
        NamedNode::new("http://example.org/name"),
        Literal::new("Bob"),
        GraphLabel::Default,
    ));

    let result = rdfc1::canonicalize(&ds).unwrap();
    assert!(result.contains("_:c14n0"));
    assert!(result.contains("_:c14n1"));
    // Original labels should be gone
    assert!(!result.contains("_:b0"));
    assert!(!result.contains("_:b1"));
}

/// Test: different blank node labels for the same structure produce identical output.
#[test]
fn deterministic_across_labels() {
    let make_dataset = |label1: &str, label2: &str| {
        let mut ds = Dataset::new();
        ds.add(Quad::new(
            BlankNode::new(label1),
            NamedNode::new("http://example.org/name"),
            Literal::new("Alice"),
            GraphLabel::Default,
        ));
        ds.add(Quad::new(
            BlankNode::new(label2),
            NamedNode::new("http://example.org/name"),
            Literal::new("Bob"),
            GraphLabel::Default,
        ));
        ds.add(Quad::new(
            BlankNode::new(label1),
            NamedNode::new("http://example.org/knows"),
            BlankNode::new(label2),
            GraphLabel::Default,
        ));
        ds
    };

    let ds1 = make_dataset("x", "y");
    let ds2 = make_dataset("a", "b");
    let ds3 = make_dataset("node99", "node1");

    let result1 = rdfc1::canonicalize(&ds1).unwrap();
    let result2 = rdfc1::canonicalize(&ds2).unwrap();
    let result3 = rdfc1::canonicalize(&ds3).unwrap();

    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
}

/// Test: blank nodes in a cycle (mutual references).
#[test]
fn cycle_detection() {
    let mut ds = Dataset::new();
    ds.add(Quad::new(
        BlankNode::new("a"),
        NamedNode::new("http://example.org/next"),
        BlankNode::new("b"),
        GraphLabel::Default,
    ));
    ds.add(Quad::new(
        BlankNode::new("b"),
        NamedNode::new("http://example.org/next"),
        BlankNode::new("a"),
        GraphLabel::Default,
    ));

    let result = rdfc1::canonicalize(&ds).unwrap();
    assert!(result.contains("_:c14n0"));
    assert!(result.contains("_:c14n1"));
    // The two quads should both be present
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 2);
}

/// Test: named graph quads are preserved and sorted.
#[test]
fn named_graph() {
    let mut ds = Dataset::new();
    ds.add(Quad::new(
        NamedNode::new("http://example.org/s"),
        NamedNode::new("http://example.org/p"),
        Literal::new("in graph"),
        GraphLabel::Named(NamedNode::new("http://example.org/g")),
    ));
    ds.add(Quad::new(
        NamedNode::new("http://example.org/s"),
        NamedNode::new("http://example.org/p"),
        Literal::new("default graph"),
        GraphLabel::Default,
    ));

    let result = rdfc1::canonicalize(&ds).unwrap();
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 2);
    // Both quads should be present
    assert!(result.contains("in graph"));
    assert!(result.contains("default graph"));
}

/// Test: blank node in object position.
#[test]
fn blank_node_object() {
    let mut ds = Dataset::new();
    ds.add(Quad::new(
        NamedNode::new("http://example.org/s"),
        NamedNode::new("http://example.org/p"),
        BlankNode::new("obj"),
        GraphLabel::Default,
    ));
    ds.add(Quad::new(
        BlankNode::new("obj"),
        NamedNode::new("http://example.org/name"),
        Literal::new("Object Node"),
        GraphLabel::Default,
    ));

    let result = rdfc1::canonicalize(&ds).unwrap();
    assert!(result.contains("_:c14n0"));
    assert!(!result.contains("_:obj"));
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 2);
}

/// Test: shared/non-unique blank node hashes (blank nodes with identical structure).
#[test]
fn non_unique_hashes() {
    let mut ds = Dataset::new();
    // Two blank nodes with identical first-degree hash structure
    // Both have the same predicate and same literal value
    ds.add(Quad::new(
        BlankNode::new("b0"),
        NamedNode::new("http://example.org/value"),
        Literal::new("same"),
        GraphLabel::Default,
    ));
    ds.add(Quad::new(
        BlankNode::new("b1"),
        NamedNode::new("http://example.org/value"),
        Literal::new("same"),
        GraphLabel::Default,
    ));
    // Add a relationship to disambiguate
    ds.add(Quad::new(
        NamedNode::new("http://example.org/root"),
        NamedNode::new("http://example.org/first"),
        BlankNode::new("b0"),
        GraphLabel::Default,
    ));
    ds.add(Quad::new(
        NamedNode::new("http://example.org/root"),
        NamedNode::new("http://example.org/second"),
        BlankNode::new("b1"),
        GraphLabel::Default,
    ));

    let result = rdfc1::canonicalize(&ds).unwrap();
    assert!(result.contains("_:c14n0"));
    assert!(result.contains("_:c14n1"));
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 4);
}
