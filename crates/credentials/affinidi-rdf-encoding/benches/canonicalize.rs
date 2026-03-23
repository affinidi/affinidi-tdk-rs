use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;

use affinidi_rdf_encoding::model::*;
use affinidi_rdf_encoding::{jsonld, nquads, rdfc1};

fn b1_credential() -> serde_json::Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
        "type": ["VerifiableCredential", "AlumniCredential"],
        "name": "Alumni Credential",
        "description": "A minimum viable example of an Alumni Credential.",
        "issuer": "https://vc.example/issuers/5678",
        "validFrom": "2023-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:abcdefgh",
            "alumniOf": "The School of Examples"
        }
    })
}

fn b1_proof_options() -> serde_json::Value {
    json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-rdfc-2022",
        "created": "2023-02-24T23:36:38Z",
        "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
        "proofPurpose": "assertionMethod",
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ]
    })
}

fn named_nodes_dataset() -> Dataset {
    let mut ds = Dataset::new();
    for i in 0..8 {
        ds.add(Quad::new(
            NamedNode::new(format!("http://example.org/s{i}")),
            NamedNode::new("http://example.org/p"),
            Literal::new(format!("value {i}")),
            GraphLabel::Default,
        ));
    }
    ds
}

fn bench_canonicalize_no_blank_nodes(c: &mut Criterion) {
    let ds = named_nodes_dataset();
    c.bench_function("canonicalize_no_blank_nodes", |b| {
        b.iter(|| rdfc1::canonicalize(&ds).unwrap())
    });
}

fn bench_canonicalize_with_blank_nodes(c: &mut Criterion) {
    let doc = b1_proof_options();
    let ds = jsonld::expand_and_to_rdf(&doc).unwrap();
    c.bench_function("canonicalize_with_blank_nodes", |b| {
        b.iter(|| rdfc1::canonicalize(&ds).unwrap())
    });
}

fn bench_jsonld_expand_and_to_rdf_vc(c: &mut Criterion) {
    let doc = b1_credential();
    c.bench_function("jsonld_expand_and_to_rdf_vc", |b| {
        b.iter(|| jsonld::expand_and_to_rdf(&doc).unwrap())
    });
}

fn bench_full_pipeline(c: &mut Criterion) {
    let doc = b1_credential();
    c.bench_function("full_pipeline_expand_canonicalize", |b| {
        b.iter(|| affinidi_rdf_encoding::expand_canonicalize_and_hash(&doc).unwrap())
    });
}

fn bench_nquads_parse(c: &mut Criterion) {
    let input = "\
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://schema.org/name> \"Alumni Credential\" .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://schema.org/description> \"A minimum viable example of an Alumni Credential.\" .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#issuer> <https://vc.example/issuers/5678> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#validFrom> \"2023-01-01T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:abcdefgh> .
<did:example:abcdefgh> <https://www.w3.org/ns/credentials/examples#alumniOf> \"The School of Examples\" .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/credentials/examples#AlumniCredential> .
";
    c.bench_function("nquads_parse", |b| b.iter(|| nquads::parse(input).unwrap()));
}

fn bench_nquads_serialize(c: &mut Criterion) {
    let ds = named_nodes_dataset();
    c.bench_function("nquads_serialize", |b| {
        b.iter(|| nquads::serialize_dataset(ds.quads()))
    });
}

criterion_group!(
    benches,
    bench_canonicalize_no_blank_nodes,
    bench_canonicalize_with_blank_nodes,
    bench_jsonld_expand_and_to_rdf_vc,
    bench_full_pipeline,
    bench_nquads_parse,
    bench_nquads_serialize,
);
criterion_main!(benches);
