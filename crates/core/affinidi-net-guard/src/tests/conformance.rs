//! Runs `conformance/egress-vectors.v1.json` against this crate.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Name, Resolve};
use serde_json::{Map, Value};
use url::Url;

use super::harness::{self, Counter, Network, Route, StubResolver};
use crate::{
    AllowList, Cidr, DevLoopback, EgressError, EgressPolicy, GuardedClient, GuardedClientBuilder,
    GuardedResolver, HostRule, IpClass, PortPolicy, RedirectMode, Scheme, blocked_in_chain,
    classify, is_globally_routable,
};

const VECTORS: &str = include_str!("../../conformance/egress-vectors.v1.json");

const SECTIONS: &[&str] = &[
    "ip",
    "url",
    "names",
    "scheme",
    "webvh",
    "mediatorDoc",
    "dns",
    "rebinding",
    "redirect",
];

/// Capabilities this runner implements.
const SUPPORTED: &[&str] = &["classify", "vet", "dns", "pinning", "redirect-inspect"];

/// Capabilities this runner does not implement, and why. A capability in
/// neither list fails the run.
const NOT_SUPPORTED: &[(&str, &str)] = &[
    (
        "webvh-url",
        "did:webvh URL derivation belongs to didwebvh-rs, whose runner executes this section",
    ),
    (
        "mediator-doc",
        "DID-document endpoint extraction belongs to the consuming SDK, not the guard",
    ),
    (
        "dns-online",
        "this runner is hermetic; the online DNS job is optional",
    ),
];

const POLICY_FIELDS: &[&str] = &["devLoopback", "allowList", "allowCidrs", "ports", "schemes"];

#[derive(Default)]
struct Tally {
    passed: usize,
    skipped: Vec<(String, usize, &'static str)>,
}

impl Tally {
    fn skip(&mut self, what: String, count: usize, reason: &'static str) {
        self.skipped.push((what, count, reason));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn egress_vectors_v1() {
    let document: Value = serde_json::from_str(VECTORS).expect("vector file is JSON");
    assert_eq!(document["version"], 1, "this runner implements version 1");
    let declared = document["capabilities"]
        .as_object()
        .expect("a capabilities object");
    let sections = document["sections"].as_object().expect("a sections object");
    for expected in SECTIONS {
        assert!(
            sections.contains_key(*expected),
            "section `{expected}` is missing from the vector file"
        );
    }

    let mut tally = Tally::default();
    for (name, section) in sections {
        assert!(
            SECTIONS.contains(&name.as_str()),
            "unknown section `{name}`: a runner must fail rather than ignore it"
        );
        let vectors = section["vectors"]
            .as_array()
            .unwrap_or_else(|| panic!("section `{name}` has no vectors"));
        let context = format!("section `{name}`");
        if let Some(reason) = missing_capability(declared, section.get("requires"), &context) {
            tally.skip(name.clone(), vectors.len(), reason);
            continue;
        }
        match name.as_str() {
            "ip" => run_ip(vectors, &mut tally),
            "url" | "names" | "scheme" => run_vet(name, vectors, declared, &mut tally),
            "dns" => run_dns(vectors, declared, &mut tally).await,
            "rebinding" => run_rebinding(vectors, &mut tally).await,
            "redirect" => run_redirect(section, vectors, &mut tally).await,
            other => panic!("section `{other}` is runnable but this runner has no arm for it"),
        }
    }

    let skipped: usize = tally.skipped.iter().map(|(_, count, _)| count).sum();
    println!(
        "egress-vectors.v1: {} passed, {skipped} skipped",
        tally.passed
    );
    for (what, count, reason) in &tally.skipped {
        println!("  skipped {count} in {what}: {reason}");
    }
    assert!(tally.passed > 0, "no vectors ran");
}

fn missing_capability(
    declared: &Map<String, Value>,
    requires: Option<&Value>,
    context: &str,
) -> Option<&'static str> {
    for capability in requires.and_then(Value::as_array).into_iter().flatten() {
        let capability = capability.as_str().expect("capability names are strings");
        assert!(
            declared.contains_key(capability),
            "{context} requires `{capability}`, which the file does not declare"
        );
        if SUPPORTED.contains(&capability) {
            continue;
        }
        let reason = NOT_SUPPORTED
            .iter()
            .find(|(name, _)| *name == capability)
            .map(|(_, reason)| *reason)
            .unwrap_or_else(|| {
                panic!(
                    "{context} requires `{capability}`, which this runner neither supports nor \
                     declares a reason to skip"
                )
            });
        return Some(reason);
    }
    None
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("vector {value} needs a string `{key}`"))
}

fn ips(value: &Value) -> Vec<IpAddr> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{value} is not an array of addresses"))
        .iter()
        .map(|ip| {
            ip.as_str()
                .and_then(|ip| ip.parse().ok())
                .unwrap_or_else(|| panic!("{ip} is not an IP address"))
        })
        .collect()
}

fn scheme_named(name: &str) -> Scheme {
    match name {
        "https" => Scheme::Https,
        "wss" => Scheme::Wss,
        "http" => Scheme::Http,
        "ws" => Scheme::Ws,
        other => panic!("unknown scheme {other}"),
    }
}

fn policy_from(spec: Option<&Value>) -> EgressPolicy {
    let mut policy = EgressPolicy::public_internet();
    let Some(spec) = spec else {
        return policy;
    };
    for key in spec.as_object().expect("a policy object").keys() {
        assert!(
            POLICY_FIELDS.contains(&key.as_str()),
            "unknown policy field `{key}`: a runner must fail rather than ignore it"
        );
    }
    if spec["devLoopback"].as_bool() == Some(true) {
        policy = policy
            .with_dev_loopback(DevLoopback::acknowledge_ssrf_protection_disabled_for_loopback());
    }
    if let Some(rules) = spec["allowList"].as_array() {
        let rules = rules.iter().map(|rule| {
            if let Some(host) = rule["exact"].as_str() {
                HostRule::Exact(host.to_owned())
            } else if let Some(domain) = rule["suffix"].as_str() {
                HostRule::Suffix(domain.to_owned())
            } else if let Some(origin) = rule["origin"].as_str() {
                let origin = Url::parse(origin).expect("origin rule is a URL");
                HostRule::Origin {
                    scheme: scheme_named(origin.scheme()),
                    host: origin.host_str().expect("origin host").to_owned(),
                    port: origin.port_or_known_default().expect("origin port"),
                }
            } else {
                panic!("unknown allow-list rule {rule}")
            }
        });
        policy = policy.with_allow_list(AllowList::new(rules).expect("valid allow-list"));
    }
    if let Some(cidrs) = spec["allowCidrs"].as_array() {
        policy =
            policy.allow_cidrs(cidrs.iter().map(|cidr| {
                Cidr::from_str(cidr.as_str().expect("CIDR string")).expect("valid CIDR")
            }));
    }
    if let Some(ports) = spec["ports"].as_array() {
        policy = policy.with_ports(PortPolicy::Only(
            ports
                .iter()
                .map(|port| {
                    port.as_u64()
                        .and_then(|port| u16::try_from(port).ok())
                        .expect("port number")
                })
                .collect(),
        ));
    }
    if let Some(schemes) = spec["schemes"].as_array() {
        let schemes: Vec<Scheme> = schemes
            .iter()
            .map(|scheme| scheme_named(scheme.as_str().expect("scheme string")))
            .collect();
        policy = policy.with_schemes(&schemes);
    }
    policy
}

fn mode_from(spec: Option<&Value>) -> RedirectMode {
    let Some(spec) = spec else {
        return RedirectMode::None;
    };
    let max = || {
        spec["max"]
            .as_u64()
            .and_then(|max| u8::try_from(max).ok())
            .expect("redirect max")
    };
    match text(spec, "type") {
        "none" => RedirectMode::None,
        "revet" => RedirectMode::ReVet { max: max() },
        "same-origin" => RedirectMode::SameOrigin { max: max() },
        other => panic!("unknown redirect mode {other}"),
    }
}

fn reason_of(error: &EgressError) -> &'static str {
    match error {
        EgressError::RedirectBlocked { reason, .. } => reason_of(reason),
        EgressError::SchemeNotAllowed(_) => "scheme",
        EgressError::UserinfoNotAllowed => "userinfo",
        EgressError::BlockedAddress { .. } => "address",
        EgressError::BlockedName(_) => "name",
        EgressError::HostNotAllowed(_) => "not-allowed",
        EgressError::CrossOrigin(_) => "cross-origin",
        EgressError::PortNotAllowed(_) => "port",
        EgressError::TooManyRedirects { .. } => "too-many-redirects",
        _ => "other",
    }
}

fn run_ip(vectors: &[Value], tally: &mut Tally) {
    for vector in vectors {
        let input = text(vector, "input");
        let ip: IpAddr = input
            .parse()
            .unwrap_or_else(|e| panic!("ip vector {input}: {e}"));
        let class = classify(ip);
        let allow = match text(vector, "expect") {
            "allow" => true,
            "block" => false,
            other => panic!("ip {input}: unknown expectation {other}"),
        };
        assert_eq!(
            is_globally_routable(ip),
            allow,
            "ip {input} classified {class}"
        );
        assert_eq!(class.name(), text(vector, "class"), "ip {input}");
        if let IpClass::Embedded { via, inner } = &class {
            assert_eq!(via.name(), text(vector, "via"), "ip {input}");
            assert_eq!(inner.name(), text(vector, "inner"), "ip {input}");
        }
        tally.passed += 1;
    }
}

fn run_vet(section: &str, vectors: &[Value], declared: &Map<String, Value>, tally: &mut Tally) {
    for vector in vectors {
        let input = text(vector, "input");
        let context = format!(
            "{section} {input} (policy {})",
            vector
                .get("policy")
                .map_or_else(|| "default".to_owned(), Value::to_string)
        );
        if let Some(reason) = missing_capability(declared, vector.get("requires"), &context) {
            tally.skip(context, 1, reason);
            continue;
        }
        let result = policy_from(vector.get("policy")).vet(input);
        match text(vector, "expect") {
            "allow" => {
                let vetted =
                    result.unwrap_or_else(|e| panic!("{context}: expected allow, got {e}"));
                if let Some(host) = vector["host"].as_str() {
                    assert_eq!(vetted.as_url().host_str(), Some(host), "{context}");
                }
            }
            "block" => {
                let error = match result {
                    Ok(vetted) => panic!("{context}: expected block, vetted {vetted}"),
                    Err(error) => error,
                };
                assert!(
                    error.is_refusal(),
                    "{context}: expected a refusal, got {error}"
                );
                if let Some(reason) = vector["reason"].as_str() {
                    assert_eq!(reason_of(&error), reason, "{context}: {error}");
                }
                if let Some(host) = vector["host"].as_str() {
                    let parsed = Url::parse(input).expect("a blocked vector parses");
                    assert_eq!(parsed.host_str(), Some(host), "{context}: canonical host");
                }
            }
            "invalid" => assert!(
                matches!(result, Err(EgressError::InvalidUrl(_))),
                "{context}: expected invalid, got {result:?}"
            ),
            other => panic!("{context}: unknown expectation {other}"),
        }
        tally.passed += 1;
    }
}

async fn run_dns(vectors: &[Value], declared: &Map<String, Value>, tally: &mut Tally) {
    for vector in vectors {
        let name = text(vector, "name");
        let context = format!("dns {name} (policy {:?})", vector.get("policy"));
        if let Some(reason) = missing_capability(declared, vector.get("requires"), &context) {
            tally.skip(context, 1, reason);
            continue;
        }
        let answers = ips(&vector["answers"]);
        let stub = StubResolver::new(HashMap::from([(name.to_owned(), vec![answers.clone()])]), 0);
        let resolver = GuardedResolver::new(policy_from(vector.get("policy"))).with_inner(stub);
        let lookup = Name::from_str(name).unwrap_or_else(|_| panic!("{context}: invalid name"));
        let result = resolver.resolve(lookup).await;
        match text(vector, "expect") {
            "allow" => {
                let resolved: Vec<IpAddr> = result
                    .unwrap_or_else(|e| panic!("{context}: expected allow, got {e}"))
                    .map(|addr| addr.ip())
                    .collect();
                assert_eq!(
                    resolved, answers,
                    "{context}: must return exactly the vetted answers"
                );
            }
            "block" => {
                let Err(error) = result else {
                    panic!("{context}: expected block, resolved");
                };
                assert!(
                    matches!(
                        blocked_in_chain(error.as_ref()),
                        Some(EgressError::BlockedAddress { .. })
                    ),
                    "{context}: expected BlockedAddress, got {error}"
                );
            }
            "error" => {
                let Err(error) = result else {
                    panic!("{context}: expected an error, resolved");
                };
                assert!(
                    blocked_in_chain(error.as_ref()).is_none(),
                    "{context}: {error}"
                );
                assert!(
                    matches!(
                        error.downcast_ref::<EgressError>(),
                        Some(EgressError::NoAddresses(_))
                    ),
                    "{context}: expected NoAddresses, got {error}"
                );
            }
            other => panic!("{context}: unknown expectation {other}"),
        }
        tally.passed += 1;
    }
}

#[derive(Debug)]
enum Outcome {
    Allow,
    NotFollowed,
    Block(&'static str),
    Failed(String),
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block(reason) => write!(f, "block ({reason})"),
            Self::Failed(detail) => write!(f, "failed: {detail}"),
            other => f.write_str(other.label()),
        }
    }
}

impl Outcome {
    fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::NotFollowed => "not-followed",
            Self::Block(_) => "block",
            Self::Failed(_) => "failed",
        }
    }
}

async fn outcome_of(result: Result<reqwest::Response, reqwest::Error>) -> Outcome {
    match result {
        Ok(response) if response.status().is_success() => {
            let _ = response.bytes().await;
            Outcome::Allow
        }
        Ok(response) if response.status().is_redirection() => Outcome::NotFollowed,
        Ok(response) => Outcome::Failed(format!("status {}", response.status())),
        Err(error) => match blocked_in_chain(&error) {
            Some(refusal) => Outcome::Block(reason_of(refusal)),
            None => Outcome::Failed(format!("{error:?}")),
        },
    }
}

fn live_client(
    policy: EgressPolicy,
    mode: RedirectMode,
    stub: Arc<StubResolver>,
    network: Network,
    tls: rustls::ClientConfig,
) -> GuardedClient {
    GuardedClientBuilder::new(policy)
        .redirects(mode)
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .inner_resolver(stub)
        .tls_preconfigured(tls)
        .wrap_resolver(Box::new(move |guarded| network.around(guarded)))
        .build()
        .expect("guarded client builds")
}

/// Lets a connection that should not have happened reach its listener's
/// accept loop before the counters are read.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

async fn run_rebinding(vectors: &[Value], tally: &mut Tally) {
    for vector in vectors {
        let id = text(vector, "id");
        let name = text(vector, "name");
        let lookups: Vec<Vec<IpAddr>> = vector["lookups"]
            .as_array()
            .expect("lookups")
            .iter()
            .map(ips)
            .collect();
        let tls = harness::tls_for(&[name.to_owned()]);
        let routes = Arc::new(HashMap::from([(
            "/".to_owned(),
            Route {
                status: 200,
                location: None,
            },
        )]));
        let (sink_port, sink) = harness::spawn_sink().await;
        let mut listeners = HashMap::new();
        let mut public = Vec::new();
        for ip in lookups
            .iter()
            .flatten()
            .copied()
            .filter(|ip| is_globally_routable(*ip))
        {
            if let std::collections::hash_map::Entry::Vacant(slot) = listeners.entry(ip) {
                let (port, counter) =
                    harness::spawn_tls_listener(tls.server.clone(), routes.clone()).await;
                slot.insert(port);
                public.push(counter);
            }
        }
        let stub = StubResolver::new(HashMap::from([(name.to_owned(), lookups)]), sink_port);
        let network = Network::new(listeners);
        let policy = policy_from(vector.get("policy"));
        let client = live_client(
            policy.clone(),
            RedirectMode::None,
            stub.clone(),
            network.clone(),
            tls.client.clone(),
        );
        let url = policy
            .vet(&format!("https://{name}/"))
            .unwrap_or_else(|e| panic!("{id}: {e}"));

        let requests = vector["requests"].as_array().expect("requests");
        let mut allowed = 0;
        for (index, request) in requests.iter().enumerate() {
            let outcome = outcome_of(client.get(&url).expect("re-vets").send().await).await;
            assert_eq!(
                outcome.label(),
                text(request, "expect"),
                "{id} request {index}: {outcome}"
            );
            if matches!(outcome, Outcome::Allow) {
                allowed += 1;
            }
        }
        settle().await;

        let assertions = &vector["assert"];
        if assertions["lookupsPerConnection"].as_u64() == Some(1) {
            assert_eq!(
                stub.lookups(name),
                requests.len(),
                "{id}: every new connection resolves exactly once, and never twice"
            );
        }
        if let Some(expected) = assertions["blockedTargetConnections"].as_u64() {
            assert_eq!(
                sink.get() as u64,
                expected,
                "{id}: the rebound target was reached"
            );
        }
        if assertions["connectTargetIsVetted"].as_bool() == Some(true) {
            let connections: usize = public.iter().map(Counter::get).sum();
            assert_eq!(
                connections, allowed,
                "{id}: connections to the vetted address"
            );
            let vetted = network.vetted();
            assert_eq!(
                vetted.len(),
                allowed,
                "{id}: only vetted answers reach the connector"
            );
            assert!(
                vetted.iter().all(|ip| is_globally_routable(*ip)),
                "{id}: the connector was handed {vetted:?}"
            );
        }
        tally.passed += 1;
    }
}

fn routes_from(vector: &Value, sink_port: u16) -> HashMap<String, Route> {
    if let Some(hops) = vector["chain"].as_u64() {
        let mut routes: HashMap<String, Route> = (0..hops)
            .map(|hop| {
                let next = hop + 1;
                (
                    format!("/hop/{hop}"),
                    Route {
                        status: 302,
                        location: Some(format!("/hop/{next}")),
                    },
                )
            })
            .collect();
        routes.insert(
            format!("/hop/{hops}"),
            Route {
                status: 200,
                location: None,
            },
        );
        return routes;
    }
    vector["routes"]
        .as_object()
        .expect("routes or chain")
        .iter()
        .map(|(path, route)| {
            let status = route["status"]
                .as_u64()
                .and_then(|status| u16::try_from(status).ok())
                .expect("status");
            let location = route["location"]
                .as_str()
                .map(|location| location.replace("{sink}", &sink_port.to_string()));
            (path.clone(), Route { status, location })
        })
        .collect()
}

async fn run_redirect(section: &Value, vectors: &[Value], tally: &mut Tally) {
    let zone: HashMap<String, Vec<Vec<IpAddr>>> = section["zone"]
        .as_object()
        .expect("a zone")
        .iter()
        .map(|(name, answers)| (name.clone(), vec![ips(answers)]))
        .collect();
    let names: Vec<String> = zone.keys().cloned().collect();
    let tls = harness::tls_for(&names);

    for vector in vectors {
        let id = text(vector, "id");
        let (sink_port, sink) = harness::spawn_sink().await;
        let routes = Arc::new(routes_from(vector, sink_port));
        let mut listeners = HashMap::new();
        let mut counters: HashMap<&str, Counter> = HashMap::new();
        for (name, lookups) in &zone {
            for ip in lookups
                .iter()
                .flatten()
                .copied()
                .filter(|ip| is_globally_routable(*ip))
            {
                let (port, counter) =
                    harness::spawn_tls_listener(tls.server.clone(), routes.clone()).await;
                listeners.insert(ip, port);
                counters.insert(name.as_str(), counter);
            }
        }
        let stub = StubResolver::new(zone.clone(), sink_port);
        let policy = policy_from(vector.get("policy"));
        let client = live_client(
            policy.clone(),
            mode_from(vector.get("mode")),
            stub,
            Network::new(listeners),
            tls.client.clone(),
        );
        let start = policy
            .vet(text(vector, "start"))
            .unwrap_or_else(|e| panic!("{id}: start URL refused: {e}"));

        let outcome = outcome_of(client.get(&start).expect("re-vets").send().await).await;
        settle().await;

        assert_eq!(outcome.label(), text(vector, "expect"), "{id}: {outcome}");
        if let Some(reason) = vector["reason"].as_str() {
            assert!(
                matches!(outcome, Outcome::Block(actual) if actual == reason),
                "{id}: expected reason {reason}, got {outcome}"
            );
        }
        for target in vector["zeroConnections"].as_array().into_iter().flatten() {
            let target = target.as_str().expect("listener name");
            let count = if target == "sink" {
                sink.get()
            } else {
                counters
                    .get(target)
                    .unwrap_or_else(|| panic!("{id}: {target} is not a public zone name"))
                    .get()
            };
            assert_eq!(count, 0, "{id}: {target} received {count} connection(s)");
        }
        tally.passed += 1;
    }
}
