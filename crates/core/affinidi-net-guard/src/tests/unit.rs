//! Behaviour the shared vectors do not pin: composition of narrowing, client
//! wiring, and the body cap.

use std::net::Ipv4Addr;
use std::str::FromStr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

use crate::redirect::check_redirect;
use crate::{
    AllowList, Cidr, DevLoopback, EgressError, EgressPolicy, GuardedClientBuilder, HostRule,
    PortPolicy, RedirectMode, Scheme, blocked_in_chain,
};

fn public() -> EgressPolicy {
    EgressPolicy::public_internet()
}

fn dev() -> EgressPolicy {
    public().with_dev_loopback(DevLoopback::acknowledge_ssrf_protection_disabled_for_loopback())
}

#[test]
fn narrowing_composes_and_never_widens() {
    let ports = public()
        .with_ports(PortPolicy::Only(vec![443, 8443]))
        .with_ports(PortPolicy::Only(vec![8443, 9443]))
        .with_ports(PortPolicy::Any);
    assert!(matches!(
        ports.vet("https://example.com/"),
        Err(EgressError::PortNotAllowed(443))
    ));
    assert!(ports.vet("https://example.com:8443/").is_ok());
    assert!(matches!(
        ports.vet("https://example.com:9443/"),
        Err(EgressError::PortNotAllowed(9443))
    ));

    let schemes = public()
        .with_schemes(&[Scheme::Https, Scheme::Wss])
        .with_schemes(&[Scheme::Https, Scheme::Http]);
    assert!(matches!(
        schemes.vet("wss://example.com/"),
        Err(EgressError::SchemeNotAllowed(_))
    ));
    assert!(matches!(
        schemes.vet("http://example.com/"),
        Err(EgressError::SchemeNotAllowed(_))
    ));

    let lists = public()
        .with_allow_list(AllowList::new([HostRule::Suffix(".example.com".into())]).unwrap())
        .with_allow_list(AllowList::new([HostRule::Exact("a.example.com".into())]).unwrap());
    assert!(lists.vet("https://a.example.com/").is_ok());
    assert!(matches!(
        lists.vet("https://b.example.com/"),
        Err(EgressError::HostNotAllowed(_))
    ));
}

#[test]
fn allow_cidrs_never_readmit_loopback_link_local_unspecified_multicast_or_broadcast() {
    let policy =
        public().allow_cidrs(["0.0.0.0/0", "::/0"].map(|cidr| Cidr::from_str(cidr).unwrap()));
    for raw in [
        "https://127.0.0.1/",
        "https://169.254.169.254/",
        "https://0.0.0.0/",
        "https://224.0.0.1/",
        "https://255.255.255.255/",
        "https://[::1]/",
        "https://[fe80::1]/",
        "https://[::ffff:169.254.169.254]/",
    ] {
        assert!(
            matches!(policy.vet(raw), Err(EgressError::BlockedAddress { .. })),
            "{raw}"
        );
    }
    assert!(policy.vet("https://10.1.2.3/").is_ok());
    assert!(policy.vet("https://[fd00:ec2::254]/").is_ok());
}

#[test]
fn allow_list_rules_are_canonicalised_and_validated() {
    let policy =
        public().with_allow_list(AllowList::new([HostRule::Exact("BÜCHER.de.".into())]).unwrap());
    assert!(policy.vet("https://xn--bcher-kva.de/").is_ok());
    assert!(matches!(
        AllowList::new([HostRule::Exact("exa mple.com".into())]),
        Err(EgressError::InvalidConfig(_))
    ));
    assert!(matches!(
        AllowList::new(Vec::<HostRule>::new()),
        Err(EgressError::InvalidConfig(_))
    ));
}

#[test]
fn cidr_parsing_masks_host_bits_and_rejects_nonsense() {
    let cidr = Cidr::from_str("10.20.1.2/16").unwrap();
    assert_eq!(cidr.to_string(), "10.20.0.0/16");
    assert!(cidr.contains("10.20.255.1".parse().unwrap()));
    assert!(!cidr.contains("10.21.0.1".parse().unwrap()));
    assert!(!cidr.contains("::ffff:10.20.0.1".parse().unwrap()));
    assert!(
        Cidr::from_str("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap())
    );
    for bad in [
        "10.0.0.0/33",
        "::/129",
        "10.0.0.0",
        "nonsense/8",
        "10.0.0.0/-1",
    ] {
        assert!(Cidr::from_str(bad).is_err(), "{bad}");
    }
}

#[test]
fn vetted_host_is_canonical_for_display() {
    assert_eq!(
        public().vet("https://EXAMPLE.com./x").unwrap().host(),
        "example.com"
    );
    assert_eq!(
        dev().vet("http://2130706433:8080/").unwrap().host(),
        "127.0.0.1"
    );
    assert_eq!(dev().vet("http://[0:0::1]/").unwrap().host(), "[::1]");
}

#[test]
fn join_same_origin_refuses_to_leave_the_origin() {
    let base = public().vet("https://example.com/users/alice/").unwrap();
    assert_eq!(
        base.join_same_origin("did.json").unwrap().as_url().as_str(),
        "https://example.com/users/alice/did.json"
    );
    for escape in [
        "//169.254.169.254/latest/meta-data",
        "https://evil.example/",
        "http://example.com/",
        "https://example.com:8443/",
    ] {
        assert!(
            matches!(
                base.join_same_origin(escape),
                Err(EgressError::CrossOrigin(_))
            ),
            "{escape}"
        );
    }
}

#[test]
fn a_redirect_downgrade_is_refused_even_under_dev_loopback() {
    let next = Url::parse("http://localhost:8080/").unwrap();
    let from_https = [Url::parse("https://localhost:8443/").unwrap()];
    let refusal =
        check_redirect(&dev(), RedirectMode::ReVet { max: 10 }, &next, &from_https).unwrap_err();
    assert!(
        matches!(&refusal, EgressError::RedirectBlocked { reason, .. } if matches!(**reason, EgressError::SchemeNotAllowed(_))),
        "{refusal}"
    );
    let from_http = [Url::parse("http://localhost:8443/").unwrap()];
    assert!(check_redirect(&dev(), RedirectMode::ReVet { max: 10 }, &next, &from_http).is_ok());
}

#[test]
fn the_hop_cap_counts_redirects_not_requests() {
    let next = Url::parse("https://example.com/next").unwrap();
    let chain = |requests: usize| -> Vec<Url> {
        (0..requests)
            .map(|index| Url::parse(&format!("https://example.com/{index}")).unwrap())
            .collect()
    };
    let mode = RedirectMode::ReVet { max: 2 };
    assert!(check_redirect(&public(), mode, &next, &chain(2)).is_ok());
    assert!(matches!(
        check_redirect(&public(), mode, &next, &chain(3)),
        Err(EgressError::TooManyRedirects { max: 2 })
    ));
}

#[test]
fn blocked_in_chain_finds_refusals_and_ignores_other_errors() {
    assert!(blocked_in_chain(&EgressError::NoAddresses("x.test".into())).is_none());
    let nested = EgressError::RedirectBlocked {
        to: "https://[::1]/".into(),
        reason: Box::new(EgressError::BlockedName("localhost".into())),
    };
    assert!(matches!(
        blocked_in_chain(&nested),
        Some(EgressError::RedirectBlocked { .. })
    ));
}

#[tokio::test]
async fn a_client_re_vets_urls_under_its_own_policy() {
    let vetted_elsewhere = dev().vet("https://127.0.0.1:8443/").unwrap();
    let client = GuardedClientBuilder::new(public()).build().unwrap();
    assert!(matches!(
        client.get(&vetted_elsewhere),
        Err(EgressError::BlockedAddress { .. })
    ));
}

#[tokio::test]
async fn execute_refuses_a_request_for_another_origin_or_a_blocked_host() {
    let client = GuardedClientBuilder::new(public()).build().unwrap();
    let vetted = public().vet("https://example.com/").unwrap();
    let other = reqwest::Request::new(
        reqwest::Method::POST,
        Url::parse("https://example.org/").unwrap(),
    );
    assert!(matches!(
        client.execute(&vetted, other).await,
        Err(EgressError::CrossOrigin(_))
    ));
    let internal = reqwest::Request::new(
        reqwest::Method::POST,
        Url::parse("https://127.0.0.1/").unwrap(),
    );
    assert!(matches!(
        client.execute(&vetted, internal).await,
        Err(EgressError::BlockedAddress { .. })
    ));
}

async fn serve_once(response: Vec<u8>) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let response = response.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 4096];
                let _ = stream.read(&mut head).await;
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn the_body_cap_holds_with_and_without_content_length() {
    let body = vec![b'x'; 64];
    let mut declared =
        b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\n".to_vec();
    declared.extend_from_slice(&body);
    let mut chunked =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n40\r\n"
            .to_vec();
    chunked.extend_from_slice(&body);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");

    let policy = dev();
    let client = GuardedClientBuilder::new(policy.clone())
        .max_body(16)
        .build()
        .unwrap();
    for response in [declared, chunked] {
        let port = serve_once(response).await;
        let url = policy.vet(&format!("http://127.0.0.1:{port}/")).unwrap();
        let response = client.get(&url).unwrap().send().await.unwrap();
        assert!(matches!(
            client.read_body_capped(response).await,
            Err(EgressError::BodyTooLarge { max: 16 })
        ));
    }
}
