//! Address classification: the canonical table that the guards in other
//! languages port, and that `conformance/egress-vectors.v1.json` pins.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What kind of address an [`IpAddr`] is, for egress purposes.
///
/// Only [`IpClass::Global`], and an [`IpClass::Embedded`] address whose
/// embedded IPv4 destination is `Global`, are globally routable. See
/// [`IpClass::is_globally_routable`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IpClass {
    /// Globally routable unicast.
    Global,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
    Private,
    /// `169.254.0.0/16` (which holds the cloud-metadata address
    /// `169.254.169.254`) and `fe80::/10`.
    LinkLocal,
    /// Carrier-grade NAT `100.64.0.0/10`, which holds `100.100.100.200` (the
    /// Alibaba Cloud metadata address) and many Kubernetes node ranges.
    SharedCgnat,
    /// `0.0.0.0/8` ("this network", including the unspecified address) and
    /// `::`.
    ThisNetwork,
    /// `255.255.255.255`.
    Broadcast,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`,
    /// `3fff::/20`.
    Documentation,
    /// `198.18.0.0/15`, `2001:2::/48`.
    Benchmarking,
    /// IETF protocol assignments: `192.0.0.0/24`, and `2001::/23` apart from
    /// the assignments in it that are globally reachable.
    ProtocolAssignment,
    /// `240.0.0.0/4` (apart from broadcast), discard-only `100::/64`, SRv6
    /// SIDs `5f00::/16`, and local-use NAT64 addresses that are not in the
    /// `/96` form.
    Reserved,
    /// `fc00::/7`, which holds the AWS IMDSv6 address `fd00:ec2::254`.
    UniqueLocal,
    /// Deprecated site-local `fec0::/10`.
    SiteLocal,
    /// An IPv6 address that carries an IPv4 destination.
    Embedded {
        /// How the IPv4 address is carried.
        via: Embedding,
        /// The class of the embedded IPv4 address.
        inner: Box<IpClass>,
    },
}

/// How an [`IpClass::Embedded`] IPv6 address carries its IPv4 destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Embedding {
    /// IPv4-mapped `::ffff:0:0/96`.
    V4Mapped,
    /// Deprecated IPv4-compatible `::/96` (apart from `::` and `::1`).
    V4Compatible,
    /// NAT64 well-known prefix `64:ff9b::/96` (RFC 6052).
    Nat64,
    /// Local-use NAT64 `64:ff9b:1::/48` (RFC 8215), with the IPv4 address in
    /// the low 32 bits and bits 48 to 95 zero.
    Nat64LocalUse,
    /// 6to4 `2002::/16`, with the IPv4 address in bits 16 to 47.
    SixToFour,
    /// Teredo `2001::/32`. The IPv4 address is the client's, stored inverted
    /// in the low 32 bits.
    Teredo,
}

impl IpClass {
    /// `true` for [`IpClass::Global`], and for an embedded address whose IPv4
    /// destination is `Global`: a DNS64 network hands out `64:ff9b::808:808`
    /// for a public host, and refusing it would break every lookup there.
    pub fn is_globally_routable(&self) -> bool {
        match self {
            Self::Global => true,
            Self::Embedded { inner, .. } => inner.is_globally_routable(),
            _ => false,
        }
    }

    /// A stable kebab-case name, as used in the conformance vectors.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link-local",
            Self::SharedCgnat => "shared-cgnat",
            Self::ThisNetwork => "this-network",
            Self::Broadcast => "broadcast",
            Self::Multicast => "multicast",
            Self::Documentation => "documentation",
            Self::Benchmarking => "benchmarking",
            Self::ProtocolAssignment => "protocol-assignment",
            Self::Reserved => "reserved",
            Self::UniqueLocal => "unique-local",
            Self::SiteLocal => "site-local",
            Self::Embedded { .. } => "embedded",
        }
    }
}

impl fmt::Display for IpClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Embedded { via, inner } => write!(f, "{inner} via {}", via.name()),
            other => f.write_str(other.name()),
        }
    }
}

impl Embedding {
    /// A stable kebab-case name, as used in the conformance vectors.
    pub fn name(self) -> &'static str {
        match self {
            Self::V4Mapped => "v4-mapped",
            Self::V4Compatible => "v4-compatible",
            Self::Nat64 => "nat64",
            Self::Nat64LocalUse => "nat64-local-use",
            Self::SixToFour => "6to4",
            Self::Teredo => "teredo",
        }
    }
}

/// Classify an address. Pure; no I/O.
pub fn classify(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(addr) => classify_v4(addr),
        IpAddr::V6(addr) => classify_v6(addr),
    }
}

/// Whether an egress may connect to `ip` under a policy with no exceptions.
/// Equivalent to `classify(ip).is_globally_routable()`.
pub fn is_globally_routable(ip: IpAddr) -> bool {
    classify(ip).is_globally_routable()
}

fn classify_v4(addr: Ipv4Addr) -> IpClass {
    match addr.octets() {
        [0, ..] => IpClass::ThisNetwork,
        [10, ..] => IpClass::Private,
        [100, second, ..] if (64..128).contains(&second) => IpClass::SharedCgnat,
        [127, ..] => IpClass::Loopback,
        [169, 254, ..] => IpClass::LinkLocal,
        [172, second, ..] if (16..32).contains(&second) => IpClass::Private,
        [192, 0, 0, _] => IpClass::ProtocolAssignment,
        [192, 0, 2, _] => IpClass::Documentation,
        [192, 168, ..] => IpClass::Private,
        [198, 18 | 19, ..] => IpClass::Benchmarking,
        [198, 51, 100, _] => IpClass::Documentation,
        [203, 0, 113, _] => IpClass::Documentation,
        [224..=239, ..] => IpClass::Multicast,
        [255, 255, 255, 255] => IpClass::Broadcast,
        [240..=255, ..] => IpClass::Reserved,
        _ => IpClass::Global,
    }
}

fn classify_v6(addr: Ipv6Addr) -> IpClass {
    if addr.is_unspecified() {
        return IpClass::ThisNetwork;
    }
    if addr.is_loopback() {
        return IpClass::Loopback;
    }
    if let Some((via, v4)) = embedded_v4(addr) {
        return IpClass::Embedded {
            via,
            inner: Box::new(classify_v4(v4)),
        };
    }
    let s = addr.segments();
    match s {
        // Local-use NAT64 outside the /96 form. Its gateway may embed the
        // IPv4 address at another RFC 6052 offset, so there is no single
        // destination to classify.
        [0x64, 0xff9b, 1, ..] => IpClass::Reserved,
        [0x100, 0, 0, 0, ..] => IpClass::Reserved,
        [0x2001, second, ..] if second < 0x200 => classify_2001_23(s),
        [0x2001, 0xdb8, ..] => IpClass::Documentation,
        [0x3fff, second, ..] if second < 0x1000 => IpClass::Documentation,
        [0x5f00, ..] => IpClass::Reserved,
        [first, ..] if first & 0xfe00 == 0xfc00 => IpClass::UniqueLocal,
        [first, ..] if first & 0xffc0 == 0xfe80 => IpClass::LinkLocal,
        [first, ..] if first & 0xffc0 == 0xfec0 => IpClass::SiteLocal,
        [first, ..] if first & 0xff00 == 0xff00 => IpClass::Multicast,
        _ => IpClass::Global,
    }
}

/// `2001::/23` (IANA IPv6 special-purpose registry). Teredo is handled by
/// [`embedded_v4`] before this is reached.
fn classify_2001_23(s: [u16; 8]) -> IpClass {
    let globally_reachable = match s[1] {
        // 2001:1::1, ::2 and ::3 (PCP, TURN and DNS-SD SRP anycast)
        1 => s[2..7] == [0; 5] && (1..=3).contains(&s[7]),
        // 2001:3::/32 AMT
        3 => true,
        // 2001:4:112::/48 AS112-v6
        4 => s[2] == 0x112,
        // 2001:20::/28 ORCHIDv2, 2001:30::/28 DRIP DETs
        second => matches!(second & 0xfff0, 0x20 | 0x30),
    };
    if globally_reachable {
        IpClass::Global
    } else if s[1] == 2 && s[2] == 0 {
        IpClass::Benchmarking
    } else {
        IpClass::ProtocolAssignment
    }
}

/// The IPv4 destination an IPv6 address carries, if it is one of the
/// [`Embedding`] forms.
pub(crate) fn embedded_v4(addr: Ipv6Addr) -> Option<(Embedding, Ipv4Addr)> {
    let s = addr.segments();
    let o = addr.octets();
    let low32 = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    match s {
        [0, 0, 0, 0, 0, 0xffff, ..] => Some((Embedding::V4Mapped, low32)),
        [0, 0, 0, 0, 0, 0, ..] if !addr.is_unspecified() && !addr.is_loopback() => {
            Some((Embedding::V4Compatible, low32))
        }
        [0x64, 0xff9b, 0, 0, 0, 0, ..] => Some((Embedding::Nat64, low32)),
        [0x64, 0xff9b, 1, 0, 0, 0, ..] => Some((Embedding::Nat64LocalUse, low32)),
        [0x2002, high, low, ..] => Some((
            Embedding::SixToFour,
            Ipv4Addr::from((u32::from(high) << 16) | u32::from(low)),
        )),
        [0x2001, 0, ..] => Some((Embedding::Teredo, Ipv4Addr::from(!u32::from(low32)))),
        _ => None,
    }
}
