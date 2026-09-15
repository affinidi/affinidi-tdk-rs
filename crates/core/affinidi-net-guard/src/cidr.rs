//! Explicit address ranges for [`EgressPolicy::allow_cidrs`](crate::EgressPolicy::allow_cidrs).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::EgressError;

/// An IP network in CIDR notation, such as `10.20.0.0/16` or `fd12:3456::/48`.
///
/// Host bits are cleared on construction, so `10.20.1.2/16` is `10.20.0.0/16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Build a range from an address and a prefix length.
    ///
    /// # Errors
    ///
    /// [`EgressError::InvalidConfig`] if `prefix_len` is longer than the
    /// address (32 bits for IPv4, 128 for IPv6).
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, EgressError> {
        let network = match addr {
            IpAddr::V4(v4) if prefix_len <= 32 => {
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask_v4(prefix_len)))
            }
            IpAddr::V6(v6) if prefix_len <= 128 => {
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask_v6(prefix_len)))
            }
            _ => {
                return Err(EgressError::InvalidConfig(format!(
                    "prefix length /{prefix_len} is too long for {addr}"
                )));
            }
        };
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// The network address (host bits cleared).
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether `addr` falls inside this range. An IPv4 range never contains an
    /// IPv6 address, nor the reverse.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(network), IpAddr::V4(addr)) => {
                u32::from(addr) & mask_v4(self.prefix_len) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(addr)) => {
                u128::from(addr) & mask_v6(self.prefix_len) == u128::from(network)
            }
            _ => false,
        }
    }
}

fn mask_v4(prefix_len: u8) -> u32 {
    u32::MAX
        .checked_shl(32 - u32::from(prefix_len))
        .unwrap_or(0)
}

fn mask_v6(prefix_len: u8) -> u128 {
    u128::MAX
        .checked_shl(128 - u32::from(prefix_len))
        .unwrap_or(0)
}

impl FromStr for Cidr {
    type Err = EgressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || EgressError::InvalidConfig(format!("{s:?} is not CIDR notation"));
        let (addr, prefix_len) = s.split_once('/').ok_or_else(invalid)?;
        let addr = addr.parse::<IpAddr>().map_err(|_| invalid())?;
        let prefix_len = prefix_len.parse::<u8>().map_err(|_| invalid())?;
        Self::new(addr, prefix_len)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}
