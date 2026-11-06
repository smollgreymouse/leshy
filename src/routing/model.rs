//! Canonical cross-family route types shared by the registry, the aggregator
//! and every platform backend.
//!
//! This is the only module allowed to manipulate raw prefix bits; everything
//! else must go through [`RoutePrefix`] so a non-canonical network address can
//! never reach the kernel.
//
// The registry and the platform backends consume these types in later steps of
// the route-registry rollout; until then the canonical model is exercised only
// by its own tests.
#![allow(dead_code)]

use anyhow::{bail, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Address family derived from the IP address itself.
///
/// The family is always taken from the address, never from configuration:
/// `ZoneConfig::ipv6` is an enable policy, not a family selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum AddressFamily {
    V4,
    V6,
}

/// Family of a bare address, mirroring the unstable `IpAddr::family`.
pub fn family_of(ip: IpAddr) -> AddressFamily {
    match ip {
        IpAddr::V4(_) => AddressFamily::V4,
        IpAddr::V6(_) => AddressFamily::V6,
    }
}

/// A canonical network prefix (always canonicalized network bits).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct RoutePrefix {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl RoutePrefix {
    /// Create a new prefix, canonicalizing the network bits.
    pub fn new(ip: IpAddr, prefix_len: u8) -> Result<Self> {
        match ip {
            IpAddr::V4(addr) => {
                if prefix_len > 32 {
                    bail!("prefix length {prefix_len} exceeds 32 for IPv4 {addr}");
                }
                let mask = if prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix_len)
                };
                Ok(Self {
                    network: IpAddr::V4(Ipv4Addr::from(addr.to_bits() & mask)),
                    prefix_len,
                })
            }
            IpAddr::V6(addr) => {
                if prefix_len > 128 {
                    bail!("prefix length {prefix_len} exceeds 128 for IPv6 {addr}");
                }
                let mask = if prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix_len)
                };
                Ok(Self {
                    network: IpAddr::V6(Ipv6Addr::from(addr.to_bits() & mask)),
                    prefix_len,
                })
            }
        }
    }

    /// Create a host prefix (/32 or /128).
    pub fn host(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self {
                network: ip,
                prefix_len: 32,
            },
            IpAddr::V6(_) => Self {
                network: ip,
                prefix_len: 128,
            },
        }
    }

    /// Return the address family.
    pub fn family(&self) -> AddressFamily {
        match self.network {
            IpAddr::V4(_) => AddressFamily::V4,
            IpAddr::V6(_) => AddressFamily::V6,
        }
    }
}

/// Route target: how traffic for this prefix is forwarded.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum RouteTarget {
    Device { name: String, ifindex: Option<u32> },
    Gateway(IpAddr),
    Unreachable,
}

/// Key identifying a route in the registry.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RouteKey {
    pub prefix: RoutePrefix,
    pub table: u32, // 254/main for current Leshy routes
}

/// Source of a route intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RouteSource {
    Dns,
    Static,
}

/// A desired route intent produced by DNS resolution or static config.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteIntent {
    pub key: RouteKey,
    pub zone: String,
    pub target: RouteTarget,
    pub source: RouteSource,
}

/// The exact kernel identity of one observed row (08D1 §14.1): every
/// writer-controlled field the platform exposes. A previous owned exact
/// observation is the only row a backend may replace or delete; any other
/// same-key row is foreign. `interface_luid` is Windows-only (§31.19);
/// Linux/macOS store `None`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteKernelIdentity {
    pub ifindex: Option<u32>,
    pub next_hop: Option<IpAddr>,
    pub protocol: u8,
    pub metric: u32,
    pub scope: u8,
    pub interface_luid: Option<u64>,
}

/// A route observed in the kernel routing table with its exact identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedRoute {
    pub key: RouteKey,
    pub target: RouteTarget,
    pub identity: RouteKernelIdentity,
}

/// Ownership of one installed route (08D1 §14.1): `owned` means this
/// process created the row and may delete it; a pre-existing compatible row
/// is `owned: false` with the exact observation attached — it may satisfy
/// forwarding but must never be deleted as ours.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteOwnership {
    pub owned: bool,
    pub observed: Option<ObservedRoute>,
}

/// State of a registry entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteState {
    Pending,
    Verified,
    Dirty,
    Denied,
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn host_prefix_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = RoutePrefix::host(ip);
        assert_eq!(prefix.prefix_len, 32);
        assert_eq!(prefix.family(), AddressFamily::V4);
    }

    #[test]
    fn host_prefix_v6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let prefix = RoutePrefix::host(ip);
        assert_eq!(prefix.prefix_len, 128);
        assert_eq!(prefix.family(), AddressFamily::V6);
    }

    #[test]
    fn canonicalize_v4() {
        // Non-canonical /24: host bits set
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255));
        let prefix = RoutePrefix::new(ip, 24).unwrap();
        assert_eq!(prefix.network, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(prefix.prefix_len, 24);
    }

    #[test]
    fn canonicalize_v6() {
        // Non-canonical /64: host bits set
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0x1234, 0x5678));
        let prefix = RoutePrefix::new(ip, 64).unwrap();
        assert_eq!(
            prefix.network,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
        );
        assert_eq!(prefix.prefix_len, 64);
    }

    #[test]
    fn canonicalize_v4_zero_prefix() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let prefix = RoutePrefix::new(ip, 0).unwrap();
        assert_eq!(prefix.prefix_len, 0);
        assert_eq!(prefix.network, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn canonicalize_v6_zero_prefix() {
        let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let prefix = RoutePrefix::new(ip, 0).unwrap();
        assert_eq!(prefix.prefix_len, 0);
        assert_eq!(
            prefix.network,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
        );
    }

    #[test]
    fn v4_prefix_overflow_rejected() {
        assert!(RoutePrefix::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33).is_err());
    }

    #[test]
    fn v6_prefix_overflow_rejected() {
        assert!(RoutePrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 129).is_err());
    }

    #[test]
    fn family_from_prefix() {
        let v4 = RoutePrefix::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 24).unwrap();
        assert_eq!(v4.family(), AddressFamily::V4);

        let v6 = RoutePrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 64).unwrap();
        assert_eq!(v6.family(), AddressFamily::V6);
    }

    #[test]
    fn route_key_equality_and_hashing() {
        let k1 = RouteKey {
            prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            table: 254,
        };
        let k2 = RouteKey {
            prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            table: 254,
        };
        let k3 = RouteKey {
            prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            table: 254,
        };
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);

        // The registry keys its map by RouteKey, so equal keys must collide.
        let mut set = std::collections::HashSet::new();
        set.insert(k1);
        assert!(set.contains(&k2));
        assert!(!set.contains(&k3));
    }

    #[test]
    fn host_and_aggregate_keys_are_distinct() {
        let host = RouteKey {
            prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))),
            table: 254,
        };
        let aggregate = RouteKey {
            prefix: RoutePrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), 24).unwrap(),
            table: 254,
        };
        assert_ne!(host, aggregate);
        assert_eq!(
            aggregate.prefix.network,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))
        );
    }

    #[test]
    fn route_target_equality() {
        let g1 = RouteTarget::Gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let g2 = RouteTarget::Gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(g1, g2);

        let d1 = RouteTarget::Device {
            name: "tun0".to_string(),
            ifindex: Some(5),
        };
        let d2 = RouteTarget::Device {
            name: "tun0".to_string(),
            ifindex: Some(5),
        };
        assert_eq!(d1, d2);
    }
}
