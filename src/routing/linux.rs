//! Linux route backend: rtnetlink writer plus kernel read-back.
//!
//! `ensure_route` never treats EEXIST as unconditional success: a row for the
//! same destination that points at another interface or gateway is a conflict,
//! not a match. The kernel is the source of truth, so every mutation is
//! followed by a read-back of the affected prefix.

use super::backend::{EnsureOutcome, RouteBackend, RouteInvalidation};
use super::model::{AddressFamily, ObservedRoute, RouteIntent, RouteKey, RoutePrefix, RouteTarget};
use crate::config::{RouteType, ZoneConfig};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::TryStreamExt;
use netlink_packet_route::route::{RouteAddress, RouteProtocol, RouteScope};
use rtnetlink::{new_connection, Handle, IpVersion};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::{mpsc, Mutex};

/// Protocol stamped on every row Leshy creates.
///
/// `Boot` is what `ip route add` uses by default, so rows installed by earlier
/// Leshy versions are adopted without a migration step.
const LESHY_PROTOCOL: RouteProtocol = RouteProtocol::Boot;

/// The main routing table.
const MAIN_TABLE: u32 = 254;

/// `RouteHeader::table` is a single byte, so the main table is compared in
/// that width.
const MAIN_TABLE_U8: u8 = MAIN_TABLE as u8;

pub struct LinuxRouteBackend {
    handle: Handle,
    invalidation_rx: Mutex<Option<mpsc::UnboundedReceiver<RouteInvalidation>>>,
}

impl LinuxRouteBackend {
    pub fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);

        // A monitor that cannot start is not fatal: the periodic audit still
        // catches drift, just later.
        let invalidation_rx = match super::linux_monitor::spawn_monitor() {
            Ok(rx) => Some(rx),
            Err(e) => {
                tracing::warn!(error = %e, "Kernel route monitor unavailable, relying on the periodic audit");
                None
            }
        };

        Ok(Self {
            handle,
            invalidation_rx: Mutex::new(invalidation_rx),
        })
    }

    /// Resolve an interface name to its current index.
    async fn ifindex_of(&self, device: &str) -> Result<u32> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(device.to_string())
            .execute();
        let link = links
            .try_next()
            .await?
            .with_context(|| format!("Device '{device}' not found"))?;
        Ok(link.header.index)
    }

    /// Map every interface index to its name, so a snapshot can report device
    /// targets with the same identity the intents carry.
    async fn link_names(&self) -> Result<HashMap<u32, String>> {
        let mut links = self.handle.link().get().execute();
        let mut names = HashMap::new();
        while let Some(link) = links.try_next().await? {
            let name = link
                .attributes
                .iter()
                .find_map(|attr| match attr {
                    netlink_packet_route::link::LinkAttribute::IfName(name) => Some(name.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            names.insert(link.header.index, name);
        }
        Ok(names)
    }

    /// Read the main table for one address family.
    async fn dump_family(
        &self,
        version: IpVersion,
        names: &HashMap<u32, String>,
    ) -> Result<Vec<ObservedRoute>> {
        let mut routes = self.handle.route().get(version).execute();
        let mut out = Vec::new();
        while let Some(msg) = routes.try_next().await? {
            if msg.header.table != MAIN_TABLE_U8 {
                continue;
            }
            let Some(network) = destination_of(&msg) else {
                continue;
            };
            let Ok(prefix) = RoutePrefix::new(network, msg.header.destination_prefix_length) else {
                continue;
            };
            let Some(target) = target_of(&msg, names) else {
                continue;
            };
            out.push(ObservedRoute {
                key: RouteKey {
                    prefix,
                    table: MAIN_TABLE,
                },
                target,
                protocol: msg.header.protocol.into(),
                metric: 0,
            });
        }
        Ok(out)
    }

    /// Find the row that currently occupies `intent.key`, if any.
    async fn find_row(&self, intent: &RouteIntent) -> Result<Option<ObservedRoute>> {
        let version = match intent.key.prefix.family() {
            AddressFamily::V4 => IpVersion::V4,
            AddressFamily::V6 => IpVersion::V6,
        };
        let names = self.link_names().await?;
        let rows = self.dump_family(version, &names).await?;
        Ok(rows.into_iter().find(|row| row.key == intent.key))
    }

    /// Whether a refused add means "a row for this destination already
    /// exists": EEXIST outright, or EBUSY — what the IPv6 route code answers
    /// for an identical existing route.
    fn is_busy_class(e: &anyhow::Error) -> bool {
        matches!(
            e.downcast_ref::<rtnetlink::Error>(),
            Some(rtnetlink::Error::NetlinkError(err))
                if matches!(err.code, Some(code) if code.get() == -17 || code.get() == -16)
        )
    }

    /// A typed refusal to touch a destination someone else owns. The registry
    /// classifies this as `RouteError::Conflict`, which the DNS layer answers
    /// with SERVFAIL instead of handing out an unrouted address.
    fn conflict_error(&self, intent: &RouteIntent, owner: &RouteTarget) -> anyhow::Error {
        anyhow::anyhow!(super::backend::RouteConflict {
            prefix: format!(
                "{}/{}",
                intent.key.prefix.network, intent.key.prefix.prefix_len
            ),
            owner: format!("{owner:?}"),
        })
    }

    /// Build the netlink add request for an intent.
    async fn add_row(&self, intent: &RouteIntent) -> Result<()> {
        let prefix = &intent.key.prefix;
        let result = match prefix.network {
            IpAddr::V4(addr) => {
                let mut route = self.handle.route().add().v4();
                route.message_mut().header.destination_prefix_length = prefix.prefix_len;
                route.message_mut().header.protocol = LESHY_PROTOCOL;
                route.message_mut().attributes.push(
                    netlink_packet_route::route::RouteAttribute::Destination(RouteAddress::Inet(
                        addr,
                    )),
                );
                match &intent.target {
                    RouteTarget::Gateway(IpAddr::V4(gw)) => {
                        route.message_mut().attributes.push(
                            netlink_packet_route::route::RouteAttribute::Gateway(
                                RouteAddress::Inet(*gw),
                            ),
                        );
                        route.message_mut().header.scope = RouteScope::Universe;
                    }
                    RouteTarget::Device {
                        ifindex: Some(index),
                        ..
                    } => {
                        route
                            .message_mut()
                            .attributes
                            .push(netlink_packet_route::route::RouteAttribute::Oif(*index));
                        route.message_mut().header.scope = RouteScope::Link;
                    }
                    other => anyhow::bail!(
                        "route {} cannot be installed with target {other:?}",
                        intent.key.prefix.network
                    ),
                }
                route.execute().await
            }
            IpAddr::V6(addr) => {
                let mut route = self.handle.route().add().v6();
                route.message_mut().header.destination_prefix_length = prefix.prefix_len;
                route.message_mut().header.protocol = LESHY_PROTOCOL;
                route.message_mut().attributes.push(
                    netlink_packet_route::route::RouteAttribute::Destination(RouteAddress::Inet6(
                        addr,
                    )),
                );
                match &intent.target {
                    RouteTarget::Gateway(IpAddr::V6(gw)) => {
                        route.message_mut().attributes.push(
                            netlink_packet_route::route::RouteAttribute::Gateway(
                                RouteAddress::Inet6(*gw),
                            ),
                        );
                        route.message_mut().header.scope = RouteScope::Universe;
                    }
                    RouteTarget::Device {
                        ifindex: Some(index),
                        ..
                    } => {
                        route
                            .message_mut()
                            .attributes
                            .push(netlink_packet_route::route::RouteAttribute::Oif(*index));
                        route.message_mut().header.scope = RouteScope::Link;
                    }
                    other => anyhow::bail!(
                        "route {} cannot be installed with target {other:?}",
                        intent.key.prefix.network
                    ),
                }
                route.execute().await
            }
        };

        match result {
            Ok(()) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(err)) if matches!(err.code, Some(code) if code.get() == -17) =>
            {
                // EEXIST: the caller decides whether the existing row matches.
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Delete the row occupying `intent.key`.
    async fn delete_row(&self, intent: &RouteIntent) -> Result<()> {
        let prefix = &intent.key.prefix;
        let mut msg = netlink_packet_route::route::RouteMessage::default();
        // The doit handler is registered per family: a DEL with an unspecified
        // family is rejected by the kernel before the prefix is even looked at.
        msg.header.address_family = match prefix.network {
            IpAddr::V4(_) => netlink_packet_route::AddressFamily::Inet,
            IpAddr::V6(_) => netlink_packet_route::AddressFamily::Inet6,
        };
        msg.header.destination_prefix_length = prefix.prefix_len;
        msg.header.table = MAIN_TABLE_U8;
        // Ownership was already proven by the exact read-back before this
        // delete runs, so the DEL must match the row whatever its scope,
        // protocol or metric are: the kernel compares all three and an
        // assumed Boot/link delete silently misses the row (ESRCH), leaving
        // it in the table. NOWHERE scope and UNSPEC protocol mean "match
        // any"; an absent priority matches any metric.
        msg.header.scope = RouteScope::Nowhere;
        msg.header.protocol = RouteProtocol::Unspec;
        match prefix.network {
            IpAddr::V4(addr) => {
                msg.attributes
                    .push(netlink_packet_route::route::RouteAttribute::Destination(
                        RouteAddress::Inet(addr),
                    ));
            }
            IpAddr::V6(addr) => {
                msg.header.address_family = netlink_packet_route::AddressFamily::Inet6;
                msg.attributes
                    .push(netlink_packet_route::route::RouteAttribute::Destination(
                        RouteAddress::Inet6(addr),
                    ));
            }
        }

        match self.handle.route().del(msg).execute().await {
            Ok(()) => Ok(()),
            // ESRCH: nothing to delete.
            Err(rtnetlink::Error::NetlinkError(err)) if matches!(err.code, Some(code) if code.get() == -3) => {
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Extract the destination address from a route message.
fn destination_of(msg: &netlink_packet_route::route::RouteMessage) -> Option<IpAddr> {
    msg.attributes.iter().find_map(|attr| match attr {
        netlink_packet_route::route::RouteAttribute::Destination(RouteAddress::Inet(addr)) => {
            Some(IpAddr::V4(*addr))
        }
        netlink_packet_route::route::RouteAttribute::Destination(RouteAddress::Inet6(addr)) => {
            Some(IpAddr::V6(*addr))
        }
        _ => None,
    })
}

/// Extract the forwarding target from a route message.
fn target_of(
    msg: &netlink_packet_route::route::RouteMessage,
    names: &HashMap<u32, String>,
) -> Option<RouteTarget> {
    let mut oif = None;
    let mut gateway = None;
    for attr in msg.attributes.iter() {
        match attr {
            netlink_packet_route::route::RouteAttribute::Oif(index) => oif = Some(*index),
            netlink_packet_route::route::RouteAttribute::Gateway(gw) => match gw {
                RouteAddress::Inet(v4) => gateway = Some(IpAddr::V4(*v4)),
                RouteAddress::Inet6(v6) => gateway = Some(IpAddr::V6(*v6)),
                _ => {}
            },
            _ => {}
        }
    }
    if let Some(gw) = gateway {
        return Some(RouteTarget::Gateway(gw));
    }
    oif.map(|index| RouteTarget::Device {
        name: names.get(&index).cloned().unwrap_or_default(),
        ifindex: Some(index),
    })
}

#[async_trait]
impl RouteBackend for LinuxRouteBackend {
    async fn resolve_target(
        &self,
        zone: &ZoneConfig,
        family: AddressFamily,
    ) -> Result<RouteTarget> {
        match zone.route_type {
            RouteType::Dev => {
                let device = tokio::fs::read_to_string(&zone.route_target)
                    .await
                    .with_context(|| {
                        format!(
                            "Device file '{}' not found (VPN not connected?)",
                            zone.route_target
                        )
                    })?;
                let device = device.trim().to_string();
                if device.is_empty() {
                    anyhow::bail!("Device file '{}' is empty", zone.route_target);
                }
                let ifindex = self.ifindex_of(&device).await?;
                Ok(RouteTarget::Device {
                    name: device,
                    ifindex: Some(ifindex),
                })
            }
            RouteType::Via => {
                let gateway = zone.gateway_for(family)?.ok_or_else(|| {
                    anyhow::anyhow!("zone '{}': no gateway configured for {family:?}", zone.name)
                })?;
                Ok(RouteTarget::Gateway(gateway))
            }
        }
    }

    async fn ensure_route(&self, intent: &RouteIntent) -> Result<EnsureOutcome> {
        // A row already occupying this prefix decides the outcome: an exact
        // match is a no-op, anything else is a conflict we must not clobber.
        if let Some(existing) = self.find_row(intent).await? {
            if existing.target == intent.target {
                return Ok(EnsureOutcome::AlreadyMatching);
            }
            return Err(self.conflict_error(intent, &existing.target));
        }

        if let Err(e) = self.add_row(intent).await {
            // A concurrent writer may have installed the exact row between
            // our lookup and the add; the kernel then refuses the add with
            // EEXIST — or EBUSY, which is what IPv6 answers for an identical
            // existing route. Only an exact read-back turns that into a
            // verified no-op; anything else keeps the error.
            if Self::is_busy_class(&e) {
                match self.find_row(intent).await? {
                    Some(row) if row.target == intent.target => {
                        return Ok(EnsureOutcome::AlreadyMatching);
                    }
                    Some(row) => return Err(self.conflict_error(intent, &row.target)),
                    None => {
                        return Err(e).context(format!(
                            "route {} add was refused and the row is absent",
                            intent.key.prefix.network
                        ))
                    }
                }
            }
            return Err(e);
        }

        // Read back: the kernel is the only proof the route exists.
        match self.find_row(intent).await? {
            Some(row) if row.target == intent.target => Ok(EnsureOutcome::Added),
            // Something else took the destination between our add and the
            // read-back; treat it as a foreign route, not ours to fix.
            Some(row) => Err(self.conflict_error(intent, &row.target)),
            None => anyhow::bail!(
                "route {} is missing right after it was added",
                intent.key.prefix.network
            ),
        }
    }

    async fn remove_route(&self, intent: &RouteIntent) -> Result<()> {
        match self.find_row(intent).await? {
            // Only delete a row Leshy owns; a foreign row on the same prefix
            // belongs to someone else.
            Some(row) if row.target == intent.target => self.delete_row(intent).await,
            Some(row) => {
                tracing::debug!(
                    prefix = %intent.key.prefix.network,
                    prefix_len = intent.key.prefix.prefix_len,
                    owner = ?row.target,
                    "Leaving a foreign route in place"
                );
                Ok(())
            }
            None => Ok(()),
        }
    }

    async fn snapshot(&self) -> Result<Vec<ObservedRoute>> {
        let names = self.link_names().await?;
        let mut out = self.dump_family(IpVersion::V4, &names).await?;
        out.extend(self.dump_family(IpVersion::V6, &names).await?);
        Ok(out)
    }

    fn take_invalidation_receiver(&self) -> Option<mpsc::UnboundedReceiver<RouteInvalidation>> {
        self.invalidation_rx
            .try_lock()
            .ok()
            .and_then(|mut guard| guard.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn leshy_protocol_is_boot() {
        // Rows installed by earlier versions used the kernel default, which is
        // `boot`; keeping it avoids an adoption migration.
        assert_eq!(u8::from(LESHY_PROTOCOL), 3);
    }

    #[test]
    fn main_table_is_254() {
        assert_eq!(MAIN_TABLE, 254);
    }

    #[test]
    fn destination_extraction_v4() {
        let mut msg = netlink_packet_route::route::RouteMessage::default();
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Destination(
                RouteAddress::Inet(Ipv4Addr::new(10, 1, 2, 3)),
            ));
        assert_eq!(
            destination_of(&msg),
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
        );
    }

    #[test]
    fn destination_extraction_v6() {
        let mut msg = netlink_packet_route::route::RouteMessage::default();
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Destination(
                RouteAddress::Inet6(Ipv6Addr::LOCALHOST),
            ));
        assert_eq!(destination_of(&msg), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn destination_missing_is_none() {
        let msg = netlink_packet_route::route::RouteMessage::default();
        assert_eq!(destination_of(&msg), None);
    }

    #[test]
    fn gateway_wins_over_oif() {
        let mut msg = netlink_packet_route::route::RouteMessage::default();
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Oif(7));
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Gateway(
                RouteAddress::Inet(Ipv4Addr::new(192, 168, 1, 1)),
            ));
        let names = HashMap::new();
        assert_eq!(
            target_of(&msg, &names),
            Some(RouteTarget::Gateway(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1
            ))))
        );
    }

    #[test]
    fn oif_becomes_device_target_with_name() {
        let mut msg = netlink_packet_route::route::RouteMessage::default();
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Oif(7));
        let mut names = HashMap::new();
        names.insert(7u32, "tun0".to_string());
        assert_eq!(
            target_of(&msg, &names),
            Some(RouteTarget::Device {
                name: "tun0".to_string(),
                ifindex: Some(7),
            })
        );
    }

    #[test]
    fn no_target_attributes_is_none() {
        let msg = netlink_packet_route::route::RouteMessage::default();
        assert_eq!(target_of(&msg, &HashMap::new()), None);
    }
}
