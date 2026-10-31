use super::RouteAdder;
use crate::config::{RouteType, ZoneConfig};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::TryStreamExt;
use netlink_packet_route::route::{RouteAddress, RouteProtocol, RouteScope};
use rtnetlink::{new_connection, Handle, IpVersion};
use std::net::IpAddr;

pub struct LinuxRouteAdder {
    handle: Handle,
}

impl LinuxRouteAdder {
    pub fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }
}

#[async_trait]
impl RouteAdder for LinuxRouteAdder {
    async fn add_via_route(&self, ip: IpAddr, prefix_len: u8, gateway: &str) -> Result<()> {
        let gateway_ip: IpAddr = gateway.parse().context("Failed to parse gateway IP")?;

        tracing::info!(ip = %ip, prefix_len = prefix_len, gateway = %gateway, "Adding route via gateway");

        let route = match ip {
            IpAddr::V4(addr) => {
                let mut route = self.handle.route().add().v4();
                route.message_mut().header.destination_prefix_length = prefix_len;
                route.message_mut().attributes.push(
                    netlink_packet_route::route::RouteAttribute::Destination(RouteAddress::Inet(
                        addr,
                    )),
                );

                if let IpAddr::V4(gw) = gateway_ip {
                    route.message_mut().attributes.push(
                        netlink_packet_route::route::RouteAttribute::Gateway(RouteAddress::Inet(
                            gw,
                        )),
                    );
                }

                route.message_mut().header.scope = RouteScope::Universe;
                route.execute().await
            }
            IpAddr::V6(addr) => {
                let mut route = self.handle.route().add().v6();
                route.message_mut().header.destination_prefix_length = prefix_len;
                route.message_mut().attributes.push(
                    netlink_packet_route::route::RouteAttribute::Destination(RouteAddress::Inet6(
                        addr,
                    )),
                );

                if let IpAddr::V6(gw) = gateway_ip {
                    route.message_mut().attributes.push(
                        netlink_packet_route::route::RouteAttribute::Gateway(RouteAddress::Inet6(
                            gw,
                        )),
                    );
                }

                route.message_mut().header.scope = RouteScope::Universe;
                route.execute().await
            }
        };

        match route {
            Ok(_) => {
                tracing::debug!(ip = %ip, gateway = %gateway, "Route added successfully");
                Ok(())
            }
            Err(rtnetlink::Error::NetlinkError(err)) if matches!(err.code, Some(code) if code.get() == -17) =>
            {
                tracing::debug!(ip = %ip, "Route already exists");
                Ok(())
            }
            Err(e) => {
                tracing::error!(ip = %ip, error = %e, "Failed to add route");
                Err(e.into())
            }
        }
    }

    async fn add_dev_route(&self, ip: IpAddr, prefix_len: u8, device: &str) -> Result<()> {
        tracing::info!(ip = %ip, prefix_len = prefix_len, device = device, "Adding route via device");

        let mut links = self
            .handle
            .link()
            .get()
            .match_name(device.to_string())
            .execute();
        let link = links
            .try_next()
            .await?
            .context(format!("Device '{device}' not found"))?;

        let route = match ip {
            IpAddr::V4(addr) => {
                let mut route = self.handle.route().add().v4();
                route.message_mut().header.destination_prefix_length = prefix_len;
                route.message_mut().attributes.push(
                    netlink_packet_route::route::RouteAttribute::Destination(RouteAddress::Inet(
                        addr,
                    )),
                );
                route.message_mut().attributes.push(
                    netlink_packet_route::route::RouteAttribute::Oif(link.header.index),
                );
                route.message_mut().header.scope = RouteScope::Link;
                route.execute().await
            }
            IpAddr::V6(addr) => {
                let mut route = self.handle.route().add().v6();
                route.message_mut().header.destination_prefix_length = prefix_len;
                route.message_mut().attributes.push(
                    netlink_packet_route::route::RouteAttribute::Destination(RouteAddress::Inet6(
                        addr,
                    )),
                );
                route.message_mut().attributes.push(
                    netlink_packet_route::route::RouteAttribute::Oif(link.header.index),
                );
                route.message_mut().header.scope = RouteScope::Link;
                route.execute().await
            }
        };

        match route {
            Ok(_) => {
                tracing::debug!(ip = %ip, device = device, "Route added successfully");
                Ok(())
            }
            Err(rtnetlink::Error::NetlinkError(err)) if matches!(err.code, Some(code) if code.get() == -17) =>
            {
                tracing::debug!(ip = %ip, "Route already exists");
                Ok(())
            }
            Err(e) => {
                tracing::error!(ip = %ip, error = %e, "Failed to add route");
                Err(e.into())
            }
        }
    }

    /// Report whether the kernel still routes `ip/prefix_len` through the
    /// zone's target. The in-memory bookkeeping cannot be trusted alone: the
    /// Go core withdraws routes during fail-closed recovery and external
    /// daemons may drop them, so a stale "installed" set must not mask the
    /// loss. Mirrors the Windows implementation.
    async fn route_matches(&self, ip: IpAddr, prefix_len: u8, zone: &ZoneConfig) -> Result<bool> {
        let version = match ip {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        };
        let (target_index, target_gateway): (Option<u32>, Option<IpAddr>) = match zone.route_type {
            RouteType::Dev => {
                let device = tokio::fs::read_to_string(&zone.route_target)
                    .await
                    .with_context(|| format!("read device file {}", zone.route_target))?;
                let device = device.trim().to_string();
                let mut links = self.handle.link().get().match_name(device.clone()).execute();
                let link = links
                    .try_next()
                    .await?
                    .with_context(|| format!("Device '{device}' not found"))?;
                (Some(link.header.index), None)
            }
            RouteType::Via => {
                let gw: IpAddr = zone
                    .route_target
                    .trim()
                    .parse()
                    .with_context(|| format!("parse gateway {}", zone.route_target))?;
                (None, Some(gw))
            }
        };

        // rtnetlink's route GET is implemented as a dump, and the kernel
        // ignores the destination/table fields of a dump request (verified on
        // 6.x: every route from every table comes back). Filter in userspace:
        // only the exact destination/prefix inside the main table counts.
        let mut req = self.handle.route().get(version);

        let mut routes = req.execute();
        let mut considered = 0usize;
        while let Some(msg) = routes.try_next().await? {
            if msg.header.table != netlink_packet_route::route::RouteHeader::RT_TABLE_MAIN
                || msg.header.destination_prefix_length != prefix_len
            {
                continue;
            }
            let dst_matches = msg.attributes.iter().any(|attr| match (ip, attr) {
                (IpAddr::V4(addr), netlink_packet_route::route::RouteAttribute::Destination(
                    RouteAddress::Inet(found),
                )) => *found == addr,
                (IpAddr::V6(addr), netlink_packet_route::route::RouteAttribute::Destination(
                    RouteAddress::Inet6(found),
                )) => *found == addr,
                _ => false,
            });
            if !dst_matches {
                continue;
            }
            considered += 1;
            let mut oif: Option<u32> = None;
            let mut gateway: Option<IpAddr> = None;
            for attr in msg.attributes.iter() {
                match attr {
                    netlink_packet_route::route::RouteAttribute::Oif(index) => {
                        oif = Some(*index);
                    }
                    netlink_packet_route::route::RouteAttribute::Gateway(gw) => match gw {
                        RouteAddress::Inet(v4) => gateway = Some(IpAddr::V4(*v4)),
                        RouteAddress::Inet6(v6) => gateway = Some(IpAddr::V6(*v6)),
                        _ => {}
                    },
                    _ => {}
                }
            }
            match (target_index, target_gateway) {
                (Some(index), _) if oif == Some(index) => {
                    tracing::debug!(ip = %ip, prefix = prefix_len, "Route matches zone target");
                    return Ok(true);
                }
                (_, Some(gw)) if gateway == Some(gw) => {
                    tracing::debug!(ip = %ip, prefix = prefix_len, "Route matches zone gateway");
                    return Ok(true);
                }
                _ => {}
            }
        }
        tracing::info!(ip = %ip, prefix = prefix_len, zone = zone.name, considered = considered, "Kernel route check: destination is not routed via the zone target");
        Ok(false)
    }

    async fn remove_route(&self, ip: IpAddr, prefix_len: u8) -> Result<()> {
        tracing::info!(ip = %ip, prefix_len = prefix_len, "Removing route");

        let result = match ip {
            IpAddr::V4(addr) => {                let mut msg = netlink_packet_route::route::RouteMessage::default();
                msg.header.destination_prefix_length = prefix_len;
                msg.header.protocol = RouteProtocol::Boot;
                msg.attributes
                    .push(netlink_packet_route::route::RouteAttribute::Destination(
                        RouteAddress::Inet(addr),
                    ));
                self.handle.route().del(msg).execute().await
            }
            IpAddr::V6(addr) => {
                let mut msg = netlink_packet_route::route::RouteMessage::default();
                msg.header.destination_prefix_length = prefix_len;
                msg.header.protocol = RouteProtocol::Boot;
                msg.header.address_family = netlink_packet_route::AddressFamily::Inet6;
                msg.attributes
                    .push(netlink_packet_route::route::RouteAttribute::Destination(
                        RouteAddress::Inet6(addr),
                    ));
                self.handle.route().del(msg).execute().await
            }
        };

        match result {
            Ok(_) => {
                tracing::debug!(ip = %ip, prefix_len = prefix_len, "Route removed successfully");
                Ok(())
            }
            Err(rtnetlink::Error::NetlinkError(err)) if matches!(err.code, Some(code) if code.get() == -3) =>
            {
                // ESRCH = no such route, not an error
                tracing::debug!(ip = %ip, "Route does not exist, nothing to remove");
                Ok(())
            }
            Err(e) => {
                tracing::error!(ip = %ip, error = %e, "Failed to remove route");
                Err(e.into())
            }
        }
    }
}
