//! Linux kernel route monitor.
//!
//! Subscribes to the `RTNLGRP_ROUTE` and `RTNLGRP_LINK` multicast groups and
//! turns kernel notifications into [`RouteInvalidation`] signals. Bursts are
//! coalesced with a short debounce so a single `ip route flush` does not turn
//! into hundreds of reconciles.
//!
//! The monitor never reads the routing table itself: it only reports that
//! something changed. The registry decides what to re-verify.

use super::backend::RouteInvalidation;
use super::model::{RouteKey, RoutePrefix};
use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;

/// `RTNLGRP_LINK` from `linux/rtnetlink.h`.
const RTNLGRP_LINK: u32 = 1;
/// `RTNLGRP_ROUTE` from `linux/rtnetlink.h`.
const RTNLGRP_ROUTE: u32 = 7;

/// How long to wait for more events before emitting a coalesced signal.
const DEBOUNCE: Duration = Duration::from_millis(100);

/// The main routing table every Leshy route lives in.
const MAIN_TABLE: u32 = 254;

/// Spawn the monitor, returning the receiver its signals arrive on.
///
/// The socket is created synchronously so a permission problem surfaces at
/// startup rather than as a silently dead monitor.
pub fn spawn_monitor() -> anyhow::Result<mpsc::UnboundedReceiver<RouteInvalidation>> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind(&SocketAddr::new(0, 0))?;
    socket.add_membership(RTNLGRP_ROUTE)?;
    socket.add_membership(RTNLGRP_LINK)?;
    socket.set_non_blocking(true)?;

    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = run(socket, tx).await {
            tracing::warn!(error = %e, "Route monitor stopped");
        }
    });
    Ok(rx)
}

/// Read notifications until the socket fails.
async fn run(socket: Socket, tx: mpsc::UnboundedSender<RouteInvalidation>) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; 32 * 1024];
    let mut pending: Option<RouteInvalidation> = None;

    loop {
        // Drain everything currently queued, folding it into one signal.
        loop {
            match socket.recv_from(&mut buffer, 0) {
                Ok((len, _addr)) => {
                    if let Some(signal) = classify(&buffer[..len]) {
                        pending = Some(merge(pending.take(), signal));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }

        if let Some(signal) = pending.take() {
            // Debounce: give the kernel a moment to finish the burst.
            tokio::time::sleep(DEBOUNCE).await;
            if tx.send(signal).is_err() {
                // The registry is gone; nothing left to notify.
                return Ok(());
            }
        } else {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Fold a new signal into a pending one, widening it when necessary.
fn merge(pending: Option<RouteInvalidation>, next: RouteInvalidation) -> RouteInvalidation {
    match (pending, next) {
        (None, next) => next,
        // A full invalidation subsumes everything else.
        (Some(RouteInvalidation::Full), _) | (_, RouteInvalidation::Full) => {
            RouteInvalidation::Full
        }
        // Two different prefixes cannot be expressed as one targeted signal.
        (Some(RouteInvalidation::Prefix(a)), RouteInvalidation::Prefix(b)) => {
            if a == b {
                RouteInvalidation::Prefix(a)
            } else {
                RouteInvalidation::Full
            }
        }
        (Some(RouteInvalidation::Interface(a)), RouteInvalidation::Interface(b)) => {
            if a == b {
                RouteInvalidation::Interface(a)
            } else {
                RouteInvalidation::Full
            }
        }
        // Mixed kinds: widen to a full audit.
        _ => RouteInvalidation::Full,
    }
}

/// Turn one netlink message into an invalidation signal.
fn classify(buffer: &[u8]) -> Option<RouteInvalidation> {
    let message: NetlinkMessage<RouteNetlinkMessage> = NetlinkMessage::deserialize(buffer).ok()?;
    match message.payload {
        netlink_packet_core::NetlinkPayload::InnerMessage(inner) => match inner {
            RouteNetlinkMessage::NewRoute(route) | RouteNetlinkMessage::DelRoute(route) => {
                // Only the main table matters; other tables are not ours.
                if u32::from(route.header.table) != MAIN_TABLE {
                    return None;
                }
                let network = route.attributes.iter().find_map(|attr| match attr {
                    netlink_packet_route::route::RouteAttribute::Destination(
                        netlink_packet_route::route::RouteAddress::Inet(addr),
                    ) => Some(IpAddr::V4(*addr)),
                    netlink_packet_route::route::RouteAttribute::Destination(
                        netlink_packet_route::route::RouteAddress::Inet6(addr),
                    ) => Some(IpAddr::V6(*addr)),
                    _ => None,
                })?;
                let prefix =
                    RoutePrefix::new(network, route.header.destination_prefix_length).ok()?;
                Some(RouteInvalidation::Prefix(RouteKey {
                    prefix,
                    table: MAIN_TABLE,
                }))
            }
            RouteNetlinkMessage::NewLink(link) | RouteNetlinkMessage::DelLink(link) => {
                Some(RouteInvalidation::Interface(link.header.index))
            }
            // Anything else may still have moved a route we care about.
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(a: u8, b: u8, c: u8, d: u8) -> RouteKey {
        RouteKey {
            prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(a, b, c, d))),
            table: MAIN_TABLE,
        }
    }

    #[test]
    fn merge_keeps_a_single_prefix() {
        let k = key(10, 0, 0, 1);
        let merged = merge(
            Some(RouteInvalidation::Prefix(k.clone())),
            RouteInvalidation::Prefix(k.clone()),
        );
        assert_eq!(merged, RouteInvalidation::Prefix(k));
    }

    #[test]
    fn merge_widens_two_prefixes_to_full() {
        let merged = merge(
            Some(RouteInvalidation::Prefix(key(10, 0, 0, 1))),
            RouteInvalidation::Prefix(key(10, 0, 0, 2)),
        );
        assert_eq!(merged, RouteInvalidation::Full);
    }

    #[test]
    fn merge_keeps_a_single_interface() {
        let merged = merge(
            Some(RouteInvalidation::Interface(7)),
            RouteInvalidation::Interface(7),
        );
        assert_eq!(merged, RouteInvalidation::Interface(7));
    }

    #[test]
    fn merge_widens_two_interfaces_to_full() {
        let merged = merge(
            Some(RouteInvalidation::Interface(7)),
            RouteInvalidation::Interface(8),
        );
        assert_eq!(merged, RouteInvalidation::Full);
    }

    #[test]
    fn full_subsumes_everything() {
        assert_eq!(
            merge(
                Some(RouteInvalidation::Full),
                RouteInvalidation::Prefix(key(10, 0, 0, 1))
            ),
            RouteInvalidation::Full
        );
        assert_eq!(
            merge(
                Some(RouteInvalidation::Interface(3)),
                RouteInvalidation::Full
            ),
            RouteInvalidation::Full
        );
    }

    #[test]
    fn mixed_kinds_widen_to_full() {
        assert_eq!(
            merge(
                Some(RouteInvalidation::Prefix(key(10, 0, 0, 1))),
                RouteInvalidation::Interface(7)
            ),
            RouteInvalidation::Full
        );
    }

    #[test]
    fn first_signal_passes_through() {
        let k = key(10, 0, 0, 1);
        assert_eq!(
            merge(None, RouteInvalidation::Prefix(k.clone())),
            RouteInvalidation::Prefix(k)
        );
    }

    #[test]
    fn garbage_is_ignored() {
        assert_eq!(classify(&[0u8; 4]), None);
        assert_eq!(classify(&[]), None);
    }
}
