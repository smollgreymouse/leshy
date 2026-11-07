//! Linux kernel route monitor.
//!
//! Subscribes to the link, IPv4 route and IPv6 route multicast groups and
//! turns kernel notifications into [`RouteInvalidation`] signals. Bursts are
//! coalesced with a short debounce so a single `ip route flush` does not turn
//! into hundreds of reconciles.
//!
//! The monitor never reads the routing table itself: it only reports that
//! something changed. The registry decides what to re-verify.
//!
//! Every relevant event bumps the shared monitor generation *before* the
//! debounced signal is delivered (08D1 §16.2). The backend uses that counter
//! to refuse to declare a cache current across an event that happened during
//! its snapshot.

use super::backend::RouteInvalidation;
use super::model::{RouteKey, RoutePrefix};
use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// `RTNLGRP_LINK` from `linux/rtnetlink.h`.
const RTNLGRP_LINK: u32 = 1;
/// `RTNLGRP_IPV4_ROUTE` from `linux/rtnetlink.h`.
const RTNLGRP_IPV4_ROUTE: u32 = 7;
/// `RTNLGRP_IPV6_ROUTE` from `linux/rtnetlink.h`. The old code used the IPv4
/// group for both families, so an externally deleted /128 never produced an
/// event.
const RTNLGRP_IPV6_ROUTE: u32 = 11;

/// How long to wait for more events before emitting a coalesced signal.
const DEBOUNCE: Duration = Duration::from_millis(100);

/// The main routing table every Leshy route lives in.
const MAIN_TABLE: u32 = 254;

/// Spawn the monitor, returning the receiver its signals arrive on.
///
/// `generation` is shared with the backend: every relevant event increments it
/// before the debounced signal is sent (08D1 §16.2).
///
/// The socket is created synchronously so a permission problem surfaces at
/// startup rather than as a silently dead monitor.
pub fn spawn_monitor(
    generation: Arc<AtomicU64>,
) -> anyhow::Result<mpsc::UnboundedReceiver<RouteInvalidation>> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind(&SocketAddr::new(0, 0))?;
    socket.add_membership(RTNLGRP_IPV4_ROUTE)?;
    socket.add_membership(RTNLGRP_IPV6_ROUTE)?;
    socket.add_membership(RTNLGRP_LINK)?;
    socket.set_non_blocking(true)?;

    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = run(socket, tx, generation).await {
            tracing::warn!(error = %e, "Route monitor stopped");
        }
    });
    Ok(rx)
}

/// Read notifications until the socket fails.
async fn run(
    socket: Socket,
    tx: mpsc::UnboundedSender<RouteInvalidation>,
    generation: Arc<AtomicU64>,
) -> anyhow::Result<()> {
    let mut pending: Option<RouteInvalidation> = None;

    loop {
        // Drain everything currently queued, folding it into one signal.
        // recv_from_full returns one exact datagram per call; a reused
        // BufMut buffer would accumulate messages and every later slice
        // would start mid-stream, which silently drops all notifications
        // after the first one.
        loop {
            match socket.recv_from_full() {
                Ok((data, _addr)) => {
                    if let Some(signal) = classify(&data) {
                        // §16.2: bump the generation before the signal can be
                        // delivered, so a snapshot taken concurrently can tell
                        // it raced with this event.
                        generation.fetch_add(1, Ordering::SeqCst);
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
    use netlink_packet_route::route::RouteAddress;
    use std::net::IpAddr;
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

    // --- classify coverage: real serialized netlink messages ---------------

    fn serialize(payload: RouteNetlinkMessage) -> Vec<u8> {
        let mut message = NetlinkMessage::from(payload);
        // netlink-packet-core writes into the existing buffer: finalize
        // computes the length field and the buffer must be pre-sized to
        // buffer_len() before serialize.
        message.finalize();
        let mut bytes = vec![0u8; message.buffer_len()];
        message.serialize(&mut bytes);
        bytes
    }

    #[test]
    fn classify_ignores_non_main_tables() {
        let mut msg = netlink_packet_route::route::RouteMessage::default();
        // A valid non-main table (08D1 §16.5): 999 overflows the u8 header
        // field and breaks the Linux build.
        msg.header.table = 253;
        msg.header.destination_prefix_length = 32;
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Destination(
                RouteAddress::Inet(Ipv4Addr::new(10, 0, 0, 1)),
            ));
        let bytes = serialize(RouteNetlinkMessage::NewRoute(msg));
        assert_eq!(classify(&bytes), None, "a non-main table must be ignored");
    }

    #[test]
    fn classify_del_route_yields_prefix_invalidation() {
        let mut msg = netlink_packet_route::route::RouteMessage::default();
        msg.header.table = MAIN_TABLE as u8;
        msg.header.address_family = netlink_packet_route::AddressFamily::Inet;
        msg.header.destination_prefix_length = 32;
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Destination(
                RouteAddress::Inet(Ipv4Addr::new(10, 5, 5, 5)),
            ));
        let bytes = serialize(RouteNetlinkMessage::DelRoute(msg));
        let signal = classify(&bytes).expect("a DelRoute on the main table must classify");
        match signal {
            RouteInvalidation::Prefix(key) => {
                assert_eq!(
                    key.prefix,
                    RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 5, 5, 5)))
                );
            }
            other => panic!("expected a prefix invalidation, got {other:?}"),
        }
    }

    #[test]
    fn classify_new_route_yields_prefix_invalidation() {
        let mut msg = netlink_packet_route::route::RouteMessage::default();
        msg.header.table = MAIN_TABLE as u8;
        msg.header.address_family = netlink_packet_route::AddressFamily::Inet6;
        msg.header.destination_prefix_length = 128;
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Destination(
                RouteAddress::Inet6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ));
        let bytes = serialize(RouteNetlinkMessage::NewRoute(msg));
        let signal = classify(&bytes).expect("a NewRoute on the main table must classify");
        match signal {
            RouteInvalidation::Prefix(key) => {
                assert_eq!(
                    key.prefix,
                    RoutePrefix::host(IpAddr::V6(std::net::Ipv6Addr::new(
                        0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
                    )))
                );
            }
            other => panic!("expected a prefix invalidation, got {other:?}"),
        }
    }

    #[test]
    fn classify_new_link_yields_interface_invalidation() {
        let msg = netlink_packet_route::link::LinkMessage::default();
        let bytes = serialize(RouteNetlinkMessage::NewLink(msg));
        let signal = classify(&bytes).expect("a link event must classify");
        assert!(matches!(signal, RouteInvalidation::Interface(_)));
    }

    #[test]
    fn classify_ignores_routes_without_a_destination() {
        let msg = netlink_packet_route::route::RouteMessage::default();
        let bytes = serialize(RouteNetlinkMessage::NewRoute(msg));
        assert_eq!(classify(&bytes), None, "no destination -> no key");
    }
}
