//! Disposable-namespace probe for the kernel route monitor.
//!
//! Run inside the netns harness:
//! `ip netns exec <ns> target/debug/deps/netns_monitor_probe-* --ignored --nocapture`
//! It opens a raw netlink socket exactly like the production monitor and
//! prints what arrives, so a silent monitor can be told apart from a
//! parse-dropping one.

#![cfg(target_os = "linux")]

use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::process::Command;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn raw_monitor_sees_route_churn() {
    let dev = std::env::var("LESHY_NETNS_DEV").expect("LESHY_NETNS_DEV");

    let mut socket = Socket::new(NETLINK_ROUTE).expect("socket");
    socket.bind(&SocketAddr::new(0, 0)).expect("bind");
    socket.add_membership(1).expect("link membership");
    socket.add_membership(7).expect("route membership");
    socket.set_non_blocking(true).expect("non-blocking");

    Command::new("ip")
        .args([
            "route",
            "add",
            "10.55.42.1/32",
            "dev",
            &dev,
            "table",
            "main",
        ])
        .output()
        .expect("add route");
    Command::new("ip")
        .args(["route", "del", "10.55.42.1/32", "table", "main"])
        .output()
        .expect("del route");

    let mut buffer = vec![0u8; 32 * 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut received = 0usize;
    while tokio::time::Instant::now() < deadline && received < 2 {
        match socket.recv_from(&mut buffer, 0) {
            Ok((len, addr)) => {
                received += 1;
                println!("RECV {len} bytes from {:?}", addr);
                let message: Result<NetlinkMessage<RouteNetlinkMessage>, _> =
                    NetlinkMessage::deserialize(&buffer[..len]);
                match message {
                    Ok(msg) => println!("PARSED: {:?}", msg.payload),
                    Err(e) => println!("PARSE ERROR: {e}"),
                }
            }
            Err(e) => {
                assert!(
                    e.kind() == std::io::ErrorKind::WouldBlock,
                    "unexpected recv error: {e}"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(received > 0, "the raw netlink socket must see route churn");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn production_monitor_delivers_invalidations() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("leshy=trace,warn"))
        .with_test_writer()
        .try_init();

    let dev = std::env::var("LESHY_NETNS_DEV").expect("LESHY_NETNS_DEV");
    let mut rx = leshy::routing::spawn_monitor_probe().expect("monitor spawns");

    Command::new("ip")
        .args([
            "route",
            "add",
            "10.55.43.1/32",
            "dev",
            &dev,
            "table",
            "main",
        ])
        .output()
        .expect("add route");
    Command::new("ip")
        .args(["route", "del", "10.55.43.1/32", "table", "main"])
        .output()
        .expect("del route");

    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline && seen.len() < 2 {
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Some(invalidation)) => {
                println!("INVALIDATION: {invalidation:?}");
                seen.push(invalidation);
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(
        !seen.is_empty(),
        "the monitor must deliver at least one invalidation for route churn"
    );
    println!("received {} invalidations", seen.len());
}
