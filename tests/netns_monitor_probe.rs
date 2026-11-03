//! Disposable-namespace probe for the kernel route monitor.
//!
//! Run inside the netns harness:
//! `sudo ./tests/linux-route-registry-netns.sh` builds and runs the acceptance
//! tests; this probe is executed by
//! `ip netns exec <ns> target/debug/deps/netns_monitor_probe-* --ignored --nocapture`
//! when you need to see exactly which invalidations the monitor delivers.

#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn monitor_delivers_route_and_link_notifications() {
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
