//! Privileged netns acceptance for the unified route registry (plan §14).
//!
//! Drives the production `RouteManager` (local backend) against the real
//! kernel inside a disposable network namespace created by
//! `tests/linux-route-registry-netns.sh`, and reads the truth back with `ip`
//! — independent of Leshy's own netlink view.
//!
//! Run only through that script: `sudo ./tests/linux-route-registry-netns.sh`.
//! The tests are `#[ignore]`d so a plain `cargo test` never touches the
//! workstation's routing table.

#![cfg(target_os = "linux")]

use leshy::config::Config;
use leshy::routing::RouteManager;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::time::Duration;

/// The dummy interface the script created inside the namespace.
fn netns_dev() -> Option<String> {
    std::env::var("LESHY_NETNS_DEV")
        .ok()
        .filter(|s| !s.is_empty())
}

fn running_as_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
        .unwrap_or(false)
}

fn ip(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().expect("iproute2");
    assert!(
        output.status.success(),
        "ip {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// The prefixes the acceptance walks use; cleared best-effort before each
/// test so a previously failed run cannot poison the next one.
fn clear_test_prefixes() {
    for prefix in [
        "10.55.7.1/32",
        "10.55.7.3/32",
        "10.55.8.1/32",
        "10.55.9.9/32",
        "fd00:55::7/128",
        "fd00:55::8/128",
    ] {
        let _ = Command::new("ip")
            .args(["route", "del", prefix, "table", "main"])
            .output();
    }
}

/// `ip route show table main` for both families, the kernel's own truth.
fn kernel_table() -> String {
    format!(
        "{}{}",
        ip(&["route", "show", "table", "main"]),
        ip(&["-6", "route", "show", "table", "main"])
    )
}

/// The current kernel ifindex of a device, from `ip -o link show`.
fn ifindex(dev: &str) -> u32 {
    let line = ip(&["-o", "link", "show", "dev", dev]);
    line.split(':')
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| panic!("cannot parse the ifindex from {line:?}"))
}

/// Poll a kernel-truth condition; monitor-driven changes are asynchronous
/// (event debounce plus reconcile), so the acceptance waits for them.
async fn wait_for(timeout: Duration, mut cond: impl FnMut() -> bool, what: &str) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = std::fmt::format(format_args!("{what}"));
    cond()
}

/// Build the production manager against a dev zone in the current namespace.
async fn manager_with_dev_zone() -> (RouteManager, Config) {
    let dev = netns_dev().expect("LESHY_NETNS_DEV must be set by the netns script");
    let device_file = std::env::temp_dir().join("leshy-netns-dev-file");
    std::fs::write(&device_file, &dev).expect("write device file");

    let config: Config = toml::from_str(&format!(
        r#"
[server]
listen_address = "127.0.0.1:15390"
default_upstream = ["10.55.0.254:53"]
route_failure_mode = "servfail"

[[zones]]
name = "netns"
route_type = "dev"
route_target = "{}"
ipv6 = true
domains = ["netns.test"]
"#,
        device_file.display()
    ))
    .unwrap();
    config.validate().unwrap();

    let manager = RouteManager::for_server(&config.server).expect("manager");
    (manager, config)
}

/// Install a tracing subscriber so monitor/reconcile decisions are visible
/// with RUST_LOG when the acceptance runs.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("leshy=debug,warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

/// The whole acceptance walk in one test so the namespace state stays
/// sequential and deterministic (the script passes --test-threads=1 anyway).
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn real_kernel_add_readback_delete_and_conflict_safety() {
    let Some(_dev) = netns_dev() else {
        eprintln!("skipping: not inside the netns harness (LESHY_NETNS_DEV unset)");
        return;
    };
    assert!(running_as_root(), "the netns harness runs as root");
    init_tracing();
    clear_test_prefixes();

    let (manager, config) = manager_with_dev_zone().await;
    let zone = config.zones[0].clone();

    const V4_HOST: Ipv4Addr = Ipv4Addr::new(10, 55, 7, 1);
    const V6_HOST: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x55, 0, 0, 0, 0, 0, 7);

    // --- real /32 add and exact read-back --------------------------------
    manager
        .add_route(IpAddr::V4(V4_HOST), &zone)
        .await
        .expect("v4 /32 add");
    let table = kernel_table();
    assert!(
        table.contains(&format!("{V4_HOST} dev")),
        "the /32 row must exist after the add:\n{table}"
    );

    // --- stable state: repeated classifications write nothing ------------
    let stable_before = kernel_table();
    for _ in 0..1000 {
        manager
            .add_route(IpAddr::V4(V4_HOST), &zone)
            .await
            .expect("repeated v4 add stays ok");
    }
    assert_eq!(
        kernel_table(),
        stable_before,
        "a converged table must not change under repeated DNS classifications"
    );

    // --- external deletion is restored by the monitor, exactly once -------
    Command::new("ip")
        .args(["route", "del", &V4_HOST.to_string(), "table", "main"])
        .output()
        .expect("delete the row externally");
    assert!(
        !kernel_table().contains(&format!("{V4_HOST} dev")),
        "the row must be gone after the external delete"
    );
    // A DNS classification for a still-Verified entry is the zero-IO fast
    // path: the monitor owns the restoration, not the request path.
    manager
        .add_route(IpAddr::V4(V4_HOST), &zone)
        .await
        .expect("fast-path classification stays ok");
    assert!(
        !kernel_table().contains(&format!("{V4_HOST} dev")),
        "the request path must not restore the row: kernel drift is the monitor's job"
    );
    // §16.6: <5s proves the event path, not the 30s periodic audit.
    let restored = wait_for(
        Duration::from_secs(5),
        || kernel_table().contains(&format!("{V4_HOST} dev")),
        "the monitor must restore the externally deleted row",
    )
    .await;
    assert!(restored, "the /32 row must be back after reconciliation");
    let after_restore = kernel_table();

    // Repeated classifications after the restore stay flat.
    for _ in 0..1000 {
        manager.add_route(IpAddr::V4(V4_HOST), &zone).await.unwrap();
    }
    assert_eq!(kernel_table(), after_restore);

    // --- real /128 add and exact read-back --------------------------------
    manager
        .add_route(IpAddr::V6(V6_HOST), &zone)
        .await
        .expect("v6 /128 add");
    let table = kernel_table();
    assert!(
        table.contains(&format!("{V6_HOST} dev")),
        "the /128 row must exist after the add:\n{table}"
    );
    for _ in 0..1000 {
        manager.add_route(IpAddr::V6(V6_HOST), &zone).await.unwrap();
    }
    assert!(kernel_table().contains(&format!("{V6_HOST} dev")));

    // --- a foreign row is never replaced nor deleted ----------------------
    const FOREIGN: &str = "10.55.9.9/32";
    // `ip route show` prints host routes without the /32 suffix.
    const FOREIGN_ROW: &str = "10.55.9.9 dev lo";
    ip(&["route", "add", FOREIGN, "dev", "lo", "table", "main"]);
    let foreign_before = kernel_table();
    assert!(
        foreign_before.contains(FOREIGN_ROW),
        "the foreign fixture row must exist:
{foreign_before}"
    );

    let result = manager
        .add_route(IpAddr::V4(Ipv4Addr::new(10, 55, 9, 9)), &zone)
        .await;
    assert!(
        result.is_err(),
        "a foreign row on the same prefix must be refused, not replaced"
    );
    assert!(
        kernel_table().contains(FOREIGN_ROW),
        "the foreign row must survive the refused ensure:
{}",
        kernel_table()
    );

    // Explicit zone cleanup must not delete it either. Owned rows go away;
    // the foreign row and everything else stay byte-identical.
    manager.cleanup_zone(&zone.name).await.unwrap();
    let _ = wait_for(
        Duration::from_secs(5),
        || !kernel_table().contains(&format!("{V4_HOST} dev")),
        "owned rows are cleaned up",
    )
    .await;
    let foreign_after = kernel_table();
    assert!(
        foreign_after.contains(FOREIGN_ROW),
        "the foreign row must survive the zone cleanup:\n{foreign_after}"
    );
    assert!(
        !foreign_after.contains(&format!("{V4_HOST} dev")),
        "owned rows are cleaned up:\n{foreign_after}"
    );
    assert!(
        !foreign_after.contains(&format!("{V6_HOST} dev")),
        "owned v6 rows are cleaned up:\n{foreign_after}"
    );
    // Nothing new appeared: cleanup may only remove rows, never add or
    // rewrite one. (Owned rows disappearing is asserted above.)
    for line in foreign_after.lines() {
        assert!(
            foreign_before.contains(line),
            "cleanup must not introduce or rewrite rows: {line:?} was not there before:\nbefore:\n{foreign_before}\nafter:\n{foreign_after}"
        );
    }

    // Cleanup is idempotent: a second pass touches nothing.
    let before_second = kernel_table();
    manager.cleanup_zone(&zone.name).await.unwrap();
    assert_eq!(kernel_table(), before_second);

    // Remove the foreign row the harness created.
    ip(&["route", "del", FOREIGN, "table", "main"]);
}

/// A shared manager instance must also survive an IPv4-then-IPv6 sequence
/// where the zone serves both families through one device file.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn real_kernel_dual_stack_through_one_device() {
    let Some(_dev) = netns_dev() else {
        eprintln!("skipping: not inside the netns harness (LESHY_NETNS_DEV unset)");
        return;
    };
    clear_test_prefixes();

    let (manager, config) = manager_with_dev_zone().await;
    let zone = config.zones[0].clone();

    manager
        .add_route(IpAddr::V4(Ipv4Addr::new(10, 55, 8, 1)), &zone)
        .await
        .unwrap();
    manager
        .add_route(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0x55, 0, 0, 0, 0, 0, 8)),
            &zone,
        )
        .await
        .unwrap();

    let table = kernel_table();
    assert!(table.contains("10.55.8.1 dev"));
    assert!(table.contains("fd00:55::8 dev"));

    // Both families enter the same registry: the dynamic quota counts two
    // intents, one per address, not one per family model.
    assert_eq!(manager.dynamic_route_count().await, 2);

    manager.cleanup_zone(&zone.name).await.unwrap();
    let _ = wait_for(
        Duration::from_secs(5),
        || !kernel_table().contains("10.55.8.1 dev"),
        "owned v4 row must be cleaned up",
    )
    .await;
    let table = kernel_table();
    assert!(
        !table.contains("10.55.8.1 dev"),
        "owned v4 row must be cleaned up:
{table}"
    );
    assert!(
        !table.contains("fd00:55::8 dev"),
        "owned v6 row must be cleaned up:
{table}"
    );
}

/// §16.5/§16.6: an externally deleted /128 is restored by the IPv6 route
/// event, not by the 30s periodic audit. The wait is <5s so the audit cannot
/// be the mechanism.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn ipv6_route_event_restores_externally_deleted_128() {
    let Some(_dev) = netns_dev() else {
        eprintln!("skipping: not inside the netns harness (LESHY_NETNS_DEV unset)");
        return;
    };
    assert!(running_as_root(), "the netns harness runs as root");
    init_tracing();
    clear_test_prefixes();

    let (manager, config) = manager_with_dev_zone().await;
    let zone = config.zones[0].clone();
    const V6_HOST: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x55, 0, 0, 0, 0, 0, 7);

    manager
        .add_route(IpAddr::V6(V6_HOST), &zone)
        .await
        .expect("v6 /128 add");
    assert!(
        kernel_table().contains(&format!("{V6_HOST} dev")),
        "the /128 row must exist before the external delete"
    );

    Command::new("ip")
        .args([
            "-6",
            "route",
            "del",
            &format!("{V6_HOST}/128"),
            "table",
            "main",
        ])
        .output()
        .expect("delete the /128 row externally");
    assert!(
        !kernel_table().contains(&format!("{V6_HOST} dev")),
        "the /128 row must be gone after the external delete"
    );

    let restored = wait_for(
        Duration::from_secs(5),
        || kernel_table().contains(&format!("{V6_HOST} dev")),
        "the IPv6 route event must restore the /128 row",
    )
    .await;
    assert!(
        restored,
        "the /128 row must be restored by the IPv6 event in <5s"
    );

    // 08D1 §16.3: the event path stays targeted — the repair came from a
    // per-key read-back, never from a full v4+v6 FIB snapshot.
    let counters = manager.reconcile_counters();
    assert_eq!(
        counters.full_snapshots, 0,
        "an event-driven repair must not read the full FIB: {counters:?}"
    );
    assert!(
        counters.targeted_reads >= 1,
        "the event must produce at least one targeted read: {counters:?}"
    );
}

/// §16.6: deleting and recreating the interface invalidates the old ifindex.
/// The kernel drops the route with the device; the monitor observes the
/// link/route deletion, and the next classification re-resolves the device
/// and installs the exact row through the NEW ifindex. A stale ownership
/// record must not turn the repair into a conflict or a fast-path no-op.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn real_kernel_interface_recreate_invalidates_old_ifindex() {
    let Some(dev) = netns_dev() else {
        eprintln!("skipping: not inside the netns harness (LESHY_NETNS_DEV unset)");
        return;
    };
    assert!(running_as_root(), "the netns harness runs as root");
    init_tracing();
    clear_test_prefixes();

    let (manager, config) = manager_with_dev_zone().await;
    let zone = config.zones[0].clone();
    const HOST: Ipv4Addr = Ipv4Addr::new(10, 55, 7, 3);

    manager
        .add_route(IpAddr::V4(HOST), &zone)
        .await
        .expect("add through the original device");
    assert!(
        kernel_table().contains(&format!("{HOST} dev")),
        "the row must exist before the interface is deleted"
    );
    let old_ifindex = ifindex(&dev);

    // Deleting the interface makes the kernel drop every route through it.
    ip(&["link", "del", "dev", &dev]);
    assert!(
        !kernel_table().contains(&format!("{HOST} dev")),
        "the kernel removes the route when the device is deleted"
    );

    // Let the monitor observe the link/route deletion and fail its reconcile
    // against the now-stale ifindex.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Recreate the device under the same name; the kernel assigns a new index.
    ip(&["link", "add", &dev, "type", "dummy"]);
    ip(&["address", "add", "10.55.0.254/24", "dev", &dev]);
    ip(&["-6", "address", "add", "fd00:55::254/64", "dev", &dev]);
    ip(&["link", "set", &dev, "up"]);
    let new_ifindex = ifindex(&dev);
    assert_ne!(
        new_ifindex, old_ifindex,
        "a recreated device must carry a new ifindex"
    );

    // The next classification resolves the device afresh and installs the
    // exact row through the new ifindex.
    manager
        .add_route(IpAddr::V4(HOST), &zone)
        .await
        .expect("re-add after the interface was recreated");
    assert!(
        kernel_table().contains(&format!("{HOST} dev")),
        "the row must be restored through the recreated device:\n{}",
        kernel_table()
    );

    manager.cleanup_zone(&zone.name).await.unwrap();
    let _ = wait_for(
        Duration::from_secs(5),
        || !kernel_table().contains(&format!("{HOST} dev")),
        "cleanup removes the row installed through the new ifindex",
    )
    .await;
    assert!(
        !kernel_table().contains(&format!("{HOST} dev")),
        "the row installed through the new ifindex must be cleaned up"
    );
}
