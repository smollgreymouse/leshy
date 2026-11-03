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

/// `ip route show table main` for both families, the kernel's own truth.
fn kernel_table() -> String {
    format!(
        "{}{}",
        ip(&["route", "show", "table", "main"]),
        ip(&["-6", "route", "show", "table", "main"])
    )
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
    for _ in 0..50 {
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

    // --- external deletion is restored once -------------------------------
    Command::new("ip")
        .args(["route", "del", &V4_HOST.to_string(), "table", "main"])
        .output()
        .expect("delete the row externally");
    assert!(
        !kernel_table().contains(&format!("{V4_HOST} dev")),
        "the row must be gone after the external delete"
    );
    manager
        .add_route(IpAddr::V4(V4_HOST), &zone)
        .await
        .expect("the missing row is restored");
    assert!(
        kernel_table().contains(&format!("{V4_HOST} dev")),
        "the /32 row must be back after reconciliation"
    );
    let after_restore = kernel_table();

    // Repeated classifications after the restore stay flat.
    for _ in 0..50 {
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
    for _ in 0..50 {
        manager.add_route(IpAddr::V6(V6_HOST), &zone).await.unwrap();
    }
    assert!(kernel_table().contains(&format!("{V6_HOST} dev")));

    // --- a foreign row is never replaced nor deleted ----------------------
    const FOREIGN: &str = "10.55.9.9/32";
    ip(&["route", "add", FOREIGN, "dev", "lo", "table", "main"]);
    let foreign_before = kernel_table();

    let result = manager
        .add_route(IpAddr::V4(Ipv4Addr::new(10, 55, 9, 9)), &zone)
        .await;
    assert!(
        result.is_err(),
        "a foreign row on the same prefix must be refused, not replaced"
    );
    assert!(
        kernel_table().contains(FOREIGN),
        "the foreign row must survive the refused ensure"
    );

    // Explicit zone cleanup must not delete it either.
    manager.cleanup_zone(&zone.name).await.unwrap();
    let foreign_after = kernel_table();
    assert!(
        foreign_after.contains(FOREIGN),
        "the foreign row must survive the zone cleanup"
    );
    assert!(
        !foreign_after.contains(&format!("{V4_HOST} dev")),
        "owned rows are cleaned up"
    );
    assert!(
        !foreign_after.contains(&format!("{V6_HOST} dev")),
        "owned v6 rows are cleaned up"
    );
    assert_eq!(
        foreign_after, foreign_before,
        "cleanup must remove only owned rows, leaving the table otherwise identical"
    );

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
    let table = kernel_table();
    assert!(!table.contains("10.55.8.1 dev"));
    assert!(!table.contains("fd00:55::8 dev"));
}
