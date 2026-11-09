//! Windows native route-registry acceptance (08D1 §41.3 / rescue R5).
//!
//! Drives the production `RouteManager` (local backend) against the real
//! Windows IP Helper forwarding table and reads the truth back with
//! `Get-NetRoute` — independent of Leshy's own view.
//!
//! Run only through `windows/tests/route-registry.ps1`, which requires
//! Administrator, pins disposable TEST-NET prefixes and snapshots unrelated
//! routes before/after. Every test is `#[ignore]` so a plain `cargo test`
//! never touches the forwarding table.
//!
//! Required environment (set by the harness):
//!   LESHY_WIN_ROUTE_TEST=1        explicit safety switch
//!   LESHY_WIN_TEST_ADAPTER        disposable adapter name (e.g. the tunnel)
//!   LESHY_WIN_TEST_OTHER_ADAPTER  a second adapter for foreign-row cases
//!   LESHY_WIN_TEST_SHA            exact source SHA under test (reported)

#![cfg(target_os = "windows")]

use leshy::config::{DnsProtocol, RouteType, ZoneConfig, ZoneMode};
use leshy::routing::{RouteManager, DEFAULT_MAX_DYNAMIC_ROUTES};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

const V4_HOST: Ipv4Addr = Ipv4Addr::new(198, 18, 77, 1);
const V6_HOST: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x77, 0, 0, 0, 0, 0, 1);
const TEST_TAG: &str = "198.18.77.1/32";
const TEST_TAG_V6: &str = "fd00:77::1/128";

fn enabled() -> bool {
    std::env::var("LESHY_WIN_ROUTE_TEST").as_deref() == Ok("1")
}

fn require_enabled() {
    assert!(
        enabled(),
        "set LESHY_WIN_ROUTE_TEST=1 and run through windows/tests/route-registry.ps1"
    );
    assert!(is_admin(), "the Windows route acceptance runs elevated");
}

fn is_admin() -> bool {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ])
        .output()
        .expect("powershell available");
    String::from_utf8_lossy(&output.stdout).trim() == "True"
}

fn test_adapter(name_var: &str) -> String {
    std::env::var(name_var)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("{name_var} must name a disposable interface"))
}

fn powershell(script: &str) -> String {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .expect("powershell available");
    assert!(
        output.status.success(),
        "powershell failed: {}\n{}",
        script,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// `<ifIndex>|<nextHop>|<metric>|<protocol>` for every row on `destination`.
fn rows(family: &str, destination: &str) -> Vec<String> {
    let script = format!(
        "Get-NetRoute -AddressFamily {family} -DestinationPrefix '{destination}' -ErrorAction SilentlyContinue | \
         ForEach-Object {{ \"$($_.ifIndex)|$($_.NextHop)|$($_.RouteMetric)|$($_.Protocol)\" }}; exit 0"
    );
    powershell(&script)
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

fn ifindex_of(adapter: &str) -> String {
    let script = format!("(Get-NetAdapter -Name '{adapter}' -ErrorAction Stop).ifIndex");
    powershell(&script).trim().to_string()
}

fn delete_row(family: &str, destination: &str, ifindex: &str) {
    let script = format!(
        "Remove-NetRoute -AddressFamily {family} -DestinationPrefix '{destination}' -InterfaceIndex {ifindex} -Confirm:$false -ErrorAction SilentlyContinue; exit 0"
    );
    powershell(&script);
}

/// Remove every row on a disposable test prefix (and nothing else).
fn delete_prefix(family: &str, destination: &str) {
    let script = format!(
        "Remove-NetRoute -AddressFamily {family} -DestinationPrefix '{destination}' -Confirm:$false -ErrorAction SilentlyContinue; exit 0"
    );
    powershell(&script);
}

fn add_foreign_row(family: &str, destination: &str, ifindex: &str, metric: u32) {
    let script = format!(
        "New-NetRoute -AddressFamily {family} -DestinationPrefix '{destination}' -InterfaceIndex {ifindex} \
         -NextHop 0.0.0.0 -RouteMetric {metric} -Protocol NetMgmt -ErrorAction Stop | Out-Null"
    );
    powershell(&script);
}

/// Every route line that is not one of the disposable test prefixes.
fn unrelated_routes() -> Vec<String> {
    let script =
        "Get-NetRoute -ErrorAction SilentlyContinue | ForEach-Object { \"$($_.AddressFamily)|$($_.DestinationPrefix)|$($_.ifIndex)|$($_.NextHop)|$($_.RouteMetric)\" }";
    let mut lines: Vec<String> = powershell(script)
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .filter(|line| !line.contains("198.18.77.1/32") && !line.contains("fd00:77::1/128"))
        .collect();
    lines.sort();
    lines
}

fn zone(adapter: &str, ipv6: bool) -> (ZoneConfig, tempfile::NamedTempFile) {
    // `RouteType::Dev` resolves the adapter through the device file, exactly
    // like the production VPN handoff.
    let mut device_file = tempfile::NamedTempFile::new().expect("temp device file");
    writeln!(device_file, "{adapter}").expect("write device file");
    let config = ZoneConfig {
        name: "winrt".to_string(),
        mode: ZoneMode::Inclusive,
        dns_servers: vec![],
        route_type: RouteType::Dev,
        route_target: device_file.path().to_string_lossy().to_string(),
        route_target_ipv6: None,
        domains: vec![],
        patterns: vec![],
        static_routes: vec![],
        dns_protocol: DnsProtocol::Udp,
        cache_min_ttl: None,
        cache_max_ttl: None,
        cache_negative_ttl: None,
        ipv6,
    };
    (config, device_file)
}

fn manager() -> RouteManager {
    RouteManager::with_capacity(None, DEFAULT_MAX_DYNAMIC_ROUTES).expect("local route manager")
}

/// Best-effort reset of the disposable prefixes before and after a case.
async fn cleanup(manager: &RouteManager) {
    let _ = manager.cleanup_zone("winrt").await;
    delete_prefix("IPv4", TEST_TAG);
    delete_prefix("IPv6", TEST_TAG_V6);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn windows_ipv4_exact_add_read_back_delete() {
    require_enabled();
    let adapter = test_adapter("LESHY_WIN_TEST_ADAPTER");
    let ifindex = ifindex_of(&adapter);
    let (zone, _device) = zone(&adapter, false);
    let manager = manager();
    cleanup(&manager).await;

    manager
        .add_route(IpAddr::V4(V4_HOST), &zone)
        .await
        .expect("IPv4 /32 add");

    let observed = rows("IPv4", TEST_TAG);
    assert_eq!(observed.len(), 1, "exactly one row: {observed:?}");
    assert!(
        observed[0].starts_with(&format!("{ifindex}|")),
        "the row must be installed through {adapter}: {observed:?}"
    );

    manager.cleanup_zone("winrt").await.expect("cleanup");
    assert!(
        rows("IPv4", TEST_TAG).is_empty(),
        "the owned row must be gone after cleanup"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn windows_ipv6_exact_add_read_back_delete() {
    require_enabled();
    let adapter = test_adapter("LESHY_WIN_TEST_ADAPTER");
    let (zone, _device) = zone(&adapter, true);
    let manager = manager();
    cleanup(&manager).await;

    manager
        .add_route(IpAddr::V6(V6_HOST), &zone)
        .await
        .expect("IPv6 /128 add");

    let observed = rows("IPv6", TEST_TAG_V6);
    assert_eq!(observed.len(), 1, "exactly one row: {observed:?}");

    manager.cleanup_zone("winrt").await.expect("cleanup");
    assert!(
        rows("IPv6", TEST_TAG_V6).is_empty(),
        "the owned /128 must be gone after cleanup"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn windows_thousand_duplicate_ensures_do_not_churn() {
    require_enabled();
    let adapter = test_adapter("LESHY_WIN_TEST_ADAPTER");
    let (zone, _device) = zone(&adapter, false);
    let manager = manager();
    cleanup(&manager).await;

    for _ in 0..1000 {
        manager
            .add_route(IpAddr::V4(V4_HOST), &zone)
            .await
            .expect("repeated ensure");
    }

    let observed = rows("IPv4", TEST_TAG);
    assert_eq!(
        observed.len(),
        1,
        "1000 ensures must leave exactly one row: {observed:?}"
    );
    manager.cleanup_zone("winrt").await.expect("cleanup");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn windows_preexisting_compatible_row_is_foreign_and_survives() {
    require_enabled();
    let adapter = test_adapter("LESHY_WIN_TEST_ADAPTER");
    let ifindex = ifindex_of(&adapter);
    let (zone, _device) = zone(&adapter, false);
    let manager = manager();
    cleanup(&manager).await;

    add_foreign_row("IPv4", TEST_TAG, &ifindex, 0);
    assert_eq!(rows("IPv4", TEST_TAG).len(), 1, "pre-existing row");

    // A compatible pre-existing row satisfies forwarding but is not ours.
    manager
        .add_route(IpAddr::V4(V4_HOST), &zone)
        .await
        .expect("a compatible row is a no-op");

    manager.cleanup_zone("winrt").await.expect("cleanup");
    assert_eq!(
        rows("IPv4", TEST_TAG).len(),
        1,
        "cleanup must not delete a row this process does not own"
    );

    delete_row("IPv4", TEST_TAG, &ifindex);
    assert!(rows("IPv4", TEST_TAG).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn windows_same_prefix_foreign_row_conflicts_and_survives() {
    require_enabled();
    let adapter = test_adapter("LESHY_WIN_TEST_ADAPTER");
    let ifindex = ifindex_of(&adapter);
    let other = ifindex_of(&test_adapter("LESHY_WIN_TEST_OTHER_ADAPTER"));
    assert_ne!(ifindex, other, "the test adapters must differ");
    let (zone, _device) = zone(&adapter, false);
    let manager = manager();
    cleanup(&manager).await;

    add_foreign_row("IPv4", TEST_TAG, &other, 0);
    let before = rows("IPv4", TEST_TAG);
    assert_eq!(before.len(), 1, "foreign row installed");

    let error = manager
        .add_route(IpAddr::V4(V4_HOST), &zone)
        .await
        .expect_err("a foreign same-prefix row must conflict");
    assert!(
        error.to_string().contains("conflict"),
        "expected a route conflict, got: {error}"
    );

    assert_eq!(
        rows("IPv4", TEST_TAG),
        before,
        "the foreign row must survive unchanged"
    );
    delete_row("IPv4", TEST_TAG, &other);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn windows_wrong_metric_row_is_foreign() {
    require_enabled();
    let adapter = test_adapter("LESHY_WIN_TEST_ADAPTER");
    let other = ifindex_of(&test_adapter("LESHY_WIN_TEST_OTHER_ADAPTER"));
    let (zone, _device) = zone(&adapter, false);
    let manager = manager();
    cleanup(&manager).await;

    add_foreign_row("IPv4", TEST_TAG, &other, 5);
    let before = rows("IPv4", TEST_TAG);
    assert_eq!(before.len(), 1, "wrong-metric row installed");

    let error = manager
        .add_route(IpAddr::V4(V4_HOST), &zone)
        .await
        .expect_err("a wrong-metric row must be foreign");
    assert!(
        error.to_string().contains("conflict"),
        "expected a route conflict, got: {error}"
    );
    assert_eq!(rows("IPv4", TEST_TAG), before, "the row must survive");
    delete_row("IPv4", TEST_TAG, &other);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn windows_exact_previous_owned_target_is_replaced() {
    require_enabled();
    let adapter = test_adapter("LESHY_WIN_TEST_ADAPTER");
    let (first_zone, _first_device) = zone(&adapter, false);
    let (second_zone, _second_device) = zone(&test_adapter("LESHY_WIN_TEST_OTHER_ADAPTER"), false);
    let other = ifindex_of(&test_adapter("LESHY_WIN_TEST_OTHER_ADAPTER"));
    let manager = manager();
    cleanup(&manager).await;

    manager
        .add_route(IpAddr::V4(V4_HOST), &first_zone)
        .await
        .expect("first add");
    let before = rows("IPv4", TEST_TAG);
    assert_eq!(before.len(), 1, "first row installed");

    // The same key now demands a different exact target: the recorded owned
    // row is replaced, nothing foreign is touched.
    manager
        .add_route(IpAddr::V4(V4_HOST), &second_zone)
        .await
        .expect("exact previous target replacement");

    let after = rows("IPv4", TEST_TAG);
    assert_eq!(after.len(), 1, "still exactly one row: {after:?}");
    assert!(
        after[0].starts_with(&format!("{other}|")),
        "the row must move to the second adapter: {after:?}"
    );

    manager.cleanup_zone("winrt").await.expect("cleanup");
    assert!(rows("IPv4", TEST_TAG).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn windows_external_delete_repairs_through_the_observer() {
    require_enabled();
    let adapter = test_adapter("LESHY_WIN_TEST_ADAPTER");
    let (zone, _device) = zone(&adapter, false);
    let manager = manager();
    cleanup(&manager).await;

    manager
        .add_route(IpAddr::V4(V4_HOST), &zone)
        .await
        .expect("add");
    assert_eq!(rows("IPv4", TEST_TAG).len(), 1);
    let before = manager.reconcile_counters();

    delete_prefix("IPv4", TEST_TAG);

    // The observer may repair the row faster than this thread can observe the
    // gap, so the proof is the counter movement plus the restored row: a
    // targeted read-back ran, and no full snapshot did.
    let restored = wait_for(std::time::Duration::from_secs(10), || {
        let counters = manager.reconcile_counters();
        counters.targeted_reads > before.targeted_reads && !rows("IPv4", TEST_TAG).is_empty()
    });
    let counters = manager.reconcile_counters();
    assert!(
        restored,
        "NotifyRouteChange2 must make the backend repair the deleted row: {counters:?}"
    );
    assert_eq!(
        counters.full_snapshots, before.full_snapshots,
        "the event repair must stay targeted: {counters:?}"
    );
    assert!(
        counters.targeted_reads > before.targeted_reads,
        "the event must read the key back: {counters:?}"
    );

    manager.cleanup_zone("winrt").await.expect("cleanup");
}

fn wait_for(timeout: std::time::Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    predicate()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn windows_unrelated_routes_are_untouched() {
    require_enabled();
    let before = unrelated_routes();
    let adapter = test_adapter("LESHY_WIN_TEST_ADAPTER");
    let ifindex = ifindex_of(&adapter);
    let (zone, _device) = zone(&adapter, false);
    let manager = manager();

    manager
        .add_route(IpAddr::V4(V4_HOST), &zone)
        .await
        .expect("add");
    manager.cleanup_zone("winrt").await.expect("cleanup");

    assert_eq!(
        before,
        unrelated_routes(),
        "the acceptance must not change any unrelated route"
    );
    let _ = ifindex;
}
