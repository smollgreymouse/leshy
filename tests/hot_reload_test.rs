// Hot-reload Configuration Test
// Tests reload functionality: channel-based config updates

use leshy::config::Config;
use leshy::dns::DnsHandler;
use leshy::reload::diff_zones;
use leshy::server::apply_reload;
use leshy::zones::ZoneMatcher;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_config_hot_reload_via_channel() -> anyhow::Result<()> {
    // Initial config with zone1
    let initial_config: Config = toml::from_str(
        r#"
[server]
listen_address = "127.0.0.1:15380"
default_upstream = ["8.8.8.8:53"]
route_failure_mode = "fallback"
auto_reload = true

[[zones]]
name = "zone1"
dns_servers = []
route_type = "via"
route_target = "192.168.100.1"
domains = ["example.com"]
patterns = []
    "#,
    )?;

    let matcher = ZoneMatcher::new(initial_config.zones.clone())?;
    let handler = Arc::new(RwLock::new(DnsHandler::new(
        initial_config.clone(),
        matcher,
    )?));

    // Create a channel to simulate reload signals (same as ConfigWatcher produces)
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::unbounded_channel::<Config>();

    // Spawn reload handler task running the production reload transaction
    let handler_clone = handler.clone();
    tokio::spawn(async move {
        while let Some(new_config) = reload_rx.recv().await {
            let _ = apply_reload(&handler_clone, new_config).await;
        }
    });

    // Verify initial state
    {
        let guard = handler.read().await;
        assert_eq!(guard.config().zones.len(), 1);
        assert_eq!(guard.config().zones[0].name, "zone1");
    }

    // Send new config through channel (simulates what ConfigWatcher does on file change)
    let updated_config: Config = toml::from_str(
        r#"
[server]
listen_address = "127.0.0.1:15380"
default_upstream = ["8.8.8.8:53"]
route_failure_mode = "fallback"
auto_reload = true

[[zones]]
name = "zone2"
dns_servers = []
route_type = "via"
route_target = "192.168.200.1"
domains = ["example.net"]
patterns = []
    "#,
    )?;

    reload_tx.send(updated_config)?;

    // Give the spawned task time to process
    sleep(Duration::from_millis(100)).await;

    // Verify config was reloaded
    {
        let guard = handler.read().await;
        assert_eq!(
            guard.config().zones.len(),
            1,
            "Should have 1 zone after reload"
        );
        assert_eq!(
            guard.config().zones[0].name,
            "zone2",
            "Zone should be zone2 after reload"
        );
    }

    println!("✓ Hot reload via channel test passed!");
    Ok(())
}

#[tokio::test]
async fn test_zone_cleanup_on_removal() -> anyhow::Result<()> {
    let initial_config: Config = toml::from_str(
        r#"
[server]
listen_address = "127.0.0.1:15381"
default_upstream = ["8.8.8.8:53"]
route_failure_mode = "fallback"

[[zones]]
name = "zone_a"
dns_servers = []
route_type = "via"
route_target = "192.168.100.1"
domains = ["example.com"]
patterns = []

[[zones]]
name = "zone_b"
dns_servers = []
route_type = "via"
route_target = "192.168.100.2"
domains = ["example.org"]
patterns = []
    "#,
    )?;

    let matcher = ZoneMatcher::new(initial_config.zones.clone())?;
    let mut handler = DnsHandler::new(initial_config.clone(), matcher)?;

    assert_eq!(handler.config().zones.len(), 2, "Should have 2 zones");

    // Updated config with only zone_b
    let new_config: Config = toml::from_str(
        r#"
[server]
listen_address = "127.0.0.1:15381"
default_upstream = ["8.8.8.8:53"]
route_failure_mode = "fallback"

[[zones]]
name = "zone_b"
dns_servers = []
route_type = "via"
route_target = "192.168.100.2"
domains = ["example.org"]
patterns = []
    "#,
    )?;

    let new_matcher = ZoneMatcher::new(new_config.zones.clone())?;

    // Cleanup zone_a before updating
    handler.cleanup_zone("zone_a").await?;

    // Update config
    handler.update_config(new_config, new_matcher).await?;

    assert_eq!(
        handler.config().zones.len(),
        1,
        "Should have 1 zone after update"
    );
    assert_eq!(
        handler.config().zones[0].name,
        "zone_b",
        "Remaining zone should be zone_b"
    );

    println!("✓ Zone cleanup test passed!");
    Ok(())
}

#[tokio::test]
async fn test_config_reload_with_current_dir() -> anyhow::Result<()> {
    let test_config = r#"
[server]
listen_address = "127.0.0.1:15382"
default_upstream = ["8.8.8.8:53"]
route_failure_mode = "fallback"

[[zones]]
name = "test"
dns_servers = []
route_type = "via"
route_target = "192.168.1.1"
domains = ["test.local"]
patterns = []
    "#;

    let config_path = std::env::current_dir()?.join("test_leshy.toml");
    std::fs::write(&config_path, test_config)?;

    let config = Config::from_file(&config_path)?;
    assert_eq!(
        config.server.listen_address,
        "127.0.0.1:15382".parse::<SocketAddr>()?,
    );
    assert_eq!(config.zones.len(), 1);

    std::fs::remove_file(&config_path)?;

    println!("✓ Current directory config test passed!");
    Ok(())
}

#[tokio::test]
async fn test_zone_diff_functions() -> anyhow::Result<()> {
    let old_config: Config = toml::from_str(
        r#"
[server]
listen_address = "127.0.0.1:15383"
default_upstream = ["8.8.8.8:53"]

[[zones]]
name = "eu"
route_type = "via"
route_target = "192.168.169.1"
domains = ["github.com"]

[[zones]]
name = "corporate"
route_type = "dev"
route_target = "/run/vpn/corporate.dev"
domains = ["internal.company.com"]
    "#,
    )?;

    let new_config: Config = toml::from_str(
        r#"
[server]
listen_address = "127.0.0.1:15383"
default_upstream = ["8.8.8.8:53"]

[[zones]]
name = "corporate"
route_type = "dev"
route_target = "/run/vpn/corporate.dev"
domains = ["internal.company.com"]

[[zones]]
name = "office"
route_type = "dev"
route_target = "/run/vpn/office.dev"
domains = ["office.local"]
    "#,
    )?;

    let changes = diff_zones(&old_config.zones, &new_config.zones);
    assert_eq!(changes.len(), 2);
    assert!(
        matches!(&changes[0], leshy::reload::ZoneChange::Added(z) if z.name == "office"),
        "added zone must be reported"
    );
    assert!(
        matches!(&changes[1], leshy::reload::ZoneChange::Removed(z) if z.name == "eu"),
        "removed zone must be reported"
    );

    // A same-name zone whose route target changed is a Changed zone.
    let retargeted: Config = toml::from_str(
        r#"
[server]
listen_address = "127.0.0.1:15383"
default_upstream = ["8.8.8.8:53"]

[[zones]]
name = "eu"
route_type = "via"
route_target = "10.8.0.1"
domains = ["github.com"]
    "#,
    )?;
    let changes = diff_zones(&old_config.zones, &retargeted.zones);
    assert_eq!(changes.len(), 2);
    assert!(
        matches!(&changes[..], [leshy::reload::ZoneChange::Changed { old, new }, ..]
        if old.name == "eu" && new.route_target == "10.8.0.1")
    );

    println!("✓ Zone diff functions test passed!");
    Ok(())
}
