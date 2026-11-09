#[test]
fn test_config_validation() {
    use leshy::config::Config;
    use std::path::PathBuf;

    // Valid config should load
    let valid_path = PathBuf::from("tests/fixtures/test_config.toml");
    let config = Config::from_file(&valid_path);
    assert!(config.is_ok());

    // Config with empty default_upstream should fail
    let invalid_config = r#"
[server]
listen_address = "127.0.0.1:53"
default_upstream = []
    "#;

    let temp_dir = tempfile::tempdir().unwrap();
    let invalid_path = temp_dir.path().join("invalid.toml");
    std::fs::write(&invalid_path, invalid_config).unwrap();

    let result = Config::from_file(&invalid_path);
    assert!(result.is_err());
}

#[test]
fn test_exclusive_zone_config_validation() {
    use leshy::config::{Config, ZoneMode};

    let config_str = r#"
[server]
listen_address = "127.0.0.1:15360"
default_upstream = ["8.8.8.8:53"]

[[zones]]
name = "corporate"
dns_servers = []
route_type = "via"
route_target = "192.168.1.1"
domains = ["internal.company.com"]
patterns = []

[[zones]]
name = "vpn-all"
mode = "exclusive"
dns_servers = []
route_type = "via"
route_target = "192.168.1.1"
domains = ["google.com"]
patterns = ['\.ru$']
    "#;

    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("exclusive.toml");
    std::fs::write(&path, config_str).unwrap();

    let config = Config::from_file(&path).unwrap();
    assert_eq!(config.zones.len(), 2);
    assert_eq!(config.zones[0].mode, ZoneMode::Inclusive);
    assert_eq!(config.zones[1].mode, ZoneMode::Exclusive);
}

#[test]
fn test_exclusive_zone_empty_exclusions_valid() {
    use leshy::config::Config;

    let config_str = r#"
[server]
listen_address = "127.0.0.1:15361"
default_upstream = ["8.8.8.8:53"]

[[zones]]
name = "catch-all"
mode = "exclusive"
dns_servers = []
route_type = "via"
route_target = "192.168.1.1"
domains = []
patterns = []
    "#;

    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("exclusive-empty.toml");
    std::fs::write(&path, config_str).unwrap();

    let result = Config::from_file(&path);
    assert!(
        result.is_ok(),
        "Exclusive zone with empty exclusions should be valid"
    );
}

#[test]
fn test_inclusive_zone_still_requires_matchers() {
    use leshy::config::Config;

    let config_str = r#"
[server]
listen_address = "127.0.0.1:15362"
default_upstream = ["8.8.8.8:53"]

[[zones]]
name = "empty-inclusive"
dns_servers = []
route_type = "via"
route_target = "192.168.1.1"
domains = []
patterns = []
    "#;

    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("inclusive-empty.toml");
    std::fs::write(&path, config_str).unwrap();

    let result = Config::from_file(&path);
    assert!(
        result.is_err(),
        "Inclusive zone with no matchers should fail validation"
    );
}

#[test]
fn test_invalid_regex_in_config_fails() {
    use leshy::config::Config;

    let config_str = r#"
[server]
listen_address = "127.0.0.1:15363"
default_upstream = ["8.8.8.8:53"]

[[zones]]
name = "bad-regex"
mode = "exclusive"
dns_servers = []
route_type = "via"
route_target = "192.168.1.1"
domains = []
patterns = ["[bad"]
    "#;

    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("bad-regex.toml");
    std::fs::write(&path, config_str).unwrap();

    let result = Config::from_file(&path);
    assert!(
        result.is_err(),
        "Invalid regex pattern should fail validation"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("bad-regex"),
        "Error should mention zone name: {err}"
    );
}

// The real hickory serve loop: DnsServer::new binds, run() accepts, and a
// real UDP client gets a real answer through DnsHandler. Covers the
// bootstrap that unit tests cannot reach (dns/server.rs).
#[tokio::test(flavor = "multi_thread")]
async fn dns_server_binds_and_answers_over_udp() -> anyhow::Result<()> {
    use leshy::config::{Config, RouteFailureMode, ServerConfig};
    use leshy::dns::server::DnsServer;
    use leshy::zones::ZoneMatcher;
    use std::sync::Arc;

    let config = Config {
        server: ServerConfig {
            listen_address: "127.0.0.1:0".parse()?,
            default_upstream: vec!["127.0.0.1:1".parse()?],
            route_failure_mode: RouteFailureMode::Fallback,
            auto_reload: false,
            config_dir: None,
            cache_size: 100,
            cache_min_ttl: 0,
            cache_max_ttl: 3600,
            cache_negative_ttl: 30,
            route_aggregation_prefix: None,
            max_dynamic_routes: leshy::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
            routing_backend: Default::default(),
            kikimora_socket: None,
            writer_lock: None,
            kikimora_auth_file: None,
            kikimora_activation_id: None,
            kikimora_mode_generation: None,
        },
        zones: vec![],
    };
    let matcher = ZoneMatcher::new(config.zones.clone())?;
    let handler = Arc::new(tokio::sync::RwLock::new(leshy::dns::DnsHandler::new(
        config, matcher,
    )?));

    // Bound-then-drop proves the bootstrap (socket bind + registration).
    let server = DnsServer::new("127.0.0.1:0".parse()?, handler.clone()).await?;
    drop(server);

    // The serving path: bind on a known port, query over real UDP.
    let known: std::net::SocketAddr = "127.0.0.1:15399".parse()?;
    let server = DnsServer::new(known, handler).await?;
    let task = tokio::spawn(async move { server.run().await });

    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    sock.send_to(&query, known).await?;
    let mut buf = vec![0u8; 512];
    let (len, _from) =
        tokio::time::timeout(std::time::Duration::from_secs(10), sock.recv_from(&mut buf))
            .await??;
    assert!(len > 12, "a DNS response must come back ({} bytes)", len);
    // No zone matched and the upstream is unreachable: NXDOMAIN/SERVFAIL is
    // fine — the point is that the serve loop answered.
    task.abort();
    Ok(())
}
