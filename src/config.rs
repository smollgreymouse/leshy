use crate::routing::{family_of, AddressFamily};
use serde::{Deserialize, Deserializer, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub zones: Vec<ZoneConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub listen_address: SocketAddr,
    pub default_upstream: Vec<SocketAddr>,

    /// What to do when route addition fails:
    /// - "servfail": Return SERVFAIL to client
    /// - "fallback": Continue and return DNS response (default)
    #[serde(default = "default_route_failure_mode")]
    pub route_failure_mode: RouteFailureMode,

    /// Enable automatic config reload when file changes
    #[serde(default)]
    pub auto_reload: bool,

    /// Directory to load additional zone configs from.
    /// Defaults to config.d/ next to the main config file.
    #[serde(default)]
    pub config_dir: Option<String>,

    /// Maximum number of cache entries (0 = disabled)
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,

    /// TTL used only when the upstream sends TTL=0; otherwise the
    /// authoritative TTL is honored, capped by `cache_max_ttl`.
    #[serde(default = "default_cache_min_ttl")]
    pub cache_min_ttl: u64,

    /// Maximum TTL for cached responses (seconds)
    #[serde(default = "default_cache_max_ttl")]
    pub cache_max_ttl: u64,

    /// TTL for NXDOMAIN / empty responses (seconds)
    #[serde(default = "default_cache_negative_ttl")]
    pub cache_negative_ttl: u64,

    /// CIDR prefix length for route aggregation (e.g. 22 = /22, 1024 IPs).
    /// When set, DNS-resolved IPv4 addresses are grouped into wider subnets
    /// to reduce the number of kernel routes. Unset or 32 = disabled.
    #[serde(default)]
    pub route_aggregation_prefix: Option<u8>,

    /// Hard cap on dynamic (DNS-sourced) route intents.
    ///
    /// A long-lived zone can accumulate CDN destinations indefinitely. When
    /// the cap is reached a new unique address is denied fail-closed instead
    /// of silently growing the routing table. Static routes do not count.
    #[serde(default = "default_max_dynamic_routes")]
    pub max_dynamic_routes: usize,

    /// Which writer installs the selected routes.
    ///
    /// `local` (default) is the standalone mode: Leshy writes the kernel FIB
    /// itself through its platform backend. `kikimora` is the managed mode:
    /// Leshy only sends route intents to the Kikimora control socket and
    /// never touches the local FIB (no fallback either way).
    #[serde(default)]
    pub routing_backend: RoutingBackend,

    /// Path to the Kikimora control socket, required for
    /// `routing_backend = "kikimora"` (e.g. "/run/kikimora/core.sock").
    #[serde(default)]
    pub kikimora_socket: Option<String>,
}

/// Route-writer selection for the server (plan section 12).
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RoutingBackend {
    /// Standalone: Leshy's own platform backend writes the kernel routes.
    #[default]
    Local,
    /// Managed: Kikimora is the single FIB writer for Leshy-selected routes.
    Kikimora,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RouteFailureMode {
    Servfail,
    Fallback,
}

fn default_route_failure_mode() -> RouteFailureMode {
    RouteFailureMode::Fallback
}

fn default_cache_size() -> usize {
    1000
}
fn default_cache_min_ttl() -> u64 {
    0
}
fn default_cache_max_ttl() -> u64 {
    3600
}
fn default_cache_negative_ttl() -> u64 {
    30
}
fn default_max_dynamic_routes() -> usize {
    crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZoneConfig {
    pub name: String,

    /// Zone matching mode: "inclusive" (default) or "exclusive"
    /// Inclusive: matches only listed domains/patterns
    /// Exclusive: matches everything EXCEPT listed domains/patterns
    #[serde(default)]
    pub mode: ZoneMode,

    /// DNS servers for this zone. Empty = use default upstream.
    /// Supports both simple format: ["10.44.2.2:53"]
    /// and rich format: [{ address = "10.44.2.2:53", cache_min_ttl = 10 }]
    #[serde(default, deserialize_with = "deserialize_dns_servers")]
    pub dns_servers: Vec<DnsServerConfig>,

    /// How to route resolved IPs
    pub route_type: RouteType,

    /// For "via": the IPv4 gateway address.
    /// For "dev": path to the device file (used for both families).
    pub route_target: String,

    /// IPv6 gateway for `route_type = "via"` zones with `ipv6 = true`.
    ///
    /// A `via` zone needs a separate IPv6 next hop because an IPv4 gateway
    /// cannot carry IPv6 traffic. Must be absent for `dev` zones, where the
    /// single device file serves both families.
    #[serde(default)]
    pub route_target_ipv6: Option<String>,

    /// Exact domain matches (domain + all subdomains)
    #[serde(default)]
    pub domains: Vec<String>,

    /// Substring pattern matches
    #[serde(default)]
    pub patterns: Vec<String>,

    /// Static IP/CIDR routes to add on startup (e.g. "149.154.160.0/20", "1.2.3.4")
    #[serde(default)]
    pub static_routes: Vec<String>,

    /// Protocol for upstream DNS queries: "udp" (default) or "tcp".
    /// Use "tcp" when upstream is reachable only through a SOCKS5/TCP proxy (e.g. tun2socks).
    #[serde(default)]
    pub dns_protocol: DnsProtocol,

    /// Per-zone cache minimum TTL override (seconds)
    #[serde(default)]
    pub cache_min_ttl: Option<u64>,

    /// Per-zone cache maximum TTL override (seconds)
    #[serde(default)]
    pub cache_max_ttl: Option<u64>,

    /// Per-zone negative TTL override (seconds)
    #[serde(default)]
    pub cache_negative_ttl: Option<u64>,

    /// Advertise and route IPv6 for this zone.
    ///
    /// IPv4 is always enabled. IPv6 is enabled only when this is `true`, for
    /// both `dev` and `via` zones: the managed interface that carries a `dev`
    /// zone usually has no global IPv6 address, so an AAAA answer would send
    /// the client around the tunnel over the physical link (or into a black
    /// hole). A `via` zone needs `route_target_ipv6` as well.
    #[serde(default)]
    pub ipv6: bool,
}

impl ZoneConfig {
    /// Whether AAAA answers may be handed to clients and routed through this
    /// zone. This is exactly the configured policy: the address family of a
    /// route always comes from the address itself, never from this flag.
    pub fn advertises_ipv6(&self) -> bool {
        self.ipv6
    }

    /// Whether routes of `family` may be installed for this zone.
    pub fn family_enabled(&self, family: AddressFamily) -> bool {
        match family {
            AddressFamily::V4 => true,
            AddressFamily::V6 => self.ipv6,
        }
    }

    /// The configured gateway for `family`, if this zone routes via a gateway.
    ///
    /// Returns `Ok(None)` for `dev` zones, which have no gateway at all.
    pub fn gateway_for(&self, family: AddressFamily) -> anyhow::Result<Option<IpAddr>> {
        if self.route_type == RouteType::Dev {
            return Ok(None);
        }
        let raw = match family {
            AddressFamily::V4 => Some(&self.route_target),
            AddressFamily::V6 => self.route_target_ipv6.as_ref(),
        };
        let Some(raw) = raw else {
            anyhow::bail!(
                "zone '{}': route_target_ipv6 is required for an IPv6 via zone",
                self.name
            );
        };
        let gateway: IpAddr = raw
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("zone '{}': invalid gateway '{raw}'", self.name))?;
        if family_of(gateway) != family {
            anyhow::bail!(
                "zone '{}': gateway {gateway} does not match the {family:?} route family",
                self.name
            );
        }
        Ok(Some(gateway))
    }
}

/// Per-server DNS configuration with optional cache TTL overrides.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DnsServerConfig {
    pub address: SocketAddr,
    #[serde(default)]
    pub cache_min_ttl: Option<u64>,
    #[serde(default)]
    pub cache_max_ttl: Option<u64>,
    #[serde(default)]
    pub cache_negative_ttl: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum DnsServerEntry {
    Simple(SocketAddr),
    Rich(DnsServerConfig),
}

fn deserialize_dns_servers<'de, D>(deserializer: D) -> Result<Vec<DnsServerConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    let entries: Vec<DnsServerEntry> = Vec::deserialize(deserializer)?;
    Ok(entries
        .into_iter()
        .map(|entry| match entry {
            DnsServerEntry::Simple(address) => DnsServerConfig {
                address,
                cache_min_ttl: None,
                cache_max_ttl: None,
                cache_negative_ttl: None,
            },
            DnsServerEntry::Rich(config) => config,
        })
        .collect())
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    #[default]
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ZoneMode {
    /// Match only listed domains/patterns (default)
    #[default]
    Inclusive,
    /// Match everything EXCEPT listed domains/patterns
    Exclusive,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RouteType {
    /// Static gateway IP
    Via,
    /// Dynamic device from file
    Dev,
}

impl Config {
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load config from main file and merge with config.d directory
    ///
    /// Main config file contains server settings.
    /// config.d directory contains zone definitions (*.toml files).
    /// All zones are merged together.
    pub fn from_file_with_includes(path: &PathBuf) -> anyhow::Result<Self> {
        // Load main config
        let mut config = Self::from_file(path)?;

        // Use explicit config_dir if set, otherwise look next to main config
        let config_dir = if let Some(ref dir) = config.server.config_dir {
            PathBuf::from(dir)
        } else {
            path.parent()
                .map(|p| p.join("config.d"))
                .unwrap_or_else(|| PathBuf::from("config.d"))
        };

        if config_dir.exists() && config_dir.is_dir() {
            tracing::info!(dir = %config_dir.display(), "Loading additional configs from directory");

            // Load all .toml files from config.d
            let mut entries: Vec<_> = std::fs::read_dir(&config_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s == "toml")
                        .unwrap_or(false)
                })
                .collect();

            // Sort by filename for predictable ordering
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                let zone_file = entry.path();
                match Self::load_zones_from_file(&zone_file) {
                    Ok(zones) => {
                        tracing::info!(
                            file = %zone_file.display(),
                            zone_count = zones.len(),
                            "Loaded zones from file"
                        );
                        config.zones.extend(zones);
                    }
                    Err(e) => {
                        tracing::warn!(
                            file = %zone_file.display(),
                            error = %e,
                            "Failed to load zone file, skipping"
                        );
                    }
                }
            }
        }

        config.validate()?;
        Ok(config)
    }

    /// Load only zones from a config file (ignore server settings)
    fn load_zones_from_file(path: &PathBuf) -> anyhow::Result<Vec<ZoneConfig>> {
        let content = std::fs::read_to_string(path)?;

        // Try to parse as full config (for compatibility)
        if let Ok(config) = toml::from_str::<Config>(&content) {
            return Ok(config.zones);
        }

        // Try to parse as zones-only config
        #[derive(Deserialize)]
        struct ZonesOnly {
            zones: Vec<ZoneConfig>,
        }

        if let Ok(zones_only) = toml::from_str::<ZonesOnly>(&content) {
            return Ok(zones_only.zones);
        }

        anyhow::bail!("Could not parse zones from file");
    }

    /// Check the whole configuration for structural and policy errors.
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate listen address is not 0.0.0.0:0
        if self.server.listen_address.port() == 0 {
            anyhow::bail!("Server listen port cannot be 0");
        }

        // Managed mode needs to know where the controller listens. There is
        // no auto-detection and no fallback to the local writer.
        if self.server.routing_backend == RoutingBackend::Kikimora
            && self
                .server
                .kikimora_socket
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
        {
            anyhow::bail!(
                "routing_backend = \"kikimora\" requires kikimora_socket \
                 (e.g. \"/run/kikimora/core.sock\")"
            );
        }

        // Validate default upstream not empty
        if self.server.default_upstream.is_empty() {
            anyhow::bail!("default_upstream cannot be empty");
        }

        // Validate zones
        for zone in &self.zones {
            if zone.mode == ZoneMode::Inclusive
                && zone.domains.is_empty()
                && zone.patterns.is_empty()
                && zone.static_routes.is_empty()
            {
                anyhow::bail!(
                    "Zone '{}' must have at least one domain, pattern, or static route",
                    zone.name
                );
            }

            // Validate pattern regexes
            for pattern in &zone.patterns {
                if let Err(e) = regex::Regex::new(pattern) {
                    anyhow::bail!(
                        "Zone '{}': invalid regex pattern '{}': {}",
                        zone.name,
                        pattern,
                        e
                    );
                }
            }

            // Validate the route target against the zone's family policy.
            match zone.route_type {
                RouteType::Dev => {
                    if zone.route_target_ipv6.is_some() {
                        anyhow::bail!(
                            "Zone '{}': route_target_ipv6 is not allowed for a dev zone; \
                             the device file serves both families",
                            zone.name
                        );
                    }
                }
                RouteType::Via => {
                    let v4: IpAddr = zone.route_target.trim().parse().map_err(|_| {
                        anyhow::anyhow!(
                            "Zone '{}': route_target '{}' is not a valid IPv4 gateway",
                            zone.name,
                            zone.route_target
                        )
                    })?;
                    if family_of(v4) != AddressFamily::V4 {
                        anyhow::bail!(
                            "Zone '{}': route_target '{}' must be an IPv4 gateway",
                            zone.name,
                            zone.route_target
                        );
                    }
                    if zone.ipv6 {
                        let raw = zone.route_target_ipv6.as_ref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "Zone '{}': route_target_ipv6 is required when ipv6 = true",
                                zone.name
                            )
                        })?;
                        let v6: IpAddr = raw.trim().parse().map_err(|_| {
                            anyhow::anyhow!(
                                "Zone '{}': route_target_ipv6 '{}' is not a valid IPv6 gateway",
                                zone.name,
                                raw
                            )
                        })?;
                        if family_of(v6) != AddressFamily::V6 {
                            anyhow::bail!(
                                "Zone '{}': route_target_ipv6 '{}' must be an IPv6 gateway",
                                zone.name,
                                raw
                            );
                        }
                    }
                }
            }

            // An IPv6 static route is meaningless when the zone is IPv4-only.
            if !zone.ipv6 {
                for cidr in &zone.static_routes {
                    if let Ok(ip) = cidr
                        .split_once('/')
                        .map(|(ip, _)| ip)
                        .unwrap_or(cidr)
                        .parse::<IpAddr>()
                    {
                        if family_of(ip) == AddressFamily::V6 {
                            anyhow::bail!(
                                "Zone '{}': static route '{}' is IPv6 but ipv6 = false",
                                zone.name,
                                cidr
                            );
                        }
                    }
                }
            }
        }

        // Validate route_aggregation_prefix
        if let Some(prefix) = self.server.route_aggregation_prefix {
            if !(8..=32).contains(&prefix) {
                anyhow::bail!("route_aggregation_prefix must be between 8 and 32, got {prefix}");
            }
        }

        // Check for duplicate zone names
        let mut seen = std::collections::HashSet::new();
        for zone in &self.zones {
            if !seen.insert(&zone.name) {
                anyhow::bail!("Duplicate zone name: '{}'", zone.name);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_src: &str) -> anyhow::Result<Config> {
        let config: Config = toml::from_str(toml_src)?;
        config.validate()?;
        Ok(config)
    }

    const SERVER: &str = r#"
[server]
listen_address = "127.0.0.1:53"
default_upstream = ["1.1.1.1:53"]
"#;

    #[test]
    fn ipv6_defaults_to_false_for_dev_zones() {
        let cfg = parse(&format!(
            r#"{SERVER}
[[zones]]
name = "corp"
route_type = "dev"
route_target = "/run/vpn/corp.dev"
domains = ["corp.example.com"]
"#
        ))
        .unwrap();
        assert!(!cfg.zones[0].ipv6);
        assert!(!cfg.zones[0].advertises_ipv6());
        assert!(!cfg.zones[0].family_enabled(AddressFamily::V6));
        assert!(cfg.zones[0].family_enabled(AddressFamily::V4));
    }

    #[test]
    fn ipv6_defaults_to_false_for_via_zones() {
        let cfg = parse(&format!(
            r#"{SERVER}
[[zones]]
name = "gw"
route_type = "via"
route_target = "192.0.2.1"
domains = ["example.com"]
"#
        ))
        .unwrap();
        // The old implicit dual-stack behaviour for `via` zones is gone.
        assert!(!cfg.zones[0].advertises_ipv6());
    }

    #[test]
    fn dev_zone_can_opt_into_ipv6() {
        let cfg = parse(&format!(
            r#"{SERVER}
[[zones]]
name = "corp"
route_type = "dev"
route_target = "/run/vpn/corp.dev"
domains = ["corp.example.com"]
ipv6 = true
"#
        ))
        .unwrap();
        assert!(cfg.zones[0].advertises_ipv6());
        assert!(cfg.zones[0].family_enabled(AddressFamily::V6));
        // A dev zone has no gateway at all.
        assert_eq!(cfg.zones[0].gateway_for(AddressFamily::V4).unwrap(), None);
        assert_eq!(cfg.zones[0].gateway_for(AddressFamily::V6).unwrap(), None);
    }

    #[test]
    fn dev_zone_rejects_route_target_ipv6() {
        let result = parse(&format!(
            r#"{SERVER}
[[zones]]
name = "corp"
route_type = "dev"
route_target = "/run/vpn/corp.dev"
route_target_ipv6 = "2001:db8::1"
domains = ["corp.example.com"]
ipv6 = true
"#
        ));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("route_target_ipv6"));
    }

    #[test]
    fn via_zone_with_ipv6_needs_a_v6_gateway() {
        let result = parse(&format!(
            r#"{SERVER}
[[zones]]
name = "gw"
route_type = "via"
route_target = "192.0.2.1"
domains = ["example.com"]
ipv6 = true
"#
        ));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("route_target_ipv6"));
    }

    #[test]
    fn via_zone_with_separate_gateways() {
        let cfg = parse(&format!(
            r#"{SERVER}
[[zones]]
name = "gw"
route_type = "via"
route_target = "192.0.2.1"
route_target_ipv6 = "2001:db8::1"
domains = ["example.com"]
ipv6 = true
"#
        ))
        .unwrap();
        assert_eq!(
            cfg.zones[0].gateway_for(AddressFamily::V4).unwrap(),
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(
            cfg.zones[0].gateway_for(AddressFamily::V6).unwrap(),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn via_zone_rejects_a_v6_route_target() {
        let result = parse(&format!(
            r#"{SERVER}
[[zones]]
name = "gw"
route_type = "via"
route_target = "2001:db8::1"
domains = ["example.com"]
"#
        ));
        assert!(result.is_err());
    }

    #[test]
    fn via_zone_rejects_a_v4_route_target_ipv6() {
        let result = parse(&format!(
            r#"{SERVER}
[[zones]]
name = "gw"
route_type = "via"
route_target = "192.0.2.1"
route_target_ipv6 = "192.0.2.2"
domains = ["example.com"]
ipv6 = true
"#
        ));
        assert!(result.is_err());
    }

    #[test]
    fn ipv6_static_route_requires_ipv6_enabled() {
        let result = parse(&format!(
            r#"{SERVER}
[[zones]]
name = "gw"
route_type = "via"
route_target = "192.0.2.1"
static_routes = ["2001:db8::/32"]
domains = ["example.com"]
"#
        ));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ipv6 = false"));
    }

    #[test]
    fn ipv6_static_route_is_allowed_when_enabled() {
        let cfg = parse(&format!(
            r#"{SERVER}
[[zones]]
name = "gw"
route_type = "via"
route_target = "192.0.2.1"
route_target_ipv6 = "2001:db8::1"
static_routes = ["2001:db8:1::/48"]
domains = ["example.com"]
ipv6 = true
"#
        ))
        .unwrap();
        assert_eq!(cfg.zones[0].static_routes.len(), 1);
    }

    #[test]
    fn max_dynamic_routes_defaults_to_the_registry_cap() {
        let cfg = parse(&format!(
            r#"{SERVER}
[[zones]]
name = "gw"
route_type = "via"
route_target = "192.0.2.1"
domains = ["example.com"]
"#
        ))
        .unwrap();
        assert_eq!(
            cfg.server.max_dynamic_routes,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES
        );
    }

    #[test]
    fn max_dynamic_routes_is_configurable() {
        let cfg = parse(
            r#"
[server]
listen_address = "127.0.0.1:53"
default_upstream = ["1.1.1.1:53"]
max_dynamic_routes = 512

[[zones]]
name = "gw"
route_type = "via"
route_target = "192.0.2.1"
domains = ["example.com"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.server.max_dynamic_routes, 512);
    }
}
