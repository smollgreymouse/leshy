use crate::config::{Config, ZoneConfig};
use anyhow::Result;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Watches config file for changes and sends reload signals
pub struct ConfigWatcher {
    config_path: PathBuf,
    config_dir: Option<PathBuf>,
    reload_tx: mpsc::UnboundedSender<Config>,
}

impl ConfigWatcher {
    pub fn new(
        config_path: PathBuf,
        config_dir: Option<PathBuf>,
    ) -> (Self, mpsc::UnboundedReceiver<Config>) {
        let (reload_tx, reload_rx) = mpsc::unbounded_channel();
        (
            Self {
                config_path,
                config_dir,
                reload_tx,
            },
            reload_rx,
        )
    }

    /// Start watching the config file and config.d directory for changes
    pub async fn watch(self) -> Result<()> {
        let (tx, mut rx) = mpsc::unbounded_channel::<notify::Result<Event>>();
        let config_path = self.config_path.clone();
        let reload_tx = self.reload_tx.clone();

        // Spawn file watcher in blocking task
        let watch_path = config_path.clone();
        let explicit_config_dir = self.config_dir.clone();
        tokio::task::spawn_blocking(move || {
            let mut watcher = RecommendedWatcher::new(
                move |res: notify::Result<Event>| {
                    let _ = tx.send(res);
                },
                notify::Config::default(),
            )
            .expect("Failed to create watcher");

            // Watch main config file
            if let Err(e) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
                error!("Failed to watch config file: {}", e);
                return;
            }

            info!("Watching config file for changes: {}", watch_path.display());

            // Watch config.d directory if it exists
            // Try explicit config_dir first, then look next to config file
            let candidates: Vec<std::path::PathBuf> = vec![
                explicit_config_dir.clone(),
                watch_path.parent().map(|p| p.join("config.d")),
            ]
            .into_iter()
            .flatten()
            .collect();

            for config_dir in candidates {
                if config_dir.exists() && config_dir.is_dir() {
                    if let Err(e) = watcher.watch(&config_dir, RecursiveMode::Recursive) {
                        warn!("Failed to watch config.d directory: {}", e);
                    } else {
                        info!("Watching config.d directory: {}", config_dir.display());
                    }
                    break;
                }
            }

            // Keep watcher alive
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });

        // Process file change events
        while let Some(event_result) = rx.recv().await {
            match event_result {
                Ok(event) => {
                    if matches!(
                        event.kind,
                        notify::EventKind::Modify(_)
                            | notify::EventKind::Create(_)
                            | notify::EventKind::Remove(_)
                    ) {
                        info!("Config changed, reloading...");
                        match Config::from_file_with_includes(&config_path) {
                            Ok(new_config) => {
                                info!("Config reloaded successfully");
                                if let Err(e) = reload_tx.send(new_config) {
                                    error!("Failed to send reload signal: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to reload config, keeping old config: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Watch error: {}", e);
                }
            }
        }

        Ok(())
    }
}

/// A routing-relevant difference between the old and the new zone sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneChange {
    /// The zone is new in the upcoming configuration.
    Added(ZoneConfig),
    /// The zone was deleted; its owned rows are explicitly retired.
    Removed(ZoneConfig),
    /// A same-name zone whose route policy changed. Replacement rows are
    /// applied before the old-zone owned rows are removed.
    Changed {
        old: Box<ZoneConfig>,
        new: Box<ZoneConfig>,
    },
}

/// Whether two zone configurations carry the same routing policy.
///
/// Only fields that decide which routes are installed count here: a pure
/// cache-TTL or upstream-address change must not trigger route churn on an
/// otherwise idempotent reload replay.
fn same_routing_policy(a: &ZoneConfig, b: &ZoneConfig) -> bool {
    a.mode == b.mode
        && a.route_type == b.route_type
        && a.route_target == b.route_target
        && a.route_target_ipv6 == b.route_target_ipv6
        && a.ipv6 == b.ipv6
        && a.static_routes == b.static_routes
        && a.domains == b.domains
        && a.patterns == b.patterns
}

/// Diff the old and new zone sets into routing-relevant changes.
///
/// Zones are identified by name. A same-name zone is `Changed` when any
/// routing-relevant field differs (route type, targets, IPv6 policy, static
/// routes/exclusions, mode, domain/pattern ownership); cosmetic changes such
/// as cache TTLs do not show up.
pub fn diff_zones(old: &[ZoneConfig], new: &[ZoneConfig]) -> Vec<ZoneChange> {
    let mut changes = Vec::new();

    for zone in new {
        match old.iter().find(|z| z.name == zone.name) {
            Some(previous) => {
                if !same_routing_policy(previous, zone) {
                    changes.push(ZoneChange::Changed {
                        old: Box::new(previous.clone()),
                        new: Box::new(zone.clone()),
                    });
                }
            }
            None => changes.push(ZoneChange::Added(zone.clone())),
        }
    }

    for zone in old {
        if !new.iter().any(|z| z.name == zone.name) {
            changes.push(ZoneChange::Removed(zone.clone()));
        }
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RouteType, ZoneConfig};

    fn test_zone(name: &str, route_type: RouteType, route_target: &str) -> ZoneConfig {
        ZoneConfig {
            name: name.to_string(),
            mode: Default::default(),
            dns_servers: vec![],
            route_type,
            route_target: route_target.to_string(),
            route_target_ipv6: None,
            domains: vec![],
            patterns: vec![],
            static_routes: vec![],
            dns_protocol: Default::default(),
            cache_min_ttl: None,
            cache_max_ttl: None,
            cache_negative_ttl: None,
            ipv6: false,
        }
    }

    #[test]
    fn removed_zone_is_reported() {
        let old_zones = vec![
            test_zone("zone1", RouteType::Via, "192.168.1.1"),
            test_zone("zone2", RouteType::Via, "192.168.1.1"),
        ];
        let new_zones = vec![test_zone("zone2", RouteType::Via, "192.168.1.1")];

        let changes = diff_zones(&old_zones, &new_zones);
        assert_eq!(
            changes,
            vec![ZoneChange::Removed(test_zone(
                "zone1",
                RouteType::Via,
                "192.168.1.1"
            ))]
        );
    }

    #[test]
    fn added_zone_is_reported() {
        let old_zones = vec![test_zone("zone1", RouteType::Via, "192.168.1.1")];
        let new_zones = vec![
            test_zone("zone1", RouteType::Via, "192.168.1.1"),
            test_zone("zone2", RouteType::Dev, "/tmp/test.dev"),
        ];

        let changes = diff_zones(&old_zones, &new_zones);
        assert_eq!(
            changes,
            vec![ZoneChange::Added(test_zone(
                "zone2",
                RouteType::Dev,
                "/tmp/test.dev"
            ))]
        );
    }

    #[test]
    fn same_name_target_change_is_detected() {
        let old_zones = vec![test_zone("corp", RouteType::Via, "192.168.1.1")];
        let new_zones = vec![test_zone("corp", RouteType::Via, "10.0.0.1")];

        let changes = diff_zones(&old_zones, &new_zones);
        assert!(matches!(&changes[..], [ZoneChange::Changed { old, new }]
                if old.route_target == "192.168.1.1" && new.route_target == "10.0.0.1"
        ));
    }

    #[test]
    fn same_name_ipv6_policy_change_is_detected() {
        let mut old_zone = test_zone("corp", RouteType::Via, "192.168.1.1");
        let mut new_zone = old_zone.clone();
        new_zone.ipv6 = true;
        new_zone.route_target_ipv6 = Some("2001:db8::1".to_string());
        old_zone.ipv6 = false;

        let changes = diff_zones(&[old_zone.clone()], &[new_zone.clone()]);
        assert_eq!(
            changes,
            vec![ZoneChange::Changed {
                old: Box::new(old_zone),
                new: Box::new(new_zone),
            }]
        );
    }

    #[test]
    fn static_route_change_is_detected() {
        let mut old_zone = test_zone("corp", RouteType::Via, "192.168.1.1");
        let mut new_zone = old_zone.clone();
        new_zone.static_routes = vec!["10.0.0.0/8".to_string()];
        old_zone.static_routes = vec![];

        assert!(matches!(
            diff_zones(&[old_zone], &[new_zone])[0],
            ZoneChange::Changed { .. }
        ));
    }

    #[test]
    fn cosmetic_change_is_not_a_routing_change() {
        let mut old_zone = test_zone("corp", RouteType::Via, "192.168.1.1");
        let mut new_zone = old_zone.clone();
        new_zone.cache_max_ttl = Some(900);
        old_zone.cache_max_ttl = None;

        assert!(diff_zones(&[old_zone], &[new_zone]).is_empty());
    }

    #[test]
    fn identical_reload_replay_produces_no_changes() {
        let zones = vec![test_zone("corp", RouteType::Via, "192.168.1.1")];
        assert!(diff_zones(&zones, &zones).is_empty());
    }
}
