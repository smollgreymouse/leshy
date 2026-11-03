//! Route orchestration: turns DNS answers and static config into route intents
//! and drives them through the unified registry.
//!
//! The manager owns no kernel state of its own. Every mutation goes through
//! [`RouteRegistry`], which dedupes concurrent intents for the same prefix and
//! only reports success once the platform backend has verified the row.

mod aggregator;
pub(crate) mod backend;
mod model;
pub(crate) mod registry;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod linux_monitor;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub use model::{
    family_of, AddressFamily, RouteIntent, RouteKey, RoutePrefix, RouteSource, RouteTarget,
};
// The DNS handler starts classifying these in the typed-safety step; the
// kernel monitor drives `reconcile_all`/`dynamic_route_count` in the Linux
// snapshot step.
#[allow(unused_imports)]
pub use registry::{ReconcileReport, RouteError};

use crate::config::ZoneConfig;
use aggregator::{RouteAction, RouteAggregator};
use anyhow::{Context, Result};
use backend::{EnsureOutcome, RouteBackend};
use registry::RouteRegistry;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(target_os = "linux")]
use linux::LinuxRouteBackend as PlatformBackend;
#[cfg(target_os = "macos")]
use macos::MacosRouteBackend as PlatformBackend;
#[cfg(target_os = "windows")]
use windows::WindowsRouteBackend as PlatformBackend;

/// The main routing table every Leshy route lives in.
const MAIN_TABLE: u32 = 254;

/// Default cap on dynamic (DNS-sourced) route intents.
pub const DEFAULT_MAX_DYNAMIC_ROUTES: usize = 16384;

/// How often the safety audit re-reads the routing table.
const AUDIT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

pub struct RouteManager {
    backend: Arc<dyn RouteBackend>,
    registry: Arc<RouteRegistry>,
    aggregator: Mutex<RouteAggregator>,
    kernel_epoch: AtomicU64,
}

impl RouteManager {
    /// Production constructor: creates the platform backend, the registry and
    /// the Linux monitor/audit task.
    pub fn with_capacity(
        aggregation_prefix: Option<u8>,
        max_dynamic_routes: usize,
    ) -> Result<Self> {
        let backend = Arc::new(PlatformBackend::new()?);
        let manager = Self {
            backend,
            registry: Arc::new(RouteRegistry::new(max_dynamic_routes)),
            aggregator: Mutex::new(RouteAggregator::new(aggregation_prefix)),
            kernel_epoch: AtomicU64::new(0),
        };
        manager.start_kernel_watch();
        Ok(manager)
    }

    /// Start the kernel invalidation listener and the periodic safety audit.
    ///
    /// Both are best-effort: a platform without an invalidation stream simply
    /// keeps the audit, and a failed audit is logged rather than fatal.
    fn start_kernel_watch(&self) {
        if let Some(mut rx) = self.backend.take_invalidation_receiver() {
            let registry = Arc::clone(&self.registry);
            let backend = Arc::clone(&self.backend);
            let epoch = Arc::new(AtomicU64::new(0));

            tokio::spawn(async move {
                while let Some(invalidation) = rx.recv().await {
                    let next = epoch.fetch_add(1, Ordering::SeqCst) + 1;
                    registry.mark_dirty(invalidation, next).await;
                    match backend.snapshot().await {
                        Ok(snapshot) => {
                            let report = registry
                                .reconcile_dirty(backend.as_ref(), &snapshot, next)
                                .await;
                            if report.adds > 0 || report.removes > 0 {
                                tracing::info!(
                                    adds = report.adds,
                                    removes = report.removes,
                                    noops = report.noops,
                                    "Kernel route drift reconciled"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Route snapshot failed after an invalidation");
                        }
                    }
                }
            });
        }

        // Periodic safety audit: catches drift the event stream missed.
        let registry = Arc::clone(&self.registry);
        let backend = Arc::clone(&self.backend);
        let epoch = Arc::new(AtomicU64::new(0));
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(AUDIT_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let next = epoch.fetch_add(1, Ordering::SeqCst) + 1;
                registry
                    .mark_dirty(backend::RouteInvalidation::Full, next)
                    .await;
                match backend.snapshot().await {
                    Ok(snapshot) => {
                        let report = registry
                            .reconcile_dirty(backend.as_ref(), &snapshot, next)
                            .await;
                        if report.adds > 0 || report.removes > 0 {
                            tracing::info!(
                                adds = report.adds,
                                removes = report.removes,
                                "Periodic route audit reconciled drift"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "Periodic route audit could not read the table");
                    }
                }
            }
        });
    }

    /// Construct a manager around an arbitrary backend. Used by tests to drive
    /// reconciliation against a fake kernel.
    #[cfg(test)]
    pub(crate) fn with_backend<B>(
        backend: Arc<B>,
        aggregation_prefix: Option<u8>,
        max_dynamic_routes: usize,
    ) -> Self
    where
        B: RouteBackend + 'static,
    {
        Self {
            backend,
            registry: Arc::new(RouteRegistry::new(max_dynamic_routes)),
            aggregator: Mutex::new(RouteAggregator::new(aggregation_prefix)),
            kernel_epoch: AtomicU64::new(0),
        }
    }

    /// Current kernel epoch. Bumped whenever the kernel state is invalidated.
    pub fn kernel_epoch(&self) -> u64 {
        self.kernel_epoch.load(Ordering::SeqCst)
    }

    /// Add a route for the given IP based on zone configuration.
    ///
    /// Both families take the same path: resolve the target, build a canonical
    /// intent, and let the registry dedupe it. IPv4 additionally passes through
    /// the aggregation planner, which may widen the prefix.
    pub async fn add_route(&self, ip: IpAddr, zone: &ZoneConfig) -> Result<()> {
        let family = family_of(ip);
        if !zone.family_enabled(family) {
            anyhow::bail!(
                "zone '{}': {family:?} routing is disabled for this zone",
                zone.name
            );
        }
        let target = self.backend.resolve_target(zone, family).await?;

        match ip {
            IpAddr::V4(v4) => self.add_route_v4(v4, zone, target).await,
            IpAddr::V6(_) => {
                let intent = RouteIntent {
                    key: RouteKey {
                        prefix: RoutePrefix::host(ip),
                        table: MAIN_TABLE,
                    },
                    zone: zone.name.clone(),
                    target,
                    source: RouteSource::Dns,
                };
                self.ensure_intent(intent).await.map(|_| ())
            }
        }
    }

    async fn add_route_v4(
        &self,
        ip: Ipv4Addr,
        zone: &ZoneConfig,
        target: RouteTarget,
    ) -> Result<()> {
        let plan = {
            let mut agg = self.aggregator.lock().await;
            agg.plan_ip(ip, &zone.name, zone.route_type, &zone.route_target)
        };

        if plan.actions.is_empty() {
            // The aggregator already covers this address. The registry still
            // has to confirm the covering prefix is verified, otherwise a row
            // dropped outside Leshy would stay missing.
            let prefix_len = {
                let agg = self.aggregator.lock().await;
                agg.installed_prefix(ip).unwrap_or(32)
            };
            let intent = RouteIntent {
                key: RouteKey {
                    prefix: RoutePrefix::new(IpAddr::V4(ip), prefix_len)?,
                    table: MAIN_TABLE,
                },
                zone: zone.name.clone(),
                target,
                source: RouteSource::Dns,
            };
            return self.ensure_intent(intent).await.map(|_| ());
        }

        // The planner orders every add before every remove, so a failure part
        // way through leaves a route in place instead of a hole.
        for action in &plan.actions {
            self.execute_action(action, zone).await?;
        }
        Ok(())
    }

    /// Execute one aggregator action against the registry.
    async fn execute_action(&self, action: &RouteAction, zone: &ZoneConfig) -> Result<()> {
        match action {
            RouteAction::Add(intent) => {
                // A `dev` target carries the device-file path; resolve it to a
                // real interface before the backend sees the intent.
                let intent = match &intent.target {
                    RouteTarget::Device {
                        name,
                        ifindex: None,
                    } if name == &zone.route_target => {
                        let resolved = self.backend.resolve_target(zone, AddressFamily::V4).await?;
                        RouteIntent {
                            target: resolved,
                            ..intent.clone()
                        }
                    }
                    _ => intent.clone(),
                };
                self.ensure_intent(intent).await.map(|_| ())
            }
            RouteAction::Remove(intent) => self.backend.remove_route(intent).await,
        }
    }

    /// Push one intent through the registry.
    async fn ensure_intent(&self, intent: RouteIntent) -> Result<EnsureOutcome> {
        let epoch = self.kernel_epoch();
        self.registry
            .ensure(intent, self.backend.as_ref(), epoch)
            .await
    }

    /// Add a static route from a CIDR string (e.g. "149.154.160.0/20" or "1.2.3.4").
    ///
    /// Static routes bypass aggregation but register their IPs so aggregates
    /// don't overlap, and they do not consume the dynamic quota.
    pub async fn add_static_route(&self, cidr: &str, zone: &ZoneConfig) -> Result<()> {
        let prefix = parse_prefix(cidr)?;
        let family = prefix.family();

        tracing::info!(cidr = cidr, zone = zone.name, "Adding static route");

        if let IpAddr::V4(v4) = prefix.network {
            let mut agg = self.aggregator.lock().await;
            agg.register_static_ip(v4, &zone.name);
        }

        let target = self.backend.resolve_target(zone, family).await?;
        let intent = RouteIntent {
            key: RouteKey {
                prefix,
                table: MAIN_TABLE,
            },
            zone: zone.name.clone(),
            target,
            source: RouteSource::Static,
        };
        self.ensure_intent(intent).await.map(|_| ())
    }

    /// Clean up routes for a specific zone.
    ///
    /// This is explicit operator intent: the zone is gone, so its owned rows
    /// are removed from the kernel. A row on the same prefix that Leshy does
    /// not own is left alone by the backend.
    pub async fn cleanup_zone(&self, zone_name: &str) -> Result<()> {
        let report = self
            .registry
            .remove_zone(zone_name, self.backend.as_ref())
            .await;

        let mut agg = self.aggregator.lock().await;
        agg.cleanup_zone(zone_name);

        tracing::info!(
            zone = zone_name,
            removed = report.removed,
            errors = report.errors,
            "Zone routes retired"
        );
        Ok(())
    }

    /// Count of dynamic (DNS-sourced) intents currently registered.
    #[allow(dead_code)]
    pub async fn dynamic_route_count(&self) -> u64 {
        self.registry.count_dynamic().await
    }

    /// Mark every entry dirty and reconcile against a fresh snapshot.
    ///
    /// Called by the kernel monitor when it cannot map a change to individual
    /// keys, and by the periodic safety audit.
    #[allow(dead_code)]
    pub async fn reconcile_all(&self) -> Result<ReconcileReport> {
        let epoch = self.kernel_epoch.fetch_add(1, Ordering::SeqCst) + 1;
        self.registry
            .mark_dirty(backend::RouteInvalidation::Full, epoch)
            .await;
        let snapshot = self.backend.snapshot().await?;
        Ok(self
            .registry
            .reconcile_dirty(self.backend.as_ref(), &snapshot, epoch)
            .await)
    }
}

/// Parse a CIDR string like "149.154.160.0/20" or plain IP "1.2.3.4".
fn parse_prefix(cidr: &str) -> Result<RoutePrefix> {
    if let Some((ip_str, prefix_str)) = cidr.split_once('/') {
        let ip: IpAddr = ip_str.parse().context("Failed to parse IP in CIDR")?;
        let prefix_len: u8 = prefix_str
            .parse()
            .context("Failed to parse prefix length")?;
        RoutePrefix::new(ip, prefix_len)
    } else {
        let ip: IpAddr = cidr.parse().context("Failed to parse IP")?;
        Ok(RoutePrefix::host(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsProtocol, RouteType, ZoneMode};
    use crate::routing::backend::fake::FakeBackend;
    use crate::routing::model::ObservedRoute;
    use std::net::Ipv6Addr;

    fn via_zone(name: &str, gateway: &str) -> ZoneConfig {
        ZoneConfig {
            name: name.to_string(),
            mode: ZoneMode::Inclusive,
            dns_servers: vec![],
            route_type: RouteType::Via,
            route_target: gateway.to_string(),
            route_target_ipv6: None,
            domains: vec![],
            patterns: vec![],
            static_routes: vec![],
            dns_protocol: DnsProtocol::Udp,
            cache_min_ttl: None,
            cache_max_ttl: None,
            cache_negative_ttl: None,
            ipv6: false,
        }
    }

    fn manager(backend: Arc<FakeBackend>, aggregation: Option<u8>) -> RouteManager {
        RouteManager::with_backend(backend, aggregation, DEFAULT_MAX_DYNAMIC_ROUTES)
    }

    #[test]
    fn parse_cidr_v4_with_prefix() {
        let prefix = parse_prefix("10.0.0.0/8").unwrap();
        assert_eq!(prefix.network, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(prefix.prefix_len, 8);
    }

    #[test]
    fn parse_cidr_v4_host() {
        let prefix = parse_prefix("1.2.3.4").unwrap();
        assert_eq!(prefix.network, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(prefix.prefix_len, 32);
    }

    #[test]
    fn parse_cidr_v6_host() {
        let prefix = parse_prefix("2001:db8::1").unwrap();
        assert_eq!(prefix.prefix_len, 128);
        assert_eq!(prefix.family(), AddressFamily::V6);
    }

    #[test]
    fn parse_cidr_invalid_prefix() {
        assert!(parse_prefix("10.0.0.0/33").is_err());
    }

    #[test]
    fn parse_cidr_canonicalizes() {
        let prefix = parse_prefix("10.0.0.255/24").unwrap();
        assert_eq!(prefix.network, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    }

    #[tokio::test]
    async fn duplicate_v4_route_is_one_mutation() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), None);
        let zone = via_zone("corp", "192.168.1.1");
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..1000 {
            mgr.add_route(ip, &zone).await.unwrap();
        }
        assert_eq!(backend.ensure_count(), 1);
    }

    #[tokio::test]
    async fn duplicate_v6_route_is_one_mutation() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), None);
        let mut zone = via_zone("corp", "192.168.1.1");
        zone.ipv6 = true;
        zone.route_target_ipv6 = Some("2001:db8::1".to_string());
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        for _ in 0..1000 {
            mgr.add_route(ip, &zone).await.unwrap();
        }
        assert_eq!(backend.ensure_count(), 1);
    }

    #[tokio::test]
    async fn ipv6_route_is_rejected_when_the_zone_is_ipv4_only() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), None);
        let zone = via_zone("corp", "192.168.1.1");

        let result = mgr.add_route(IpAddr::V6(Ipv6Addr::LOCALHOST), &zone).await;
        assert!(result.is_err());
        assert_eq!(backend.ensure_count(), 0);
    }

    #[tokio::test]
    async fn v4_and_v6_share_the_registry() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), None);
        let zone = via_zone("corp", "192.168.1.1");

        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &zone)
            .await
            .unwrap();
        assert_eq!(mgr.dynamic_route_count().await, 1);

        // A v6 intent needs a v6 gateway; the fake rejects the mismatch, which
        // is exactly the family guard the plan requires.
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(mgr.add_route(v6, &zone).await.is_err());
        assert_eq!(mgr.dynamic_route_count().await, 1);
    }

    #[tokio::test]
    async fn static_route_does_not_consume_quota() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = RouteManager::with_backend(Arc::clone(&backend), None, 1);
        let zone = via_zone("corp", "192.168.1.1");

        mgr.add_static_route("10.0.0.0/8", &zone).await.unwrap();
        assert_eq!(mgr.dynamic_route_count().await, 0);

        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &zone)
            .await
            .unwrap();
        assert_eq!(mgr.dynamic_route_count().await, 1);
    }

    #[tokio::test]
    async fn cleanup_zone_removes_owned_rows() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), None);
        let zone = via_zone("corp", "192.168.1.1");

        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &zone)
            .await
            .unwrap();
        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), &zone)
            .await
            .unwrap();

        mgr.cleanup_zone("corp").await.unwrap();
        assert_eq!(backend.remove_count(), 2);
        assert_eq!(mgr.dynamic_route_count().await, 0);
    }

    #[tokio::test]
    async fn aggregation_installs_a_wider_prefix() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), Some(24));
        let zone = via_zone("corp", "192.168.1.1");

        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), &zone)
            .await
            .unwrap();

        let ensured = backend.ensured();
        assert_eq!(ensured.len(), 1);
        assert_eq!(ensured[0].key.prefix.prefix_len, 24);
        assert_eq!(
            ensured[0].key.prefix.network,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))
        );
    }

    #[tokio::test]
    async fn same_zone_covered_ip_is_a_noop() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), Some(24));
        let zone = via_zone("corp", "192.168.1.1");

        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), &zone)
            .await
            .unwrap();
        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)), &zone)
            .await
            .unwrap();

        // The second address is covered by the /24, so the registry sees the
        // same intent and performs no extra mutation.
        assert_eq!(backend.ensure_count(), 1);
    }

    #[tokio::test]
    async fn reconcile_all_restores_a_dropped_route() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), None);
        let zone = via_zone("corp", "192.168.1.1");

        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &zone)
            .await
            .unwrap();
        assert_eq!(backend.ensure_count(), 1);

        // The fake snapshot is empty, so the audit must re-add the row.
        let report = mgr.reconcile_all().await.unwrap();
        assert_eq!(report.adds, 1);
        assert_eq!(backend.ensure_count(), 2);
    }

    #[tokio::test]
    async fn reconcile_all_is_idempotent_when_the_row_survives() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), None);
        let zone = via_zone("corp", "192.168.1.1");
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        mgr.add_route(ip, &zone).await.unwrap();
        let ensured = backend.ensured();
        backend.push_observed(ObservedRoute {
            key: ensured[0].key.clone(),
            target: ensured[0].target.clone(),
            protocol: 3,
            metric: 0,
        });

        let report = mgr.reconcile_all().await.unwrap();
        assert_eq!(report.noops, 1);
        assert_eq!(report.adds, 0);
        assert_eq!(backend.ensure_count(), 1);
    }

    #[tokio::test]
    async fn cross_zone_split_never_removes_before_replacing() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), Some(24));
        let zone1 = via_zone("zone1", "192.168.1.1");
        let zone2 = via_zone("zone2", "192.168.2.1");

        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), &zone1)
            .await
            .unwrap();
        backend.reset_counters();

        // A second zone in the same /24 forces a split of zone1's aggregate.
        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200)), &zone2)
            .await
            .unwrap();

        // Every replacement add must land before the broad route is removed.
        assert_eq!(backend.remove_count(), 1);
        assert!(backend.ensure_count() >= 9);
    }

    #[tokio::test]
    async fn failed_split_keeps_the_broad_route() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), Some(24));
        let zone1 = via_zone("zone1", "192.168.1.1");
        let zone2 = via_zone("zone2", "192.168.2.1");

        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), &zone1)
            .await
            .unwrap();
        backend.reset_counters();

        // The first replacement add fails, so the broad route must survive.
        backend.set_outcome(Err(anyhow::anyhow!("netlink EPERM")));
        let result = mgr
            .add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200)), &zone2)
            .await;

        assert!(result.is_err());
        assert_eq!(
            backend.remove_count(),
            0,
            "the broad route must not be removed when a replacement failed"
        );
    }
}
