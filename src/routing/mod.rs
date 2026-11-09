//! Route orchestration: turns DNS answers and static config into route intents
//! and drives them through the unified registry.
//!
//! The manager owns no kernel state of its own. Every mutation goes through
//! [`RouteRegistry`], which dedupes concurrent intents for the same prefix and
//! only reports success once the platform backend has verified the row.

mod aggregator;
pub(crate) mod backend;
pub mod kikimora;
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
pub use registry::{ReconcileReport, RouteError};

/// Direct handle on the kernel invalidation stream for the disposable-namespace
/// monitor probe (`tests/netns_monitor_probe.rs`). The probe uses the lib
/// export; the bin's shared module tree never calls it, hence the allow.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn spawn_monitor_probe(
) -> anyhow::Result<tokio::sync::mpsc::UnboundedReceiver<backend::RouteInvalidation>> {
    let generation = Arc::new(AtomicU64::new(0));
    linux_monitor::spawn_monitor(generation)
}

use crate::config::{RoutingBackend, ServerConfig, ZoneConfig};
use aggregator::{RouteAction, RouteAggregator};
use anyhow::{Context, Result};
use backend::{EnsureOutcome, ReconcileMode, RouteBackend};
#[cfg(target_os = "linux")]
use linux::LinuxRouteBackend as PlatformBackend;
#[cfg(target_os = "macos")]
use macos::MacosRouteBackend as PlatformBackend;
use registry::RouteRegistry;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
#[cfg(target_os = "windows")]
use windows::WindowsRouteBackend as PlatformBackend;

/// The main routing table every Leshy route lives in.
const MAIN_TABLE: u32 = 254;

/// Default cap on dynamic (DNS-sourced) route intents.
pub const DEFAULT_MAX_DYNAMIC_ROUTES: usize = 16384;

/// How often the safety audit re-reads the routing table.
const AUDIT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// What one `retire_intents` call did to the exact old-zone ownership set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetirementReport {
    /// Exact owned rows deleted and registry entries dropped.
    pub retired: usize,
    /// Keys already owned by a newer (replacement) intent; left untouched.
    pub skipped_replaced: usize,
}

/// Kernel I/O counters for the invalidation path (08D1 §16.3).
///
/// `full_snapshots` counts manager-level full-FIB reads: a `Full`
/// invalidation (periodic safety audit, explicit diagnostic) or an initial
/// read. `targeted_reads` counts the per-key read-backs a Prefix, Interface or
/// Zone event performs. A targeted event must never move `full_snapshots`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub struct ReconcileCounters {
    pub full_snapshots: u64,
    pub targeted_reads: u64,
}

#[derive(Debug, Default)]
struct ReconcileCounterState {
    full_snapshots: AtomicU64,
    targeted_reads: AtomicU64,
}

impl ReconcileCounterState {
    #[allow(dead_code)]
    fn read(&self) -> ReconcileCounters {
        ReconcileCounters {
            full_snapshots: self.full_snapshots.load(Ordering::SeqCst),
            targeted_reads: self.targeted_reads.load(Ordering::SeqCst),
        }
    }
}

pub struct RouteManager {
    backend: Arc<dyn RouteBackend>,
    registry: Arc<RouteRegistry>,
    aggregator: Mutex<RouteAggregator>,
    /// Shared so the monitor/audit tasks and the request path see one epoch.
    kernel_epoch: Arc<AtomicU64>,
    /// Unsupported invalidations observed on an AuthorityOnDemand listener.
    /// Managed mode understands only Zone and AuthorityLost; every other
    /// kind is an invariant violation and must never trigger a snapshot.
    authority_invariant_violations: Arc<AtomicU64>,
    /// Proof that surfaced events stay targeted (08D1 §16.3).
    reconcile_counters: Arc<ReconcileCounterState>,
}

impl RouteManager {
    /// Production constructor driven by the server configuration: picks the
    /// standalone platform backend or the Kikimora managed backend, creates
    /// the registry and the Linux monitor/audit task.
    pub fn for_server(server: &ServerConfig) -> Result<Self> {
        match server.routing_backend {
            RoutingBackend::Local => {
                Self::with_capacity(server.route_aggregation_prefix, server.max_dynamic_routes)
            }
            RoutingBackend::Kikimora => {
                let socket = server
                    .kikimora_socket
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        anyhow::anyhow!("routing_backend = \"kikimora\" requires kikimora_socket")
                    })?;
                let backend: Arc<dyn RouteBackend> = Arc::new(kikimora::KikimoraRouteBackend::new(
                    socket,
                    server.kikimora_auth_file.as_deref(),
                    server.kikimora_activation_id.as_deref(),
                    server.kikimora_mode_generation,
                )?);
                Ok(Self::from_backend(
                    backend,
                    server.route_aggregation_prefix,
                    server.max_dynamic_routes,
                ))
            }
        }
    }

    /// Production constructor for the standalone mode: creates the platform
    /// backend, the registry and the Linux monitor/audit task.
    pub fn with_capacity(
        aggregation_prefix: Option<u8>,
        max_dynamic_routes: usize,
    ) -> Result<Self> {
        let backend: Arc<dyn RouteBackend> = Arc::new(PlatformBackend::new()?);
        Ok(Self::from_backend(
            backend,
            aggregation_prefix,
            max_dynamic_routes,
        ))
    }

    /// Start the kernel invalidation listener and, for local platforms, the
    /// periodic safety audit.
    ///
    /// §18.5 dispatches on the backend's reconcile mode:
    /// - KernelSnapshot: mark matching dirty and reconcile immediately;
    /// - AuthorityOnDemand: consume controller invalidations, mark dirty
    ///   locally and never issue a bulk RPC/snapshot;
    /// - RegistryOnly: no kernel invalidation reconcile at all.
    fn start_kernel_watch(&self) {
        match self.backend.reconcile_mode() {
            ReconcileMode::KernelSnapshot => {
                self.start_kernel_snapshot_watch();
            }
            ReconcileMode::AuthorityOnDemand => {
                self.start_authority_on_demand_watch();
            }
            ReconcileMode::RegistryOnly => {}
        }
    }

    /// Local-platform listener: every event is reconciled against a fresh
    /// snapshot, plus a periodic safety audit catches drift the stream missed.
    fn start_kernel_snapshot_watch(&self) {
        if let Some(mut rx) = self.backend.take_invalidation_receiver() {
            let epoch = Arc::clone(&self.kernel_epoch);
            let registry = Arc::clone(&self.registry);
            let backend = Arc::clone(&self.backend);
            let counters = Arc::clone(&self.reconcile_counters);
            tokio::spawn(async move {
                while let Some(invalidation) = rx.recv().await {
                    let report = reconcile_after_invalidation(
                        &registry,
                        backend.as_ref(),
                        &epoch,
                        &counters,
                        invalidation,
                    )
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
            });
        }

        // Periodic safety audit: catches drift the event stream missed.
        let epoch = Arc::clone(&self.kernel_epoch);
        let registry = Arc::clone(&self.registry);
        let backend = Arc::clone(&self.backend);
        let counters = Arc::clone(&self.reconcile_counters);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(AUDIT_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // interval's first tick completes immediately; the registry has
            // nothing stale that early, so consume it without auditing.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let report = reconcile_after_invalidation(
                    &registry,
                    backend.as_ref(),
                    &epoch,
                    &counters,
                    backend::RouteInvalidation::Full,
                )
                .await;
                if report.adds > 0 || report.removes > 0 {
                    tracing::info!(
                        adds = report.adds,
                        removes = report.removes,
                        "Periodic route audit reconciled drift"
                    );
                }
            }
        });
    }

    /// Managed listener: local dirtying only. Kikimora's own observer repairs
    /// kernel drift; Leshy never walks the whole managed set after a socket
    /// loss/reconnect and never calls `snapshot()` in this mode.
    fn start_authority_on_demand_watch(&self) {
        let Some(mut rx) = self.backend.take_invalidation_receiver() else {
            return;
        };
        let registry = Arc::clone(&self.registry);
        let epoch = Arc::clone(&self.kernel_epoch);
        let violations = Arc::clone(&self.authority_invariant_violations);
        tokio::spawn(async move {
            while let Some(invalidation) = rx.recv().await {
                dispatch_authority_invalidation(&registry, &epoch, &violations, invalidation).await;
            }
        });
    }

    /// Apply one invalidation signal through the backend's reconcile mode.
    ///
    /// AuthorityOnDemand never reaches the snapshot path: Zone and
    /// AuthorityLost only mark local registry state Dirty.
    pub(crate) async fn handle_invalidation(
        &self,
        invalidation: backend::RouteInvalidation,
    ) -> ReconcileReport {
        if self.backend.reconcile_mode() == ReconcileMode::AuthorityOnDemand {
            dispatch_authority_invalidation(
                &self.registry,
                &self.kernel_epoch,
                &self.authority_invariant_violations,
                invalidation,
            )
            .await;
            return ReconcileReport::default();
        }
        reconcile_after_invalidation(
            &self.registry,
            self.backend.as_ref(),
            &self.kernel_epoch,
            &self.reconcile_counters,
            invalidation,
        )
        .await
    }

    /// Counters proving the event path stays targeted (08D1 §16.3):
    /// `full_snapshots` only moves for a `Full` invalidation/audit.
    #[allow(dead_code)]
    pub fn reconcile_counters(&self) -> ReconcileCounters {
        self.reconcile_counters.read()
    }

    /// Test-visible count of invalidations an AuthorityOnDemand backend could
    /// not attribute. Must stay zero (08D1 §18.5 invariant).
    #[cfg(test)]
    pub(crate) fn authority_invariant_violations(&self) -> u64 {
        self.authority_invariant_violations.load(Ordering::SeqCst)
    }

    /// Test-visible reconcile mode of the manager's chosen backend.
    #[cfg(test)]
    pub(crate) fn reconcile_mode(&self) -> ReconcileMode {
        self.backend.reconcile_mode()
    }

    /// Assemble a manager around an arbitrary backend. Tests use it to drive
    /// reconciliation against a fake kernel or the managed backend.
    #[cfg(test)]
    pub(crate) fn with_backend<B>(
        backend: Arc<B>,
        aggregation_prefix: Option<u8>,
        max_dynamic_routes: usize,
    ) -> Self
    where
        B: RouteBackend + 'static,
    {
        Self::from_backend(
            backend as Arc<dyn RouteBackend>,
            aggregation_prefix,
            max_dynamic_routes,
        )
    }

    fn from_backend(
        backend: Arc<dyn RouteBackend>,
        aggregation_prefix: Option<u8>,
        max_dynamic_routes: usize,
    ) -> Self {
        let manager = Self {
            backend,
            registry: Arc::new(RouteRegistry::new(max_dynamic_routes)),
            aggregator: Mutex::new(RouteAggregator::new(aggregation_prefix)),
            kernel_epoch: Arc::new(AtomicU64::new(0)),
            authority_invariant_violations: Arc::new(AtomicU64::new(0)),
            reconcile_counters: Arc::new(ReconcileCounterState::default()),
        };
        manager.start_kernel_watch();
        manager
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
            self.execute_action(action, &target).await?;
        }
        Ok(())
    }

    /// Execute one aggregator action against the registry.
    ///
    /// The planner's target is only a provisional guess; the backend-resolved
    /// target for this zone/family is authoritative for every Add. This keeps
    /// the intent identical between the first aggregate plan and later
    /// covered-address hits, so the registry's fast path stays exact (and the
    /// managed backend always sees its synthetic controller target).
    async fn execute_action(&self, action: &RouteAction, target: &RouteTarget) -> Result<()> {
        match action {
            RouteAction::Add(intent) => {
                let intent = RouteIntent {
                    target: target.clone(),
                    ..intent.clone()
                };
                self.ensure_intent(intent).await.map(|_| ())
            }
            // §49.1: the aggregated Remove retires through the registry —
            // the recorded actual intent/ownership decides, never a planner
            // guess with None ownership.
            RouteAction::Remove(intent) => {
                self.registry
                    .retire_key(&intent.key, &intent.zone, self.backend.as_ref())
                    .await
            }
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
        // §49.6: an exact-delete failure must surface — a caller (reload or
        // operator cleanup) must not claim successful retirement while old
        // owned rows remain.
        if report.errors > 0 {
            anyhow::bail!(
                "zone '{}' cleanup retired {} route(s) but {} deletion(s) failed; ownership evidence kept",
                zone_name,
                report.removed,
                report.errors
            );
        }
        Ok(())
    }

    /// Snapshot the route intents currently owned by a zone (reload support).
    pub async fn zone_intents(&self, zone: &str) -> Vec<RouteIntent> {
        self.registry.zone_intents(zone).await
    }

    /// Retire exactly these owned intents (old-zone state during a reload).
    ///
    /// A replacement intent that was verified in the meantime keeps its
    /// registry entry and kernel row; a foreign row on the same prefix is
    /// never touched by the backend. An exact-delete failure is returned so
    /// the caller can abort the reload instead of dropping the error (08D1
    /// section 19.1); ownership evidence stays in the registry.
    pub async fn retire_intents(&self, intents: &[RouteIntent]) -> Result<RetirementReport> {
        let mut report = RetirementReport::default();
        for intent in intents {
            match self
                .registry
                .retire_intent(intent, self.backend.as_ref())
                .await?
            {
                registry::RetireOutcome::Retired => report.retired += 1,
                registry::RetireOutcome::ReplacedByNewerIntent => report.skipped_replaced += 1,
                registry::RetireOutcome::Absent => {}
            }
        }
        if report.retired > 0 || report.skipped_replaced > 0 {
            tracing::info!(
                retired = report.retired,
                skipped_replaced = report.skipped_replaced,
                "Old-zone route intents retired"
            );
        }
        Ok(report)
    }

    /// Count of dynamic (DNS-sourced) intents currently registered.
    #[allow(dead_code)]
    pub async fn dynamic_route_count(&self) -> u64 {
        self.registry.count_dynamic().await
    }

    /// Mark every entry dirty and reconcile against a fresh snapshot.
    ///
    /// Test-facing twin of [`reconcile_after_invalidation`] on an owned
    /// manager; production callers go through the free function.
    #[cfg(test)]
    pub async fn reconcile_all(&self) -> Result<ReconcileReport> {
        Ok(self
            .handle_invalidation(backend::RouteInvalidation::Full)
            .await)
    }
}

/// Consume one invalidation for an AuthorityOnDemand backend (08D1 §18.5).
///
/// Only two kinds are meaningful: a per-zone generation change dirties that
/// zone's entries, and total authority loss dirties every managed entry. Both
/// are purely local — the controller owns kernel repair, so there is no
/// snapshot and no bulk Ensure. Any other kind is a test-visible invariant
/// violation and is logged rather than acted on.
async fn dispatch_authority_invalidation(
    registry: &RouteRegistry,
    kernel_epoch: &AtomicU64,
    violations: &AtomicU64,
    invalidation: backend::RouteInvalidation,
) {
    match invalidation {
        backend::RouteInvalidation::Zone(zone) => {
            let epoch = kernel_epoch.load(Ordering::SeqCst);
            registry
                .mark_dirty(backend::RouteInvalidation::Zone(zone), epoch)
                .await;
        }
        backend::RouteInvalidation::AuthorityLost => {
            registry.mark_authority_lost().await;
        }
        unsupported => {
            violations.fetch_add(1, Ordering::SeqCst);
            tracing::error!(
                invalidation = ?unsupported,
                "managed authority-on-demand backend received an unsupported invalidation; \
                 ignored without a snapshot or bulk RPC"
            );
        }
    }
}

/// Bump the shared kernel epoch, mark entries dirty per the invalidation and
/// reconcile them against exactly the proof the invalidation allows.
///
/// A `Full` invalidation (periodic safety audit, explicit diagnostic) is the
/// only path that reads the whole FIB. Prefix, Interface and Zone events read
/// back only the keys they invalidated (08D1 §16.3): the event path must never
/// turn one kernel notification into a full v4+v6 snapshot.
async fn reconcile_after_invalidation(
    registry: &Arc<RouteRegistry>,
    backend: &dyn RouteBackend,
    kernel_epoch: &AtomicU64,
    counters: &ReconcileCounterState,
    invalidation: backend::RouteInvalidation,
) -> ReconcileReport {
    // §15 targeted-epoch semantics: only a Full invalidation advances the
    // epoch (it is the full-kernel-snapshot proof). Targeted Prefix /
    // Interface / Zone invalidations mark the matching entries Dirty and
    // re-verify them against the CURRENT full_epoch — unrelated Verified
    // entries keep their fast path without any kernel I/O.
    if matches!(invalidation, backend::RouteInvalidation::Full) {
        kernel_epoch.fetch_add(1, Ordering::SeqCst);
    }
    let epoch = kernel_epoch.load(Ordering::SeqCst);
    let dirty_keys = registry.mark_dirty(invalidation.clone(), epoch).await;
    // §14.2: the dispatch branches on the backend's reconcile mode.
    match backend.reconcile_mode() {
        ReconcileMode::KernelSnapshot => match invalidation {
            backend::RouteInvalidation::Full => {
                counters.full_snapshots.fetch_add(1, Ordering::SeqCst);
                match backend.snapshot().await {
                    Ok(snapshot) => registry.reconcile_dirty(backend, &snapshot, epoch).await,
                    Err(e) => {
                        // A Full invalidation already advanced the epoch, so
                        // no entry can claim Verified against stale kernel
                        // state until the next reconcile succeeds.
                        tracing::debug!(error = %e, "Route snapshot failed after an invalidation");
                        ReconcileReport::default()
                    }
                }
            }
            // 08D1 §16.3: targeted events read back exactly their own keys.
            backend::RouteInvalidation::Prefix(_)
            | backend::RouteInvalidation::Interface(_)
            | backend::RouteInvalidation::Zone(_) => {
                reconcile_targeted_keys(registry, backend, &dirty_keys, epoch, counters).await
            }
            // A local-kernel backend never originates AuthorityLost; the
            // managed dispatch owns it (08D1 §18.4).
            backend::RouteInvalidation::AuthorityLost => ReconcileReport::default(),
        },
        // AuthorityOnDemand and RegistryOnly never snapshot here: the
        // demand-driven path (L14) and the shell backend own their own
        // revalidation.
        ReconcileMode::AuthorityOnDemand | ReconcileMode::RegistryOnly => {
            ReconcileReport::default()
        }
    }
}

/// Reconcile the keys a targeted invalidation named, one exact read-back each.
///
/// A failed read-back leaves the entry Dirty: no entry may claim Verified
/// against a key the backend could not read.
async fn reconcile_targeted_keys(
    registry: &RouteRegistry,
    backend: &dyn RouteBackend,
    keys: &[model::RouteKey],
    epoch: u64,
    counters: &ReconcileCounterState,
) -> ReconcileReport {
    let mut report = ReconcileReport::default();
    for key in keys {
        counters.targeted_reads.fetch_add(1, Ordering::SeqCst);
        match backend.observe_key(key).await {
            Ok(rows) => {
                let one = registry.reconcile_key(backend, key, &rows, epoch).await;
                report.adds += one.adds;
                report.removes += one.removes;
                report.noops += one.noops;
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    prefix = %key.prefix.network,
                    "targeted read-back failed; the entry stays dirty"
                );
            }
        }
    }
    report
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
    use crate::dns::DnsHandler;
    use crate::routing::backend::fake::FakeBackend;
    use crate::routing::kikimora::fake::{applied_result, FakeTransport};
    use crate::routing::kikimora::KikimoraRouteBackend;
    use crate::routing::model::ObservedRoute;
    use crate::server::apply_reload;
    use crate::zones::ZoneMatcher;
    use std::net::Ipv6Addr;
    use tokio::sync::RwLock;

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

    fn managed_backend(transport: &Arc<FakeTransport>) -> Arc<KikimoraRouteBackend> {
        Arc::new(KikimoraRouteBackend::with_test_transport(Box::new(
            Arc::clone(transport),
        )))
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
            identity: crate::routing::model::RouteKernelIdentity {
                ifindex: Some(1),
                next_hop: None,
                protocol: 3,
                metric: 0,
                scope: 0,
                interface_luid: None,
            },
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

    #[tokio::test]
    async fn removed_zone_deletes_only_its_owned_rows() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), None);
        let corp = via_zone("corp", "192.168.1.1");
        let other = via_zone("other", "192.168.2.1");

        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &corp)
            .await
            .unwrap();
        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), &other)
            .await
            .unwrap();
        backend.reset_counters();

        mgr.cleanup_zone("corp").await.unwrap();
        let removed = backend.removed();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].zone, "corp");
        assert_eq!(mgr.dynamic_route_count().await, 1);
    }

    #[tokio::test]
    async fn retirement_spares_a_replacement_verified_in_the_meantime() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), None);
        let old_zone = via_zone("corp", "192.168.1.1");
        let mut new_zone = via_zone("corp", "10.8.0.1");
        new_zone.static_routes = vec!["10.0.0.1".to_string()];

        // Old zone state: a dynamic host route through the old gateway.
        mgr.add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &old_zone)
            .await
            .unwrap();
        let old_intents = mgr.zone_intents("corp").await;
        assert_eq!(old_intents.len(), 1);

        // Reload: the replacement (static, new gateway) is verified first...
        mgr.add_static_route("10.0.0.1", &new_zone).await.unwrap();
        assert_eq!(backend.ensure_count(), 2);

        // ...then the old intent is retired. The registry key now belongs to
        // the replacement, so neither the row nor the entry may be deleted.
        let retired = mgr.retire_intents(&old_intents).await.unwrap();
        assert_eq!(retired.retired, 0);
        assert_eq!(retired.skipped_replaced, 1);
        assert_eq!(
            backend.remove_count(),
            0,
            "a verified replacement row must not be deleted by old-zone retirement"
        );
    }

    #[tokio::test]
    async fn reload_replay_converges_to_zero_mutations() {
        let backend = Arc::new(FakeBackend::new());
        let mgr =
            RouteManager::with_backend(Arc::clone(&backend), None, DEFAULT_MAX_DYNAMIC_ROUTES);
        let zone = via_zone("corp", "192.168.1.1");

        // First reload: one static route add.
        mgr.add_static_route("10.9.0.0/16", &zone).await.unwrap();
        assert_eq!(backend.ensure_count(), 1);

        // Publish the row as observed so a reconcile sees a matching kernel.
        let intent = mgr.zone_intents("corp").await.remove(0);
        backend.push_observed(ObservedRoute {
            key: intent.key,
            target: intent.target,
            identity: crate::routing::model::RouteKernelIdentity {
                ifindex: Some(1),
                next_hop: None,
                protocol: 3,
                metric: 0,
                scope: 0,
                interface_luid: None,
            },
        });

        // Reload replay: re-applying the identical state mutates nothing.
        mgr.add_static_route("10.9.0.0/16", &zone).await.unwrap();
        let report = mgr.reconcile_all().await.unwrap();
        assert_eq!(backend.ensure_count(), 1);
        assert_eq!(report.adds, 0);
        assert_eq!(report.removes, 0);
        assert_eq!(report.noops, 1);
    }

    // -----------------------------------------------------------------
    // Soak / performance regression (plan commit 8): deterministic
    // fake-kernel load that must stay flat after convergence.
    // -----------------------------------------------------------------

    /// Publish every owned intent as observed, so audits see a matching
    /// kernel instead of re-adding the routes.
    async fn publish_all_as_observed(backend: &FakeBackend, mgr: &RouteManager) {
        for zone in ["corp4", "corp6"] {
            for intent in mgr.zone_intents(zone).await {
                backend.push_observed(ObservedRoute {
                    key: intent.key,
                    target: intent.target,
                    identity: crate::routing::model::RouteKernelIdentity {
                        ifindex: Some(1),
                        next_hop: None,
                        protocol: 3,
                        metric: 0,
                        scope: 0,
                        interface_luid: None,
                    },
                });
            }
        }
    }

    #[tokio::test]
    async fn soak_ten_thousand_classifications_over_200_addresses() {
        let backend = Arc::new(FakeBackend::new());
        let mgr = manager(Arc::clone(&backend), None);
        let zone4 = via_zone("corp4", "192.168.1.1");
        let mut zone6 = via_zone("corp6", "192.168.1.1");
        zone6.ipv6 = true;
        zone6.route_target_ipv6 = Some("2001:db8::1".to_string());

        let v4: Vec<Ipv4Addr> = (0..100u32)
            .map(|i| Ipv4Addr::from(0x0A010000u32 + i))
            .collect();
        let v6: Vec<Ipv6Addr> = (0..100u16)
            .map(|i| Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i))
            .collect();

        // First pass converges: exactly one mutation per address, and the
        // request path never touches a FIB dump.
        for ip in &v4 {
            mgr.add_route(IpAddr::V4(*ip), &zone4).await.unwrap();
        }
        for ip in &v6 {
            mgr.add_route(IpAddr::V6(*ip), &zone6).await.unwrap();
        }
        assert_eq!(backend.ensure_count(), 200);
        assert_eq!(backend.snapshot_count(), 0);

        // 10k more classifications over the same set: mutations stay flat.
        for round in 0..10_000u32 {
            let i = (round % 100) as usize;
            mgr.add_route(IpAddr::V4(v4[i]), &zone4).await.unwrap();
            mgr.add_route(IpAddr::V6(v6[i]), &zone6).await.unwrap();
        }
        assert_eq!(backend.ensure_count(), 200);
        assert_eq!(backend.snapshot_count(), 0);

        // One audit per simulated interval: exactly one snapshot each, and
        // a matching kernel mutates nothing.
        publish_all_as_observed(&backend, &mgr).await;
        let ensures_before = backend.ensure_count();
        let snapshots_before = backend.snapshot_count();
        for _ in 0..10 {
            let report = mgr
                .handle_invalidation(backend::RouteInvalidation::Full)
                .await;
            assert_eq!(report.adds, 0);
            assert_eq!(report.removes, 0);
        }
        assert_eq!(backend.snapshot_count(), snapshots_before + 10);
        assert_eq!(backend.ensure_count(), ensures_before);

        // External loss of one row is reconciled exactly once, and the
        // following audit is flat again.
        backend.clear_observed();
        let report = mgr
            .handle_invalidation(backend::RouteInvalidation::Full)
            .await;
        assert_eq!(report.adds, 200);
        publish_all_as_observed(&backend, &mgr).await;
        let report = mgr
            .handle_invalidation(backend::RouteInvalidation::Full)
            .await;
        assert_eq!(report.adds, 0);
    }

    #[tokio::test]
    async fn capacity_denies_the_16385th_unique_dynamic_intent() {
        let backend = Arc::new(FakeBackend::new());
        let mgr =
            RouteManager::with_backend(Arc::clone(&backend), None, DEFAULT_MAX_DYNAMIC_ROUTES);
        let zone = via_zone("corp", "192.168.1.1");

        // The registry fills to exactly the configured capacity.
        for i in 0..DEFAULT_MAX_DYNAMIC_ROUTES as u32 {
            let ip = Ipv4Addr::from(0x0A000000u32 + i);
            mgr.add_route(IpAddr::V4(ip), &zone).await.unwrap();
        }
        assert_eq!(
            mgr.dynamic_route_count().await,
            DEFAULT_MAX_DYNAMIC_ROUTES as u64
        );

        // The next unique address is denied fail-closed and consumes no slot.
        let ip = Ipv4Addr::from(0x0A000000u32 + DEFAULT_MAX_DYNAMIC_ROUTES as u32);
        let result = mgr.add_route(IpAddr::V4(ip), &zone).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "route capacity exceeded");
        assert_eq!(
            mgr.dynamic_route_count().await,
            DEFAULT_MAX_DYNAMIC_ROUTES as u64
        );

        // Static entries never consume the dynamic quota.
        mgr.add_static_route("172.16.0.0/12", &zone).await.unwrap();
        assert_eq!(
            mgr.dynamic_route_count().await,
            DEFAULT_MAX_DYNAMIC_ROUTES as u64
        );
    }

    #[tokio::test]
    async fn managed_authority_loss_is_local_and_demand_is_one_rpc() {
        let transport = Arc::new(FakeTransport::new());
        transport.set_result(applied_result("10.0.0.1/32", 4));
        let backend = managed_backend(&transport);
        let mgr =
            RouteManager::with_backend(Arc::clone(&backend), None, DEFAULT_MAX_DYNAMIC_ROUTES);
        let zone = via_zone("corp", "192.168.1.1");

        for i in 0..1000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0A000000u32 + i));
            mgr.add_route(ip, &zone).await.unwrap();
        }
        assert_eq!(transport.call_count(), 1000);

        // §18.5/§18.8: authority loss dirties all 1000 entries with zero
        // controller calls and zero snapshots.
        let report = mgr
            .handle_invalidation(backend::RouteInvalidation::AuthorityLost)
            .await;
        assert_eq!(report.adds, 0);
        assert_eq!(report.removes, 0);
        assert_eq!(
            transport.call_count(),
            1000,
            "authority loss must never bulk RPC"
        );
        assert_eq!(backend.snapshot_calls(), 0);
        assert_eq!(mgr.registry.dirty_count().await, 1000);

        // One demand revalidates exactly one key.
        let ip = IpAddr::V4(Ipv4Addr::from(0x0A000000u32));
        mgr.add_route(ip, &zone).await.unwrap();
        assert_eq!(transport.call_count(), 1001);
        for _ in 0..1000 {
            mgr.add_route(ip, &zone).await.unwrap();
        }
        assert_eq!(
            transport.call_count(),
            1001,
            "a Verified key returns to the zero-RPC fast path"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn managed_concurrent_demands_for_one_dirty_key_make_one_rpc() {
        let transport = Arc::new(FakeTransport::new());
        transport.set_result(applied_result("10.0.0.1/32", 4));
        let backend = managed_backend(&transport);
        let mgr = Arc::new(RouteManager::with_backend(
            Arc::clone(&backend),
            None,
            DEFAULT_MAX_DYNAMIC_ROUTES,
        ));
        let zone = via_zone("corp", "192.168.1.1");
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        mgr.add_route(ip, &zone).await.unwrap();
        assert_eq!(transport.call_count(), 1);
        mgr.handle_invalidation(backend::RouteInvalidation::AuthorityLost)
            .await;
        assert_eq!(mgr.registry.dirty_count().await, 1);

        let mut tasks = Vec::new();
        for _ in 0..32 {
            let mgr = Arc::clone(&mgr);
            let zone = zone.clone();
            tasks.push(tokio::spawn(async move {
                mgr.add_route(ip, &zone).await.unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(
            transport.call_count(),
            2,
            "32 concurrent same-key demands must collapse to one Ensure"
        );
        assert_eq!(mgr.registry.dirty_count().await, 0);
    }

    #[tokio::test]
    async fn managed_zone_invalidation_only_dirties_that_zone() {
        let transport = Arc::new(FakeTransport::new());
        transport.set_result(applied_result("10.0.0.1/32", 4));
        let backend = managed_backend(&transport);
        let mgr =
            RouteManager::with_backend(Arc::clone(&backend), None, DEFAULT_MAX_DYNAMIC_ROUTES);
        let corp = via_zone("corp", "192.168.1.1");
        let other = via_zone("other", "192.168.2.1");
        let corp_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let other_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        mgr.add_route(corp_ip, &corp).await.unwrap();
        mgr.add_route(other_ip, &other).await.unwrap();
        assert_eq!(transport.call_count(), 2);

        mgr.handle_invalidation(backend::RouteInvalidation::Zone("corp".to_string()))
            .await;
        assert_eq!(mgr.registry.dirty_count().await, 1);

        // The unchanged zone stays on the zero-RPC fast path.
        mgr.add_route(other_ip, &other).await.unwrap();
        assert_eq!(transport.call_count(), 2);
        assert_eq!(mgr.registry.dirty_count().await, 1);

        // Only the invalidated zone is revalidated.
        mgr.add_route(corp_ip, &corp).await.unwrap();
        assert_eq!(transport.call_count(), 3);
        assert_eq!(mgr.registry.dirty_count().await, 0);
    }

    #[tokio::test]
    async fn managed_full_invalidation_is_an_invariant_without_snapshot() {
        let transport = Arc::new(FakeTransport::new());
        transport.set_result(applied_result("10.0.0.1/32", 4));
        let backend = managed_backend(&transport);
        let mgr =
            RouteManager::with_backend(Arc::clone(&backend), None, DEFAULT_MAX_DYNAMIC_ROUTES);
        let zone = via_zone("corp", "192.168.1.1");
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        mgr.add_route(ip, &zone).await.unwrap();
        assert_eq!(transport.call_count(), 1);

        let report = mgr
            .handle_invalidation(backend::RouteInvalidation::Full)
            .await;
        assert_eq!(report.adds, 0);
        assert_eq!(report.removes, 0);
        assert_eq!(transport.call_count(), 1);
        assert_eq!(
            backend.snapshot_calls(),
            0,
            "AuthorityOnDemand must never call snapshot()"
        );
        assert_eq!(mgr.authority_invariant_violations(), 1);
        assert_eq!(
            mgr.registry.dirty_count().await,
            0,
            "an unsupported kind must not dirty or revalidate anything"
        );

        // The existing Verified entry keeps its zero-RPC fast path.
        mgr.add_route(ip, &zone).await.unwrap();
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn managed_for_server_never_selects_the_local_platform_backend() {
        // Both paths start a subscription pump that fails to connect; the
        // manager's reconcile mode proves the backend is the managed one, not
        // PlatformBackend (which always reports KernelSnapshot).
        let server: crate::config::ServerConfig = toml::from_str(
            r#"
listen_address = "127.0.0.1:5399"
default_upstream = ["127.0.0.1:5300"]
routing_backend = "kikimora"
kikimora_socket = "leshy-l14-absent.sock"
"#,
        )
        .unwrap();
        let mgr = RouteManager::for_server(&server).unwrap();
        assert_eq!(mgr.reconcile_mode(), ReconcileMode::AuthorityOnDemand);
        assert_eq!(mgr.authority_invariant_violations(), 0);
    }

    #[tokio::test]
    async fn managed_reload_sends_zero_controller_calls_until_changed() -> anyhow::Result<()> {
        let transport = Arc::new(FakeTransport::new());
        transport.set_result(crate::routing::kikimora::fake::applied_result(
            "10.0.0.1/32",
            4,
        ));
        let backend = managed_backend(&transport);
        let mgr = Arc::new(RouteManager::with_backend(
            Arc::clone(&backend),
            None,
            DEFAULT_MAX_DYNAMIC_ROUTES,
        ));
        let zone = via_zone("corp", "192.168.1.1");
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 1);

        mgr.add_route(std::net::IpAddr::V4(ip), &zone)
            .await
            .unwrap();
        assert_eq!(transport.call_count(), 1);

        // Reload with no changes should not emit any invalidations.
        let new_config = crate::config::Config {
            server: crate::config::ServerConfig {
                listen_address: std::net::SocketAddr::from(([127, 0, 0, 1], 5399)),
                default_upstream: vec![],
                route_failure_mode: crate::config::RouteFailureMode::Servfail,
                auto_reload: false,
                config_dir: None,
                cache_size: 100,
                cache_min_ttl: 0,
                cache_max_ttl: 0,
                cache_negative_ttl: 0,
                route_aggregation_prefix: None,
                max_dynamic_routes: DEFAULT_MAX_DYNAMIC_ROUTES,
                routing_backend: crate::config::RoutingBackend::Kikimora,
                kikimora_socket: Some("leshy-l14-test.sock".to_string()),
                writer_lock: None,
                kikimora_auth_file: None,
                kikimora_activation_id: None,
                kikimora_mode_generation: None,
            },
            zones: vec![zone.clone()],
        };
        let new_mgr = Arc::new(RouteManager::for_server(&new_config.server).unwrap());

        // No invalidations should be sent.
        let report = new_mgr
            .handle_invalidation(backend::RouteInvalidation::Zone("corp".to_string()))
            .await;
        assert_eq!(report.adds, 0);
        assert_eq!(report.removes, 0);
        assert_eq!(transport.call_count(), 1);
        Ok(())
    }

    fn reload_test_server() -> ServerConfig {
        toml::from_str(
            r#"
listen_address = "127.0.0.1:5399"
default_upstream = ["127.0.0.1:5300"]
routing_backend = "kikimora"
kikimora_socket = "/run/kikimora/core.sock"
max_dynamic_routes = 100
"#,
        )
        .expect("reload test server config parses")
    }

    /// Build a handler whose route manager is the fake backend, so the reload
    /// tests can observe every backend mutation and prove that a rejected
    /// transaction touched nothing.
    fn reload_test_handler(
        server: &ServerConfig,
        backend: &Arc<FakeBackend>,
    ) -> Result<Arc<RwLock<DnsHandler>>> {
        let zones = vec![via_zone("corp", "192.168.1.1")];
        let config = crate::config::Config {
            server: server.clone(),
            zones: zones.clone(),
        };
        let matcher = ZoneMatcher::new(zones)?;
        let manager = RouteManager::with_backend(
            Arc::clone(backend),
            server.route_aggregation_prefix,
            server.max_dynamic_routes,
        );
        Ok(Arc::new(RwLock::new(DnsHandler::with_route_manager(
            config, matcher, manager,
        ))))
    }

    /// Shared body of the restart-only reload regressions (08D1 §19.1).
    ///
    /// The change must be rejected by the real `apply_reload` transaction with
    /// the documented restart error, before any route is retired and before
    /// the live configuration is swapped.
    async fn assert_restart_only_rejection(
        field: &str,
        mutate: impl FnOnce(&mut ServerConfig),
    ) -> Result<()> {
        let server = reload_test_server();
        let backend = Arc::new(FakeBackend::new());
        let handler = reload_test_handler(&server, &backend)?;

        let mut changed_server = server.clone();
        mutate(&mut changed_server);
        let reload_config = crate::config::Config {
            server: changed_server,
            zones: vec![via_zone("corp", "192.168.1.1")],
        };

        let error = apply_reload(&handler, reload_config)
            .await
            .expect_err("apply_reload must reject a restart-only change");

        anyhow::ensure!(
            error.to_string().contains("restart Leshy"),
            "changed {field}: expected the restart-only error, got: {error}"
        );

        let live = handler.read().await.config().server.clone();
        assert_eq!(
            live.kikimora_socket, server.kikimora_socket,
            "changed {field}: the live socket must not be swapped"
        );
        assert_eq!(
            live.route_aggregation_prefix, server.route_aggregation_prefix,
            "changed {field}: the live aggregation prefix must not be swapped"
        );
        assert_eq!(
            live.max_dynamic_routes, server.max_dynamic_routes,
            "changed {field}: the live capacity must not be swapped"
        );
        assert_eq!(
            live.routing_backend, server.routing_backend,
            "changed {field}: the live backend must not be swapped"
        );

        assert_eq!(
            backend.ensure_count(),
            0,
            "changed {field}: a rejected reload must not ensure any route"
        );
        assert_eq!(
            backend.remove_count(),
            0,
            "changed {field}: a rejected reload must not retire any route"
        );
        assert_eq!(
            backend.snapshot_count(),
            0,
            "changed {field}: a rejected reload must not snapshot the kernel"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reload_rejects_kikimora_socket_changes() -> Result<()> {
        assert_restart_only_rejection("kikimora_socket", |server| {
            server.kikimora_socket = Some("/run/kikimora/core.sock.bak".to_string());
        })
        .await
    }

    #[tokio::test]
    async fn reload_rejects_capacity_changes() -> Result<()> {
        assert_restart_only_rejection("max_dynamic_routes", |server| {
            server.max_dynamic_routes = 200;
        })
        .await
    }

    #[tokio::test]
    async fn reload_rejects_aggregation_prefix_changes() -> Result<()> {
        assert_restart_only_rejection("route_aggregation_prefix", |server| {
            server.route_aggregation_prefix = Some(24);
        })
        .await
    }

    #[tokio::test]
    async fn reload_rejects_routing_backend_changes() -> Result<()> {
        assert_restart_only_rejection("routing_backend", |server| {
            server.routing_backend = RoutingBackend::Local;
        })
        .await
    }

    /// 08D1 §19.2: a reload that changes one zone retires exactly that zone's
    /// owned rows through the real `apply_reload` transaction. The untouched
    /// zone keeps its ownership with zero backend calls.
    #[tokio::test]
    async fn reload_two_zones_only_changed_one_is_targeted() -> Result<()> {
        let server = reload_test_server();
        let corp = via_zone("corp", "192.168.1.1");
        let mut edge = via_zone("edge", "192.168.2.1");
        edge.domains = vec!["edge.example.com".to_string()];

        let config = crate::config::Config {
            server: server.clone(),
            zones: vec![corp.clone(), edge.clone()],
        };
        let matcher = ZoneMatcher::new(vec![corp.clone(), edge.clone()])?;
        let backend = Arc::new(FakeBackend::new());
        let manager = RouteManager::with_backend(
            Arc::clone(&backend),
            server.route_aggregation_prefix,
            server.max_dynamic_routes,
        );

        let corp_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let edge_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        manager.add_route(corp_ip, &corp).await?;
        manager.add_route(edge_ip, &edge).await?;
        assert_eq!(backend.ensure_count(), 2);

        let handler = Arc::new(RwLock::new(DnsHandler::with_route_manager(
            config, matcher, manager,
        )));
        backend.reset_counters();

        // Only `edge` changes; `corp` keeps the same routing policy.
        let mut changed_edge = edge.clone();
        changed_edge.domains = vec!["reloaded.example.com".to_string()];
        let mut reload_config = handler.read().await.config().clone();
        reload_config.zones = vec![corp.clone(), changed_edge.clone()];

        apply_reload(&handler, reload_config).await?;

        let removed = backend.removed();
        assert_eq!(
            removed.len(),
            1,
            "only the changed zone may retire an owned row, got {removed:?}"
        );
        assert_eq!(removed[0].zone, "edge");
        assert_eq!(
            backend.ensure_count(),
            0,
            "the unchanged zone must not be re-ensured on reload"
        );

        let live = handler.read().await.config().clone();
        assert_eq!(live.zones.len(), 2);
        assert_eq!(live.zones[0], corp, "the unchanged zone keeps its config");
        assert_eq!(
            live.zones[1].domains,
            vec!["reloaded.example.com".to_string()],
            "the changed zone is swapped in"
        );
        Ok(())
    }

    /// 08D1 §19.1/§19.2 reload transaction matrix: a failure at any point
    /// before the config swap must abort, keep the old config and matcher, and
    /// keep the exact ownership evidence.
    mod reload_transaction_tests {
        use super::*;

        async fn handler_with_owned_route(
            server: &ServerConfig,
            zone: &ZoneConfig,
            backend: &Arc<FakeBackend>,
            ip: IpAddr,
        ) -> Result<Arc<RwLock<DnsHandler>>> {
            let manager = RouteManager::with_backend(
                Arc::clone(backend),
                server.route_aggregation_prefix,
                server.max_dynamic_routes,
            );
            manager.add_route(ip, zone).await?;
            let config = crate::config::Config {
                server: server.clone(),
                zones: vec![zone.clone()],
            };
            let matcher = ZoneMatcher::new(vec![zone.clone()])?;
            Ok(Arc::new(RwLock::new(DnsHandler::with_route_manager(
                config, matcher, manager,
            ))))
        }

        #[tokio::test]
        async fn removed_zone_cleanup_failure_aborts_reload() -> Result<()> {
            let server = reload_test_server();
            let corp = via_zone("corp", "192.168.1.1");
            let backend = Arc::new(FakeBackend::new());
            let handler = handler_with_owned_route(
                &server,
                &corp,
                &backend,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            )
            .await?;
            assert_eq!(backend.ensure_count(), 1);

            backend.set_remove_error("kernel delete failed");
            let reload_config = crate::config::Config {
                server: server.clone(),
                zones: vec![],
            };

            let error = apply_reload(&handler, reload_config)
                .await
                .expect_err("a failed removed-zone cleanup must abort the reload");
            assert!(
                error.to_string().contains("failed"),
                "expected a cleanup failure, got: {error}"
            );

            assert_eq!(
                handler.read().await.config().zones.len(),
                1,
                "the old config must survive a failed transaction"
            );
            assert!(
                !handler
                    .read()
                    .await
                    .zone_route_intents("corp")
                    .await
                    .is_empty(),
                "ownership evidence must survive a failed retirement"
            );
            Ok(())
        }

        #[tokio::test]
        async fn changed_zone_retirement_failure_aborts_reload() -> Result<()> {
            let server = reload_test_server();
            let corp = via_zone("corp", "192.168.1.1");
            let backend = Arc::new(FakeBackend::new());
            let handler = handler_with_owned_route(
                &server,
                &corp,
                &backend,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            )
            .await?;

            backend.set_remove_error("kernel delete failed");
            let mut changed = corp.clone();
            changed.domains = vec!["changed.example.com".to_string()];
            let reload_config = crate::config::Config {
                server: server.clone(),
                zones: vec![changed],
            };

            let error = apply_reload(&handler, reload_config)
                .await
                .expect_err("a failed changed-zone retirement must abort the reload");
            assert!(
                error.to_string().contains("retiring"),
                "expected a retirement failure, got: {error}"
            );

            let live = handler.read().await.config().clone();
            assert_eq!(
                live.zones[0].domains, corp.domains,
                "the old zone must survive a failed transaction"
            );
            assert!(
                !handler
                    .read()
                    .await
                    .zone_route_intents("corp")
                    .await
                    .is_empty(),
                "ownership evidence must survive a failed retirement"
            );
            Ok(())
        }

        #[tokio::test]
        async fn replacement_static_route_failure_aborts_before_retirement() -> Result<()> {
            let server = reload_test_server();
            let corp = via_zone("corp", "192.168.1.1");
            let backend = Arc::new(FakeBackend::new());
            let handler = handler_with_owned_route(
                &server,
                &corp,
                &backend,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            )
            .await?;
            assert_eq!(backend.remove_count(), 0);

            backend.set_outcome(Err(anyhow::anyhow!("add refused")));
            let mut changed = corp.clone();
            changed.static_routes = vec!["10.9.9.0/24".to_string()];
            let reload_config = crate::config::Config {
                server: server.clone(),
                zones: vec![changed],
            };

            let error = apply_reload(&handler, reload_config)
                .await
                .expect_err("a failed replacement row must abort the reload");
            assert!(
                error.to_string().contains("failed to verify"),
                "expected a replacement failure, got: {error}"
            );
            assert_eq!(
                backend.remove_count(),
                0,
                "retirement must not start when the replacement proof failed"
            );
            assert_eq!(
                handler.read().await.config().zones[0].static_routes.len(),
                0,
                "the old config must survive"
            );
            Ok(())
        }

        #[tokio::test]
        async fn managed_reload_without_changes_sends_no_controller_rpc() -> Result<()> {
            let server = reload_test_server();
            let zone = via_zone("corp", "192.168.1.1");
            let transport = Arc::new(FakeTransport::new());
            transport.set_result(crate::routing::kikimora::fake::applied_result(
                "10.0.0.1/32",
                4,
            ));
            let backend = managed_backend(&transport);
            let manager =
                RouteManager::with_backend(Arc::clone(&backend), None, DEFAULT_MAX_DYNAMIC_ROUTES);
            assert_eq!(manager.reconcile_mode(), ReconcileMode::AuthorityOnDemand);
            manager
                .add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &zone)
                .await?;
            assert_eq!(transport.call_count(), 1);

            let config = crate::config::Config {
                server: server.clone(),
                zones: vec![zone.clone()],
            };
            let matcher = ZoneMatcher::new(vec![zone.clone()])?;
            let handler = Arc::new(RwLock::new(DnsHandler::with_route_manager(
                config, matcher, manager,
            )));

            let before = transport.call_count();
            let reload_config = handler.read().await.config().clone();
            apply_reload(&handler, reload_config).await?;

            assert_eq!(
                transport.call_count(),
                before,
                "a no-change managed reload must send zero controller RPC"
            );
            Ok(())
        }
    }

    /// 08D1 §16.3/§6.5: the invalidation path reads back exactly the keys the
    /// event named and never turns one kernel notification into a full-FIB
    /// snapshot.
    mod targeted_reconcile_tests {
        use super::*;

        fn key_of(ip: IpAddr) -> model::RouteKey {
            model::RouteKey {
                prefix: model::RoutePrefix::host(ip),
                table: MAIN_TABLE,
            }
        }

        fn ip(last: u8) -> IpAddr {
            IpAddr::V4(Ipv4Addr::new(10, 9, 0, last))
        }

        async fn manager_with_routes(
            routes: &[(&ZoneConfig, IpAddr)],
        ) -> Result<(Arc<RouteManager>, Arc<FakeBackend>)> {
            let backend = Arc::new(FakeBackend::new());
            let mgr = Arc::new(RouteManager::with_backend(
                Arc::clone(&backend),
                None,
                DEFAULT_MAX_DYNAMIC_ROUTES,
            ));
            for (zone, addr) in routes {
                mgr.add_route(*addr, zone).await?;
            }
            backend.reset_counters();
            Ok((mgr, backend))
        }

        #[tokio::test]
        async fn prefix_event_triggers_one_targeted_read_and_no_snapshot() -> Result<()> {
            let zone = via_zone("corp", "192.168.1.1");
            let (mgr, backend) = manager_with_routes(&[(&zone, ip(1)), (&zone, ip(2))]).await?;

            let report = mgr
                .handle_invalidation(backend::RouteInvalidation::Prefix(key_of(ip(1))))
                .await;

            assert_eq!(
                backend.snapshot_count(),
                0,
                "a Prefix event must not full-snapshot"
            );
            assert_eq!(
                backend.targeted_read_count(),
                1,
                "exactly the named key is read back"
            );
            assert_eq!(
                backend.ensure_count(),
                1,
                "the externally deleted row is repaired through the targeted path"
            );
            assert_eq!(report.adds, 1);
            assert_eq!(mgr.reconcile_counters().full_snapshots, 0);
            assert_eq!(mgr.reconcile_counters().targeted_reads, 1);
            assert_eq!(
                mgr.registry.dirty_count().await,
                0,
                "no entry may stay dirty after a successful targeted reconcile"
            );
            Ok(())
        }

        #[tokio::test]
        async fn interface_event_reads_back_only_the_affected_keys() -> Result<()> {
            let zone = via_zone("corp", "192.168.1.1");
            let (mgr, backend) =
                manager_with_routes(&[(&zone, ip(1)), (&zone, ip(2)), (&zone, ip(3))]).await?;

            // An unrelated ifindex dirties nothing and performs zero I/O.
            let quiet = mgr
                .handle_invalidation(backend::RouteInvalidation::Interface(99))
                .await;
            assert_eq!(quiet.adds + quiet.removes + quiet.noops, 0);
            assert_eq!(backend.targeted_read_count(), 0);
            assert_eq!(backend.snapshot_count(), 0);

            // Every recorded row was installed through ifindex 1.
            let report = mgr
                .handle_invalidation(backend::RouteInvalidation::Interface(1))
                .await;
            assert_eq!(backend.targeted_read_count(), 3);
            assert_eq!(
                backend.snapshot_count(),
                0,
                "an Interface event must not full-snapshot"
            );
            assert_eq!(report.adds, 3);
            Ok(())
        }

        #[tokio::test]
        async fn zone_event_reads_back_only_that_zones_keys() -> Result<()> {
            let corp = via_zone("corp", "192.168.1.1");
            let edge = via_zone("edge", "192.168.2.1");
            let (mgr, backend) =
                manager_with_routes(&[(&corp, ip(1)), (&corp, ip(2)), (&edge, ip(3))]).await?;

            let report = mgr
                .handle_invalidation(backend::RouteInvalidation::Zone("corp".to_string()))
                .await;

            assert_eq!(backend.targeted_read_count(), 2);
            assert_eq!(
                backend.snapshot_count(),
                0,
                "a Zone event must not full-snapshot"
            );
            assert_eq!(report.adds, 2);
            Ok(())
        }

        #[tokio::test]
        async fn full_invalidation_still_reads_exactly_one_full_snapshot() -> Result<()> {
            let zone = via_zone("corp", "192.168.1.1");
            let (mgr, backend) = manager_with_routes(&[(&zone, ip(1)), (&zone, ip(2))]).await?;

            mgr.handle_invalidation(backend::RouteInvalidation::Full)
                .await;

            assert_eq!(backend.snapshot_count(), 1);
            assert_eq!(backend.targeted_read_count(), 0);
            assert_eq!(
                backend.ensure_count(),
                2,
                "a Full reconcile still proves every desired key"
            );
            assert_eq!(mgr.reconcile_counters().full_snapshots, 1);
            Ok(())
        }

        #[tokio::test]
        async fn one_prefix_event_among_a_thousand_verified_keys_stays_flat() -> Result<()> {
            let zone = via_zone("corp", "192.168.1.1");
            let backend = Arc::new(FakeBackend::new());
            let mgr = Arc::new(RouteManager::with_backend(
                Arc::clone(&backend),
                None,
                DEFAULT_MAX_DYNAMIC_ROUTES,
            ));

            let mut addrs = Vec::new();
            for index in 0..1000u32 {
                let addr = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + index + 1));
                mgr.add_route(addr, &zone).await?;
                addrs.push(addr);
            }
            backend.reset_counters();

            let report = mgr
                .handle_invalidation(backend::RouteInvalidation::Prefix(key_of(addrs[500])))
                .await;
            assert_eq!(report.adds, 1);
            assert_eq!(
                backend.targeted_read_count(),
                1,
                "one Prefix event performs one targeted read"
            );
            assert_eq!(
                backend.snapshot_count(),
                0,
                "a targeted event never reads the full FIB"
            );

            // The other 999 keys keep their Verified fast path: zero extra
            // backend work of any kind.
            backend.reset_counters();
            for addr in &addrs {
                mgr.add_route(*addr, &zone).await?;
            }
            assert_eq!(
                backend.ensure_count(),
                0,
                "verified keys must not re-ensure"
            );
            assert_eq!(
                backend.targeted_read_count(),
                0,
                "no unrelated targeted reads"
            );
            assert_eq!(backend.snapshot_count(), 0, "no extra full snapshots");
            Ok(())
        }
    }
}
