//! Windows local route backend: one injected API, one coherent cache and one
//! observer (08D1 §41.3 production contract).
//!
//! The cache is the only source of truth for reads. A converged request never
//! enumerates the forwarding table: `NotifyRouteChange2` bumps a generation,
//! and only a stale generation forces one stable full refresh.

use super::backend::{EnsureOutcome, EnsureResult, ReconcileMode, RouteBackend, RouteInvalidation};
use super::model::{
    family_of, AddressFamily, ObservedRoute, RouteIntent, RouteKernelIdentity, RouteKey,
    RouteOwnership, RouteTarget,
};
use super::windows_api::{
    RealWindowsRouteApi, ResolvedWindowsRoute, WindowsCreateOutcome, WindowsDeleteOutcome,
    WindowsRouteApi, WindowsRouteSubscription, WINDOWS_METRIC, WINDOWS_PROTOCOL_NETMGMT,
};
use anyhow::{bail, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::{mpsc, Mutex, RwLock};

/// Test-visible cache counters.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CacheCounters {
    pub full_refreshes: u64,
    pub cache_hits: u64,
    pub ready: bool,
}

struct WindowsRouteCache {
    rows: RwLock<HashMap<RouteKey, Vec<ObservedRoute>>>,
    notify_generation: Arc<AtomicU64>,
    cache_generation: AtomicU64,
    ready: AtomicBool,
    refresh_lock: Mutex<()>,
    full_refreshes: AtomicU64,
    cache_hits: AtomicU64,
}

impl WindowsRouteCache {
    fn new(notify_generation: Arc<AtomicU64>) -> Self {
        Self {
            rows: RwLock::new(HashMap::new()),
            notify_generation,
            cache_generation: AtomicU64::new(0),
            ready: AtomicBool::new(false),
            refresh_lock: Mutex::new(()),
            full_refreshes: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
        }
    }

    fn is_current(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
            && self.cache_generation.load(Ordering::SeqCst)
                == self.notify_generation.load(Ordering::SeqCst)
    }
}

/// Windows local backend over the injected IP Helper seam.
pub struct WindowsRouteBackend {
    api: Arc<dyn WindowsRouteApi>,
    cache: Arc<WindowsRouteCache>,
    /// Keeps the notification registration alive for the backend lifetime.
    _subscription: Option<Box<dyn WindowsRouteSubscription>>,
    rx: StdMutex<Option<mpsc::UnboundedReceiver<RouteInvalidation>>>,
}

impl WindowsRouteBackend {
    /// Production constructor: real IP Helper API, one observer, one cache.
    pub fn new() -> Result<Self> {
        Self::with_api(Arc::new(RealWindowsRouteApi))
    }

    /// Constructor used by tests with a scripted `WindowsRouteApi`.
    pub(crate) fn with_api(api: Arc<dyn WindowsRouteApi>) -> Result<Self> {
        let notify_generation = Arc::new(AtomicU64::new(0));
        let cache = Arc::new(WindowsRouteCache::new(Arc::clone(&notify_generation)));
        let (tx, rx) = mpsc::unbounded_channel();

        // Observer registration happens before the first snapshot (08D1 §41.3).
        let subscription = match api.subscribe(Arc::clone(&notify_generation), tx) {
            Ok(subscription) => Some(subscription),
            Err(e) => {
                // Losing the event stream degrades repair latency; it must not
                // disable forwarding. Reads then refresh per request.
                tracing::warn!(error = %e, "Windows route monitor unavailable");
                None
            }
        };

        Ok(Self {
            api,
            cache,
            _subscription: subscription,
            rx: StdMutex::new(Some(rx)),
        })
    }

    /// One stable full refresh: retried while an event lands mid-read.
    async fn refresh(&self) -> Result<()> {
        let _guard = self.cache.refresh_lock.lock().await;
        loop {
            let before = self.cache.notify_generation.load(Ordering::SeqCst);
            let mut rows: HashMap<RouteKey, Vec<ObservedRoute>> = HashMap::new();
            for family in [AddressFamily::V4, AddressFamily::V6] {
                for row in self.api.dump_family(family).await? {
                    rows.entry(row.key.clone()).or_default().push(row);
                }
            }
            self.cache.full_refreshes.fetch_add(1, Ordering::SeqCst);
            let after = self.cache.notify_generation.load(Ordering::SeqCst);
            if before != after {
                // An event landed while we were reading: this table is not
                // current, read it again instead of publishing a stale map.
                continue;
            }
            *self.cache.rows.write().await = rows;
            self.cache.cache_generation.store(after, Ordering::SeqCst);
            self.cache.ready.store(true, Ordering::SeqCst);
            if self.cache.notify_generation.load(Ordering::SeqCst) != after {
                continue;
            }
            return Ok(());
        }
    }

    /// Rows for one key, read from the coherent cache. A converged request
    /// performs zero `GetIpForwardTable2` calls.
    async fn read_key(&self, key: &RouteKey) -> Result<Vec<ObservedRoute>> {
        if self.cache.is_current() {
            self.cache.cache_hits.fetch_add(1, Ordering::SeqCst);
        } else {
            self.refresh().await?;
        }
        Ok(self.cached(key).await)
    }

    async fn cached(&self, key: &RouteKey) -> Vec<ObservedRoute> {
        self.cache
            .rows
            .read()
            .await
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    async fn all_rows(&self) -> Vec<ObservedRoute> {
        self.cache
            .rows
            .read()
            .await
            .values()
            .flatten()
            .cloned()
            .collect()
    }

    /// Resolve the intent against the live interface state. The result carries
    /// the exact Windows identity (index + LUID + next hop + protocol + metric).
    async fn resolve_desired(&self, intent: &RouteIntent) -> Result<ResolvedWindowsRoute> {
        let prefix = &intent.key.prefix;
        let (interface, next_hop) = match &intent.target {
            RouteTarget::Device { name, .. } => {
                if name.trim().is_empty() {
                    bail!(
                        "route {}: a device route needs an interface name",
                        prefix.network
                    );
                }
                (self.api.resolve_device(name).await?, None)
            }
            RouteTarget::Gateway(gateway) => {
                if family_of(*gateway) != prefix.family() {
                    bail!(
                        "route {} cannot use gateway {gateway} of another family",
                        prefix.network
                    );
                }
                (
                    self.api.resolve_gateway_interface(*gateway).await?,
                    Some(*gateway),
                )
            }
            RouteTarget::Unreachable => bail!(
                "route {} cannot be installed as unreachable on Windows",
                prefix.network
            ),
        };

        Ok(ResolvedWindowsRoute {
            intent: intent.clone(),
            identity: RouteKernelIdentity {
                ifindex: Some(interface.index),
                next_hop,
                protocol: WINDOWS_PROTOCOL_NETMGMT,
                metric: WINDOWS_METRIC,
                scope: 0,
                interface_luid: Some(interface.luid),
            },
        })
    }

    /// Remove exactly the rows a failed create added, identified by
    /// difference against the pre-create state. Never deletes a pre-existing
    /// row.
    async fn rollback_new_rows(&self, key: &RouteKey, before: &[ObservedRoute]) {
        // A fresh dump, not the cache: the row this create added may be
        // invisible to a cache entry that was written before the create. A
        // stale cache made the rollback a no-op, leaving an unowned row that
        // no later shutdown sweep could identify (Production Plan C4
        // stress run: 25 of 800 rows leaked this way).
        if let Err(e) = self.refresh().await {
            tracing::warn!(
                ip = %key.prefix.network,
                error = %e,
                "route rollback could not refresh the table; the created row may leak"
            );
            return;
        }
        let after = self.cached(key).await;
        for row in after
            .iter()
            .filter(|row| !before.iter().any(|old| old.identity == row.identity))
        {
            if let Err(e) = self.api.delete_exact(key, &row.identity).await {
                tracing::warn!(
                    ip = %key.prefix.network,
                    error = %e,
                    "route rollback could not delete the row this create added"
                );
            }
        }
        let _ = self.refresh().await;
    }

    async fn add_desired(
        &self,
        desired: &ResolvedWindowsRoute,
        previous: Option<&RouteOwnership>,
    ) -> Result<EnsureResult> {
        let key = &desired.intent.key;
        let before = self.cached(key).await;
        match self.api.create(desired).await? {
            WindowsCreateOutcome::AlreadyExists => {
                // EEXIST is a success only when a stable read proves exactly
                // the desired identity and nothing else on the key.
                self.refresh().await?;
                let rows = self.cached(key).await;
                match rows.as_slice() {
                    [row] if matches_desired(row, desired) => {
                        let owned = previous
                            .and_then(|ownership| ownership.observed.as_ref())
                            .map(|prev| prev.identity == row.identity)
                            .unwrap_or(false);
                        Ok(EnsureResult {
                            outcome: EnsureOutcome::AlreadyMatching,
                            ownership: RouteOwnership {
                                owned,
                                observed: Some(row.clone()),
                            },
                        })
                    }
                    _ => Err(conflict_error(
                        &desired.intent,
                        "EEXIST with a row that is not the desired identity",
                    )),
                }
            }
            WindowsCreateOutcome::Created => {
                self.refresh().await?;
                let rows = self.cached(key).await;
                if let [row] = rows.as_slice() {
                    if matches_desired(row, desired) {
                        return Ok(EnsureResult {
                            outcome: EnsureOutcome::Added,
                            ownership: RouteOwnership {
                                owned: true,
                                observed: Some(row.clone()),
                            },
                        });
                    }
                }
                // The API reported success but the table does not prove it:
                // remove exactly the rows this create added and fail closed.
                self.rollback_new_rows(key, &before).await;
                Err(conflict_error(
                    &desired.intent,
                    "created row is not provable",
                ))
            }
        }
    }

    /// §A6: create Desired first, prove it, then delete the exact previous
    /// owned row and prove the final state. Never delete-first.
    async fn replace(
        &self,
        desired: &ResolvedWindowsRoute,
        previous_row: &ObservedRoute,
    ) -> Result<EnsureResult> {
        let key = &desired.intent.key;
        let before = self.cached(key).await;
        let created = self.api.create(desired).await?;
        self.refresh().await?;

        let rows = self.cached(key).await;
        let desired_rows: Vec<&ObservedRoute> = rows
            .iter()
            .filter(|row| matches_desired(row, desired))
            .collect();
        let foreign: Vec<&ObservedRoute> = rows
            .iter()
            .filter(|row| !matches_desired(row, desired) && row.identity != previous_row.identity)
            .collect();

        if desired_rows.len() != 1 || !foreign.is_empty() {
            // Roll back only the row this call created; the previous owned
            // row and every foreign row stay untouched.
            if created == WindowsCreateOutcome::Created {
                self.rollback_new_rows(key, &before).await;
            }
            return Err(conflict_error(
                &desired.intent,
                "replacement could not prove the desired row without foreign co-residents",
            ));
        }

        match self.api.delete_exact(key, &previous_row.identity).await? {
            WindowsDeleteOutcome::Deleted | WindowsDeleteOutcome::Absent => {}
        }

        self.refresh().await?;
        let rows = self.cached(key).await;
        match rows.as_slice() {
            [row] if matches_desired(row, desired) => Ok(EnsureResult {
                outcome: EnsureOutcome::Added,
                ownership: RouteOwnership {
                    owned: true,
                    observed: Some(row.clone()),
                },
            }),
            _ => bail!(
                "route {}: the previous owned row was removed but the desired row is not proven",
                key.prefix.network
            ),
        }
    }
}

/// Classification of the live rows for one key (§A5). Never returns on the
/// first desired row: every co-resident row is examined.
enum Classification {
    Add,
    AlreadyMatching(ObservedRoute),
    Replace(ObservedRoute),
    Conflict(&'static str),
}

fn classify(
    rows: &[ObservedRoute],
    desired: &ResolvedWindowsRoute,
    previous: Option<&RouteOwnership>,
) -> Classification {
    if rows.is_empty() {
        return Classification::Add;
    }

    let desired_count = rows
        .iter()
        .filter(|row| matches_desired(row, desired))
        .count();
    if desired_count > 1 {
        return Classification::Conflict("duplicate desired rows");
    }
    if desired_count == 1 {
        if rows.len() == 1 {
            return Classification::AlreadyMatching(rows[0].clone());
        }
        return Classification::Conflict("desired row coexists with a foreign row");
    }

    let Some(recorded) = previous
        .filter(|ownership| ownership.owned)
        .and_then(|ownership| ownership.observed.as_ref())
    else {
        return Classification::Conflict("foreign row on the key");
    };
    if rows.len() == 1 && rows[0].identity == recorded.identity {
        return Classification::Replace(rows[0].clone());
    }
    Classification::Conflict("neither desired nor the recorded owned row")
}

/// Exact Windows match: key, target kind, ifIndex, LUID, next hop, protocol,
/// metric and model scope.
fn matches_desired(row: &ObservedRoute, desired: &ResolvedWindowsRoute) -> bool {
    let target_matches = match (&row.target, &desired.intent.target) {
        (RouteTarget::Gateway(a), RouteTarget::Gateway(b)) => a == b,
        (RouteTarget::Device { .. }, RouteTarget::Device { .. }) => true,
        _ => false,
    };
    row.key == desired.intent.key
        && target_matches
        && row.identity.ifindex == desired.identity.ifindex
        && row.identity.interface_luid == desired.identity.interface_luid
        && row.identity.next_hop == desired.identity.next_hop
        && row.identity.protocol == desired.identity.protocol
        && row.identity.metric == desired.identity.metric
        && row.identity.scope == 0
}

fn conflict_error(intent: &RouteIntent, owner: &str) -> anyhow::Error {
    anyhow::anyhow!(super::backend::RouteConflict {
        prefix: format!(
            "{}/{}",
            intent.key.prefix.network, intent.key.prefix.prefix_len
        ),
        owner: owner.to_string(),
    })
}

#[async_trait]
impl RouteBackend for WindowsRouteBackend {
    async fn resolve_target(
        &self,
        zone: &crate::config::ZoneConfig,
        family: AddressFamily,
    ) -> Result<RouteTarget> {
        use crate::config::RouteType;
        match zone.route_type {
            RouteType::Dev => {
                let device = std::fs::read_to_string(&zone.route_target).map_err(|e| {
                    anyhow::anyhow!(
                        "Device file '{}' not found (VPN not connected?): {e}",
                        zone.route_target
                    )
                })?;
                let device = device.trim().to_string();
                if device.is_empty() {
                    bail!("Device file '{}' is empty", zone.route_target);
                }
                let identity = self.api.resolve_device(&device).await?;
                Ok(RouteTarget::Device {
                    name: device,
                    ifindex: Some(identity.index),
                })
            }
            RouteType::Via => {
                let gateway = zone.gateway_for(family)?.ok_or_else(|| {
                    anyhow::anyhow!("zone '{}': no gateway configured for {family:?}", zone.name)
                })?;
                Ok(RouteTarget::Gateway(gateway))
            }
        }
    }

    async fn ensure_route(
        &self,
        intent: &RouteIntent,
        previous: Option<&RouteOwnership>,
    ) -> Result<EnsureResult> {
        let desired = self.resolve_desired(intent).await?;
        let rows = self.read_key(&intent.key).await?;
        match classify(&rows, &desired, previous) {
            Classification::Add => self.add_desired(&desired, previous).await,
            Classification::AlreadyMatching(row) => {
                let owned = previous
                    .and_then(|ownership| ownership.observed.as_ref())
                    .map(|prev| prev.identity == row.identity)
                    .unwrap_or(false);
                Ok(EnsureResult {
                    outcome: EnsureOutcome::AlreadyMatching,
                    ownership: RouteOwnership {
                        owned,
                        observed: Some(row),
                    },
                })
            }
            Classification::Replace(previous_row) => self.replace(&desired, &previous_row).await,
            Classification::Conflict(reason) => Err(conflict_error(intent, reason)),
        }
    }

    async fn remove_route(
        &self,
        intent: &RouteIntent,
        ownership: Option<&RouteOwnership>,
    ) -> Result<()> {
        // §14.5/§49.5: no ownership or owned=false performs no kernel deletion.
        let Some(RouteOwnership {
            owned: true,
            observed: Some(observed),
        }) = ownership
        else {
            return Ok(());
        };
        self.api
            .delete_exact(&intent.key, &observed.identity)
            .await?;
        self.refresh().await?;
        Ok(())
    }

    async fn snapshot(&self) -> Result<Vec<ObservedRoute>> {
        self.refresh().await?;
        Ok(self.all_rows().await)
    }

    async fn observe_key(&self, key: &RouteKey) -> Result<Vec<ObservedRoute>> {
        // Targeted read from the coherent cache; may force one stable refresh
        // when an event invalidated it, never a per-request FIB walk.
        self.read_key(key).await
    }

    fn take_invalidation_receiver(&self) -> Option<mpsc::UnboundedReceiver<RouteInvalidation>> {
        self.rx.lock().unwrap().take()
    }

    fn reconcile_mode(&self) -> ReconcileMode {
        ReconcileMode::KernelSnapshot
    }

    fn cache_counters(&self) -> Option<super::backend::BackendCacheCounters> {
        Some(super::backend::BackendCacheCounters {
            full_refreshes: self.cache.full_refreshes.load(Ordering::SeqCst),
            cache_hits: self.cache.cache_hits.load(Ordering::SeqCst),
        })
    }
}

#[cfg(test)]
impl WindowsRouteBackend {
    pub(crate) fn counters(&self) -> CacheCounters {
        CacheCounters {
            full_refreshes: self.cache.full_refreshes.load(Ordering::SeqCst),
            cache_hits: self.cache.cache_hits.load(Ordering::SeqCst),
            ready: self.cache.ready.load(Ordering::SeqCst),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{RoutePrefix, RouteSource, RouteTarget};
    use super::super::windows_api::fake::FakeWindowsRouteApi;
    use super::super::windows_api::MAIN_TABLE;
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const LUID_A: u64 = 0x1000_0000_0000_0001;
    const LUID_B: u64 = 0x1000_0000_0000_0002;
    const IFINDEX_A: u32 = 7;
    const IFINDEX_B: u32 = 8;

    fn api() -> Arc<FakeWindowsRouteApi> {
        let api = Arc::new(FakeWindowsRouteApi::new());
        api.add_device("tun0", IFINDEX_A, LUID_A);
        api.add_device("tun1", IFINDEX_B, LUID_B);
        api.add_gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), IFINDEX_A, LUID_A);
        api
    }

    fn backend(api: &Arc<FakeWindowsRouteApi>) -> WindowsRouteBackend {
        let api: Arc<dyn WindowsRouteApi> = api.clone();
        WindowsRouteBackend::with_api(api).unwrap()
    }

    fn device_intent(last: u8) -> RouteIntent {
        RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 9, 0, last))),
                table: MAIN_TABLE,
            },
            zone: "test".to_string(),
            target: RouteTarget::Device {
                name: "tun0".to_string(),
                ifindex: Some(IFINDEX_A),
            },
            source: RouteSource::Dns,
        }
    }

    fn observed(
        intent: &RouteIntent,
        ifindex: u32,
        luid: u64,
        next_hop: Option<IpAddr>,
        protocol: u8,
        metric: u32,
    ) -> ObservedRoute {
        ObservedRoute {
            key: intent.key.clone(),
            target: intent.target.clone(),
            identity: RouteKernelIdentity {
                ifindex: Some(ifindex),
                next_hop,
                protocol,
                metric,
                scope: 0,
                interface_luid: Some(luid),
            },
        }
    }

    fn desired_row(intent: &RouteIntent) -> ObservedRoute {
        observed(intent, IFINDEX_A, LUID_A, None, 3, 0)
    }

    /// A5/§41.3: the observer registration must exist before the first
    /// snapshot, otherwise an event between snapshot and registration is lost.
    #[tokio::test]
    async fn observer_registration_precedes_the_first_snapshot() {
        let api = api();
        let backend = backend(&api);
        let calls = api.calls();
        assert_eq!(
            calls.first().map(String::as_str),
            Some("subscribe"),
            "subscribe must be the first API call: {calls:?}"
        );
        assert!(
            !calls.iter().any(|call| call.starts_with("dump:")),
            "no dump may happen before subscribe: {calls:?}"
        );
        backend.snapshot().await.unwrap();
        assert!(api.calls().iter().any(|call| call.starts_with("dump:")));
    }

    /// A4: an event that lands during the first dump forces a retry.
    #[tokio::test]
    async fn event_during_the_first_snapshot_retries() {
        let api = api();
        let backend = backend(&api);
        api.bump_generation_during_next_dump(2);
        backend.snapshot().await.unwrap();
        let counters = backend.counters();
        assert!(
            counters.full_refreshes >= 2,
            "a raced snapshot must be retried: {counters:?}"
        );
        assert!(counters.ready, "the cache must end current: {counters:?}");
    }

    /// A4: 1000 converged ensures perform zero extra full refreshes.
    #[tokio::test]
    async fn thousand_converged_ensures_keep_full_refresh_flat() {
        let api = api();
        let backend = backend(&api);
        let intent = device_intent(1);

        backend.ensure_route(&intent, None).await.unwrap();
        let after_first = backend.counters();
        assert_eq!(
            after_first.full_refreshes, 2,
            "the first mutation classifies against one refresh and proves with one more: {after_first:?}"
        );

        for _ in 0..1000 {
            backend.ensure_route(&intent, None).await.unwrap();
        }
        let after = backend.counters();
        assert_eq!(
            after.full_refreshes, after_first.full_refreshes,
            "a converged request must not scan the FIB: {after:?}"
        );
        assert!(
            after.cache_hits >= 1000,
            "every converged ensure must be a cache hit: {after:?}"
        );
        assert_eq!(api.rows().len(), 1);
    }

    /// A2/A5: same ifIndex with another LUID is foreign.
    #[tokio::test]
    async fn same_ifindex_with_a_different_luid_conflicts() {
        let api = api();
        let backend = backend(&api);
        let intent = device_intent(2);
        api.push_row(observed(&intent, IFINDEX_A, LUID_B, None, 3, 0));

        let error = backend
            .ensure_route(&intent, None)
            .await
            .expect_err("a different LUID must conflict");
        assert!(error.to_string().contains("already owned"), "{error}");
        assert_eq!(
            api.rows(),
            vec![observed(&intent, IFINDEX_A, LUID_B, None, 3, 0)]
        );
    }

    /// A5: every identity field participates in the exact match.
    #[tokio::test]
    async fn wrong_identity_fields_are_foreign() {
        let cases = [
            (
                "protocol",
                observed(&device_intent(3), IFINDEX_A, LUID_A, None, 4, 0),
            ),
            (
                "metric",
                observed(&device_intent(3), IFINDEX_A, LUID_A, None, 3, 7),
            ),
            (
                "next-hop",
                observed(
                    &device_intent(3),
                    IFINDEX_A,
                    LUID_A,
                    Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
                    3,
                    0,
                ),
            ),
            (
                "interface",
                observed(&device_intent(3), IFINDEX_B, LUID_B, None, 3, 0),
            ),
        ];

        for (label, foreign) in cases {
            let api = api();
            let backend = backend(&api);
            let intent = device_intent(3);
            api.push_row(foreign.clone());
            let error = backend
                .ensure_route(&intent, None)
                .await
                .expect_err("a foreign identity must conflict");
            assert!(
                error.to_string().contains("already owned"),
                "{label}: expected conflict, got {error}"
            );
            assert_eq!(api.rows(), vec![foreign], "{label}: row must survive");
        }
    }

    /// A5: a desired row co-resident with anything else is a conflict.
    #[tokio::test]
    async fn desired_with_a_co_resident_foreign_row_conflicts() {
        let api = api();
        let backend = backend(&api);
        let intent = device_intent(4);
        api.push_row(desired_row(&intent));
        api.push_row(observed(&intent, IFINDEX_B, LUID_B, None, 3, 0));

        let error = backend
            .ensure_route(&intent, None)
            .await
            .expect_err("co-resident foreign row must conflict");
        assert!(error.to_string().contains("already owned"), "{error}");
        assert_eq!(api.rows().len(), 2, "nothing may be deleted");
    }

    /// A5: duplicate desired rows are ambiguous.
    #[tokio::test]
    async fn duplicate_desired_rows_conflict() {
        let api = api();
        let backend = backend(&api);
        let intent = device_intent(5);
        let row = desired_row(&intent);
        api.push_row(row.clone());
        api.push_row(row);

        let error = backend
            .ensure_route(&intent, None)
            .await
            .expect_err("duplicate desired rows must conflict");
        assert!(error.to_string().contains("already owned"), "{error}");
        assert_eq!(api.rows().len(), 2);
    }

    /// A6: EEXIST with exactly the desired identity is a safe success and
    /// performs zero deletes.
    #[tokio::test]
    async fn eexist_exact_desired_is_safe_success_with_zero_delete() {
        let api = api();
        let backend = backend(&api);
        let intent = device_intent(6);
        let row = desired_row(&intent);
        api.script_already_exists(row.clone());

        let result = backend.ensure_route(&intent, None).await.unwrap();
        assert_eq!(result.outcome, EnsureOutcome::AlreadyMatching);
        assert!(
            !api.calls().iter().any(|call| call.starts_with("delete:")),
            "{:?}",
            api.calls()
        );
        assert_eq!(api.rows(), vec![row]);
    }

    /// A6: EEXIST with a foreign row conflicts and performs zero deletes.
    #[tokio::test]
    async fn eexist_foreign_row_conflicts_with_zero_delete() {
        let api = api();
        let backend = backend(&api);
        let intent = device_intent(7);
        let foreign = observed(&intent, IFINDEX_B, LUID_B, None, 3, 0);
        api.script_already_exists(foreign.clone());

        let error = backend
            .ensure_route(&intent, None)
            .await
            .expect_err("EEXIST with a foreign row must conflict");
        assert!(error.to_string().contains("already owned"), "{error}");
        assert!(
            !api.calls().iter().any(|call| call.starts_with("delete:")),
            "{:?}",
            api.calls()
        );
        assert_eq!(api.rows(), vec![foreign]);
    }

    /// A6: replacement creates and proves Desired before deleting the exact
    /// previous owned row.
    #[tokio::test]
    async fn replacement_creates_and_proves_before_deleting_the_previous_row() {
        let api = api();
        let backend = backend(&api);
        let intent = device_intent(8);
        let previous = observed(&intent, IFINDEX_B, LUID_B, None, 3, 0);
        api.push_row(previous.clone());

        // The new desired row targets tun0 (LUID_A).
        let previous_ownership = RouteOwnership {
            owned: true,
            observed: Some(previous.clone()),
        };

        let result = backend
            .ensure_route(&intent, Some(&previous_ownership))
            .await
            .unwrap();
        assert_eq!(result.outcome, EnsureOutcome::Added);
        assert!(result.ownership.owned);

        let calls = api.calls();
        let create_at = calls.iter().position(|c| c == "create").expect("create");
        let delete_at = calls
            .iter()
            .position(|c| c.starts_with("delete:"))
            .expect("delete");
        assert!(
            create_at < delete_at,
            "replacement must create/prove before deleting: {calls:?}"
        );
        assert_eq!(api.rows(), vec![desired_row(&intent)]);
    }

    /// A6: if the create succeeds but the proof fails, the previous owned row
    /// is still there and only our own created row is rolled back.
    #[tokio::test]
    async fn failed_replacement_proof_keeps_the_previous_owned_row() {
        let api = api();
        let backend = backend(&api);
        let intent = device_intent(9);
        let previous = observed(&intent, IFINDEX_B, LUID_B, None, 3, 0);
        api.push_row(previous.clone());

        // The create reports success but inserts a row with a wrong metric.
        api.script_corrupt_create(observed(&intent, IFINDEX_A, LUID_A, None, 3, 99));

        let previous_ownership = RouteOwnership {
            owned: true,
            observed: Some(previous.clone()),
        };
        let error = backend
            .ensure_route(&intent, Some(&previous_ownership))
            .await
            .expect_err("an unprovable create must fail closed");
        assert!(error.to_string().contains("already owned"), "{error}");

        let rows = api.rows();
        assert!(
            rows.iter().any(|row| row.identity == previous.identity),
            "the previous owned row must survive a failed replacement: {rows:?}"
        );
        assert!(
            !rows.iter().any(|row| row.identity.metric == 99),
            "our own unprovable row must be rolled back: {rows:?}"
        );
    }

    /// A7: deleting with a different live identity is a no-op.
    #[tokio::test]
    async fn remove_route_never_deletes_a_foreign_identity() {
        let api = api();
        let backend = backend(&api);
        let intent = device_intent(10);
        let foreign = observed(&intent, IFINDEX_B, LUID_B, None, 3, 0);
        api.push_row(foreign.clone());

        let recorded = RouteOwnership {
            owned: true,
            observed: Some(observed(&intent, IFINDEX_A, LUID_A, None, 3, 0)),
        };
        backend
            .remove_route(&intent, Some(&recorded))
            .await
            .unwrap();
        assert_eq!(api.rows(), vec![foreign], "the foreign row must survive");
    }

    /// A2: a gateway of another family is refused by the backend, not only by
    /// config validation.
    #[tokio::test]
    async fn gateway_of_another_family_is_rejected() {
        let api = api();
        let backend = backend(&api);
        let intent = RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                table: MAIN_TABLE,
            },
            zone: "test".to_string(),
            target: RouteTarget::Gateway(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            source: RouteSource::Dns,
        };
        let error = backend
            .ensure_route(&intent, None)
            .await
            .expect_err("a v6 gateway on a v4 prefix must be refused");
        assert!(error.to_string().contains("another family"), "{error}");
        assert!(
            !api.calls().iter().any(|call| call.starts_with("create")),
            "no kernel mutation may happen: {:?}",
            api.calls()
        );
    }
}
