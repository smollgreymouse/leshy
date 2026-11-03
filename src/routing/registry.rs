//! Unified route registry — desired/observed state with per-key serialization.
//!
//! The registry is the single source of truth for which routes Leshy wants in
//! the kernel.  It deduplicates concurrent DNS queries for the same prefix,
//! coalesces them into a single kernel write, and provides a fast path that
//! skips all I/O when a verified entry is still current.
//!
//! Capacity is bounded by `max_dynamic_routes`; when the limit is reached a
//! new unique intent is denied (fail-closed) rather than silently growing
//! the FIB.
//
// The route manager wires this registry into the DNS path in the next step of
// the rollout; until then it is exercised only by its own tests.
#![allow(dead_code)]

use crate::routing::backend::{EnsureOutcome, RouteBackend, RouteInvalidation};
use crate::routing::model::*;
use anyhow::{bail, Result};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

// ---------------------------------------------------------------------------
// Internal entry
// ---------------------------------------------------------------------------

/// State of a single route key in the registry.
struct RouteEntry {
    /// The most recent desired intent for this key.
    desired: Option<RouteIntent>,
    /// The last observed kernel route (from a snapshot).
    observed: Option<ObservedRoute>,
    /// Current state of this entry.
    state: RouteState,
    /// Epoch of the last dirty marking.
    dirty_epoch: u64,
    /// Epoch when this entry was last verified against the kernel.
    verified_epoch: u64,
    /// Last error message, if any.
    last_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Unified route registry.
///
/// Two-level locking: the map lock is held only while finding/inserting an
/// `Arc<Mutex<RouteEntry>>`.  The per-entry mutex may span one backend await,
/// deliberately coalescing concurrent DNS requests for the same route while
/// allowing different prefixes to proceed concurrently.
pub(crate) struct RouteRegistry {
    entries: RwLock<HashMap<RouteKey, Arc<Mutex<RouteEntry>>>>,
    max_dynamic_routes: usize,
    /// Atomic counter for dynamic (DNS-sourced) intents.
    dynamic_count: AtomicU64,
}

impl RouteRegistry {
    /// Create a new registry with the given capacity.
    pub(crate) fn new(max_dynamic_routes: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_dynamic_routes,
            dynamic_count: AtomicU64::new(0),
        }
    }

    /// Ensure a route intent is satisfied.
    ///
    /// Fast path: if the entry is Verified with a matching intent and the
    /// kernel epoch hasn't changed since verification, return
    /// `AlreadyMatching` without any backend I/O.
    pub(crate) async fn ensure(
        &self,
        intent: RouteIntent,
        backend: &dyn RouteBackend,
        kernel_epoch: u64,
    ) -> Result<EnsureOutcome> {
        let key = intent.key.clone();

        // Find or create the entry. Capacity is enforced only for a genuinely
        // new dynamic key: refreshing an existing intent must always be
        // allowed, otherwise a full registry would stop reconciling routes it
        // already owns.
        let entry = {
            let mut map = self.entries.write().await;
            match map.get(&key) {
                Some(entry) => Arc::clone(entry),
                None => {
                    if intent.source == RouteSource::Dns
                        && self.dynamic_count.load(Ordering::SeqCst)
                            >= self.max_dynamic_routes as u64
                    {
                        bail!(RouteError::CapacityExceeded);
                    }
                    let entry = Arc::new(Mutex::new(RouteEntry {
                        desired: None,
                        observed: None,
                        state: RouteState::Pending,
                        dirty_epoch: 0,
                        verified_epoch: 0,
                        last_error: None,
                    }));
                    map.insert(key.clone(), Arc::clone(&entry));
                    if intent.source == RouteSource::Dns {
                        self.dynamic_count.fetch_add(1, Ordering::SeqCst);
                    }
                    entry
                }
            }
        };

        // Lock the entry and do the work.
        let mut locked = entry.lock().await;

        // Fast path: verified and still current.
        if locked.state == RouteState::Verified
            && locked.verified_epoch == kernel_epoch
            && locked.desired.as_ref() == Some(&intent)
        {
            return Ok(EnsureOutcome::AlreadyMatching);
        }

        // Update desired state.
        locked.desired = Some(intent.clone());

        // Call the backend.
        let outcome = match backend.ensure_route(&intent).await {
            Ok(o) => o,
            Err(e) => {
                locked.state = RouteState::Error;
                locked.last_error = Some(e.to_string());
                bail!(RouteError::Apply(e));
            }
        };

        // Only mark Verified on success.
        locked.state = RouteState::Verified;
        locked.verified_epoch = kernel_epoch;
        locked.last_error = None;

        Ok(outcome)
    }

    /// Mark entries dirty based on an invalidation signal.
    pub(crate) async fn mark_dirty(&self, invalidation: RouteInvalidation, epoch: u64) {
        let mut map = self.entries.write().await;
        match invalidation {
            RouteInvalidation::Full => {
                for entry in map.values_mut() {
                    let mut locked = entry.lock().await;
                    if locked.desired.is_some() {
                        locked.state = RouteState::Dirty;
                        locked.dirty_epoch = epoch;
                    }
                }
            }
            RouteInvalidation::Interface(ifindex) => {
                for entry in map.values_mut() {
                    let mut locked = entry.lock().await;
                    if let Some(ref intent) = locked.desired {
                        if let RouteTarget::Device {
                            ifindex: Some(idx), ..
                        } = &intent.target
                        {
                            if *idx == ifindex {
                                locked.state = RouteState::Dirty;
                                locked.dirty_epoch = epoch;
                            }
                        }
                    }
                }
            }
            RouteInvalidation::Prefix(key) => {
                if let Some(entry) = map.get_mut(&key) {
                    let mut locked = entry.lock().await;
                    if locked.desired.is_some() {
                        locked.state = RouteState::Dirty;
                        locked.dirty_epoch = epoch;
                    }
                }
            }
        }
    }

    /// Reconcile dirty entries against a fresh snapshot.
    pub(crate) async fn reconcile_dirty(
        &self,
        backend: &dyn RouteBackend,
        snapshot: &[ObservedRoute],
        epoch: u64,
    ) -> ReconcileReport {
        let snapshot_keys: HashSet<&RouteKey> = snapshot.iter().map(|r| &r.key).collect();
        let mut adds = 0usize;
        let removes = 0usize;
        let mut noops = 0usize;

        let map = self.entries.read().await;
        for (key, entry) in map.iter() {
            let mut locked = entry.lock().await;
            if locked.state != RouteState::Dirty || locked.desired.is_none() {
                continue;
            }

            let intent = locked.desired.clone().unwrap();

            // Check if the route still exists in the snapshot.
            let still_exists = snapshot_keys.contains(key);
            let target_matches = still_exists
                && snapshot
                    .iter()
                    .any(|r| r.key == *key && r.target == intent.target);

            if target_matches {
                locked.state = RouteState::Verified;
                locked.verified_epoch = epoch;
                locked.dirty_epoch = epoch;
                noops += 1;
            } else {
                // Re-apply the route.
                match backend.ensure_route(&intent).await {
                    Ok(EnsureOutcome::Added) => {
                        locked.state = RouteState::Verified;
                        locked.verified_epoch = epoch;
                        locked.dirty_epoch = epoch;
                        adds += 1;
                    }
                    Ok(EnsureOutcome::AlreadyMatching) => {
                        locked.state = RouteState::Verified;
                        locked.verified_epoch = epoch;
                        locked.dirty_epoch = epoch;
                        noops += 1;
                    }
                    Err(_) => {
                        locked.state = RouteState::Error;
                    }
                }
            }
        }
        drop(map);

        ReconcileReport {
            adds,
            removes,
            noops,
        }
    }

    /// Remove all routes owned by a zone.
    pub(crate) async fn remove_zone(
        &self,
        zone: &str,
        backend: &dyn RouteBackend,
    ) -> ZoneRemovalReport {
        let mut map = self.entries.write().await;
        let mut to_remove = Vec::new();
        for (key, entry) in map.iter() {
            if let Some(ref intent) = entry.lock().await.desired {
                if intent.zone == zone {
                    to_remove.push((key.clone(), intent.clone()));
                }
            }
        }

        let mut removed = 0usize;
        let mut errors = 0usize;
        for (key, intent) in to_remove {
            match backend.remove_route(&intent).await {
                Ok(()) => {
                    map.remove(&key);
                    removed += 1;
                    if intent.source == RouteSource::Dns {
                        self.dynamic_count.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                Err(_) => {
                    errors += 1;
                }
            }
        }

        ZoneRemovalReport { removed, errors }
    }

    /// Count dynamic (DNS-sourced) intents in the registry.
    pub(crate) async fn count_dynamic(&self) -> u64 {
        self.dynamic_count.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

/// Result of a reconcile_dirty call.
pub struct ReconcileReport {
    pub adds: usize,
    pub removes: usize,
    pub noops: usize,
}

/// Result of a remove_zone call.
pub struct ZoneRemovalReport {
    pub removed: usize,
    pub errors: usize,
}

/// Typed routing errors for the DNS handler.
#[derive(Debug)]
pub enum RouteError {
    Apply(anyhow::Error),
    CapacityExceeded,
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteError::Apply(e) => write!(f, "route apply: {e}"),
            RouteError::CapacityExceeded => write!(f, "route capacity exceeded"),
        }
    }
}

impl std::error::Error for RouteError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::backend::fake::{host_intent_v4, FakeBackend};
    use crate::routing::backend::EnsureOutcome;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_registry(max: usize) -> RouteRegistry {
        RouteRegistry::new(max)
    }

    fn make_backend() -> FakeBackend {
        FakeBackend::new()
    }

    #[tokio::test]
    async fn first_ensure_adds() {
        let reg = make_registry(100);
        let backend = make_backend();
        let intent = host_intent_v4(10, 0, 0, 1, "corp");
        let outcome = reg.ensure(intent, &backend, 1).await.unwrap();
        assert_eq!(outcome, EnsureOutcome::Added);
        assert_eq!(backend.ensure_count(), 1);
    }

    #[tokio::test]
    async fn duplicate_same_epoch_is_fast_path() {
        let reg = make_registry(100);
        let backend = make_backend();
        let intent = host_intent_v4(10, 0, 0, 1, "corp");

        // First call — adds.
        let outcome = reg.ensure(intent.clone(), &backend, 1).await.unwrap();
        assert_eq!(outcome, EnsureOutcome::Added);
        assert_eq!(backend.ensure_count(), 1);

        // Second call, same epoch — fast path.
        let outcome = reg.ensure(intent, &backend, 1).await.unwrap();
        assert_eq!(outcome, EnsureOutcome::AlreadyMatching);
        assert_eq!(backend.ensure_count(), 1); // no extra call
    }

    #[tokio::test]
    async fn thousand_duplicates_one_mutation() {
        let reg = make_registry(100);
        let backend = make_backend();
        let intent = host_intent_v4(10, 0, 0, 1, "corp");

        for _ in 0..1000 {
            let _ = reg.ensure(intent.clone(), &backend, 1).await.unwrap();
        }
        assert_eq!(backend.ensure_count(), 1);
    }

    #[tokio::test]
    async fn different_keys_proceed_independently() {
        let reg = make_registry(100);
        let backend = make_backend();

        let i1 = host_intent_v4(10, 0, 0, 1, "corp");
        let i2 = host_intent_v4(10, 0, 0, 2, "corp");

        let _ = reg.ensure(i1, &backend, 1).await.unwrap();
        let _ = reg.ensure(i2, &backend, 1).await.unwrap();

        assert_eq!(backend.ensure_count(), 2);
    }

    #[tokio::test]
    async fn failed_add_never_becomes_verified() {
        let reg = make_registry(100);
        let backend = make_backend();
        backend.set_outcome(Err(anyhow::anyhow!("netlink EPERM")));

        let intent = host_intent_v4(10, 0, 0, 1, "corp");
        let result = reg.ensure(intent, &backend, 1).await;
        assert!(result.is_err());

        // The entry should be in Error state, not Verified.
        let map = reg.entries.read().await;
        let entry = map.get(&RouteKey {
            prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            table: 254,
        });
        assert!(entry.is_some());
        let locked = entry.unwrap().lock().await;
        assert_eq!(locked.state, RouteState::Error);
    }

    #[tokio::test]
    async fn capacity_boundary() {
        let reg = make_registry(2);
        let backend = make_backend();

        let i1 = host_intent_v4(10, 0, 0, 1, "corp");
        let i2 = host_intent_v4(10, 0, 0, 2, "corp");
        let i3 = host_intent_v4(10, 0, 0, 3, "corp");

        let _ = reg.ensure(i1, &backend, 1).await.unwrap();
        let _ = reg.ensure(i2, &backend, 1).await.unwrap();

        // Third unique intent should fail.
        let result = reg.ensure(i3, &backend, 1).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("capacity"));
    }

    #[tokio::test]
    async fn capacity_does_not_block_refresh() {
        let reg = make_registry(1);
        let backend = make_backend();

        let i1 = host_intent_v4(10, 0, 0, 1, "corp");
        let _ = reg.ensure(i1.clone(), &backend, 1).await.unwrap();

        // Refreshing the same intent should succeed even at capacity.
        let _ = reg.ensure(i1, &backend, 1).await.unwrap();
    }

    #[tokio::test]
    async fn mark_dirty_full() {
        let reg = make_registry(100);
        let backend = make_backend();
        let intent = host_intent_v4(10, 0, 0, 1, "corp");
        let _ = reg.ensure(intent, &backend, 1).await.unwrap();

        // Invalidate everything.
        reg.mark_dirty(RouteInvalidation::Full, 2).await;

        let map = reg.entries.read().await;
        let entry = map.values().next().unwrap();
        let locked = entry.lock().await;
        assert_eq!(locked.state, RouteState::Dirty);
    }

    #[tokio::test]
    async fn mark_dirty_prefix() {
        let reg = make_registry(100);
        let backend = make_backend();
        let i1 = host_intent_v4(10, 0, 0, 1, "corp");
        let i2 = host_intent_v4(10, 0, 0, 2, "corp");
        let k2 = i2.key.clone();
        let _ = reg.ensure(i1.clone(), &backend, 1).await.unwrap();
        let _ = reg.ensure(i2, &backend, 1).await.unwrap();

        // Invalidate only i1.
        reg.mark_dirty(RouteInvalidation::Prefix(i1.key.clone()), 2)
            .await;

        let map = reg.entries.read().await;
        let e1 = map.get(&i1.key).unwrap();
        let locked = e1.lock().await;
        assert_eq!(locked.state, RouteState::Dirty);
        drop(locked);

        let e2 = map.get(&k2).unwrap();
        let locked = e2.lock().await;
        assert_eq!(locked.state, RouteState::Verified);
    }

    #[tokio::test]
    async fn remove_zone_deletes_owned_entries() {
        let reg = make_registry(100);
        let backend = make_backend();
        let i1 = host_intent_v4(10, 0, 0, 1, "corp");
        let i2 = host_intent_v4(10, 0, 0, 2, "corp");
        let i3 = host_intent_v4(10, 0, 0, 3, "other");
        let _ = reg.ensure(i1, &backend, 1).await.unwrap();
        let _ = reg.ensure(i2, &backend, 1).await.unwrap();
        let _ = reg.ensure(i3, &backend, 1).await.unwrap();

        let report = reg.remove_zone("corp", &backend).await;
        assert_eq!(report.removed, 2);
        assert_eq!(report.errors, 0);
        assert_eq!(backend.remove_count(), 2);

        // "other" should still be there.
        let count = reg.count_dynamic().await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn reconcile_dirty_restores_missing_route() {
        let reg = make_registry(100);
        let backend = make_backend();
        let intent = host_intent_v4(10, 0, 0, 1, "corp");
        let _ = reg.ensure(intent.clone(), &backend, 1).await.unwrap();

        // Mark dirty.
        reg.mark_dirty(RouteInvalidation::Full, 2).await;

        // Reconcile with empty snapshot — route is missing, should re-add.
        let report = reg.reconcile_dirty(&backend, &[], 2).await;
        assert_eq!(report.adds, 1);
        assert_eq!(backend.ensure_count(), 2);
    }

    #[tokio::test]
    async fn reconcile_dirty_skips_existing_route() {
        let reg = make_registry(100);
        let backend = make_backend();
        let intent = host_intent_v4(10, 0, 0, 1, "corp");
        let _ = reg.ensure(intent.clone(), &backend, 1).await.unwrap();

        // Mark dirty.
        reg.mark_dirty(RouteInvalidation::Full, 2).await;

        // Reconcile with a matching snapshot — no-op.
        let observed = ObservedRoute {
            key: intent.key.clone(),
            target: intent.target.clone(),
            protocol: 0,
            metric: 0,
        };
        let report = reg.reconcile_dirty(&backend, &[observed], 2).await;
        assert_eq!(report.noops, 1);
        assert_eq!(report.adds, 0);
        assert_eq!(backend.ensure_count(), 1); // no extra call
    }

    #[tokio::test]
    async fn concurrent_same_key_coalesces() {
        let reg = Arc::new(make_registry(100));
        let backend = Arc::new(make_backend());
        let intent = host_intent_v4(10, 0, 0, 1, "corp");

        let mut handles = Vec::new();
        for _ in 0..100 {
            let reg = Arc::clone(&reg);
            let backend = Arc::clone(&backend);
            let intent = intent.clone();
            handles.push(tokio::spawn(async move {
                reg.ensure(intent, backend.as_ref(), 1).await
            }));
        }

        for h in handles {
            h.await.unwrap().unwrap();
        }

        // All 100 concurrent calls should have coalesced to 1 mutation.
        assert_eq!(backend.ensure_count(), 1);
    }

    #[tokio::test]
    async fn static_routes_dont_count_toward_capacity() {
        let reg = make_registry(1);
        let backend = make_backend();

        // Static route — doesn't count.
        let static_intent = RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                table: 254,
            },
            zone: "static".to_string(),
            target: RouteTarget::Gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            source: RouteSource::Static,
        };
        let _ = reg.ensure(static_intent, &backend, 1).await.unwrap();

        // DNS intent — should succeed (capacity is 1, static doesn't count).
        let dns_intent = host_intent_v4(10, 0, 0, 2, "corp");
        let _ = reg.ensure(dns_intent, &backend, 1).await.unwrap();

        // Another DNS intent — should fail.
        let dns_intent2 = host_intent_v4(10, 0, 0, 3, "corp");
        let result = reg.ensure(dns_intent2, &backend, 1).await;
        assert!(result.is_err());
    }
}
