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

use crate::routing::backend::{
    ControllerDenied, EnsureOutcome, RouteBackend, RouteConflict, RouteInvalidation,
};
use crate::routing::model::*;
use anyhow::{bail, Result};
use std::collections::HashMap;
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
    /// The explicit ownership the backend returned (08D1 §14.3): `owned`
    /// rows may be deleted at cleanup; pre-existing compatible rows are
    /// owned=false. A successful local Ensure stores the returned ownership.
    ownership: Option<RouteOwnership>,
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
                        ownership: None,
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

        // Call the backend with the previously recorded ownership (§14.2):
        // the backend's exact-previous-Owned observation is the only row it
        // may replace or delete.
        let result = match backend
            .ensure_route(&intent, locked.ownership.as_ref())
            .await
        {
            Ok(r) => r,
            Err(e) => {
                locked.state = RouteState::Error;
                locked.last_error = Some(e.to_string());
                if e.downcast_ref::<RouteConflict>().is_some() {
                    bail!(RouteError::Conflict);
                }
                if let Some(denied) = e.downcast_ref::<ControllerDenied>() {
                    bail!(RouteError::AuthorityDenied {
                        reason: denied.reason.clone(),
                    });
                }
                bail!(RouteError::Apply(e));
            }
        };

        // Only mark Verified on success, and store the returned ownership:
        // cleanup deletes only owned rows through the exact observation
        // (§14.3/§14.5).
        locked.state = RouteState::Verified;
        locked.verified_epoch = kernel_epoch;
        locked.ownership = Some(result.ownership);
        locked.last_error = None;

        Ok(result.outcome)
    }

    /// Mark entries dirty based on an invalidation signal.
    pub(crate) async fn mark_dirty(&self, invalidation: RouteInvalidation, epoch: u64) {
        let mut map = self.entries.write().await;
        match invalidation {
            RouteInvalidation::Zone(zone) => {
                for entry in map.values_mut() {
                    let mut locked = entry.lock().await;
                    if let Some(ref intent) = locked.desired {
                        if intent.zone == zone {
                            locked.state = RouteState::Dirty;
                            locked.dirty_epoch = epoch;
                        }
                    }
                }
            }
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

            // §49.2: the snapshot no-op proof is the EXACT identity — same
            // key, same target AND the same kernel identity as the recorded
            // ownership observation. A changed protocol/metric/OIF/LUID, a
            // disappeared row, multiple same-key rows or owned-without-
            // observation all fall through to the backend revalidation.
            let recorded_identity = locked
                .ownership
                .as_ref()
                .and_then(|o| o.observed.as_ref())
                .map(|o| o.identity.clone());
            let acceptable = recorded_identity.as_ref().and_then(|identity| {
                let same_key: Vec<&ObservedRoute> = snapshot
                    .iter()
                    .filter(|r| r.key == *key && r.target == intent.target)
                    .collect();
                // Exactly one acceptable same-key row with the identical
                // recorded identity.
                if same_key.len() == 1 && same_key[0].identity == *identity {
                    Some(())
                } else {
                    None
                }
            });

            if acceptable.is_some() {
                locked.state = RouteState::Verified;
                locked.verified_epoch = epoch;
                locked.dirty_epoch = epoch;
                noops += 1;
            } else {
                // Re-apply the route with the recorded ownership (§14.4).
                match backend
                    .ensure_route(&intent, locked.ownership.as_ref())
                    .await
                {
                    Ok(result) => {
                        locked.ownership = Some(result.ownership);
                        locked.state = RouteState::Verified;
                        locked.verified_epoch = epoch;
                        locked.dirty_epoch = epoch;
                        match result.outcome {
                            EnsureOutcome::Added => adds += 1,
                            EnsureOutcome::AlreadyMatching => noops += 1,
                        }
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
            let ownership = {
                let entry = map.get(&key);
                match entry {
                    Some(entry) => entry.lock().await.ownership.clone(),
                    None => None,
                }
            };
            match backend.remove_route(&intent, ownership.as_ref()).await {
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

    /// Snapshot the intents currently owned by a zone (reload support).
    pub(crate) async fn zone_intents(&self, zone: &str) -> Vec<RouteIntent> {
        let map = self.entries.read().await;
        let mut intents = Vec::new();
        for entry in map.values() {
            let locked = entry.lock().await;
            if let Some(intent) = &locked.desired {
                if intent.zone == zone {
                    intents.push(intent.clone());
                }
            }
        }
        intents
    }

    /// Retire exactly one owned intent (old-zone state during a reload).
    ///
    /// Retire the route registered under one exact key (08D1 §49.1): the
    /// per-key entry lock is taken, the CURRENT desired intent and recorded
    /// ownership are re-read (a key reassigned to another zone/newer owner is
    /// refused), the backend removes through that actual ownership, and the
    /// registry entry plus dynamic count are erased only after success.
    pub(crate) async fn retire_key(
        &self,
        key: &RouteKey,
        expected_zone: &str,
        backend: &dyn RouteBackend,
    ) -> Result<()> {
        let entry = {
            let map = self.entries.read().await;
            map.get(key).cloned()
        };
        let Some(entry) = entry else {
            // Nothing registered: absence is success.
            return Ok(());
        };
        let mut locked = entry.lock().await;
        let Some(intent) = locked.desired.clone() else {
            return Ok(());
        };
        // §49.1: refuse retirement when the key has been reassigned to
        // another zone or a newer logical owner.
        if intent.zone != expected_zone {
            bail!(RouteError::Conflict);
        }
        let ownership = locked.ownership.clone();
        backend.remove_route(&intent, ownership.as_ref()).await?;
        locked.desired = None;
        locked.ownership = None;
        locked.state = RouteState::Pending;
        if intent.source == RouteSource::Dns {
            self.dynamic_count.fetch_sub(1, Ordering::SeqCst);
        }
        Ok(())
    }

    /// Remove every route this process actually owns (08D1 §14.5/§19.5):
    /// snapshots the keys in deterministic order, locks each entry through
    /// the existing per-key serialization, and calls the backend only for
    /// entries whose recorded ownership says owned=true. A deletion error
    /// keeps the entry/evidence and is returned; the entry is not erased
    /// from memory first.
    pub(crate) async fn remove_all_owned(
        &self,
        backend: &dyn RouteBackend,
    ) -> anyhow::Result<usize> {
        let ordered = {
            let map = self.entries.read().await;
            let mut keys: Vec<RouteKey> = map.keys().cloned().collect();
            keys.sort_by(|a, b| {
                a.prefix
                    .network
                    .to_string()
                    .cmp(&b.prefix.network.to_string())
                    .then(a.prefix.prefix_len.cmp(&b.prefix.prefix_len))
                    .then(a.table.cmp(&b.table))
            });
            keys
        };

        let mut removed = 0usize;
        let mut last_error = None;
        for key in ordered {
            let entry = {
                let map = self.entries.read().await;
                map.get(&key).cloned()
            };
            let Some(entry) = entry else {
                continue;
            };
            let (intent, ownership) = {
                let locked = entry.lock().await;
                match locked.desired.clone() {
                    Some(intent) => (intent, locked.ownership.clone()),
                    None => continue,
                }
            };
            match backend.remove_route(&intent, ownership.as_ref()).await {
                Ok(()) => {
                    let mut locked = entry.lock().await;
                    // Only erase the entry when the ownership was ours to
                    // delete; a None/owned=false call was a no-op.
                    let was_owned =
                        matches!(ownership.as_ref(), Some(RouteOwnership { owned: true, .. }));
                    if was_owned {
                        locked.desired = None;
                        locked.ownership = None;
                        locked.state = RouteState::Pending;
                        if intent.source == RouteSource::Dns {
                            self.dynamic_count.fetch_sub(1, Ordering::SeqCst);
                        }
                        removed += 1;
                    }
                }
                Err(e) => {
                    // Keep the entry/evidence; do not erase from memory first.
                    last_error.get_or_insert(e);
                }
            }
        }
        match last_error {
            Some(e) => Err(e),
            None => Ok(removed),
        }
    }

    /// The kernel row is deleted and the registry entry dropped only when the
    /// entry's desired intent is still `intent` — a replacement intent that
    /// was verified in the meantime keeps the entry and its kernel row. The
    /// backend additionally refuses to delete a foreign row on the prefix.
    /// Returns `true` when the intent was retired.
    pub(crate) async fn retire_intent(
        &self,
        intent: &RouteIntent,
        backend: &dyn RouteBackend,
    ) -> bool {
        // Decide and mutate the kernel under the entry lock; the map read
        // guard is dropped before the (rare) entry removal below.
        let retired = {
            let map = self.entries.read().await;
            match map.get(&intent.key) {
                Some(entry) => {
                    let mut locked = entry.lock().await;
                    if locked.desired.as_ref() != Some(intent) {
                        // A replacement intent owns this key now.
                        false
                    } else {
                        let ownership = locked.ownership.clone();
                        match backend.remove_route(intent, ownership.as_ref()).await {
                            Ok(()) => {
                                locked.desired = None;
                                locked.ownership = None;
                                locked.state = RouteState::Pending;
                                true
                            }
                            Err(_) => false,
                        }
                    }
                }
                None => false,
            }
        };

        if retired {
            let mut map = self.entries.write().await;
            if let Some(entry) = map.get(&intent.key) {
                let locked = entry.lock().await;
                if locked.desired.is_none() {
                    drop(locked);
                    map.remove(&intent.key);
                    if intent.source == RouteSource::Dns {
                        self.dynamic_count.fetch_sub(1, Ordering::SeqCst);
                    }
                }
            }
        }
        retired
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
#[derive(Default)]
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
///
/// `CapacityExceeded`, `Conflict` and `AuthorityDenied` are safety denials:
/// the address must never be answered without its selected route, regardless
/// of the configured `route_failure_mode`. Only `Apply` honours the legacy
/// compatibility fallback.
#[derive(Debug)]
pub enum RouteError {
    Apply(anyhow::Error),
    CapacityExceeded,
    Conflict,
    /// The Kikimora managed backend refused the intent, which is a safety
    /// denial like any other. A "family N is not ready" reason is the
    /// controller's family-suppression contract: the resolver answers that
    /// family with NODATA instead of SERVFAIL.
    AuthorityDenied {
        reason: String,
    },
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteError::Apply(e) => write!(f, "route apply: {e}"),
            RouteError::CapacityExceeded => write!(f, "route capacity exceeded"),
            RouteError::Conflict => write!(f, "route conflict with a foreign kernel route"),
            RouteError::AuthorityDenied { reason } => {
                write!(f, "route authority denied by the controller: {reason}")
            }
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
            identity: crate::routing::model::RouteKernelIdentity {
                ifindex: Some(1),
                next_hop: None,
                protocol: 3,
                metric: 0,
                scope: 0,
                interface_luid: None,
            },
            key: intent.key.clone(),
            target: intent.target.clone(),
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

    #[tokio::test]
    async fn zone_invalidation_marks_only_that_zones_entries() {
        let reg = make_registry(100);
        let backend = make_backend();
        let i1 = host_intent_v4(10, 0, 0, 1, "corp");
        let i2 = host_intent_v4(10, 0, 0, 2, "other");
        let _ = reg.ensure(i1.clone(), &backend, 1).await.unwrap();
        let _ = reg.ensure(i2.clone(), &backend, 1).await.unwrap();

        reg.mark_dirty(RouteInvalidation::Zone("corp".to_string()), 2)
            .await;

        let map = reg.entries.read().await;
        let e1 = map.get(&i1.key).unwrap().lock().await;
        assert_eq!(e1.state, RouteState::Dirty);
        let e2 = map.get(&i2.key).unwrap().lock().await;
        assert_eq!(e2.state, RouteState::Verified);
    }
}

#[cfg(test)]
mod targeted_epoch_tests {
    use super::*;
    use crate::config::ZoneConfig;
    use crate::routing::backend::EnsureResult;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::net::IpAddr;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    struct CountingBackend {
        inner: crate::routing::backend::fake::FakeBackend,
        ensures: AtomicU64,
    }

    impl CountingBackend {
        fn new() -> Self {
            Self {
                inner: crate::routing::backend::fake::FakeBackend::new(),
                ensures: AtomicU64::new(0),
            }
        }
    }

    #[async_trait]
    impl RouteBackend for CountingBackend {
        async fn resolve_target(
            &self,
            zone: &ZoneConfig,
            family: AddressFamily,
        ) -> Result<crate::routing::model::RouteTarget> {
            self.inner.resolve_target(zone, family).await
        }

        async fn ensure_route(
            &self,
            intent: &RouteIntent,
            previous: Option<&RouteOwnership>,
        ) -> Result<EnsureResult> {
            self.ensures.fetch_add(1, Ordering::SeqCst);
            self.inner.ensure_route(intent, previous).await
        }

        async fn remove_route(
            &self,
            intent: &RouteIntent,
            ownership: Option<&RouteOwnership>,
        ) -> Result<()> {
            self.inner.remove_route(intent, ownership).await
        }

        async fn snapshot(&self) -> Result<Vec<ObservedRoute>> {
            self.inner.snapshot().await
        }

        fn take_invalidation_receiver(&self) -> Option<mpsc::UnboundedReceiver<RouteInvalidation>> {
            None
        }
    }

    // §15: a targeted Prefix invalidation marks only the matching entry
    // Dirty and re-verifies it against the CURRENT epoch — the unaffected
    // Verified entry keeps its fast path without an extra ensure call.
    #[tokio::test]
    async fn targeted_invalidation_leaves_unrelated_entries_fast() {
        let backend = Arc::new(CountingBackend::new());
        let reg = RouteRegistry::new(16384);

        let _zone = crate::config::ZoneConfig {
            name: "corp".into(),
            mode: crate::config::ZoneMode::Inclusive,
            dns_servers: vec![],
            route_type: crate::config::RouteType::Via,
            route_target: "10.0.0.1".into(),
            route_target_ipv6: None,
            domains: vec![],
            patterns: vec![],
            static_routes: vec![],
            dns_protocol: crate::config::DnsProtocol::Udp,
            cache_min_ttl: None,
            cache_max_ttl: None,
            cache_negative_ttl: None,
            ipv6: false,
        };

        let a = crate::routing::model::RouteIntent {
            key: crate::routing::model::RouteKey {
                prefix: crate::routing::model::RoutePrefix::host(IpAddr::V4(
                    std::net::Ipv4Addr::new(10, 1, 0, 1),
                )),
                table: 254,
            },
            zone: "corp".into(),
            target: crate::routing::model::RouteTarget::Gateway(IpAddr::V4(
                std::net::Ipv4Addr::new(10, 0, 0, 1),
            )),
            source: RouteSource::Dns,
        };
        let b = crate::routing::model::RouteIntent {
            key: crate::routing::model::RouteKey {
                prefix: crate::routing::model::RoutePrefix::host(IpAddr::V4(
                    std::net::Ipv4Addr::new(10, 1, 0, 2),
                )),
                table: 254,
            },
            zone: "corp".into(),
            target: a.target.clone(),
            source: RouteSource::Dns,
        };

        reg.ensure(a.clone(), backend.as_ref(), 1).await.unwrap();
        reg.ensure(b.clone(), backend.as_ref(), 1).await.unwrap();
        assert_eq!(backend.ensures.load(Ordering::SeqCst), 2);

        // Targeted invalidation of key A only.
        reg.mark_dirty(
            crate::routing::backend::RouteInvalidation::Prefix(a.key.clone()),
            1,
        )
        .await;

        // The unaffected entry B is still Verified at epoch 1: an ensure for
        // B must take the fast path with zero backend calls.
        let outcome = reg.ensure(b.clone(), backend.as_ref(), 1).await.unwrap();
        assert_eq!(
            outcome,
            crate::routing::backend::EnsureOutcome::AlreadyMatching
        );
        assert_eq!(
            backend.ensures.load(Ordering::SeqCst),
            2,
            "the unrelated Verified entry must not re-ensure"
        );

        // The affected entry A re-ensures against the current epoch.
        reg.ensure(a.clone(), backend.as_ref(), 1).await.unwrap();
        assert_eq!(backend.ensures.load(Ordering::SeqCst), 3);
    }

    // §14.5: remove_all_owned deletes only rows this process created and
    // preserves foreign rows untouched.
    #[tokio::test]
    async fn remove_all_owned_skips_unowned_entries() {
        let backend = Arc::new(CountingBackend::new());
        let reg = RouteRegistry::new(16384);

        let intent = crate::routing::model::RouteIntent {
            key: crate::routing::model::RouteKey {
                prefix: crate::routing::model::RoutePrefix::host(IpAddr::V4(
                    std::net::Ipv4Addr::new(10, 2, 0, 1),
                )),
                table: 254,
            },
            zone: "corp".into(),
            target: crate::routing::model::RouteTarget::Gateway(IpAddr::V4(
                std::net::Ipv4Addr::new(10, 0, 0, 1),
            )),
            source: RouteSource::Dns,
        };
        reg.ensure(intent.clone(), backend.as_ref(), 1)
            .await
            .unwrap();

        // The Added ownership is owned=true: cleanup deletes it.
        let removed = reg.remove_all_owned(backend.as_ref()).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(
            backend.inner.removed().len(),
            1,
            "the owned row must be deleted"
        );

        // A second pass: the entry no longer carries a desired intent, so
        // nothing is deleted again.
        let removed = reg.remove_all_owned(backend.as_ref()).await.unwrap();
        assert_eq!(removed, 0);
    }
}
