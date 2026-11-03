//! Platform backend contract for intent-aware route operations.
//!
//! This replaces the old low-level `RouteAdder` contract. A backend resolves
//! a zone's route target for a specific address family, then ensures or
//! removes canonical route intents. Platforms that can observe their routing
//! table also provide a snapshot and an invalidation stream.
//
// The registry and the route manager consume this trait in later steps of the
// route-registry rollout; until then the contract is exercised only by its
// own tests and the fake backend.
#![allow(dead_code)]

use crate::config::ZoneConfig;
use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

use super::model::{AddressFamily, ObservedRoute, RouteIntent, RouteKey, RouteTarget};

/// Outcome of a successful `ensure_route`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnsureOutcome {
    /// The kernel route was created by this call.
    Added,
    /// The kernel already had exactly the intended route; no mutation happened.
    AlreadyMatching,
}

/// A route Leshy does not own occupies the destination prefix.
///
/// Leshy never replaces or deletes a route it cannot prove ownership of; the
/// DNS layer turns this into a fail-closed SERVFAIL instead of answering with
/// an address that has no selected route.
#[derive(Debug)]
pub struct RouteConflict {
    pub prefix: String,
    pub owner: String,
}

impl std::fmt::Display for RouteConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "route {} is already owned by {}",
            self.prefix, self.owner
        )
    }
}

impl std::error::Error for RouteConflict {}

/// A kernel-state change that invalidates registry verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteInvalidation {
    /// One destination is no longer trustworthy.
    Prefix(RouteKey),
    /// Everything routed through an interface is no longer trustworthy.
    Interface(u32),
    /// The kernel state cannot be mapped to individual keys.
    Full,
}

// async_trait's generated #[must_use] on boxed futures trips this lint on
// newer clippy versions; the futures are always awaited internally.
#[allow(clippy::double_must_use)]
#[async_trait]
pub(crate) trait RouteBackend: Send + Sync {
    /// Resolve where traffic for `family` should be sent in this zone.
    ///
    /// Device-file reading lives here (not in the manager) because the way a
    /// target is discovered is platform-specific. Implementations must reject
    /// a target whose family does not match `family`.
    async fn resolve_target(&self, zone: &ZoneConfig, family: AddressFamily)
        -> Result<RouteTarget>;

    /// Install the route unless the kernel already has exactly this route.
    async fn ensure_route(&self, intent: &RouteIntent) -> Result<EnsureOutcome>;

    /// Remove a route owned by Leshy. A foreign route on the same destination
    /// must never be deleted.
    async fn remove_route(&self, intent: &RouteIntent) -> Result<()>;

    /// Read the kernel routing table.
    async fn snapshot(&self) -> Result<Vec<ObservedRoute>>;

    /// Kernel invalidation stream, when the platform can observe changes.
    fn take_invalidation_receiver(&self) -> Option<mpsc::UnboundedReceiver<RouteInvalidation>>;
}

/// Test backend with mutation counters and scripted outcomes.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use crate::config::RouteType;
    use crate::routing::model::{AddressFamily, RouteSource};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    pub(crate) struct FakeState {
        pub ensures: AtomicU64,
        pub removes: AtomicU64,
        pub snapshots: AtomicU64,
        pub resolves: AtomicU64,
        /// Scripted result for the next `ensure_route` calls.
        outcome: Mutex<Option<Result<EnsureOutcome>>>,
        /// Scripted foreign-route conflict for the next `ensure_route` calls.
        conflict: Mutex<Option<(String, String)>>,
        /// Scripted result for the next `resolve_target` calls.
        resolved: Mutex<Option<RouteTarget>>,
        pub ensured: Mutex<Vec<RouteIntent>>,
        pub removed: Mutex<Vec<RouteIntent>>,
        /// Routes reported by `snapshot`.
        pub observed: Mutex<Vec<ObservedRoute>>,
    }

    impl FakeState {
        fn new() -> Self {
            Self {
                ensures: AtomicU64::new(0),
                removes: AtomicU64::new(0),
                snapshots: AtomicU64::new(0),
                resolves: AtomicU64::new(0),
                outcome: Mutex::new(None),
                conflict: Mutex::new(None),
                resolved: Mutex::new(None),
                ensured: Mutex::new(Vec::new()),
                removed: Mutex::new(Vec::new()),
                observed: Mutex::new(Vec::new()),
            }
        }
    }

    pub(crate) struct FakeBackend {
        state: Arc<FakeState>,
    }

    impl Default for FakeBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl FakeBackend {
        pub(crate) fn new() -> Self {
            Self {
                state: Arc::new(FakeState::new()),
            }
        }

        pub(crate) fn ensure_count(&self) -> u64 {
            self.state.ensures.load(Ordering::SeqCst)
        }

        pub(crate) fn remove_count(&self) -> u64 {
            self.state.removes.load(Ordering::SeqCst)
        }

        pub(crate) fn snapshot_count(&self) -> u64 {
            self.state.snapshots.load(Ordering::SeqCst)
        }

        pub(crate) fn resolve_count(&self) -> u64 {
            self.state.resolves.load(Ordering::SeqCst)
        }

        pub(crate) fn set_outcome(&self, outcome: Result<EnsureOutcome>) {
            *self.state.outcome.lock().unwrap() = Some(outcome);
        }

        /// Script a foreign route conflict for the next `ensure_route` calls.
        pub(crate) fn set_conflict(&self, prefix: &str, owner: &str) {
            *self.state.conflict.lock().unwrap() = Some((prefix.to_string(), owner.to_string()));
        }

        pub(crate) fn set_resolved(&self, target: RouteTarget) {
            *self.state.resolved.lock().unwrap() = Some(target);
        }

        pub(crate) fn ensured(&self) -> Vec<RouteIntent> {
            self.state.ensured.lock().unwrap().clone()
        }

        pub(crate) fn removed(&self) -> Vec<RouteIntent> {
            self.state.removed.lock().unwrap().clone()
        }

        pub(crate) fn push_observed(&self, route: ObservedRoute) {
            self.state.observed.lock().unwrap().push(route);
        }

        /// Zero the mutation counters without dropping recorded intents.
        pub(crate) fn reset_counters(&self) {
            self.state.ensures.store(0, Ordering::SeqCst);
            self.state.removes.store(0, Ordering::SeqCst);
            self.state.snapshots.store(0, Ordering::SeqCst);
            self.state.resolves.store(0, Ordering::SeqCst);
        }

        /// Shared handle for passing the same fake into several owners.
        pub(crate) fn shared(&self) -> Arc<FakeState> {
            Arc::clone(&self.state)
        }
    }

    #[async_trait]
    impl RouteBackend for FakeBackend {
        async fn resolve_target(
            &self,
            zone: &ZoneConfig,
            family: AddressFamily,
        ) -> Result<RouteTarget> {
            self.state.resolves.fetch_add(1, Ordering::SeqCst);
            if let Some(target) = self.state.resolved.lock().unwrap().clone() {
                return Ok(target);
            }
            match zone.route_type {
                RouteType::Via => {
                    let gw = zone.gateway_for(family)?.ok_or_else(|| {
                        anyhow::anyhow!("zone '{}': no gateway for {family:?}", zone.name)
                    })?;
                    Ok(RouteTarget::Gateway(gw))
                }
                RouteType::Dev => {
                    let name = tokio::fs::read_to_string(&zone.route_target)
                        .await?
                        .trim()
                        .to_string();
                    Ok(RouteTarget::Device {
                        name,
                        ifindex: None,
                    })
                }
            }
        }

        async fn ensure_route(&self, intent: &RouteIntent) -> Result<EnsureOutcome> {
            self.state.ensures.fetch_add(1, Ordering::SeqCst);
            self.state.ensured.lock().unwrap().push(intent.clone());
            if let Some((prefix, owner)) = self.state.conflict.lock().unwrap().clone() {
                return Err(anyhow::anyhow!(super::RouteConflict { prefix, owner }));
            }
            match self.state.outcome.lock().unwrap().as_ref() {
                Some(Ok(outcome)) => Ok(*outcome),
                Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
                None => Ok(EnsureOutcome::Added),
            }
        }

        async fn remove_route(&self, intent: &RouteIntent) -> Result<()> {
            self.state.removes.fetch_add(1, Ordering::SeqCst);
            self.state.removed.lock().unwrap().push(intent.clone());
            Ok(())
        }

        async fn snapshot(&self) -> Result<Vec<ObservedRoute>> {
            self.state.snapshots.fetch_add(1, Ordering::SeqCst);
            Ok(self.state.observed.lock().unwrap().clone())
        }

        fn take_invalidation_receiver(&self) -> Option<mpsc::UnboundedReceiver<RouteInvalidation>> {
            None
        }
    }

    /// Convenience constructor for a v4 host intent used across tests.
    pub(crate) fn host_intent_v4(a: u8, b: u8, c: u8, d: u8, zone: &str) -> RouteIntent {
        use crate::routing::model::{RouteKey, RoutePrefix};
        RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(a, b, c, d))),
                table: 254,
            },
            zone: zone.to_string(),
            target: RouteTarget::Gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            source: RouteSource::Dns,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::{DnsProtocol, ZoneConfig, ZoneMode};

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

        #[tokio::test]
        async fn ensure_is_counted_and_recorded() {
            let backend = FakeBackend::new();
            let intent = host_intent_v4(10, 0, 0, 1, "corp");
            assert_eq!(
                backend.ensure_route(&intent).await.unwrap(),
                EnsureOutcome::Added
            );
            assert_eq!(backend.ensure_count(), 1);
            assert_eq!(backend.ensured(), vec![intent]);
        }

        #[tokio::test]
        async fn scripted_already_matching_is_reported() {
            let backend = FakeBackend::new();
            backend.set_outcome(Ok(EnsureOutcome::AlreadyMatching));
            let intent = host_intent_v4(10, 0, 0, 1, "corp");
            assert_eq!(
                backend.ensure_route(&intent).await.unwrap(),
                EnsureOutcome::AlreadyMatching
            );
        }

        #[tokio::test]
        async fn scripted_error_propagates() {
            let backend = FakeBackend::new();
            backend.set_outcome(Err(anyhow::anyhow!("netlink said no")));
            let intent = host_intent_v4(10, 0, 0, 1, "corp");
            assert!(backend.ensure_route(&intent).await.is_err());
        }

        #[tokio::test]
        async fn resolve_target_rejects_family_mismatch() {
            let backend = FakeBackend::new();
            let zone = via_zone("corp", "192.168.1.1");
            // An IPv4 gateway cannot serve an IPv6 route.
            assert!(backend
                .resolve_target(&zone, AddressFamily::V6)
                .await
                .is_err());
            assert!(backend
                .resolve_target(&zone, AddressFamily::V4)
                .await
                .is_ok());
        }

        #[tokio::test]
        async fn counters_are_independent() {
            let backend = FakeBackend::new();
            let intent = host_intent_v4(10, 0, 0, 1, "corp");
            backend.ensure_route(&intent).await.unwrap();
            backend.remove_route(&intent).await.unwrap();
            backend.snapshot().await.unwrap();
            assert_eq!(backend.ensure_count(), 1);
            assert_eq!(backend.remove_count(), 1);
            assert_eq!(backend.snapshot_count(), 1);
            assert_eq!(backend.resolve_count(), 0);
        }

        #[tokio::test]
        async fn no_invalidation_stream_by_default() {
            let backend = FakeBackend::new();
            assert!(backend.take_invalidation_receiver().is_none());
        }
    }
}
