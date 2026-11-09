//! Linux route backend: rtnetlink writer plus kernel read-back.
//!
//! `ensure_route` never treats EEXIST as unconditional success: a row for the
//! same destination that points at another interface or gateway is a conflict,
//! not a match. The kernel is the source of truth, but the DNS request path
//! never dumps a whole address family (08D1 §16): a lazy cache is filled by
//! one monitor-coherent snapshot, mutations re-read only the affected prefix,
//! and a generation mismatch triggers one targeted read instead of a full
//! dump.
//!
//! The only rows this backend may replace or delete are exact previous Owned
//! observations (08D1 §16.4/§49.7); anything else on the same key is foreign.

use super::backend::{EnsureOutcome, EnsureResult, RouteBackend, RouteInvalidation};
use super::model::{
    AddressFamily, ObservedRoute, RouteIntent, RouteKernelIdentity, RouteKey, RouteOwnership,
    RoutePrefix, RouteTarget,
};
use crate::config::{RouteType, ZoneConfig};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::TryStreamExt;
use netlink_packet_route::route::{RouteAddress, RouteMessage, RouteProtocol, RouteScope};
use rtnetlink::{new_connection, Handle, IpVersion};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, OnceCell, RwLock};

/// Protocol stamped on every row Leshy creates.
///
/// `Boot` is what `ip route add` uses by default, so rows installed by earlier
/// Leshy versions are adopted without a migration step.
const LESHY_PROTOCOL: RouteProtocol = RouteProtocol::Boot;

/// The main routing table.
const MAIN_TABLE: u32 = 254;

/// `RouteHeader::table` is a single byte, so the main table is compared in
/// that width.
const MAIN_TABLE_U8: u8 = MAIN_TABLE as u8;

/// Seam over the kernel calls the backend needs.
///
/// Production uses [`NetlinkIo`]; unit tests use a fake so the cache,
/// generation and replacement logic can be exercised without a kernel.
#[async_trait]
#[allow(clippy::double_must_use)]
trait KernelIo: Send + Sync {
    async fn link_names(&self) -> Result<HashMap<u32, String>>;
    async fn ifindex_of(&self, device: &str) -> Result<u32>;
    async fn dump_family(
        &self,
        family: AddressFamily,
        names: &HashMap<u32, String>,
    ) -> Result<Vec<ObservedRoute>>;
    async fn read_prefix(
        &self,
        key: &RouteKey,
        names: &HashMap<u32, String>,
    ) -> Result<Vec<ObservedRoute>>;
    async fn add(&self, intent: &RouteIntent) -> Result<()>;
    async fn replace(&self, intent: &RouteIntent) -> Result<()>;
    async fn delete(&self, intent: &RouteIntent) -> Result<()>;
}

/// rtnetlink-backed kernel I/O.
struct NetlinkIo {
    handle: Handle,
    /// Serializes kernel requests on the shared connection.
    ///
    /// `netlink_dump_start` refuses a second dump while one is running on the
    /// same socket with `-EBUSY`, and the monitor reconcile and the DNS request
    /// path can issue dumps concurrently (08D1 §16.2). Holding this across the
    /// whole request/response keeps dumps and mutations from colliding.
    io_lock: Mutex<()>,
}

#[async_trait]
impl KernelIo for NetlinkIo {
    async fn link_names(&self) -> Result<HashMap<u32, String>> {
        let _guard = self.io_lock.lock().await;
        let mut links = self.handle.link().get().execute();
        let mut names = HashMap::new();
        while let Some(link) = links.try_next().await? {
            let name = link
                .attributes
                .iter()
                .find_map(|attr| match attr {
                    netlink_packet_route::link::LinkAttribute::IfName(name) => Some(name.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            names.insert(link.header.index, name);
        }
        Ok(names)
    }

    async fn ifindex_of(&self, device: &str) -> Result<u32> {
        let _guard = self.io_lock.lock().await;
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(device.to_string())
            .execute();
        let link = links
            .try_next()
            .await?
            .with_context(|| format!("Device '{device}' not found"))?;
        Ok(link.header.index)
    }

    async fn dump_family(
        &self,
        family: AddressFamily,
        names: &HashMap<u32, String>,
    ) -> Result<Vec<ObservedRoute>> {
        let _guard = self.io_lock.lock().await;
        let version = match family {
            AddressFamily::V4 => IpVersion::V4,
            AddressFamily::V6 => IpVersion::V6,
        };
        let mut routes = self.handle.route().get(version).execute();
        let mut out = Vec::new();
        while let Some(msg) = routes.try_next().await? {
            if let Some(row) = observed_of(&msg, names) {
                out.push(row);
            }
        }
        Ok(out)
    }

    async fn read_prefix(
        &self,
        key: &RouteKey,
        names: &HashMap<u32, String>,
    ) -> Result<Vec<ObservedRoute>> {
        // §16.3: one filtered RouteGetRequest for the requested key, never a
        // whole-family dump. rtnetlink 0.14 is pinned; the filter is applied
        // by mutating the request message.
        let _guard = self.io_lock.lock().await;
        let version = match key.prefix.family() {
            AddressFamily::V4 => IpVersion::V4,
            AddressFamily::V6 => IpVersion::V6,
        };
        let mut request = self.handle.route().get(version);
        {
            let msg = request.message_mut();
            msg.header.table = MAIN_TABLE_U8;
            msg.header.destination_prefix_length = key.prefix.prefix_len;
            match key.prefix.network {
                IpAddr::V4(addr) => {
                    msg.attributes
                        .push(netlink_packet_route::route::RouteAttribute::Destination(
                            RouteAddress::Inet(addr),
                        ))
                }
                IpAddr::V6(addr) => {
                    msg.attributes
                        .push(netlink_packet_route::route::RouteAttribute::Destination(
                            RouteAddress::Inet6(addr),
                        ))
                }
            }
        }
        let mut routes = request.execute();
        let mut out = Vec::new();
        while let Some(msg) = routes.try_next().await? {
            if let Some(row) = observed_of(&msg, names) {
                if row.key == *key {
                    out.push(row);
                }
            }
        }
        Ok(out)
    }

    async fn add(&self, intent: &RouteIntent) -> Result<()> {
        let _guard = self.io_lock.lock().await;
        match intent.key.prefix.network {
            IpAddr::V4(_) => {
                let mut request = self.handle.route().add().v4();
                apply_intent(request.message_mut(), intent)?;
                match request.execute().await {
                    Ok(()) => Ok(()),
                    // EEXIST: the caller decides whether the existing row matches.
                    Err(rtnetlink::Error::NetlinkError(err)) if matches!(err.code, Some(code) if code.get() == -17) => {
                        Ok(())
                    }
                    Err(e) => Err(e.into()),
                }
            }
            IpAddr::V6(_) => {
                let mut request = self.handle.route().add().v6();
                apply_intent(request.message_mut(), intent)?;
                match request.execute().await {
                    Ok(()) => Ok(()),
                    Err(rtnetlink::Error::NetlinkError(err)) if matches!(err.code, Some(code) if code.get() == -17) => {
                        Ok(())
                    }
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    async fn replace(&self, intent: &RouteIntent) -> Result<()> {
        // §49.7: NLM_F_REPLACE swaps the matching row atomically; a broad
        // delete-by-prefix is never used.
        let _guard = self.io_lock.lock().await;
        match intent.key.prefix.network {
            IpAddr::V4(_) => {
                let mut request = self.handle.route().add().v4().replace();
                apply_intent(request.message_mut(), intent)?;
                request.execute().await?;
                Ok(())
            }
            IpAddr::V6(_) => {
                let mut request = self.handle.route().add().v6().replace();
                apply_intent(request.message_mut(), intent)?;
                request.execute().await?;
                Ok(())
            }
        }
    }

    async fn delete(&self, intent: &RouteIntent) -> Result<()> {
        let _guard = self.io_lock.lock().await;
        let prefix = &intent.key.prefix;
        let mut msg = RouteMessage::default();
        // The doit handler is registered per family: a DEL with an unspecified
        // family is rejected by the kernel before the prefix is even looked at.
        msg.header.address_family = match prefix.network {
            IpAddr::V4(_) => netlink_packet_route::AddressFamily::Inet,
            IpAddr::V6(_) => netlink_packet_route::AddressFamily::Inet6,
        };
        msg.header.destination_prefix_length = prefix.prefix_len;
        msg.header.table = MAIN_TABLE_U8;
        // Ownership was already proven by the exact read-back before this
        // delete runs, so the DEL must match the row whatever its scope,
        // protocol or metric are: the kernel compares all three and an
        // assumed Boot/link delete silently misses the row (ESRCH), leaving
        // it in the table. NOWHERE scope and UNSPEC protocol mean "match
        // any"; an absent priority matches any metric.
        msg.header.scope = RouteScope::NoWhere;
        msg.header.protocol = RouteProtocol::Unspec;
        match prefix.network {
            IpAddr::V4(addr) => {
                msg.attributes
                    .push(netlink_packet_route::route::RouteAttribute::Destination(
                        RouteAddress::Inet(addr),
                    ));
            }
            IpAddr::V6(addr) => {
                msg.attributes
                    .push(netlink_packet_route::route::RouteAttribute::Destination(
                        RouteAddress::Inet6(addr),
                    ));
            }
        }

        match self.handle.route().del(msg).execute().await {
            Ok(()) => Ok(()),
            // ESRCH: nothing to delete.
            Err(rtnetlink::Error::NetlinkError(err)) if matches!(err.code, Some(code) if code.get() == -3) => {
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Fill an add/replace request from an intent.
fn apply_intent(msg: &mut RouteMessage, intent: &RouteIntent) -> Result<()> {
    let prefix = &intent.key.prefix;
    msg.header.destination_prefix_length = prefix.prefix_len;
    msg.header.protocol = LESHY_PROTOCOL;
    match prefix.network {
        IpAddr::V4(addr) => {
            msg.attributes
                .push(netlink_packet_route::route::RouteAttribute::Destination(
                    RouteAddress::Inet(addr),
                ))
        }
        IpAddr::V6(addr) => {
            msg.attributes
                .push(netlink_packet_route::route::RouteAttribute::Destination(
                    RouteAddress::Inet6(addr),
                ))
        }
    }
    match &intent.target {
        RouteTarget::Gateway(gw) if gw.is_ipv4() == prefix.network.is_ipv4() => match gw {
            IpAddr::V4(v4) => {
                msg.attributes
                    .push(netlink_packet_route::route::RouteAttribute::Gateway(
                        RouteAddress::Inet(*v4),
                    ))
            }
            IpAddr::V6(v6) => {
                msg.attributes
                    .push(netlink_packet_route::route::RouteAttribute::Gateway(
                        RouteAddress::Inet6(*v6),
                    ))
            }
        },
        RouteTarget::Device {
            ifindex: Some(index),
            ..
        } => {
            msg.attributes
                .push(netlink_packet_route::route::RouteAttribute::Oif(*index));
        }
        other => anyhow::bail!(
            "route {} cannot be installed with target {other:?}",
            prefix.network
        ),
    }
    msg.header.scope = match prefix.family() {
        // The IPv6 kernel carries no route scope attribute; read-back truth is
        // 0, so write the same value we will observe.
        AddressFamily::V6 => RouteScope::Universe,
        AddressFamily::V4 => match &intent.target {
            RouteTarget::Device { .. } => RouteScope::Link,
            _ => RouteScope::Universe,
        },
    };
    Ok(())
}

/// Per-call kernel counters (08D1 §16.1). Kept in every build so the code has
/// one shape; only tests read them.
#[allow(dead_code)]
#[derive(Default)]
struct Counters {
    full_snapshots: AtomicU64,
    targeted_reads: AtomicU64,
    adds: AtomicU64,
    deletes: AtomicU64,
    replaces: AtomicU64,
}

pub struct LinuxRouteBackend {
    io: Arc<dyn KernelIo>,
    /// One entry per key; a prefix may temporarily hold several rows.
    cache: RwLock<HashMap<RouteKey, Vec<ObservedRoute>>>,
    /// Filled exactly once by the lazy, monitor-coherent initial snapshot.
    cache_init: OnceCell<()>,
    /// Shared with the monitor; every relevant kernel event bumps it.
    monitor_generation: Arc<AtomicU64>,
    /// Generation the cache was last proven current against.
    cache_generation: AtomicU64,
    invalidation_rx: Mutex<Option<mpsc::UnboundedReceiver<RouteInvalidation>>>,
    counters: Counters,
}

impl LinuxRouteBackend {
    pub fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);

        let monitor_generation = Arc::new(AtomicU64::new(0));

        // A monitor that cannot start is not fatal: the periodic audit still
        // catches drift, just later.
        let invalidation_rx = match super::linux_monitor::spawn_monitor(Arc::clone(
            &monitor_generation,
        )) {
            Ok(rx) => Some(rx),
            Err(e) => {
                tracing::warn!(error = %e, "Kernel route monitor unavailable, relying on the periodic audit");
                None
            }
        };

        Ok(Self::with_io(
            Arc::new(NetlinkIo {
                handle,
                io_lock: Mutex::new(()),
            }),
            monitor_generation,
            invalidation_rx,
        ))
    }

    fn with_io(
        io: Arc<dyn KernelIo>,
        monitor_generation: Arc<AtomicU64>,
        invalidation_rx: Option<mpsc::UnboundedReceiver<RouteInvalidation>>,
    ) -> Self {
        Self {
            io,
            cache: RwLock::new(HashMap::new()),
            cache_init: OnceCell::new(),
            monitor_generation,
            cache_generation: AtomicU64::new(0),
            invalidation_rx: Mutex::new(invalidation_rx),
            counters: Counters::default(),
        }
    }

    /// Read the whole main table (both families) plus the link names and
    /// publish it as the cache, retrying if a kernel event landed mid-read
    /// (08D1 §16.2). Returns the generation the cache is current against.
    async fn full_snapshot(&self) -> Result<()> {
        loop {
            let before = self.monitor_generation.load(Ordering::SeqCst);
            let names = self.io.link_names().await?;
            let mut cache: HashMap<RouteKey, Vec<ObservedRoute>> = HashMap::new();
            for family in [AddressFamily::V4, AddressFamily::V6] {
                for row in self.io.dump_family(family, &names).await? {
                    cache.entry(row.key.clone()).or_default().push(row);
                }
            }
            self.counters.full_snapshots.fetch_add(1, Ordering::SeqCst);
            let after = self.monitor_generation.load(Ordering::SeqCst);
            if before != after {
                // An event happened while we were reading: the snapshot is
                // not current, so read again instead of declaring it valid.
                continue;
            }
            *self.cache.write().await = cache;
            self.cache_generation.store(after, Ordering::SeqCst);
            return Ok(());
        }
    }

    /// Lazy one-time cache initialization (08D1 §16.1).
    async fn ensure_cache_initialized(&self) -> Result<()> {
        self.cache_init
            .get_or_try_init(|| async { self.full_snapshot().await })
            .await?;
        Ok(())
    }

    /// Targeted read-back of one key; updates that cache entry only.
    async fn refresh_key(&self, key: &RouteKey) -> Result<Vec<ObservedRoute>> {
        // A link event may have added, removed or renamed the OIF the row
        // points at, and the device name is part of the exact target match.
        // Refresh the (small) link map before the targeted route read so a
        // recreated interface never reads back as an unnamed foreign target
        // (08D1 §16.4).
        let names = self.io.link_names().await?;
        let rows = self.io.read_prefix(key, &names).await?;
        self.counters.targeted_reads.fetch_add(1, Ordering::SeqCst);
        let mut cache = self.cache.write().await;
        if rows.is_empty() {
            cache.remove(key);
        } else {
            cache.insert(key.clone(), rows.clone());
        }
        Ok(rows)
    }

    /// Rows currently known for one key.
    ///
    /// A cache hit is trusted only while `cache_generation` matches the
    /// monitor generation; otherwise the requested key is read back once
    /// instead of dumping a family (08D1 §16.2).
    async fn rows_for(&self, key: &RouteKey) -> Result<Vec<ObservedRoute>> {
        self.ensure_cache_initialized().await?;
        if self.cache_generation.load(Ordering::SeqCst)
            == self.monitor_generation.load(Ordering::SeqCst)
        {
            let cache = self.cache.read().await;
            return Ok(cache.get(key).cloned().unwrap_or_default());
        }
        self.refresh_key(key).await
    }

    /// Whether a refused add means "a row for this destination already
    /// exists": EEXIST outright, or EBUSY — what the IPv6 route code answers
    /// for an identical existing route.
    fn is_busy_class(e: &anyhow::Error) -> bool {
        matches!(
            e.downcast_ref::<rtnetlink::Error>(),
            Some(rtnetlink::Error::NetlinkError(err))
                if matches!(err.code, Some(code) if code.get() == -17 || code.get() == -16)
        )
    }

    /// A typed refusal to touch a destination someone else owns. The registry
    /// classifies this as `RouteError::Conflict`, which the DNS layer answers
    /// with SERVFAIL instead of handing out an unrouted address.
    fn conflict_error(&self, intent: &RouteIntent, owner: &RouteTarget) -> anyhow::Error {
        anyhow::anyhow!(super::backend::RouteConflict {
            prefix: format!(
                "{}/{}",
                intent.key.prefix.network, intent.key.prefix.prefix_len
            ),
            owner: format!("{owner:?}"),
        })
    }

    async fn add_row(&self, intent: &RouteIntent) -> Result<()> {
        self.io.add(intent).await?;
        self.counters.adds.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn replace_row(&self, intent: &RouteIntent) -> Result<()> {
        self.io.replace(intent).await?;
        self.counters.replaces.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn delete_row(&self, intent: &RouteIntent) -> Result<()> {
        self.io.delete(intent).await?;
        self.counters.deletes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Read the affected key back after an add/replace and prove Desired is
    /// exactly what the kernel now holds (08D1 §16.3).
    async fn prove_added(&self, intent: &RouteIntent) -> Result<EnsureResult> {
        let rows = self.refresh_key(&intent.key).await?;
        match rows.as_slice() {
            [row] if observed_matches(row, intent) => Ok(EnsureResult {
                outcome: EnsureOutcome::Added,
                ownership: RouteOwnership {
                    owned: true,
                    observed: Some(row.clone()),
                },
            }),
            [row] => Err(self.conflict_error(intent, &row.target)),
            [] => anyhow::bail!(
                "route {} is missing right after it was added",
                intent.key.prefix.network
            ),
            rows => Err(self.conflict_error(intent, &rows[0].target)),
        }
    }

    /// Decide an ensure against the rows currently occupying the key.
    async fn classify_rows(
        &self,
        intent: &RouteIntent,
        previous: Option<&RouteOwnership>,
        rows: Vec<ObservedRoute>,
    ) -> Result<EnsureResult> {
        let [row] = rows.as_slice() else {
            // No row is handled by the caller; more than one same-key row is
            // ambiguous and therefore foreign.
            let owner = rows
                .first()
                .map(|r| &r.target)
                .cloned()
                .unwrap_or(RouteTarget::Unreachable);
            return Err(self.conflict_error(intent, &owner));
        };

        if observed_matches(row, intent) {
            // Only an exact recorded identity keeps ownership; a compatible
            // pre-existing row satisfies forwarding but is not ours.
            let owned = matches!(
                previous,
                Some(RouteOwnership {
                    owned: true,
                    observed: Some(prev),
                }) if prev.identity == row.identity
            );
            return Ok(EnsureResult {
                outcome: EnsureOutcome::AlreadyMatching,
                ownership: RouteOwnership {
                    owned,
                    observed: Some(row.clone()),
                },
            });
        }

        // §49.7: an exact previous Owned row may be replaced with Desired.
        if Self::is_exact_previous_owned(previous, row) {
            self.replace_row(intent).await?;
            return self.prove_added(intent).await;
        }

        Err(self.conflict_error(intent, &row.target))
    }

    fn is_exact_previous_owned(previous: Option<&RouteOwnership>, row: &ObservedRoute) -> bool {
        matches!(
            previous,
            Some(RouteOwnership {
                owned: true,
                observed: Some(prev),
            }) if prev.key == row.key && prev.target == row.target && prev.identity == row.identity
        )
    }
}

/// Extract the destination address from a route message.
fn destination_of(msg: &RouteMessage) -> Option<IpAddr> {
    msg.attributes.iter().find_map(|attr| match attr {
        netlink_packet_route::route::RouteAttribute::Destination(RouteAddress::Inet(addr)) => {
            Some(IpAddr::V4(*addr))
        }
        netlink_packet_route::route::RouteAttribute::Destination(RouteAddress::Inet6(addr)) => {
            Some(IpAddr::V6(*addr))
        }
        _ => None,
    })
}

/// Captures the exact kernel identity of one route message (08D1 §16.4):
/// the OIF even for gateway routes, the gateway as next hop, protocol, the
/// metric/priority (default 0 only when the kernel attribute is absent) and
/// the scope.
fn linux_identity_of(msg: &RouteMessage) -> RouteKernelIdentity {
    let mut oif = None;
    let mut gateway = None;
    let mut metric = 0;
    for attr in msg.attributes.iter() {
        match attr {
            netlink_packet_route::route::RouteAttribute::Oif(index) => oif = Some(*index),
            netlink_packet_route::route::RouteAttribute::Gateway(gw) => match gw {
                RouteAddress::Inet(v4) => gateway = Some(IpAddr::V4(*v4)),
                RouteAddress::Inet6(v6) => gateway = Some(IpAddr::V6(*v6)),
                _ => {}
            },
            netlink_packet_route::route::RouteAttribute::Priority(priority) => {
                metric = *priority;
            }
            _ => {}
        }
    }
    RouteKernelIdentity {
        ifindex: oif,
        next_hop: gateway,
        protocol: msg.header.protocol.into(),
        metric,
        scope: u8::from(msg.header.scope),
        interface_luid: None,
    }
}

fn target_of(msg: &RouteMessage, names: &HashMap<u32, String>) -> Option<RouteTarget> {
    let mut oif = None;
    let mut gateway = None;
    for attr in msg.attributes.iter() {
        match attr {
            netlink_packet_route::route::RouteAttribute::Oif(index) => oif = Some(*index),
            netlink_packet_route::route::RouteAttribute::Gateway(gw) => match gw {
                RouteAddress::Inet(v4) => gateway = Some(IpAddr::V4(*v4)),
                RouteAddress::Inet6(v6) => gateway = Some(IpAddr::V6(*v6)),
                _ => {}
            },
            _ => {}
        }
    }
    if let Some(gw) = gateway {
        return Some(RouteTarget::Gateway(gw));
    }
    oif.map(|index| RouteTarget::Device {
        name: names.get(&index).cloned().unwrap_or_default(),
        ifindex: Some(index),
    })
}

/// Build one observed row from a kernel message, or `None` when it is not a
/// main-table row Leshy can represent.
fn observed_of(msg: &RouteMessage, names: &HashMap<u32, String>) -> Option<ObservedRoute> {
    if msg.header.table != MAIN_TABLE_U8 {
        return None;
    }
    let network = destination_of(msg)?;
    let prefix = RoutePrefix::new(network, msg.header.destination_prefix_length).ok()?;
    let target = target_of(msg, names)?;
    Some(ObservedRoute {
        key: RouteKey {
            prefix,
            table: MAIN_TABLE,
        },
        target,
        identity: linux_identity_of(msg),
    })
}

/// Scope the kernel reports for a row Leshy wrote (08D1 §16.4).
///
/// The IPv6 kernel carries no route scope attribute, so read-back truth is 0
/// (recorded by the Linux netns run); IPv4 device routes are link scope and
/// IPv4 gateway routes universe.
fn expected_scope(prefix: &RoutePrefix, target: &RouteTarget) -> u8 {
    match prefix.family() {
        AddressFamily::V6 => u8::from(RouteScope::Universe),
        AddressFamily::V4 => match target {
            RouteTarget::Device { .. } => u8::from(RouteScope::Link),
            _ => u8::from(RouteScope::Universe),
        },
    }
}

/// Metric/priority the kernel reports when Leshy sends none (08D1 §16.4):
/// IPv4 defaults to 0, IPv6 to `IP6_RT_PRIO_USER` (1024).
fn expected_metric(prefix: &RoutePrefix) -> u32 {
    match prefix.family() {
        AddressFamily::V4 => 0,
        AddressFamily::V6 => 1024,
    }
}

/// The exact-match contract for a row Leshy considers already correct:
/// same key, same logical target, and the writer's protocol/metric/scope.
fn observed_matches(row: &ObservedRoute, intent: &RouteIntent) -> bool {
    row.key == intent.key
        && row.target == intent.target
        && row.identity.protocol == u8::from(LESHY_PROTOCOL)
        && row.identity.metric == expected_metric(&intent.key.prefix)
        && row.identity.scope == expected_scope(&intent.key.prefix, &intent.target)
}

#[async_trait]
impl RouteBackend for LinuxRouteBackend {
    async fn resolve_target(
        &self,
        zone: &ZoneConfig,
        family: AddressFamily,
    ) -> Result<RouteTarget> {
        match zone.route_type {
            RouteType::Dev => {
                let device = tokio::fs::read_to_string(&zone.route_target)
                    .await
                    .with_context(|| {
                        format!(
                            "Device file '{}' not found (VPN not connected?)",
                            zone.route_target
                        )
                    })?;
                let device = device.trim().to_string();
                if device.is_empty() {
                    anyhow::bail!("Device file '{}' is empty", zone.route_target);
                }
                let ifindex = self.io.ifindex_of(&device).await?;
                Ok(RouteTarget::Device {
                    name: device,
                    ifindex: Some(ifindex),
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
        // A row already occupying this prefix decides the outcome: the
        // previous exact Owned observation is the only row this backend may
        // treat as its own; a compatible pre-existing row may satisfy
        // forwarding but is owned=false; anything else is a foreign row we
        // must not clobber (08D1 §16.4, §31.24 trust boundary).
        let rows = self.rows_for(&intent.key).await?;
        if rows.is_empty() {
            match self.add_row(intent).await {
                Ok(()) => return self.prove_added(intent).await,
                Err(e) if Self::is_busy_class(&e) => {
                    // A concurrent writer may have installed a row between our
                    // lookup and the add; only an exact read-back can classify
                    // it.
                    let rows = self.refresh_key(&intent.key).await?;
                    return self.classify_rows(intent, previous, rows).await;
                }
                Err(e) => return Err(e),
            }
        }
        self.classify_rows(intent, previous, rows).await
    }

    async fn remove_route(
        &self,
        intent: &RouteIntent,
        ownership: Option<&RouteOwnership>,
    ) -> Result<()> {
        // §14.5: no ownership or owned=false performs no kernel deletion; a
        // local owned=true row must carry its exact observation (invariant).
        let Some(ownership) = ownership else {
            return Ok(());
        };
        if !ownership.owned {
            return Ok(());
        }
        let Some(observed) = &ownership.observed else {
            anyhow::bail!(
                "owned route {} lost its exact observation: cleanup invariant violated",
                intent.key.prefix.network
            );
        };
        let rows = self.rows_for(&intent.key).await?;
        match rows.as_slice() {
            // Delete only the exact owned identity; a foreign row on the
            // same prefix belongs to someone else.
            [row] if row.identity == observed.identity && row.target == intent.target => {
                self.delete_row(intent).await?;
                self.refresh_key(&intent.key).await?;
                Ok(())
            }
            [row] => {
                tracing::debug!(
                    prefix = %intent.key.prefix.network,
                    prefix_len = intent.key.prefix.prefix_len,
                    owner = ?row.target,
                    identity = ?row.identity,
                    "Leaving a non-owned row in place"
                );
                Ok(())
            }
            // The exact owned row is already gone: absence is success.
            [] => Ok(()),
            rows => {
                tracing::debug!(
                    prefix = %intent.key.prefix.network,
                    rows = rows.len(),
                    "Leaving an ambiguous multi-row prefix in place"
                );
                Ok(())
            }
        }
    }

    async fn snapshot(&self) -> Result<Vec<ObservedRoute>> {
        // Explicit snapshot/audit (08D1 §16.3): the only full dump outside
        // lazy initialization.
        self.full_snapshot().await?;
        let cache = self.cache.read().await;
        Ok(cache.values().flatten().cloned().collect())
    }

    async fn observe_key(&self, key: &RouteKey) -> Result<Vec<ObservedRoute>> {
        // Targeted event path (08D1 §16.3): read this key back from the
        // kernel and update only this cache entry. Never a family dump.
        self.refresh_key(key).await
    }

    fn take_invalidation_receiver(&self) -> Option<mpsc::UnboundedReceiver<RouteInvalidation>> {
        self.invalidation_rx
            .try_lock()
            .ok()
            .and_then(|mut guard| guard.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex as StdMutex;

    #[test]
    fn leshy_protocol_is_boot() {
        // Rows installed by earlier versions used the kernel default, which is
        // `boot`; keeping it avoids an adoption migration.
        assert_eq!(u8::from(LESHY_PROTOCOL), 3);
    }

    #[test]
    fn main_table_is_254() {
        assert_eq!(MAIN_TABLE, 254);
    }

    #[test]
    fn destination_extraction_v4() {
        let mut msg = RouteMessage::default();
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Destination(
                RouteAddress::Inet(Ipv4Addr::new(10, 1, 2, 3)),
            ));
        assert_eq!(
            destination_of(&msg),
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
        );
    }

    #[test]
    fn destination_extraction_v6() {
        let mut msg = RouteMessage::default();
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Destination(
                RouteAddress::Inet6(Ipv6Addr::LOCALHOST),
            ));
        assert_eq!(destination_of(&msg), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn destination_missing_is_none() {
        let msg = RouteMessage::default();
        assert_eq!(destination_of(&msg), None);
    }

    #[test]
    fn gateway_wins_over_oif() {
        let mut msg = RouteMessage::default();
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Oif(7));
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Gateway(
                RouteAddress::Inet(Ipv4Addr::new(192, 168, 1, 1)),
            ));
        let names = HashMap::new();
        assert_eq!(
            target_of(&msg, &names),
            Some(RouteTarget::Gateway(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1
            ))))
        );
    }

    #[test]
    fn oif_becomes_device_target_with_name() {
        let mut msg = RouteMessage::default();
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Oif(7));
        let mut names = HashMap::new();
        names.insert(7u32, "tun0".to_string());
        assert_eq!(
            target_of(&msg, &names),
            Some(RouteTarget::Device {
                name: "tun0".to_string(),
                ifindex: Some(7),
            })
        );
    }

    #[test]
    fn no_target_attributes_is_none() {
        let msg = RouteMessage::default();
        assert_eq!(target_of(&msg, &HashMap::new()), None);
    }

    // --- cache/generation/replacement seam --------------------------------

    struct FakeState {
        rows: Vec<ObservedRoute>,
        names: HashMap<u32, String>,
        dumps: u64,
        reads: Vec<RouteKey>,
        adds: Vec<RouteIntent>,
        replaces: Vec<RouteIntent>,
        deletes: Vec<RouteIntent>,
        bump_generation: Option<Arc<AtomicU64>>,
        bump_after_first_dump: bool,
        force_read: Option<Vec<ObservedRoute>>,
        /// Resolve a Device target's name from the `names` map handed to
        /// `read_prefix`, like the real kernel read-back does.
        resolve_names: bool,
    }

    struct FakeIo {
        state: StdMutex<FakeState>,
    }

    impl FakeIo {
        fn new(rows: Vec<ObservedRoute>) -> Self {
            let mut names = HashMap::new();
            names.insert(7u32, "tun0".to_string());
            Self {
                state: StdMutex::new(FakeState {
                    rows,
                    names,
                    dumps: 0,
                    reads: Vec::new(),
                    adds: Vec::new(),
                    replaces: Vec::new(),
                    deletes: Vec::new(),
                    bump_generation: None,
                    bump_after_first_dump: false,
                    force_read: None,
                    resolve_names: false,
                }),
            }
        }

        fn bump_during_first_dump(mut self, generation: Arc<AtomicU64>) -> Self {
            let state = self.state.get_mut().unwrap();
            state.bump_generation = Some(generation);
            state.bump_after_first_dump = true;
            self
        }

        fn force_read(mut self, rows: Vec<ObservedRoute>) -> Self {
            self.state.get_mut().unwrap().force_read = Some(rows);
            self
        }

        fn resolve_names(mut self) -> Self {
            self.state.get_mut().unwrap().resolve_names = true;
            self
        }
    }

    #[async_trait]
    impl KernelIo for FakeIo {
        async fn link_names(&self) -> Result<HashMap<u32, String>> {
            Ok(self.state.lock().unwrap().names.clone())
        }

        async fn ifindex_of(&self, device: &str) -> Result<u32> {
            let state = self.state.lock().unwrap();
            state
                .names
                .iter()
                .find_map(|(index, name)| (name == device).then_some(*index))
                .ok_or_else(|| anyhow::anyhow!("Device '{device}' not found"))
        }

        async fn dump_family(
            &self,
            family: AddressFamily,
            _names: &HashMap<u32, String>,
        ) -> Result<Vec<ObservedRoute>> {
            let mut state = self.state.lock().unwrap();
            state.dumps += 1;
            if state.bump_after_first_dump && state.dumps == 1 {
                if let Some(generation) = &state.bump_generation {
                    generation.fetch_add(1, Ordering::SeqCst);
                }
            }
            Ok(state
                .rows
                .iter()
                .filter(|row| row.key.prefix.family() == family)
                .cloned()
                .collect())
        }

        async fn read_prefix(
            &self,
            key: &RouteKey,
            names: &HashMap<u32, String>,
        ) -> Result<Vec<ObservedRoute>> {
            let mut state = self.state.lock().unwrap();
            state.reads.push(key.clone());
            if let Some(rows) = &state.force_read {
                return Ok(rows.clone());
            }
            let mut rows: Vec<ObservedRoute> = state
                .rows
                .iter()
                .filter(|row| row.key == *key)
                .cloned()
                .collect();
            if state.resolve_names {
                for row in &mut rows {
                    if let RouteTarget::Device {
                        ifindex: Some(index),
                        name,
                    } = &mut row.target
                    {
                        *name = names.get(index).cloned().unwrap_or_default();
                    }
                }
            }
            Ok(rows)
        }

        async fn add(&self, intent: &RouteIntent) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            state.adds.push(intent.clone());
            if !state.rows.iter().any(|row| row.key == intent.key) {
                state.rows.push(synthesize(intent));
            }
            Ok(())
        }

        async fn replace(&self, intent: &RouteIntent) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            state.replaces.push(intent.clone());
            state.rows.retain(|row| row.key != intent.key);
            state.rows.push(synthesize(intent));
            Ok(())
        }

        async fn delete(&self, intent: &RouteIntent) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            state.deletes.push(intent.clone());
            state.rows.retain(|row| row.key != intent.key);
            Ok(())
        }
    }

    fn synthesize(intent: &RouteIntent) -> ObservedRoute {
        ObservedRoute {
            key: intent.key.clone(),
            target: intent.target.clone(),
            identity: RouteKernelIdentity {
                ifindex: match &intent.target {
                    RouteTarget::Device { ifindex, .. } => *ifindex,
                    _ => None,
                },
                next_hop: match &intent.target {
                    RouteTarget::Gateway(gateway) => Some(*gateway),
                    _ => None,
                },
                protocol: u8::from(LESHY_PROTOCOL),
                metric: expected_metric(&intent.key.prefix),
                scope: expected_scope(&intent.key.prefix, &intent.target),
                interface_luid: None,
            },
        }
    }

    fn host_v4(a: u8, b: u8, c: u8, d: u8, ifindex: u32) -> RouteIntent {
        RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(a, b, c, d))),
                table: MAIN_TABLE,
            },
            zone: "netns".to_string(),
            target: RouteTarget::Device {
                name: "tun0".to_string(),
                ifindex: Some(ifindex),
            },
            source: super::super::model::RouteSource::Dns,
        }
    }

    fn host_v6(a: u16, ifindex: u32) -> RouteIntent {
        RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::host(IpAddr::V6(Ipv6Addr::new(0xfd00, a, 0, 0, 0, 0, 0, 1))),
                table: MAIN_TABLE,
            },
            zone: "netns".to_string(),
            target: RouteTarget::Device {
                name: "tun0".to_string(),
                ifindex: Some(ifindex),
            },
            source: super::super::model::RouteSource::Dns,
        }
    }

    fn test_backend(io: Arc<FakeIo>, generation: Arc<AtomicU64>) -> LinuxRouteBackend {
        LinuxRouteBackend::with_io(io, generation, None)
    }

    fn snapshot_counters(backend: &LinuxRouteBackend) -> (u64, u64, u64, u64, u64) {
        (
            backend.counters.full_snapshots.load(Ordering::SeqCst),
            backend.counters.targeted_reads.load(Ordering::SeqCst),
            backend.counters.adds.load(Ordering::SeqCst),
            backend.counters.deletes.load(Ordering::SeqCst),
            backend.counters.replaces.load(Ordering::SeqCst),
        )
    }

    #[tokio::test]
    async fn lazy_cache_initializes_once() {
        let intent = host_v4(10, 0, 0, 1, 7);
        let io = Arc::new(FakeIo::new(vec![synthesize(&intent)]));
        let generation = Arc::new(AtomicU64::new(0));
        let backend = test_backend(Arc::clone(&io), Arc::clone(&generation));

        backend.ensure_cache_initialized().await.unwrap();
        backend.ensure_cache_initialized().await.unwrap();

        let (full, ..) = snapshot_counters(&backend);
        assert_eq!(full, 1, "the lazy cache must initialize exactly once");
    }

    #[tokio::test]
    async fn event_during_initial_snapshot_forces_retry() {
        let intent = host_v4(10, 0, 0, 1, 7);
        let generation = Arc::new(AtomicU64::new(0));
        let io = Arc::new(
            FakeIo::new(vec![synthesize(&intent)]).bump_during_first_dump(Arc::clone(&generation)),
        );
        let backend = test_backend(io, Arc::clone(&generation));

        backend.ensure_cache_initialized().await.unwrap();

        let (full, ..) = snapshot_counters(&backend);
        assert_eq!(
            full, 2,
            "an event during the snapshot must force a second read"
        );
        assert_eq!(
            backend.cache_generation.load(Ordering::SeqCst),
            generation.load(Ordering::SeqCst),
            "the published cache must be current against the monitor"
        );
    }

    #[tokio::test]
    async fn generation_mismatch_targets_only_the_requested_key() {
        let intent = host_v4(10, 0, 0, 1, 7);
        let other = host_v4(10, 0, 0, 2, 7);
        let io = Arc::new(FakeIo::new(vec![synthesize(&intent), synthesize(&other)]));
        let generation = Arc::new(AtomicU64::new(0));
        let backend = test_backend(Arc::clone(&io), Arc::clone(&generation));
        backend.ensure_cache_initialized().await.unwrap();

        // A kernel event lands: the cache is no longer proven current.
        generation.fetch_add(1, Ordering::SeqCst);
        let rows = backend.rows_for(&intent.key).await.unwrap();

        assert_eq!(rows.len(), 1);
        let (full, targeted, ..) = snapshot_counters(&backend);
        assert_eq!(full, 1, "a mismatch must not trigger a full snapshot");
        assert_eq!(targeted, 1, "exactly one targeted read for the key");
        let reads = &io.state.lock().unwrap().reads;
        assert_eq!(reads.as_slice(), std::slice::from_ref(&intent.key));
    }

    #[tokio::test]
    async fn exact_cache_hit_does_no_kernel_io() {
        let intent = host_v4(10, 0, 0, 1, 7);
        let io = Arc::new(FakeIo::new(vec![synthesize(&intent)]));
        let generation = Arc::new(AtomicU64::new(0));
        let backend = test_backend(io, Arc::clone(&generation));
        backend.ensure_cache_initialized().await.unwrap();

        backend.rows_for(&intent.key).await.unwrap();
        backend.rows_for(&intent.key).await.unwrap();

        let (full, targeted, ..) = snapshot_counters(&backend);
        assert_eq!(full, 1);
        assert_eq!(targeted, 0, "a current cache hit must not touch the kernel");
    }

    #[tokio::test]
    async fn targeted_read_back_v4_and_v6() {
        let io = Arc::new(FakeIo::new(Vec::new()));
        let generation = Arc::new(AtomicU64::new(0));
        let backend = test_backend(Arc::clone(&io), generation);

        let v4 = host_v4(10, 0, 0, 1, 7);
        let v6 = host_v6(0x55, 7);
        backend.ensure_route(&v4, None).await.unwrap();
        backend.ensure_route(&v6, None).await.unwrap();

        let (_, targeted, adds, _, _) = snapshot_counters(&backend);
        assert_eq!(adds, 2);
        assert_eq!(targeted, 2, "each mutation reads back only its own key");
        let reads = &io.state.lock().unwrap().reads;
        assert_eq!(reads, &[v4.key.clone(), v6.key.clone()]);
    }

    #[tokio::test]
    async fn protocol_metric_scope_or_target_mismatch_conflicts() {
        let intent = host_v4(10, 0, 0, 1, 7);
        let generation = Arc::new(AtomicU64::new(0));

        // Wrong protocol: a same-prefix row written by someone else.
        let mut foreign = synthesize(&intent);
        foreign.identity.protocol = u8::from(RouteProtocol::Static);
        let backend = test_backend(
            Arc::new(FakeIo::new(vec![foreign])),
            Arc::clone(&generation),
        );
        assert!(
            backend.ensure_route(&intent, None).await.is_err(),
            "a same-key row without Leshy's exact identity is a conflict"
        );

        // Wrong metric.
        let mut foreign = synthesize(&intent);
        foreign.identity.metric = 5;
        let backend = test_backend(
            Arc::new(FakeIo::new(vec![foreign])),
            Arc::clone(&generation),
        );
        assert!(
            backend.ensure_route(&intent, None).await.is_err(),
            "a same-key row with a different metric is a conflict"
        );

        // Wrong scope (an IPv4 device route is link scope).
        let mut foreign = synthesize(&intent);
        foreign.identity.scope = u8::from(RouteScope::Universe);
        let backend = test_backend(
            Arc::new(FakeIo::new(vec![foreign])),
            Arc::clone(&generation),
        );
        assert!(
            backend.ensure_route(&intent, None).await.is_err(),
            "a same-key row with a different scope is a conflict"
        );

        // Wrong OIF (and therefore a different Device target) is a conflict too.
        let other_ifindex = host_v4(10, 0, 0, 1, 9);
        let backend = test_backend(
            Arc::new(FakeIo::new(vec![synthesize(&intent)])),
            Arc::new(AtomicU64::new(0)),
        );
        assert!(backend.ensure_route(&other_ifindex, None).await.is_err());
    }

    #[tokio::test]
    async fn exact_previous_owned_target_is_replaced() {
        let old = host_v4(10, 0, 0, 1, 7);
        let new = host_v4(10, 0, 0, 1, 9);
        let observed = synthesize(&old);
        let previous = RouteOwnership {
            owned: true,
            observed: Some(observed.clone()),
        };
        let io = Arc::new(FakeIo::new(vec![observed]));
        let generation = Arc::new(AtomicU64::new(0));
        let backend = test_backend(Arc::clone(&io), generation);

        let result = backend.ensure_route(&new, Some(&previous)).await.unwrap();
        assert_eq!(result.outcome, EnsureOutcome::Added);
        assert!(result.ownership.owned);
        assert_eq!(
            result.ownership.observed.as_ref().unwrap().target,
            new.target
        );

        let state = io.state.lock().unwrap();
        assert_eq!(state.replaces.len(), 1, "the owned row is replaced");
        assert!(
            state.deletes.is_empty(),
            "replacement never deletes by prefix"
        );
    }

    #[tokio::test]
    async fn foreign_target_change_conflicts_without_deleting() {
        let old = host_v4(10, 0, 0, 1, 7);
        let new = host_v4(10, 0, 0, 1, 9);
        let io = Arc::new(FakeIo::new(vec![synthesize(&old)]));
        let generation = Arc::new(AtomicU64::new(0));
        let backend = test_backend(Arc::clone(&io), generation);

        // No recorded ownership: the existing row is foreign.
        assert!(backend.ensure_route(&new, None).await.is_err());
        let state = io.state.lock().unwrap();
        assert!(state.replaces.is_empty());
        assert!(state.deletes.is_empty());
        assert_eq!(state.rows.len(), 1);
        assert_eq!(state.rows[0].target, old.target);
    }

    #[tokio::test]
    async fn race_changed_identity_is_not_treated_as_owned() {
        let old = host_v4(10, 0, 0, 1, 7);
        let new = host_v4(10, 0, 0, 1, 9);
        let observed = synthesize(&old);
        let previous = RouteOwnership {
            owned: true,
            observed: Some(observed.clone()),
        };
        // The proof read sees a different row than the recorded observation.
        let mut changed = observed.clone();
        changed.identity.metric = 5;
        let io = Arc::new(FakeIo::new(vec![changed]).force_read(vec![synthesize(&old)]));
        let generation = Arc::new(AtomicU64::new(0));
        let backend = test_backend(Arc::clone(&io), generation);

        // The cached row differs from the recorded identity, so the replace
        // path is not entered; the mutation is refused.
        assert!(backend.ensure_route(&new, Some(&previous)).await.is_err());
        assert!(io.state.lock().unwrap().replaces.is_empty());
    }

    #[tokio::test]
    async fn remove_deletes_only_the_exact_owned_identity() {
        let intent = host_v4(10, 0, 0, 1, 7);
        let observed = synthesize(&intent);
        let io = Arc::new(FakeIo::new(vec![observed.clone()]));
        let generation = Arc::new(AtomicU64::new(0));
        let backend = test_backend(Arc::clone(&io), generation);

        let owned = RouteOwnership {
            owned: true,
            observed: Some(observed),
        };
        backend.remove_route(&intent, Some(&owned)).await.unwrap();
        assert_eq!(io.state.lock().unwrap().deletes.len(), 1);

        let unowned = RouteOwnership {
            owned: false,
            observed: None,
        };
        backend.remove_route(&intent, Some(&unowned)).await.unwrap();
        assert_eq!(io.state.lock().unwrap().deletes.len(), 1);
    }

    #[tokio::test]
    async fn thousand_duplicate_hits_after_convergence_stay_flat() {
        let intent = host_v4(10, 0, 0, 1, 7);
        let io = Arc::new(FakeIo::new(vec![synthesize(&intent)]));
        let generation = Arc::new(AtomicU64::new(0));
        let backend = test_backend(io, generation);

        for _ in 0..1000 {
            let result = backend.ensure_route(&intent, None).await.unwrap();
            assert_eq!(result.outcome, EnsureOutcome::AlreadyMatching);
        }

        let (full, targeted, adds, deletes, replaces) = snapshot_counters(&backend);
        assert_eq!(full, 1);
        assert_eq!(targeted, 0);
        assert_eq!(adds, 0);
        assert_eq!(deletes, 0);
        assert_eq!(replaces, 0);
    }

    #[tokio::test]
    async fn snapshot_resyncs_the_generation_for_the_fast_path() {
        let intent = host_v4(10, 0, 0, 1, 7);
        let io = Arc::new(FakeIo::new(vec![synthesize(&intent)]));
        let generation = Arc::new(AtomicU64::new(0));
        let backend = test_backend(io, Arc::clone(&generation));
        backend.ensure_cache_initialized().await.unwrap();

        generation.fetch_add(3, Ordering::SeqCst);
        backend.snapshot().await.unwrap();
        assert_eq!(
            backend.cache_generation.load(Ordering::SeqCst),
            generation.load(Ordering::SeqCst)
        );

        backend.rows_for(&intent.key).await.unwrap();
        assert_eq!(snapshot_counters(&backend).1, 0, "cache hit after resync");
    }

    #[tokio::test]
    async fn refresh_key_resolves_a_recreated_interface_name() {
        let old = host_v4(10, 0, 0, 1, 7);
        let new = host_v4(10, 0, 0, 1, 9);
        let io = Arc::new(FakeIo::new(vec![synthesize(&old)]).resolve_names());
        let generation = Arc::new(AtomicU64::new(0));
        let backend = test_backend(Arc::clone(&io), Arc::clone(&generation));

        backend.ensure_cache_initialized().await.unwrap();
        assert_eq!(
            backend.ensure_route(&old, None).await.unwrap().outcome,
            EnsureOutcome::AlreadyMatching
        );

        // The interface is recreated: the kernel keeps the device name but
        // assigns a new ifindex, and the old row is gone with the old device.
        {
            let mut state = io.state.lock().unwrap();
            state.names.clear();
            state.names.insert(9, "tun0".to_string());
            state.rows = vec![synthesize(&new)];
        }
        // A link/route event makes the cached snapshot stale.
        generation.fetch_add(1, Ordering::SeqCst);

        // The targeted read must resolve the new ifindex's name. A stale link
        // map reads the row back with an empty device name, which would turn
        // the repair into a foreign conflict (08D1 §16.4/§16.6).
        let result = backend.ensure_route(&new, None).await.unwrap();
        assert_eq!(result.outcome, EnsureOutcome::AlreadyMatching);
    }
}
