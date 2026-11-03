# Implementation plan: unified dual-stack route registry and reconciliation (Linux + Windows)

**Status:** COMPLETE — commits 1–9 landed and the acceptance gate is green (fmt, clippy `-D warnings`, full test suite, and the privileged netns harness `tests/linux-route-registry-netns.sh` on a disposable kernel; the managed backend stays unenabled until Kikimora packet 08D).  
**Leshy baseline reviewed:** master at `ba53d42ac12f2efefe66f0a1a27f8d47544d2267`; code baseline before this document is v0.5.2 / `277fd6d9699fd6a08e148a37a268e4bdefbedabc`.  
**Primary targets:** Linux and Windows. Both must receive the same registry, dedupe, exact-observation and event-driven reconciliation semantics in this fix. macOS must continue to compile and preserve current behavior; its equivalent kernel-observation/event implementation may follow separately.  
**Kikimora integration:** explicitly deferred until the standalone/local route registry is complete; the final integration architecture is fixed in section 12 and in Kikimora's own integration packet.

## 0. Final architecture decisions

These decisions are final for this fix.

1. **One logical DNS zone handles both address families.** The DNS record/address type selects the family: A/IPv4 produces IPv4 route intents; AAAA/IPv6 produces IPv6 route intents. There are no duplicate per-family zones.
2. **IPv4 and IPv6 use one route lifecycle.** Both go through the same registry, dedupe, target resolution, kernel reconciliation and error handling. IPv4 aggregation is an optional planner in front of the registry; IPv6 stays at /128 unless a future explicitly reviewed IPv6 aggregation feature is added.
3. **DNS cache and route registry remain separate.** A cached DNS response still produces route intents, but a verified registry entry makes that operation a zero-kernel-I/O fast path.
4. **Desired, observed and authorized are different states.** Never use a HashSet of previously seen addresses as proof that a route still exists.
5. **No DNS-TTL route deletion.** TTL expiry is not connection expiry. Dynamic routes live until explicit zone/config retirement or process lifecycle cleanup. Growth is bounded by a hard registry capacity; when capacity is reached, a new unique route is denied fail-closed instead of silently growing the FIB or returning an unrouted address.
6. **Kikimora parking stays in Kikimora.** Leshy does not absorb VPN lifecycle or fail-closed parking.
7. **Managed Kikimora mode ultimately has one FIB writer: Kikimora.** After integration, Leshy sends route intents to Kikimora and does not mutate managed selected routes itself. The generation/ACK dual-writer protocol proposed in the previous RFC is superseded.
8. **Standalone Leshy remains a local route writer.** The local registry/backend described below is required even when Kikimora is not installed.
9. **Existing `ipv6` is an enable policy, never a family selector.** The actual family always comes from the IP address. In v0.6 configuration semantics, IPv6 is disabled unless explicitly enabled for the zone; this removes the current special case where every `via` zone implicitly advertises IPv6.
10. **A route target must match the address family.** IPv4 and IPv6 gateway addresses are never silently mixed.

## 1. Bugs this implementation closes

The current code has these concrete defects.

- `src/routing/mod.rs::RouteManager::add_route`: IPv4 enters `add_route_v4`, but IPv6 bypasses all dedupe through `add_route_simple(ip, 128, zone)`.
- `src/routing/aggregator.rs::RouteAggregator::process_ip`: the `installed` map is mutated before all corresponding kernel actions succeed. Desired state and observed kernel state are conflated.
- `src/routing/mod.rs::RouteManager::add_route_v4`: an empty aggregation action list calls `route_matches`; on Linux this becomes a full main-table route dump on every repeated DNS classification.
- `src/routing/linux.rs::LinuxRouteAdder::route_matches`: a dump is filtered in userspace. It also compares an individual host address with `known_prefix`; when an IPv4 host is covered by a wider aggregate, the requested destination is not canonicalized to the aggregate network.
- `src/routing/linux.rs::add_via_route`: an IPv6 destination with an IPv4 gateway, or the reverse, silently omits the gateway attribute rather than rejecting the invalid route.
- `src/routing/linux.rs::add_via_route` and `add_dev_route`: EEXIST is accepted without proving that the existing route points to the intended gateway/device.
- `src/zones/matcher.rs::CidrRange`: exclusive-zone CIDR exclusions are IPv4-only.
- `src/reload.rs::get_zones_to_cleanup`: reload notices deleted zone names only; a same-name zone whose route target/family policy/static routes changed is not reconciled as a route-policy change.
- `src/routing/mod.rs::cleanup_zone`: tracking is forgotten but kernel routes are deliberately left behind.
- `src/dns/handler.rs::handle_request`: cache hits call `add_routes_from_response` again, which is correct for safety, but the current route layer turns that into repeated kernel work.
- Linux has no bounded dynamic-route admission policy. An active long-lived zone can accumulate CDN destinations indefinitely.
- `src/routing/windows.rs::find_route_rows` calls `GetIpForwardTable2` and filters the entire forwarding table. Because common `RouteManager::add_route_v4` invokes `route_matches` for repeated known IPv4 destinations, Windows has the same request-path O(FIB) scan class as Linux.
- Windows IPv6 also goes through common `add_route_simple`, so every repeated AAAA classification calls `CreateIpForwardEntry2`; on `ERROR_OBJECT_ALREADY_EXISTS` the current code then calls `find_route_rows`, turning repeated IPv6 into an add attempt plus full-table enumeration.
- `src/routing/windows.rs::create_route` deletes every same-prefix row that does not match the desired interface/metric/next hop before retrying create. A same-prefix foreign route can therefore be deleted. This must be replaced by ownership-aware conflict handling.
- `src/routing/windows.rs::delete_routes` deletes all rows matching only destination/prefix, again without proving Leshy ownership.
- `src/routing/windows.rs::route_matches` treats matching ifindex or next-hop as success but does not require the full expected row identity; it must move to the same exact `ObservedRoute` comparison as Linux.
- Windows has the same canonical-prefix bug for IPv4 aggregation: looking up the original host address with a wider prefix does not identify the canonical aggregate network reliably.

The observed legacy 0.4.0 host showed the practical form of the IPv6 defect: 1,225 IPv6 add attempts in one hour for only 127 distinct IPv6 addresses. That field measurement is a regression input, not evidence about v0.5.2 behavior.

## 2. Target module layout

Keep `src/routing/mod.rs` as the public orchestration layer and add these modules:

~~~text
src/routing/
  mod.rs             RouteManager orchestration only
  model.rs           canonical cross-family route types
  registry.rs        desired/observed route state + per-key serialization
  aggregator.rs      pure IPv4 desired-prefix planner
  backend.rs         platform backend trait and common outcomes
  linux.rs           Linux backend + snapshot/event monitor
  macos.rs           existing writer adapted to backend trait
  windows.rs         Windows IP Helper backend + snapshot/event monitor
~~~

Do not put DNS TTL/cache types in `routing/`.

### 2.1 Canonical model — new `src/routing/model.rs`

Add:

~~~rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum AddressFamily { V4, V6 }

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct RoutePrefix {
    pub network: IpAddr,   // always canonical network address
    pub prefix_len: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum RouteTarget {
    Device { name: String, ifindex: Option<u32> },
    Gateway(IpAddr),
    Unreachable,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RouteKey {
    pub prefix: RoutePrefix,
    pub table: u32,        // 254/main for current Leshy routes
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RouteSource { Dns, Static }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteIntent {
    pub key: RouteKey,
    pub zone: String,
    pub target: RouteTarget,
    pub source: RouteSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedRoute {
    pub key: RouteKey,
    pub target: RouteTarget,
    pub protocol: u8,
    pub metric: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteState { Pending, Verified, Dirty, Denied, Error }
~~~

Required helpers:

~~~rust
impl RoutePrefix {
    pub fn new(ip: IpAddr, prefix_len: u8) -> Result<Self>;
    pub fn host(ip: IpAddr) -> Self; // /32 or /128
    pub fn family(&self) -> AddressFamily;
}
~~~

`RoutePrefix::new` must canonicalize the network bits for both families. The rest of the routing code must never construct a non-canonical prefix directly.

No new CIDR crate is required; use `Ipv4Addr::to_bits/from_bits` and `Ipv6Addr::to_bits/from_bits` in this one module. Unit-test /0, host prefixes and non-canonical /24 and /64 inputs.

## 3. Platform backend contract — new `src/routing/backend.rs`

Replace the current low-level `RouteAdder` contract with one intent-aware backend contract:

~~~rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnsureOutcome {
    Added,
    AlreadyMatching,
}

#[async_trait]
pub(crate) trait RouteBackend: Send + Sync {
    async fn resolve_target(&self, zone: &ZoneConfig, family: AddressFamily)
        -> Result<RouteTarget>;

    async fn ensure_route(&self, intent: &RouteIntent) -> Result<EnsureOutcome>;

    async fn remove_route(&self, intent: &RouteIntent) -> Result<()>;

    async fn snapshot(&self) -> Result<Vec<ObservedRoute>>;

    fn take_invalidation_receiver(&self)
        -> Option<tokio::sync::mpsc::UnboundedReceiver<RouteInvalidation>>;
}
~~~

`RouteInvalidation` is:

~~~rust
pub enum RouteInvalidation {
    Prefix(RouteKey),
    Interface(u32),
    Full,
}
~~~

macOS may return `None` for the invalidation receiver in the first implementation. **Linux and Windows must both implement `snapshot()` and route-change invalidation in this fix.** The common registry fast path is platform-independent; neither Linux nor Windows may perform a full route-table enumeration because a DNS response was replayed.

### Exact entry points

- Move device-file reading out of `RouteManager::read_device_file` into each platform backend's `resolve_target`.
- Replace `add_via_route`, `add_dev_route`, `route_matches` and `remove_route` calls in `src/routing/mod.rs` with the backend interface.
- Add `RouteManager::with_backend(...)` under `#[cfg(test)]` so all reconciliation tests use a fake backend with mutation counters.

## 4. Unified registry — new `src/routing/registry.rs`

### 4.1 Data structure

Use a two-level structure so unrelated addresses are not serialized behind one lock:

~~~rust
pub struct RouteRegistry {
    entries: RwLock<HashMap<RouteKey, Arc<Mutex<RouteEntry>>>>,
    max_dynamic_routes: usize,
}

pub struct RouteEntry {
    desired: Option<RouteIntent>,
    observed: Option<ObservedRoute>,
    state: RouteState,
    dirty_epoch: u64,
    verified_epoch: u64,
    last_error: Option<String>,
}
~~~

The map lock may be held only while finding/inserting an `Arc<Mutex<RouteEntry>>`. The per-entry mutex may span one backend await; this deliberately coalesces concurrent DNS requests for the same route while allowing different prefixes to proceed concurrently.

### 4.2 Required methods

~~~rust
pub async fn ensure(
    &self,
    intent: RouteIntent,
    backend: &dyn RouteBackend,
    kernel_epoch: u64,
) -> Result<EnsureOutcome>;

pub async fn mark_dirty(&self, invalidation: RouteInvalidation, epoch: u64);

pub async fn reconcile_dirty(
    &self,
    backend: &dyn RouteBackend,
    snapshot: &[ObservedRoute],
    epoch: u64,
) -> ReconcileReport;

pub async fn remove_zone(
    &self,
    zone: &str,
    backend: &dyn RouteBackend,
) -> Result<ZoneRemovalReport>;

pub async fn count_dynamic(&self) -> usize;
~~~

### 4.3 Fast-path invariant

`ensure` returns `AlreadyMatching` **without backend I/O** only when all are true:

- the exact same `RouteIntent` is still desired;
- state is `Verified`;
- `verified_epoch == kernel_epoch` or the entry was not affected by later targeted invalidations;
- target identity has not changed.

A DNS cache hit for an unchanged verified route therefore does no netlink write and no FIB dump.

### 4.4 Capacity invariant

Add to `ServerConfig`:

~~~rust
#[serde(default = "default_max_dynamic_routes")]
pub max_dynamic_routes: usize;
~~~

Default: **16384 logical DNS host intents**.

Rules:

- existing intents are always allowed to refresh/reconcile;
- static routes do not consume this quota;
- IPv4 + IPv6 dynamic intents share the quota;
- aggregation does not hide logical intents from the quota;
- when a new unique DNS intent would exceed the quota, return a typed `RouteError::CapacityExceeded`;
- `DnsHandler` always converts `CapacityExceeded`, `AuthorityDenied` and family-policy denial into SERVFAIL/NODATA as specified below, even when legacy `route_failure_mode = "fallback"` is configured. The compatibility fallback applies only to ordinary route-application errors.

This is the bounded-growth fix. Do **not** invent automatic DNS-TTL route deletion in this change.

## 5. Make the IPv4 aggregator a pure desired-state planner

### Entry point: `src/routing/aggregator.rs`

Rename the semantic meaning of `installed`; it must no longer claim kernel truth.

Preferred shape:

~~~rust
pub struct RouteAggregator {
    known_ips: HashMap<Ipv4Addr, RouteOwner>,
    desired: HashMap<(u32, u8), RouteOwner>,
    prefix_len: u8,
}

pub struct AggregationPlan {
    pub next_desired: HashMap<(u32, u8), RouteOwner>,
    pub adds: Vec<RouteIntent>,
    pub removes: Vec<RouteIntent>,
}
~~~

`plan_ip(...)` computes the next desired prefix set. It may update logical `known_ips`, but **only RouteRegistry/backend verification determines observed/Verified state**.

### Safe mutation ordering

When an existing broad aggregate must be split:

1. add all more-specific replacement routes;
2. verify those adds;
3. add the new conflicting-zone /32;
4. verify it;
5. remove the superseded broad route last.

Never remove the broad route first. A partial failure must leave a route rather than open a direct/default gap.

If any action fails:

- keep the intended desired plan;
- mark affected registry entries Dirty/Error;
- perform one batched snapshot/reconcile;
- return failure to DNS for the new address until the correct route is Verified.

### Canonical aggregate key

Every aggregate `RouteIntent` uses `RoutePrefix::new(network, prefix)`. Never call the backend with the original host IP and a wider prefix.

## 6. Refactor RouteManager around intents

### Entry point: `src/routing/mod.rs`

Replace fields:

~~~rust
adder
zone_routes
aggregator
~~~

with:

~~~rust
backend: Arc<dyn RouteBackend>,
registry: Arc<RouteRegistry>,
aggregator: Mutex<RouteAggregator>,
kernel_epoch: AtomicU64,
~~~

Keep `RouteManager::new` as the production constructor. It creates the platform backend, registry and Linux monitor/audit task.

### 6.1 `RouteManager::add_route`

New exact behavior:

~~~text
ip + zone
  -> family policy check
  -> backend.resolve_target(zone, family)
  -> build host RouteIntent
  -> IPv4: feed optional aggregator; ensure resulting canonical intents
  -> IPv6: ensure /128 intent directly
  -> registry.ensure(...)
~~~

Delete `add_route_simple` completely.

Both IPv4 and IPv6 must reach `RouteRegistry::ensure`.

### 6.2 Static routes

`add_static_route`:

- parse through `RoutePrefix::new`;
- validate family against zone policy;
- resolve family-specific target;
- submit `RouteSource::Static` to the same registry;
- IPv4 static prefixes are registered with the aggregator conflict planner before DNS aggregation;
- static routes do not consume dynamic quota.

### 6.3 Zone cleanup

`cleanup_zone` becomes real explicit cleanup:

- obtain all registry entries whose desired intent belongs to the zone;
- for each **owned exact intent**, call backend `remove_route`;
- if the backend reports a conflicting/non-owned route, do not delete it;
- remove registry entries only after successful deletion or confirmed absence;
- remove zone entries from aggregator desired/known state.

This cleanup is called only for explicit zone removal/replacement, not DNS TTL expiry.

## 7. Linux backend: exact verification and kernel-state cache

### Entry point: `src/routing/linux.rs`

### 7.1 Target resolution

`resolve_target`:

- `dev`: read the device file, resolve current ifindex and return `RouteTarget::Device { name, ifindex: Some(index) }`;
- `via`: parse the family-specific configured gateway and require gateway family == route family. A mismatch is a validation/runtime error before netlink.

### 7.2 Exact ensure semantics

`ensure_route` must no longer treat EEXIST as unconditional success.

Algorithm under one route operation:

1. perform a targeted lookup in the local kernel snapshot/cache;
2. if an exact matching row exists (canonical prefix, main table, target, expected protocol/metric), return `AlreadyMatching`;
3. if the same prefix is occupied by a conflicting route that is not known to be Leshy-owned, return `RouteConflict`; never blindly replace/delete it;
4. otherwise add/replace the owned route;
5. read back/refresh the affected prefix and require an exact match;
6. only then return `Added`.

Set a deterministic route protocol on Linux for Leshy-created rows. Keep the current protocol value if changing it would make upgrade adoption unsafe; if a dedicated protocol value is introduced, implement explicit migration/adoption tests before deleting old rows. The executor must not choose a protocol ad hoc.

### 7.3 Kernel snapshot cache

Delete the request-path use of `route_matches`.

Create a Linux monitor owned by the backend:

- startup: one full IPv4 + IPv6 main-table snapshot;
- route/link/address notifications: emit targeted `RouteInvalidation` where possible, `Full` when identity cannot be mapped safely;
- coalesce event bursts (100 ms debounce is sufficient);
- periodic safety audit: one full snapshot every 30 seconds;
- an audit/invalidation increments `RouteManager.kernel_epoch` and reconciles Dirty entries in a batch;
- DNS queries never initiate a full FIB dump.

The implementation may use the rtnetlink multicast API available to the pinned crate or a small netlink-sys listener. This is an implementation-library choice only; the state machine above is fixed.

If the event stream terminates or reports overflow:

1. mark all registry entries Dirty;
2. take a full snapshot;
3. reconcile;
4. restart the monitor with bounded backoff.

No busy retry loop.

### 7.4 Exact observed identity

Linux comparison must include:

- address family;
- canonical destination/prefix;
- table 254;
- output ifindex for device routes OR gateway for via routes;
- protocol value used by Leshy;
- route type/scope where materially required.

A route for the same destination through another interface is not success.


## 7W. Windows backend: same registry semantics, IP Helper implementation

### Entry point: `src/routing/windows.rs`

Windows is not a compatibility-only target for this fix. It implements the same `RouteBackend` contract and the same `RouteRegistry` state machine as Linux. Only the kernel API differs.

### 7W.1 Target resolution

`resolve_target`:

- `dev`: read the device file once for the operation, resolve the adapter alias/index through `ConvertInterfaceAliasToLuid` / `ConvertInterfaceLuidToIndex` with the current case-insensitive fallback, and return `RouteTarget::Device { name, ifindex: Some(index) }`;
- `via`: obtain the family-specific gateway from `ZoneConfig::gateway_for(family)`, require gateway family == destination family, resolve the egress interface through `GetBestInterface` / `GetBestInterfaceEx`, and retain both gateway and interface index in the desired Windows row identity.

Do not allow `build_route_row` to receive a destination and next hop from different address families.

### 7W.2 Snapshot

Replace request-path `find_route_rows` scans with one backend snapshot cache.

`snapshot()` calls:

~~~text
GetIpForwardTable2(AF_UNSPEC)
~~~

once and converts every relevant row into the common `ObservedRoute` representation. `AF_UNSPEC` intentionally returns both IPv4 and IPv6 in one table enumeration.

The converter must canonicalize `DestinationPrefix` through `RoutePrefix::new` and preserve enough identity to distinguish:

- canonical destination/prefix;
- interface index;
- next hop;
- route metric offset;
- route protocol;
- any row flags required to distinguish an on-link row from a gateway row.

Free every returned table with `FreeMibTable` on all success paths.

### 7W.3 Route-change monitor

Register one `NotifyRouteChange2(AF_UNSPEC, ...)` subscription. Windows supports `AF_UNSPEC` here specifically to receive both IPv4 and IPv6 route changes. The callback must be minimal and non-blocking:

1. if the notification is initial or the row pointer is null, enqueue `RouteInvalidation::Full`;
2. otherwise copy only the route key material needed to identify the changed prefix into owned Rust data while the callback row is valid;
3. enqueue `RouteInvalidation::Prefix(key)`;
4. return immediately.

Do not perform `GetIpForwardTable2`, registry locking, DNS work or reconciliation inside the native callback.

The callback row is documented as incomplete. When exact row identity is needed, the async reconciliation side may initialize a `MIB_IPFORWARD_ROW2` from destination/next-hop/interface identity and call `GetIpForwardEntry2`, or refresh the shared snapshot. Do not interpret the incomplete callback row as a fully verified route.

Store the notification handle in the Windows backend. On backend shutdown/drop, deregister with `CancelMibChangeNotify2` from a thread/task that is not the notification callback. Never call `CancelMibChangeNotify2` from inside that callback because the Windows API explicitly permits deadlock in that case.

Use the same 30-second full safety audit as Linux. The audit is insurance against missed notifications; DNS requests do not initiate it.

### 7W.4 Exact ensure semantics

Delete the current `create_route` replacement behavior that removes every nonmatching same-prefix row.

New `ensure_route(intent)`:

1. consult the shared observed snapshot/cache for the canonical prefix;
2. if an exact Leshy-owned matching row exists, return `AlreadyMatching`;
3. if a same-prefix row exists but is not provably the row owned by this registry entry, return `RouteConflict`; **do not delete or replace it**;
4. if the registry proves an older row is this intent's previous owned identity (for example previous ifindex after a controlled target change), delete/update only that exact old row;
5. create the desired row with `CreateIpForwardEntry2`;
6. on `ERROR_OBJECT_ALREADY_EXISTS`, do not treat it as success and do not broad-delete; refresh the exact prefix state and classify it as matching owned / foreign conflict / retryable drift;
7. verify the exact created row before returning success.

The route identity comparison must include at least destination/prefix, InterfaceIndex, NextHop, Metric and Protocol. An on-link route has an unspecified next hop of the matching family; that is part of its identity.

### 7W.5 Exact removal semantics

Delete `delete_routes(family, ip, prefix_len)` as a broad removal primitive from normal registry use.

`remove_route(intent)` may delete only the exact row identity stored/verified for that registry intent. If the prefix exists but the row identity differs, return conflict/absence and leave the foreign row untouched.

Zone cleanup therefore has the same ownership guarantee on Windows as on Linux.

### 7W.6 Windows tests

Pure/unit tests in `windows.rs` and common registry tests:

- canonical /32, /128 and wider aggregate destinations survive SOCKADDR conversion;
- destination/next-hop family mismatch is rejected before IP Helper calls;
- snapshot conversion preserves prefix, ifindex, next hop, metric and protocol;
- exact matching row -> `AlreadyMatching`;
- same-prefix wrong ifindex -> conflict/no delete;
- same-prefix wrong gateway -> conflict/no delete;
- same-prefix wrong protocol/metric -> conflict/no delete;
- owned previous row may be replaced explicitly;
- broad delete helper is not used by registry cleanup;
- notification callback converts v4 and v6 rows into targeted invalidations;
- initial/null notification becomes `Full`;
- 1000 repeated v4 and 1000 repeated v6 registry ensures produce no IP Helper mutations or table scans after convergence.

Windows integration test (elevated disposable runner/VM):

1. create an isolated test adapter/known loopback route target;
2. add/read-back/remove one IPv4 /32 and one IPv6 /128;
3. externally delete a Leshy-owned row and verify one notification-driven restoration;
4. add a foreign same-prefix row and verify Leshy reports conflict without deleting it;
5. replay stable intents and verify `GetIpForwardTable2` count does not grow with DNS request count.

The existing `windows-latest` CI unit job remains mandatory. Add a privileged Windows integration job only when the runner environment can guarantee route-table mutation privileges; until then the disposable Windows VM acceptance test is a release gate.

## 8. Family policy and dual-stack configuration

### Entry point: `src/config.rs`

This fix is a v0.6 configuration semantic change.

Keep:

~~~toml
ipv6 = true|false
~~~

but make semantics uniform:

- IPv4 is always enabled in this release.
- IPv6 is enabled **only** when `ipv6 = true`, for both `dev` and `via` zones.
- default `ipv6 = false` for all zones.
- `ZoneConfig::advertises_ipv6()` becomes exactly `self.ipv6`; remove the `route_type != Dev` implicit enable.

Add:

~~~rust
#[serde(default)]
pub route_target_ipv6: Option<String>;
~~~

Rules:

- `route_type = "dev"`: `route_target` is the one device-file path used for both families; `route_target_ipv6` must be absent.
- `route_type = "via"`: `route_target` is the IPv4 gateway and must parse as IPv4. When `ipv6 = true`, `route_target_ipv6` is required and must parse as IPv6.
- an IPv6 static route is invalid when `ipv6 = false`.
- mapped IPv6 addresses are rejected where family identity matters.

Add helper:

~~~rust
impl ZoneConfig {
    pub fn family_enabled(&self, family: AddressFamily) -> bool;
    pub fn gateway_for(&self, family: AddressFamily) -> Result<Option<IpAddr>>;
}
~~~

Update `config.example.toml` and README with an explicit dual-stack example.

## 9. Make exclusive CIDR exclusions dual-stack

### Entry point: `src/zones/matcher.rs`

Replace IPv4-only `CidrRange { network: u32, prefix_len }` with the same canonical `RoutePrefix` type (or a thin wrapper around it).

Required API:

~~~rust
impl CidrRange {
    fn contains(&self, ip: IpAddr) -> bool;
}
~~~

`MatchedZone::is_excluded(ip)` must work for IPv4 and IPv6.

Parsing rules:

- plain IPv4 -> /32;
- plain IPv6 -> /128;
- CIDR canonicalized;
- prefix length validated per family;
- IPv4-mapped IPv6 rejected rather than ambiguously matching v4.

Update comments that currently claim IPv4-only behavior.

## 10. DNS handler changes

### Entry points: `src/dns/handler.rs::add_routes_from_response` and `handle_request`

### 10.1 Family handling

Keep one zone match by qname.

For each answer:

- A -> IPv4 intent if IPv4 policy permits;
- AAAA -> IPv6 intent only if `zone.ipv6 == true`;
- do not use a global "select IPv4 vs IPv6" switch;
- a response may legitimately install both families.

`without_aaaa` remains the compatibility suppression helper for IPv6-disabled zones.

### 10.2 Route result classification

Change the routing return from boolean to a typed result:

~~~rust
pub enum RouteResponse {
    Ready,
    NoRouteNeeded,
    FamilySuppressed,
}

pub enum RouteError {
    Apply(anyhow::Error),
    CapacityExceeded,
    Conflict,
    AuthorityDenied, // used by later Kikimora backend
}
~~~

Policy:

- `CapacityExceeded`, `Conflict`, `AuthorityDenied`: never return an address that has no safe selected route. Return SERVFAIL for a requested enabled family; an explicitly disabled AAAA family remains NODATA through `without_aaaa`.
- ordinary `Apply` errors honor legacy `route_failure_mode`;
- managed Kikimora mode (section 12) treats controller denial as safety denial regardless of legacy fallback.

### 10.3 Cache-hit test

The existing comment "Still add routes from the cached response" remains correct. The test must prove:

~~~text
first cached/fresh classification -> one backend mutation
1000 subsequent cache hits       -> zero additional backend mutations
one targeted invalidation        -> one reconciliation
next 1000 hits                   -> zero mutations
~~~

## 11. Hot reload and explicit retirement

### Entry points: `src/reload.rs`, `src/server.rs`, `DnsHandler::update_config`

Replace `get_zones_to_cleanup/get_new_zones` with:

~~~rust
pub enum ZoneChange {
    Added(ZoneConfig),
    Removed(ZoneConfig),
    Changed { old: ZoneConfig, new: ZoneConfig },
}

pub fn diff_zones(old: &[ZoneConfig], new: &[ZoneConfig]) -> Vec<ZoneChange>;
~~~

Derive/implement `PartialEq/Eq` for config types used in this comparison.

A zone is `Changed` when any routing-relevant field changes:

- route type;
- route target / IPv6 route target;
- IPv6 enable policy;
- static routes;
- mode/exclusion CIDRs;
- domain/pattern ownership where it changes which zone can claim an IP.

Reload order for `Changed`:

1. build/validate new config and matcher fully;
2. prevent new requests from seeing half-applied config (current handler write lock is the transaction boundary);
3. reconcile/add the new static/target state first where safe;
4. remove explicit old-zone owned rows only after replacement rows are verified;
5. swap config/matcher;
6. clear DNS cache;
7. mark affected registry entries Dirty and run one reconcile.

For `Removed`, explicit kernel cleanup is allowed: removing a zone is operator intent that the destinations are no longer selected by that zone.

For `ipv6: true -> false`, suppress new AAAA immediately. Existing IPv6 rows are explicit old-zone state and must be removed only through the reload reconciliation path; in Kikimora managed mode the integration layer parks/withdraws them before removal. Standalone mode documents that explicit family disable means the operator is relinquishing that selected-route policy.

### Dynamic route lifetime

Do not add automatic per-DNS-TTL deletion.

Dynamic entries remain until:

- zone is explicitly removed/replaced;
- service performs an explicit owned-route shutdown cleanup;
- a future separately reviewed retirement feature exists.

The 16384-entry admission limit prevents silent unbounded growth.

## 12. Fixed Kikimora integration boundary

After sections 1-11 are complete and green, add a second backend implementation:

~~~text
Standalone mode:
DNS -> Leshy RouteRegistry -> Local Platform RouteBackend -> kernel

Kikimora managed mode:
DNS -> Leshy RouteRegistry -> KikimoraRouteBackend
                              -> local Kikimora control API
                              -> Kikimora selected-route registry
                              -> Kikimora Linux route executor
                              -> kernel
~~~

**Leshy must not call `LinuxRouteBackend.ensure_route/remove_route` for a managed zone.**

Add server configuration:

~~~toml
routing_backend = "local"       # default / standalone

# or
routing_backend = "kikimora"
kikimora_socket = "/run/kikimora/core.sock"
~~~

The managed backend:

- uses the existing Kikimora framed local control socket;
- calls API v3 `EnsureLeshyRoute` for a new/dirty intent;
- receives controller route generation + exact status;
- subscribes to core state and invalidates zone/family entries when readiness/generation changes;
- on socket loss marks authority Unknown and does not trust a stale Verified entry for a new intent;
- never falls back to the local writer in managed mode.

Static and dynamic routes for a managed zone use the same controller backend; do not create a split writer.

The corresponding Go implementation sequence lives in Kikimora `docs/toad-steps/08d-leshy-managed-selected-routes.md`.

## 13. Ordered implementation sequence

The executor must land the fix in this order. Do not jump directly to Linux/Windows event monitoring or Kikimora IPC.

### Commit 1 — model + fake backend + tests, no production behavior change

Files:
- add `src/routing/model.rs`;
- add `src/routing/backend.rs`;
- add test fake backend;
- adapt existing platform writers enough to compile.

Tests:
- canonical IPv4/IPv6 prefixes;
- family mismatch;
- exact target equality;
- fake backend mutation counters.

### Commit 2 — registry and unified non-aggregated route path

Files:
- add `src/routing/registry.rs`;
- refactor `src/routing/mod.rs`;
- delete `add_route_simple`;
- route both /32 and /128 through registry.

Tests:
- 1000 duplicate v4 -> one mutation;
- 1000 duplicate v6 -> one mutation;
- 100 concurrent same-key ensures -> one mutation;
- different keys proceed independently;
- failed add never becomes Verified;
- EEXIST/conflict never becomes Verified without exact match;
- capacity boundary.

### Commit 3 — pure aggregator + safe action ordering

Files:
- `src/routing/aggregator.rs`;
- `src/routing/mod.rs`.

Tests:
- existing aggregation semantics retained;
- canonical aggregate network;
- same-zone covered IP no extra kernel mutation;
- cross-zone split order is add-specifics before remove-broad;
- injected failure leaves old broad route until replacements verified;
- retry converges.

### Commit 4 — Linux + Windows exact snapshot/reconciliation

Files:
- `src/routing/linux.rs`;
- `src/routing/windows.rs`;
- `Cargo.toml` only if the Linux rtnetlink monitor or Windows bindings need an additional feature/dependency.

Common tests:
- synthetic snapshot conversion;
- exact dev match;
- exact gateway match;
- wrong ifindex/gateway/protocol rejected;
- v4 destination/v6 gateway and v6 destination/v4 gateway rejected;
- targeted invalidation;
- monitor loss/invalid state -> full dirty + one audit;
- no DNS-request-path table enumeration after convergence.

Linux-specific:
- rtnetlink route/link invalidations;
- privileged disposable netns: real /32 and /128 add/read-back/delete;
- external deletion restored once;
- stable state produces zero writes.

Windows-specific:
- `GetIpForwardTable2(AF_UNSPEC)` snapshot conversion;
- `NotifyRouteChange2(AF_UNSPEC)` v4/v6 invalidation;
- `CancelMibChangeNotify2` lifecycle outside callback;
- `ERROR_OBJECT_ALREADY_EXISTS` cannot trigger broad same-prefix deletion;
- foreign same-prefix row is conflict/no delete;
- exact owned row add/read-back/remove;
- external deletion restored once on an elevated disposable Windows VM;
- stable state produces zero IP Helper writes and zero request-driven full-table scans.

### Commit 5 — dual-stack policy + exclusions

Files:
- `src/config.rs`;
- `src/zones/matcher.rs`;
- `config.example.toml`;
- README.

Tests:
- ipv6 default false for dev and via;
- ipv6 true dev route;
- via v4 + v6 separate gateways;
- missing v6 gateway rejected;
- IPv6 exclusion /64;
- plain IPv6 exclusion /128;
- mapped-v6 rejection;
- one zone returns both A and AAAA route intents.

Bump package minor/major as appropriate for the config semantic change; document it as v0.6 behavior.

### Commit 6 — DNS typed safety results + cache fast path

Files:
- `src/dns/handler.rs`;
- test constructors/fakes.

Tests:
- cache hit route fast path;
- capacity -> SERVFAIL even with fallback configured;
- conflict -> SERVFAIL;
- disabled AAAA -> NODATA/no IPv6 intent;
- enabled A+AAAA both verified before response;
- one family failure cannot accidentally route the address through the other family.

### Commit 7 — reload diff + explicit owned cleanup

Files:
- `src/reload.rs`;
- `src/server.rs`;
- `src/dns/handler.rs`;
- `tests/hot_reload_test.rs`.

Tests:
- removed zone deletes only its owned rows;
- same-name target change is detected;
- same-name IPv6 policy change is detected;
- new target verified before old target removed where replacement applies;
- foreign same-prefix row never deleted;
- reload replay converges to zero mutations.

### Commit 8 — soak/performance regression

Add a deterministic fake-kernel soak test:

- 10k DNS classifications over a fixed set of 100 v4 + 100 v6 addresses;
- after first convergence, route mutation count remains constant;
- no request-path snapshot calls;
- one audit snapshot per configured audit interval simulation;
- capacity denial at 16385th unique dynamic intent;
- memory registry count remains bounded by capacity plus static entries.

### Commit 9 — managed backend adapter, but do not enable it before Kikimora side exists

Files:
- new `src/routing/kikimora.rs`;
- `src/config.rs`;
- `src/routing/mod.rs`;
- protocol test fixture.

This commit may be developed against a fake control API but must not become the generated/default Kikimora configuration until Kikimora packet 08D passes.

## 14. Test commands / acceptance gate

Required non-privileged:

~~~bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
~~~

Required Linux disposable namespace test, never the active workstation:

~~~bash
sudo ./tests/linux-route-registry-netns.sh
~~~

The script must create its own namespace/interfaces and clean them with a trap.

Required Windows release acceptance on an elevated disposable Windows VM/runner, never a user's active route table:

~~~powershell
powershell -ExecutionPolicy Bypass -File .\tests\windows-route-registry.ps1
~~~

The script must snapshot the routes it creates, use dedicated test destinations/interfaces, and remove only its own exact rows in `finally`.

Required regression assertions:

- stable DNS replay: zero route writes after convergence;
- v4 and v6 have identical registry semantics;
- no full FIB dump on DNS fast path;
- external route loss is detected by monitor/audit and reconciled once;
- no wrong-family gateway is accepted;
- no IPv6 exclusion bypass;
- no foreign route replacement/deletion;
- max route capacity fails closed;
- config reload is idempotent;
- aggregation never opens a remove-before-replacement gap.

## 15. Definition of done for the Leshy-only fix

Do not call this plan complete until all are true:

- `add_route_simple` is gone;
- IPv4 and IPv6 enter the same registry;
- DNS cache replay produces zero kernel churn;
- Linux no longer dumps the FIB per repeated DNS classification;
- Windows no longer calls `GetIpForwardTable2` per repeated DNS classification or repeated IPv6 EEXIST;
- kernel drift is reconciled from invalidation/audit, not from request-path full scans;
- exact kernel route identity is checked;
- gateway family mismatch is rejected;
- IPv6 exclusion CIDRs work;
- same-name zone config changes reconcile;
- explicit zone removal cleans owned rows;
- dynamic route count is bounded and new over-capacity addresses fail closed;
- all unit/integration/Linux-netns/Windows-disposable-VM tests are green;
- only then begin Kikimora 08D integration.

## 16. Explicit non-goals

- No automatic route deletion based solely on DNS TTL.
- No IPv6 prefix aggregation.
- No moving VPN parking into Leshy.
- No fallback from Kikimora managed backend to direct local FIB writes.
- No deleting/replacing a route merely because its prefix matches; ownership/target must be proven.
- No active-host privileged test while developing this fix.
