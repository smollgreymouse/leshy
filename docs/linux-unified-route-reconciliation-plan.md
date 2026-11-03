# RFC / next fix: unified IPv4 + IPv6 routing and safe fail-closed reconciliation

**Status:** DESIGN PLAN — NOT IMPLEMENTED. Architectural decisions and test gates, not a deployment instruction.  
**Reviewed Leshy:** smollgreymouse/leshy master at 277fd6d9699fd6a08e148a37a268e4bdefbedabc (v0.5.2), 2026-11-03.  
**Integration reviewed:** Kikimora Go/Toad route ownership, bridge, parking manager, recovery driver, and dual-stack regression contract.  
**Scope:** Linux-first route lifecycle; maintain Windows/macOS API behavior and test cross-platform safety. No live-system changes.

## 0. Goals and decisions

A single DNS name and a single logical zone must support **both A/IPv4 and AAAA/IPv6 simultaneously**. The family is determined from the returned RR address type, not from a second zone name or a global IPv6 routing toggle. Maintain **independent per-family readiness, next hop, desired routes, verified kernel routes, and fail-closed policy**.

Both families use the same lifecycle:

~~~text
DNS query -> DNS cache or upstream -> zone classifier
  -> per-family address extraction / exclusions / readiness policy
  -> canonical route intents (v4 /32, v6 /128, plus configured static CIDRs)
  -> unified registry + concurrent request coalescing
  -> authority gate (standalone vs Kikimora-managed zone)
  -> kernel-state cache + event-driven invalidation
  -> minimal netlink action, iff necessary and authorized
  -> read-back/verification and registry update
  -> release or deny DNS answer according to configured failure mode
~~~

The **route registry is not the DNS response cache**, and neither is proof of a real kernel route. Likewise, "missing in kernel" is **not permission to restore** if Kikimora intentionally revoked a tunnel.

Recommendations:

1. Keep **VPN readiness, fail-closed parking, and tunnel recovery owned by Kikimora**. Leshy owns domain classification, per-family route intents and standalone route reconciliation. Do not relocate parking alone into Leshy.
2. In the near-term integration, add explicit owned-route reporting and a revocable, generation-fenced authorization contract. Preserve compatibility with the existing device-file bridge until replaced.
3. Longer term, consider **one route writer in managed mode**: Leshy submits desired selected routes to Kikimora, and Kikimora applies both functional routes and parks. This is a separate architectural milestone, not a prerequisite to unify the route registry.
4. Preserve permanent IPv6 support. The current v0.5.2 default for device zones (suppress AAAA unless ipv6=true) is a **temporary safety default**, not a reason to remove IPv6 routing support or to make IPv6 permanently disabled.
5. Avoid eager TTL-based route deletion: DNS TTL expiration does not mean applications have closed connections to that address. Removing a specific VPN route can leak through the physical default. Garbage collection requires an explicit safe-retirement policy.

## 1. Confirmed implementation gaps

- src/dns/handler.rs: cache hits and fresh answers both call add_routes_from_response(). The DNS cache does not suppress route-kernel work.
- src/routing/mod.rs: IPv4 goes via add_route_v4() and RouteAggregator; IPv6 goes via add_route_simple(.../128) and submits the add again each time.
- src/routing/aggregator.rs: IPv4 installed/known_ips tracking is in memory. Aggregator inserts bookkeeping **before** all kernel actions succeed, creating false-installed risks on failure and after partial aggregate split. It is IPv4-specific because of CIDR compression, not because IPv6 cannot be deduped.
- src/routing/linux.rs: route_matches() uses a full route dump + userspace filter, including for unchanged cached IPv4 destinations. The dump is not a cheap per-prefix proof. EEXIST in add_via_route/add_dev_route is treated as success without verifying existing row identity/target.
- src/routing/mod.rs: zone_routes stores IpAddr for both families but is not the source-of-truth route state machine. cleanup_zone() forgets bookkeeping but does not remove kernel routes. Be careful: automatic deletion without protection creates direct-path leakage.
- src/reload.rs and src/server.rs: removed zone names trigger cleanup; changes to an existing zone's target, family readiness/policy or routes need proper invalidation and reconciliation.
- src/zones/matcher.rs: CidrRange/MatchedZone::is_excluded() implement **IPv4-only** CIDR exclusions; IPv6 in an exclusive zone never matches an excluded CIDR.
- src/routing/linux.rs: with route_type=via and an IPv6 destination but an IPv4 gateway, the code does not attach a gateway to the IPv6 netlink message. Reject mismatched families and define per-family gateways; do not silently add malformed/unintended routes.
- IPv4 aggregation: the installed_prefix(ip) path can pass a **host IP** with a **wider prefix** to route_matches(), which compares exact Destination addresses. A canonical subnet key is required for correctness.
- Linux route operations do not have a distinguishable ownership tag separate from generic system/static routes, making safe replacement/removal ambiguous.

Legacy field measurements are relevant only as a regression signature: installed Leshy 0.4.0 produced 1,244 "Adding route" events/hour, with 1,225 IPv6 attempts but only 127 distinct IPv6 addresses (1,098 redundant IPv6 attempts). The measured host was **not** running the reviewed 0.5.2 master.

## 2. Why IPv4 and IPv6 should not have separate cache algorithms

Both can be represented by a canonical RouteKey:

~~~text
RouteKey = (address_family, table, canonical_network, prefix_length)
RouteIntent = (RouteKey, zone_id, route_kind, target, protocol, metric,
               source={DNS,static}, lifetime/reference metadata)
~~~

Use native address types (Rust IpAddr/IpNet or equivalent); do not normalize IPv6 into a 32-bit key.

IPv4 /32 and IPv6 /128 follow the same dedupe, reconciliation, ownership and cleanup logic. IPv4 aggregation into /N is an **optional planner** that converts multiple host intentions into one or more canonical kernel prefix intentions. That planner must preserve non-overrouting/conflict semantics, must not cover other zones, and must be separately tested. Keep IPv6 host /128 routes by default; collapsing arbitrary CDN IPv6 /128 routes into /64 would be unsafe.

A single logical domain may return several A and AAAA RRs; each becomes its own key. Shared IPs across domains/zones require explicit ownership conflict resolution and reference counts (not "last DNS response wins").

## 3. One name, two families: routing policy, not two zones

Example, with documentation-only addresses:

~~~text
example.com -> matched zone "primary"
      A 203.0.113.10 -> IPv4 readiness -> route 203.0.113.10/32
   AAAA 2001:db8::10 -> IPv6 readiness -> route 2001:db8::10/128
~~~

The DNS RR type determines family automatically. Define an **independent family policy and runtime state** for the same zone:

~~~text
Zone = name, domain/pattern matching, route policy
ZoneFamily[IPv4] = {configured, ready/denied/unknown, target, generation}
ZoneFamily[IPv6] = {configured, ready/denied/unknown, target, generation}
~~~

Separate these concepts:

- **Configured capability:** operator allows a family. This is not proof of working connectivity.
- **Published readiness:** orchestrator has verified the transport can carry user traffic for that family, including a usable address/source and route, not just interface UP.
- **DNS answer policy:** A or AAAA is exposed only when the corresponding family is safely handled. Unavailable family should be suppressed as NODATA where appropriate; a strict fail-closed policy may return SERVFAIL. Suppression is not itself sufficient to block already-known IPs or direct-IP clients.
- **Route target:** device-based zones can share one device name but family readiness may differ. For via mode IPv4 and IPv6 gateways are usually different addresses; validate against family instead of silently omitting a mismatching next hop.

Configuration compatibility proposal (exact TOML syntax subject to implementation review):

- Keep existing ipv6 boolean behavior on old config.
- Introduce explicit per-family enable policy in a new opt-in config format, and per-family gateways when needed.
- For managed zones, prefer "auto": IPv6 is eligible when Kikimora publishes IPv6-ready; otherwise don't advertise it or install its routes. "enabled" alone must not bypass readiness.
- No global IPv4-vs-IPv6 selection flag; no duplicate zones per family (ZoneMatcher currently returns the first matching zone).

Fix IPv6 CIDR exclusions as part of this work. On exclusive zones, excluded IPv6 networks must be recognized and not over-routed. Cross-family static CIDRs and invalid/mapped addresses should get explicit validation.

## 4. Ownership boundary: should parking move into Leshy?

### Option A: move *only parking* into Leshy — NOT recommended

Pros: one service has DNS-derived IP knowledge and could coordinate real-route/park replacement.

Cons: it does not know tunnel transport readiness, recovery/endpoint policy, product stop, per-family verification or underlay changes without a new contract. Kikimora already has a working parking manager and checkpoint/recovery ordering. Relocation creates duplicate state or transfers VPN orchestration authority into a DNS daemon. It also risks two independent components parking/unparking the same destination.

**Decision:** do not move parking alone.

### Option B: current split, with explicit ownership + lease protocol — recommended short-term

Kikimora remains the policy/parking owner; Leshy owns its operational DNS-selected route add/replace and reports owned prefixes. To avoid two writers racing, add a barrier and generation/ack contract described below.

### Option C: managed backend with Kikimora as sole kernel writer — cleaner long-term candidate

Leshy becomes the DNS routing-intent producer in managed mode. Kikimora atomically arbitrates route ownership and serializes real selected route mutations with parking. Leshy still directly routes in standalone mode. This best satisfies "one owner per routing resource", but is a larger cross-repository migration, requires an IPC result before DNS success and must preserve standalone portability. Implement as a separately approved milestone after Option B is tested, not as an incidental refactor.

## 5. Crucial safety model: desired ≠ installed ≠ authorized

Three separate truths, never a single installed HashSet:

1. **Desired:** the latest DNS-classified and static route intents by zone/family, including source/age/ownership references. Retain across temporary VPN withdrawal as pending, not as proof of usability.
2. **Authorized:** whether current controller policy permits installation. For a Kikimora-managed zone, this is a per-family publication with a **monotonic generation/lease**, not merely the presence of an interface named "vpn0" or "amn0". If invalid, missing or ambiguous: no new real route.
3. **Observed:** exact route/rule state in kernel (family, canonical prefix, table, metric, protocol, oif/ifindex or next hop). Kernel state can drift independently of memory. "Observed" carries an observation generation and invalidation flag.

Suggested RouteEntry state:

~~~text
Absent | Pending | Verified | Dirty | Denied | Error
  + desired owner(s), desired target and family
  + observed kernel row and generation
  + last successful verification, last used, retry/backoff
  + in-flight operation token / cancellation epoch
~~~

Only mark Verified after matching read-back or a trusted synchronized kernel snapshot. Never mark Verified before a successful mutation. Treat EEXIST as "inspect existing row", not as unconditional success; the route may belong to another program or point to a different device.

An unchanged DNS response for the same (zone,family,prefix,target,generation) performs **zero netlink writes** and in the normal fast path **zero full FIB dumps**.

### 5.1 Why re-adding a missing route is dangerous

There are two fundamentally different "missing" cases:

- **Accidental drift:** VPN role/family is still published Ready; some external actor deleted or replaced a real route. Reconcile may restore it after verifying owner and authority.
- **Intentional withdrawal:** Kikimora is parking a route, restarting VPN, or has revoked Ready. Reconciliation **must not** restore the route. The destination must be protected by Kikimora's park or a stricter family policy.

A full FIB scan cannot tell the difference. The system needs a separate authority signal, with ordering.

### 5.2 What Kikimora already provides

Reviewed Kikimora Go/Toad integration:

- toad/internal/leshy/bridge.go: Publish / Withdraw / Resync via an atomic zone .dev device-name file;
- toad/internal/parking/manager.go: PrepareOwnedWithdrawal, ObserveRestorationFromKernel, Clear;
- toad/internal/control/recovery_driver.go: capture baseline/selected ownership, prepare parking, withdraw publication, transport recovery, publish, verify restoration then release parks;
- managed parks include /32 and /128 and use a high-metric unreachable route (typically 42760);
- table 51890 underlay endpoint policy is separate and must never be treated as a Leshy user-route park.

**Weaknesses to address at the boundary:**

- Existing .dev files contain only interface name, **no generation, family readiness, lease or withdrawal acknowledgement**. File absence prevents future lookups but does not fence a pre-existing asynchronous add.
- Kikimora currently learns some route ownership from kernel baseline+delta observation. A newly installed route can disappear before it is recorded; then the park inventory may be incomplete.
- Current ObserveRestorationFromKernel checks a real row with lower metric, not all relevant target/owner identity fields; it should not release a park based on an unrelated lower-metric route.
- Successful restoration is not established by interface UP alone; the exact family and target must match.

Do not treat the file bridge as race-free. The target contract requires cooperation in both repositories.

### 5.3 Recommended fenced publish/withdraw + owned-route protocol

Extend managed-mode publication to carry:

~~~text
Publish(zone, family, generation, target, readiness=Ready)
Withdraw(zone, family, generation) -> ACK
  ACK means: all older authorized writes finished or were cancelled,
             and no later add can execute under this generation
ReserveOrReportOwnedRoute(zone, family, generation, prefix, expected_target)
  -> ACK from controller, which has safely recorded ownership/protection
Resync(zone, family, generation) -> verified / pending / denied route set
~~~

Prefer local authenticated Unix-domain IPC with generation fencing and explicit ACK for correctness. An atomic JSON document and inotify may be a migration adapter, but **cannot alone guarantee withdrawal barriers**. Retain old .dev protocol for standalone/compatibility mode until cutover; do not silently claim it supplies the stronger safety guarantee.

Implementation details:

- Serialize or fence every kernel write against publication changes. Each in-flight add carries a generation. During Withdraw, stop issuing new adds, await/cancel all older in-flight operations, then acknowledge. Re-check generation before committing registry state. A stale completion cannot be considered authorized.
- For a **new prefix**, register/commit ownership with Kikimora **before** exposing a usable DNS address or creating an unprotected real-route window. If the owner cannot durably record it, fail closed. The precise persistence/ACK boundary needs integration tests.
- An error/timeout talking to the controller cannot be treated as permission to install; do not fall back to stale .dev success in strict managed mode.
- Don't use ifname alone as identity. A reconnect can reuse a name with a different ifindex and address-family capability; change generation and invalidate old Verified entries.
- Runtime crashes and process restarts must not leave conflicting leases. Use a boot/process epoch and reconstruct managed ownership with read-back and checkpoint before declaring Ready.
- In standalone Leshy, preserve local policies and allow normal route reconciliation without a Kikimora IPC dependency.

### 5.4 Exact fail-closed order

**Healthy steady state:** each allowed zone/family has a matching real route; no redundant add. Unknown or disabled family is not advertised as safely routed.

**Planned withdrawal:**

1. Kikimora starts a withdrawal epoch for affected role/family.
2. Revoke publication and obtain the Leshy quiescence ACK (no old-generation writes in flight). Do not let new DNS answers produce new functional routes during this transition.
3. Using explicit registered owned prefixes (not a best-effort route scan alone), install fail-closed parks and verify they exist. This can be done in an order compatible with current parks and remaining real routes.
4. Withdraw the lower-metric real selected routes / take down the tunnel, preserving parks. Never leave both the selected route and protective park absent while a physical/other-tunnel fallback exists.
5. Any DNS request for that family remains denied/suppressed or protected; do not use simple fallback mode to leak via physical routing.

**Unexpected tunnel disappearance/crash:**

- The controller must have a previously acknowledged set of selected prefixes sufficient to park, and maintain checkpointed state. If no inventory exists, the guarantee cannot be established by periodic route discovery alone.
- Leshy must treat publication loss, generation mismatch and controller error as non-authorized. It may remember intents but must not recreate a real route.
- A kernel-link event invalidates target-specific verified entries. Real route disappearance is not reason to use the other VPN or physical route.

**Recovery:**

1. Kikimora establishes endpoint underlay separately, restarts/rebinds transport and independently validates actual IPv4/IPv6 data-plane readiness.
2. Publish a new per-family generation only for a ready family (IPv4 Ready does not imply IPv6 Ready).
3. Reconcile desired routes under that generation. Validate exact table/prefix/oif/gateway/protocol and effective winning route. Verify selected real routes in kernel before releasing any corresponding park.
4. Remove park **only** for a prefix whose correct expected winner is proven. A random lower-metric row on an unrelated interface is not proof. Keep other parks until their own restoration.
5. Replay the same inputs: zero further kernel mutations.

If an old lower-metric real route still points at a dead interface, it can cause timeouts despite a high-metric park. The reconciliation must explicitly handle stale real-route removal; a higher-metric unreachable park alone will not override that route.

**Important limitation:** a DNS-only classifier cannot prevent direct-IP traffic or stale cached client addresses from using an unsafe default path after its specific route is removed. Truly global zero-leak behavior must be guaranteed by the Kikimora traffic/parking policy, not by DNS AAAA suppression alone.

### 5.5 Safety matrix

| Authority | Kernel state | Action |
| --- | --- | --- |
| Ready, matching generation | Exact real route matches target | No write, Verified |
| Ready, matching generation | Missing | Reconcile owned route and verify |
| Ready, matching generation | Existing foreign/conflicting row | Do not delete foreign route blindly; error/escalate |
| Withdrawing / Unpublished | Missing or park only | Do not add; pending intent |
| Withdrawing / Unpublished | Old real row remains | Do not restore; controller withdraws safely |
| Unknown, stale epoch, controller unreachable | Any | No new add; fail closed |
| New generation, changed ifindex/target | Old route | Invalidate; replace only with owner permission |
| IPv6 not Ready, IPv4 Ready | IPv6 may be absent | Permit IPv4 only; prevent AAAA-induced bypass |

## 6. Avoid full route dump per DNS cache hit

Proposed Linux design:

1. Initial **one-time kernel snapshot** of relevant tables, families and owned routes.
2. Subscribe to netlink RTM_NEWROUTE/RTM_DELROUTE for IPv4/IPv6 (and link/address events for target changes). Update/invalidate affected entries; coalesce bursts.
3. Fast path: verified entry with same desired key, target and current publication epoch and no invalidation -> no netlink I/O.
4. On invalidation, new epoch, suspicious drift, listener restart or an uncertain state: perform **bounded batched** reconciliation; fetch one snapshot for many dirty routes rather than one full dump per DNS request.
5. Low-rate periodic audit as a safety net for lost events. Audit rate, max work per tick, timeouts and backoff are configurable; no busy loops.
6. Event streams are invalidation hints, not absolute proof; refresh kernel state when recovery safety depends on it.
7. No locks held across unrelated async syscalls; coalesce concurrent DNS requests for the same RouteKey into one in-flight operation. Ensure a route-action transaction cannot silently leave the aggregator's installed map ahead of kernel state.
8. Record counters for snapshot dumps, dirty entries, reconciliation passes, add/replace/delete success/failure, EEXIST, restore-after-drift and denied-by-authority.

For large IPv4 aggregates, compare canonical network prefixes rather than the individual member IP. Validate selected effective route after changes and avoid accidental replacement of unrelated routes.

## 7. Route retirement, cleanup and bounded growth — no leak regression

Current cleanup_zone() drops only memory tracking; routes remain in the kernel. That causes stale accumulation. But simply deleting routes after DNS TTL, on zone removal, or on cache eviction can **immediately leak existing TCP/QUIC flows** through the physical default.

Retirement must therefore be a separate safe state transition:

- Mark no-longer-desired dynamic route as Retiring rather than deleting it immediately.
- Keep active-flow protection or explicit deny/park for addresses that may still be in use; use connection tracking and/or a policy-controlled quiescence/grace protocol only where justified and tested.
- Do not repurpose DNS TTL as a connection lifetime. CDN A/AAAA rotation is normal and must not destroy ongoing sessions.
- Never reclaim a dynamic route that is still referenced by another domain/zone, a static route, or a conflicting owner.
- For managed zones, have Kikimora approve a safe retirement and ensure no direct-path fallback; in standalone mode select conservative behavior and document what guarantees cannot be offered.
- Reconcile obsolete routes on zone removal, changed target, IPv6 disable and restart, but **only after** fail-closed transition/safe ownership checks.
- Limit registry memory and provide observable high-watermark/pressure counters. Avoid an unsafe arbitrary LRU eviction that removes the last fail-closed protection.

Open design question (requires evidence before turning GC on by default): how to establish flow quiescence for routed flows, including UDP/QUIC and applications using already-resolved IPs, without retaining every old destination forever? A bounded host-route list by itself cannot deliver a universal no-leak guarantee. The first implementation should prioritize correct ownership and convergence, then enable conservative GC behind a validated policy.

## 8. Execution stages

### Stage 0 — tests, contract, measurements

- Record current 0.5.2 behavior, managed/standalone modes, IPv4 and IPv6.
- Add deterministic fake RouteAdder counters to prove cache-hit and concurrent-query behavior.
- Capture route growth and churn counters; do not run privileged tests on the user's active host.
- Agree on family policy semantics and explicit route ownership handshake before changing fail-closed behavior.

### Stage 1 — unified cache and family-safe planner (Leshy-only)

- New RouteKey and RouteEntry abstractions covering both families.
- Move IPv4-only CIDR aggregation behind a separate planner, not the shared cache.
- Fix IPv6 exclusions, gateway-family validation, IPv4 canonical prefix check.
- Commit installed state only after verified success. Handle partial aggregate update transactionally.
- Coalesce concurrent per-key requests; remove IPv6 duplicate RTM_NEWROUTE.
- Preserve existing device-zone IPv4-only default until readiness publication supports IPv6 safely.

### Stage 2 — efficient Linux kernel synchronization

- Netlink route/link/address event subscription; initial snapshot, batched read-back, dirty marking and periodic low-rate audit.
- Exact table/prefix/protocol/metric/target owner verification.
- Remove per-request full route dump from hot path.
- Correct handling of stale ifindex and unexpected external route removal.

### Stage 3 — safe managed Kikimora interaction (cross-repo)

- Define and test per-family Publish/Withdraw ACK, generation fencing and exact owned-prefix registration.
- Implement the compatibility transition from .dev file publication without two route owners or silent downgrade.
- Fix Kikimora park-release proof: expected family, prefix, target, owner and winning route must match.
- Test loss of publication, kernel drift and tunnel death at every handshake boundary.

### Stage 4 — safe retirement and configuration reload

- Diff changed zone content (not just removed names), family/target changes, static route changes.
- Add retiring state with explicit safe-to-remove conditions; confirm protection before deletion.
- Keep endpoint table 51890 and foreign/user routes untouched.
- Test no leaks across cache expiration, long-lived connection, stale client IP and restart.

### Stage 5 — optional managed sole-writer backend

- Evaluate moving managed-mode route *application* (not just parking) to Kikimora. If adopted, route intent becomes an IPC request whose kernel result arrives before DNS reply.
- Do not merge this into Stages 1-4 without its own architectural review, failure/latency budget and migration tests.

## 9. Required deterministic and privileged acceptance

**Pure Rust tests (no root):**

1. Same IPv4 /32 repeated 1,000 times -> one kernel mutation; same IPv6 /128 repeated 1,000 times -> one mutation.
2. Concurrent 100 duplicate DNS requests -> one in-flight kernel operation per key.
3. Separate A+AAAA for one hostname -> both valid routes if both families Ready; only v4 if v6 not Ready; never incorrectly route the AAAA over v4.
4. IPv6 exclusion CIDR matches; invalid family gateway rejected before syscall.
5. Aggregation: canonical /N match, distinct zones cannot steal an aggregate, no partial action marks route installed on failed syscall.
6. EEXIST for a foreign route is not accepted as verified ownership.
7. Route deleted by external actor: Ready + valid generation -> restore once; Withdrawing/Unpublished -> zero restores.
8. Route target changes at same zone name: invalidate and safely reconcile.
9. Lost netlink notification: periodic audit recovers without repeated writes in the steady state.
10. TTL expiry/duplicate domain ownership does not provoke a direct-route fallback.

**Isolated Linux network namespace tests (root in disposable namespace, NEVER active workstation):**

1. IPv4/IPv6 exact route add/read-back/delete/recover (test selected source and egress).
2. Family-specific readiness, IPv6-disabled NODATA, IPv6-enabled correct path, no false readiness for a v4-only tunnel.
3. Withdraw mid-write, before/after owner registration, during park setup, during device loss and during republish; old generations cannot recreate routes.
4. With physical default and another VPN still present, failed-zone destination must not use either fallback for both /32 and /128.
5. During restoration, parked route remains until a correct lower-metric selected route is verified; wrong interface must not release the park.
6. Crash/restart with stale registry/ownership checkpoint and reused ifname/different ifindex.
7. Foreign same-prefix routes, overlapping static CIDRs and table-51890 endpoint routes remain unmodified.
8. High-volume replay on a fixed DNS dataset: after convergence **zero route mutations**, no per-query FIB dump, bounded CPU/memory, bounded reconciliation latency.
9. Controlled dynamic address churn, active long-lived TCP and UDP/QUIC flows during conservative cleanup; prove no physical/default leak.

**Metrics to capture:** per-family intents, verified routes, parks, denied operations, netlink adds/replaces/deletes, route dumps, duplicate coalesces, reconciliation cycles, drift repairs, publication epochs, GC candidates/retirements, kernel route counts and process CPU/RSS. Keep threshold values evidence-based; do not hardcode the legacy host's 1,244/hour as an acceptable budget.

**Definition of done:** v4/v6 functional parity; no duplicate kernel adds on stable DNS; no per-hit full-table dumps; safe revalidation after drift; no write after managed withdrawal ACK; park owner remains Kikimora; no IPv6 direct bypass; no uncontrolled route retirement; tests and documentation updated. Do not claim done based only on unit tests or on an IPv4-only environment.

## 10. Files likely to change

**Leshy:** src/routing/mod.rs, src/routing/aggregator.rs, src/routing/linux.rs, src/dns/handler.rs, src/dns/cache.rs, src/zones/matcher.rs, src/config.rs, src/server.rs, src/reload.rs; tests/docker, new route-registry unit tests and Linux netns tests.

**Kikimora integration:** toad/internal/leshy/bridge.go (new protocol alongside compatibility file bridge), toad/internal/control/recovery_driver.go, toad/internal/parking/manager.go, toad/internal/routing/ownership.go, and relevant route-parking/dual-stack acceptance tests.

## 11. Unresolved decisions to review before implementation

- Prefer Option B (split with explicit lease) short-term; revisit Option C (Kikimora sole writer in managed mode) when a measured need and migration plan exist.
- Exact managed transport of generation + family capability + owned-prefix ACK (Unix socket vs file bridge plus stronger synchronization).
- Safe kernel route protocol/ownership tag for Leshy without hijacking user routes.
- What to do with IPv6 via-gateway when only IPv4 next hop is configured (fail validation vs explicit separate v6 gateway).
- Conservative GC/retirement under a strict zero-direct-leak contract.
- Whether managed DNS should suppress unavailable-family answers or return SERVFAIL for the whole request; must preserve independent v4 and v6 functionality.

**Links for contract reviewers:** Kikimora docs/go-multi-vpn-architecture.md, docs/route-parking.md (historical Linux lifecycle details), docs/toad-steps/07b-routing-parking-failclosed.md (current Go parking work), docs/toad-steps/08-dual-stack-dns-route-stability.md (regression requirements).
