# Windows feature parity and test coverage

Status: 2026-10-17, branch `windows-support` (v0.5.1), reviewed against a live
Windows 10 19045 VM that runs Leshy as a service in front of a Kikimora tunnel.

## What Windows already has

The platform split is deliberately narrow: the DNS core (zone matching, cache,
forwarding, hot reload, aggregation policy) is platform-independent, and only two
traits are implemented per OS.

| Area | Where | Linux | macOS | Windows |
|------|-------|-------|-------|---------|
| Zone matching, inclusive/exclusive, patterns | `src/zones` | yes | yes | yes |
| DNS cache with TTL overrides | `src/dns/cache.rs` | yes | yes | yes |
| Forwarding, `route_failure_mode` fallback/servfail | `src/dns/handler.rs` | yes | yes | yes |
| Hot reload (`auto_reload`) | `src/reload.rs` | yes | yes | yes |
| Route aggregation (`aggregation_prefix`) | `src/routing/aggregator.rs` | yes | yes | yes |
| Static routes per zone | `src/routing/mod.rs` | yes | yes | yes |
| `route_type = "dev"` (device file -> interface) | `RouteAdder` | yes | yes | yes (adapter alias) |
| `route_type = "via"` (static gateway) | `RouteAdder` | yes | yes | yes |
| Route removal / zone cleanup | `RouteAdder` | yes | yes | yes |
| IPv4 and IPv6 host routes | `RouteAdder` | yes | yes | yes |
| Service install/uninstall | `src/service` | systemd | launchd | SCM |
| Restart on failure | `src/service` | `Restart=on-failure` | launchd `KeepAlive` | **broken** (see below) |
| Daily rotating log file | `src/main.rs` | yes | yes | yes (`ProgramData\leshy\logs`) |
| DNS integration (resolver switch) | not in Leshy | helper `leshy-dns` | `/etc/resolver` | **absent** (see below) |
| Docker end-to-end suite | `tests/` | yes | no | no (Linux-only by design) |

## Defects found on Windows

**1. Routes were created for `0.0.0.0/32` (fixed, commit `7cd5330`).**
`build_route_row` built `DestinationPrefix.Prefix` with `prefix_sockaddr`, the
helper that zeroes the address for on-link next hops. `CreateIpForwardEntry2`
returned success, nothing was logged at INFO, and the forwarding table stayed
empty - so answers kept leaving through the physical default route although the
log said "Adding route via device ... kk-awg0". Two regression tests now assert
that the prefix carries the address (v4 and v6) while the next hop stays zeroed.

**2. `set_failure_recovery` fails with error 5 (open).**
Installing the service prints
`Warning: could not configure restart-on-failure: ChangeServiceConfig2W failed with error 5`
(ERROR_ACCESS_DENIED), so the service is auto-start but never restarted after a
crash, unlike the Linux unit. The service handle is opened with
`ServiceAccess::CHANGE_CONFIG` only; failure actions need a handle that also
carries the start/query rights, or the SCM must be told through `sc.exe`.
Verified workaround on the VM: `sc failure leshy reset= 0 actions= restart/5000`
succeeds (`ChangeServiceConfig2 SUCCESS`) and `sc qfailure` reports it as set.

**3. No Windows DNS integration helper (gap outside Leshy).**
Nothing in the repo creates NRPT rules or sets per-adapter DNS, although the
integration matrix promises "NRPT rules or per-adapter DNS set by a Windows
service helper". On the VM this had to be done by hand:

* the listener must be on `127.0.0.1:53`, not the shipped `53053`, because the
  Windows DNS client and NRPT rules cannot target a custom port;
* `Add-DnsClientNrptRule -Namespace .chatgpt.com,.openai.com -NameServers 127.0.0.1`
  scopes the change to the routed domains, so a dead listener cannot break the
  whole host;
* plaintext upstreams get rewritten on some links, so the zone needs
  `static_routes = ["1.1.1.1/32", "8.8.8.8/32"]` - the equivalent of the Linux
  upstream zone - to keep the upstream queries inside the tunnel.

## Test coverage

`cargo test -- --list` reports **123 tests**; `cargo test` is green on Windows.
Distribution by file (tests / lines):

| File | Tests | Lines |
|------|-------|-------|
| `src/routing/windows.rs` | 10 | 447 |
| `src/routing/aggregator.rs` | 10 | 590 |
| `src/zones/matcher.rs` | 11 | 458 |
| `src/dns/cache.rs` | 9 | 241 |
| `src/dns/handler.rs` | 5 | 587 |
| `src/service/windows.rs` | 4 | 333 |
| `src/routing/mod.rs` | 3 | 274 |
| `src/reload.rs` | 2 | 192 |
| `src/service/linux.rs` / `macos.rs` | 2 / 2 | 111 / 116 |
| `src/routing/linux.rs` / `macos.rs` | **0 / 0** | 194 / 131 |
| `src/server.rs`, `src/main.rs`, `src/config.rs` | 0 | 186 / 89 / 344 |
| `tests/*` (integration) | 15 | 761 |

Gaps and risks:

* **No instrumented coverage.** `cargo llvm-cov` and `cargo tarpaulin` are not
  installed, and none of the CI workflows (`ci.yml`, `publish.yml`,
  `release.yml`) measures coverage, so "coverage" is currently test presence, not
  a percentage.
* **The Linux and macOS route adders have no unit tests** - the two files that
  call `rtnetlink` and `/sbin/route` are covered only by the Docker e2e suite
  (Linux) and manual runs (macOS).
* **`dns/handler.rs` is the largest untested surface** (587 lines, 5 tests): zone
  selection, upstream choice, `route_failure_mode`, and now the Windows route
  installation all funnel through it.
* **Windows route syscalls are covered by one privileged test since 2026-10-17:**
  `windows/tests/route-isolation.ps1` (see below). Everything else about the
  Windows route path is still manual, because elevation cannot be assumed in CI.
* **Config parsing is tested only through integration configs** (`tests/*.toml`),
  not by unit tests over `src/config.rs`.

## Privileged route isolation (Windows)

`windows/tests/route-isolation.ps1` is the first automated test that exercises the
Windows route system calls. Run it elevated on a host whose tunnels are up:

```powershell
.\windows\tests\route-isolation.ps1 -DeviceDir C:\ProgramData\Kikimora\leshy\vpn
```

It backs up the service config, swaps in one zone per tunnel (`awg`, `oc`, `xray`
aimed at the device files the orchestrator publishes), restarts the service and
asserts, for every resolved address of `chatgpt.com`, `gitlab.sca.ad-tech.ru` and
`telegram.org`, that the host route lands on that zone's own adapter, that
`Find-NetRoute` selects it, and that no address carries a route on either of the
other two tunnels. It then removes the `xray` device file, flushes the route and
the cache, and asserts the traffic does not fall back to another tunnel. The
previous config is restored and the service restarted in a `finally` block.

Last run on the Windows 10 VM (three tunnels up): **20 assertions, all PASS,
exit 0**, with `104.18.32.47`/`172.64.155.209` on `kk-awg0`,
`172.25.41.169` on `kk-oc0` and `149.154.167.99` on `kk-xray-win0`.

## Suggested next steps

1. Fix `set_failure_recovery` (handle rights or `sc.exe`) and cover it with a
   test that at least asserts the requested failure actions on a throwaway service.
2. Ship a Windows DNS integration helper (NRPT add/remove with a suspend/resume
   guard) so the listener port and the scoped rules are not operator folklore.
3. Add `cargo llvm-cov` to `ci.yml` with a floor for `src/routing` and
   `src/dns/handler.rs`, and unit tests for the Linux/macOS route adders behind a
   command-execution seam.
