#!/usr/bin/env bash
# Privileged disposable-namespace acceptance for the unified route registry
# (plan section 14) and the L11 event-coherent cache (08D1 section 16).
# Never run this against an active workstation: the script creates its own
# namespace and interfaces and cleans them with a trap.
#
# Usage:
#   cargo test --test linux_route_registry_netns --no-run
#   cargo test --test netns_monitor_probe --no-run
#   sudo -E env \
#       LESHY_REGISTRY_TEST_BIN="$PWD/target/debug/deps/linux_route_registry_netns-<hash>" \
#       LESHY_MONITOR_PROBE_BIN="$PWD/target/debug/deps/netns_monitor_probe-<hash>" \
#       ./tests/linux-route-registry-netns.sh
#
# The build runs as the invoking user; this root-only script never invokes
# cargo or rustup and never rediscovers a login environment. It only creates
# the namespace/interfaces and executes the already-built binaries, which are
# passed as absolute paths (ip netns exec keeps the filesystem path, so
# relative paths would be ambiguous).
set -euo pipefail

NS="leshy-route-registry-$$"
DEV="leshy-rr-dummy"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "must run as root: sudo -E env LESHY_REGISTRY_TEST_BIN=... LESHY_MONITOR_PROBE_BIN=... $0" >&2
    exit 1
fi
if ! command -v ip >/dev/null 2>&1; then
    echo "iproute2 is required" >&2
    exit 1
fi

REGISTRY_BIN="${LESHY_REGISTRY_TEST_BIN:-}"
MONITOR_BIN="${LESHY_MONITOR_PROBE_BIN:-}"

require_binary() {
    local name="$1"
    local path="$2"
    if [[ -z "$path" ]]; then
        echo "$name is required (absolute path to the prebuilt test binary)" >&2
        exit 1
    fi
    if [[ "$path" != /* ]]; then
        echo "$name must be an absolute path, got: $path" >&2
        exit 1
    fi
    if [[ ! -f "$path" ]]; then
        echo "$name does not exist: $path" >&2
        exit 1
    fi
    if [[ ! -x "$path" ]]; then
        echo "$name is not executable: $path" >&2
        exit 1
    fi
}

require_binary LESHY_REGISTRY_TEST_BIN "$REGISTRY_BIN"
require_binary LESHY_MONITOR_PROBE_BIN "$MONITOR_BIN"

cleanup() {
    ip netns del "$NS" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ip netns add "$NS"
ip -n "$NS" link set lo up
ip -n "$NS" link add "$DEV" type dummy
ip -n "$NS" address add 10.55.0.254/24 dev "$DEV"
ip -n "$NS" -6 address add fd00:55::254/64 dev "$DEV"
ip -n "$NS" link set "$DEV" up

echo "namespace $NS ready (device $DEV)"
echo "registry binary: $REGISTRY_BIN"
echo "monitor binary:  $MONITOR_BIN"

echo "running the route registry acceptance..."
LESHY_NETNS_DEV="$DEV" ip netns exec "$NS" "$REGISTRY_BIN" \
    --ignored --test-threads=1 --nocapture

echo "running the monitor probe..."
LESHY_NETNS_DEV="$DEV" ip netns exec "$NS" "$MONITOR_BIN" \
    --ignored --test-threads=1 --nocapture
