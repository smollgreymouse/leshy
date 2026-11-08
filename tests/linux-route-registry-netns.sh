#!/usr/bin/env bash
# Privileged disposable-namespace acceptance for the unified route registry
# (plan section 14) and the L11 event-coherent cache (08D1 section 16).
# Never run this against an active workstation: the script creates its own
# namespace and interfaces and cleans them with a trap.
#
# Usage: sudo ./tests/linux-route-registry-netns.sh
#
# The build runs as the invoking user; only the already-built test binaries
# are executed inside the namespace as root (no cargo, no registry under root).
set -euo pipefail

NS="leshy-route-registry-$$"
DEV="leshy-rr-dummy"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "must run as root: sudo $0" >&2
    exit 1
fi
if ! command -v ip >/dev/null 2>&1; then
    echo "iproute2 is required" >&2
    exit 1
fi

# Resolve the invoking user's cargo: root may not have one on PATH.
if [[ -n "${SUDO_USER:-}" ]]; then
    CARGO_BIN="$(sudo -u "$SUDO_USER" bash -lc 'command -v cargo' 2>/dev/null || true)"
else
    CARGO_BIN="$(command -v cargo 2>/dev/null || true)"
fi
if [[ -z "$CARGO_BIN" ]]; then
    echo "rust cargo is required" >&2
    exit 1
fi

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

cd "$(dirname "$0")/.."

# The build must run as the registry owner (its CARGO_HOME/registry cache);
# only the already-built test binaries are executed inside the namespace.
run_as_owner() {
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" env \
            HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)" \
            CARGO_NET_OFFLINE=true \
            "$CARGO_BIN" "$@"
    else
        CARGO_NET_OFFLINE=true "$CARGO_BIN" "$@"
    fi
}

echo "building the acceptance test binaries..."
run_as_owner test --test linux_route_registry_netns --no-run
run_as_owner test --test netns_monitor_probe --no-run

test_bin() {
    ls -t "target/debug/deps/$1-"* 2>/dev/null | grep -v '\.d$' | head -1 || true
}

BIN="$(test_bin linux_route_registry_netns)"
if [[ -z "$BIN" ]]; then
    echo "could not locate the registry test binary under target/debug/deps" >&2
    exit 1
fi

PROBE="$(test_bin netns_monitor_probe)"
if [[ -z "$PROBE" ]]; then
    echo "could not locate the monitor probe binary under target/debug/deps" >&2
    exit 1
fi

echo "running the route registry acceptance..."
LESHY_NETNS_DEV="$DEV" ip netns exec "$NS" "$BIN" \
    --ignored --test-threads=1 --nocapture

echo "running the monitor probe..."
LESHY_NETNS_DEV="$DEV" ip netns exec "$NS" "$PROBE" \
    --ignored --test-threads=1 --nocapture
