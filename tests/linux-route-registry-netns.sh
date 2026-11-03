#!/usr/bin/env bash
# Privileged disposable-namespace acceptance for the unified route registry
# (plan section 14). Never run this against an active workstation: the script
# creates its own namespace and interfaces and cleans them with a trap.
#
# Usage: sudo ./tests/linux-route-registry-netns.sh
#
# The build runs as the invoking user; only the already-built test binary is
# executed inside the namespace as root (no cargo, no registry under root).
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
if ! command -v cargo >/dev/null 2>&1; then
    echo "rust cargo is required" >&2
    exit 1
fi

cleanup() {
    ip netns del "$NS" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ip netns add "$NS"
ip -n "$NS" link add "$DEV" type dummy
ip -n "$NS" address add 10.55.0.254/24 dev "$DEV"
ip -n "$NS" -6 address add fd00:55::254/64 dev "$DEV"
ip -n "$NS" link set "$DEV" up

echo "namespace $NS ready (device $DEV)"

cd "$(dirname "$0")/.."
echo "building the acceptance test binary..."
# The build must run as the registry owner (its CARGO_HOME/registry cache);
# only the already-built test binary is executed inside the namespace as root.
if [[ -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" env \
        HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)" \
        CARGO_NET_OFFLINE=true \
        cargo test --test linux_route_registry_netns --no-run
else
    CARGO_NET_OFFLINE=true cargo test --test linux_route_registry_netns --no-run
fi

BIN=$(ls -t target/debug/deps/linux_route_registry_netns-* 2>/dev/null \
    | grep -v '\.d$' | head -1 || true)
if [[ -z "$BIN" ]]; then
    echo "could not locate the test binary under target/debug/deps" >&2
    exit 1
fi

LESHY_NETNS_DEV="$DEV" ip netns exec "$NS" "$BIN" \
    --ignored --test-threads=1 --nocapture
