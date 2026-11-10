#!/usr/bin/env bash
# Privileged SIGTERM acceptance for the Leshy product (Production Plan C3).
#
# The script creates its own disposable network namespace and dummy device,
# then runs the already-built acceptance binary inside it. Nothing outside the
# namespace is touched and the namespace is deleted on exit, so this is safe on
# a disposable lab VM and deterministic in CI.
#
# Usage (as the invoking user, before sudo):
#   cargo build --bin leshy
#   cargo test --test linux_sigterm_cleanup --no-run
#   sudo -E env \
#       LESHY_BIN="$PWD/target/debug/leshy" \
#       LESHY_SIGTERM_TEST_BIN="$(ls -t target/debug/deps/linux_sigterm_cleanup-* | grep -v '\.d$' | head -1)" \
#       ./tests/linux-sigterm-netns.sh
set -euo pipefail

NS="leshy-sigterm-$$"
DEV="leshy-sg-dummy"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "must run as root: sudo -E env LESHY_BIN=... LESHY_SIGTERM_TEST_BIN=... $0" >&2
    exit 1
fi
if ! command -v ip >/dev/null 2>&1; then
    echo "iproute2 is required" >&2
    exit 1
fi

require_binary() {
    local name="$1" path="$2"
    if [[ -z "$path" ]]; then
        echo "$name is required (absolute path)" >&2
        exit 1
    fi
    if [[ "$path" != /* ]]; then
        echo "$name must be an absolute path, got: $path" >&2
        exit 1
    fi
    if [[ ! -x "$path" ]]; then
        echo "$name is not executable: $path" >&2
        exit 1
    fi
}

require_binary LESHY_BIN "${LESHY_BIN:-}"
require_binary LESHY_SIGTERM_TEST_BIN "${LESHY_SIGTERM_TEST_BIN:-}"

cleanup() {
    ip netns del "$NS" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ip netns add "$NS"
ip -n "$NS" link set lo up
ip -n "$NS" link add "$DEV" type dummy
ip -n "$NS" address add 10.66.0.254/24 dev "$DEV"
ip -n "$NS" -6 address add fd00:66::254/64 dev "$DEV"
ip -n "$NS" link set "$DEV" up

echo "namespace $NS ready (device $DEV)"
echo "leshy binary:  $LESHY_BIN"
echo "gate binary:   $LESHY_SIGTERM_TEST_BIN"

echo
echo "--- pre-run IPv4 table ---"
ip -n "$NS" -4 route show table main | sort
echo "--- pre-run IPv6 table ---"
ip -n "$NS" -6 route show table main | sort

LOG_ARCHIVE="${LESHY_SIGTERM_LOG:-$PWD/leshy-sigterm-gate.log}"
echo
echo "running the SIGTERM acceptance (log archive: $LOG_ARCHIVE)..."
LESHY_BIN="$LESHY_BIN" \
LESHY_NETNS_DEV="$DEV" \
LESHY_SIGTERM_LOG="$LOG_ARCHIVE" \
ip netns exec "$NS" "$LESHY_SIGTERM_TEST_BIN" --ignored --test-threads=1 --nocapture

echo
echo "SIGTERM acceptance: PASS"
echo "archived evidence: $LOG_ARCHIVE"
