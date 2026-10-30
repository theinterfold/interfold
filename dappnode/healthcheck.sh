#!/bin/sh
# Check the node process, protected state, listeners, and chain-ingestion heartbeats.
# Missing heartbeats are allowed during startup; stale heartbeats indicate stalled RPC reads.
# Confirm operator activation in the node dashboard.
set -eu

fail() {
    printf 'UNHEALTHY: %s\n' "$1" >&2
    exit 1
}

PROC_ROOT="${PROC_ROOT:-/proc}"
CONFIG_FILE="${CONFIG_FILE:-/data/config.yaml}"
PASSWORD_FILE="${PASSWORD_FILE:-/data/.interfold/config/_default/key}"
DB_PATH="${DB_PATH:-/data/.interfold/data/_default/db}"
EVENT_LOG_PATH="${EVENT_LOG_PATH:-/data/.interfold/data/_default/log.0}"
INGESTION_DIR="${INGESTION_DIR:-/data/.interfold/data/_default/ingestion}"
INGESTION_MAX_AGE_SECS="${INGESTION_MAX_AGE_SECS:-120}"
INGESTION_STALL_MAX_SECS="${INGESTION_STALL_MAX_SECS:-600}"
INGESTION_START_GRACE_SECS="${INGESTION_START_GRACE_SECS:-900}"
QUIC_PORT="${QUIC_PORT:-37173}"
SS_BIN="${SS_BIN:-ss}"
DASHBOARD_PROXY_CONF="${DASHBOARD_PROXY_CONF:-/tmp/interfold-nginx.conf}"
STAT_BIN="${STAT_BIN:-stat}"

case "$QUIC_PORT" in
    ''|*[!0-9]*) fail "invalid health-check setting or heartbeat timestamp" ;;
esac
case "$INGESTION_START_GRACE_SECS" in
    ''|*[!0-9]*) fail "invalid health-check setting or heartbeat timestamp" ;;
esac
[ "$QUIC_PORT" -ge 1 ] && [ "$QUIC_PORT" -le 65535 ] || fail "QUIC_PORT must be between 1 and 65535"

[ -r "$PROC_ROOT/1/cmdline" ] || fail "node process is unavailable; check package Logs"
[ "$(basename "$(readlink "$PROC_ROOT/1/exe")")" = "interfold" ] || fail "PID 1 is not Interfold; check startup Logs"

cmdline=$(tr '\000' '\n' < "$PROC_ROOT/1/cmdline")
printf '%s\n' "$cmdline" | grep -Fxq 'start' || fail "node has not started; check startup Logs"
printf '%s\n' "$cmdline" | grep -Fxq "$CONFIG_FILE" || fail "node uses an unexpected config path"

[ -s "$CONFIG_FILE" ] || fail "node configuration is missing; check startup Logs"
[ -s "$PASSWORD_FILE" ] || fail "credential key is missing; restore the encrypted backup"
[ -d "$DB_PATH" ] || fail "database is not initialized; check startup Logs"
[ -d "$EVENT_LOG_PATH" ] || fail "event log is not initialized; check startup Logs"

config_mode=$($STAT_BIN -c '%a' "$CONFIG_FILE")
password_mode=$($STAT_BIN -c '%a' "$PASSWORD_FILE")
case "$config_mode" in 400|600) ;; *) fail "config permissions must be 400 or 600" ;; esac
case "$password_mode" in 400|600) ;; *) fail "credential-key permissions must be 400 or 600" ;; esac

$SS_BIN -H -u -l -n "sport = :$QUIC_PORT" | grep -q . || fail "QUIC listener is missing; check network startup Logs"

# The entrypoint keeps the proxy configuration only when the proxy started.
if [ "${DASHBOARD_ENABLED:-false}" = true ] && [ -s "$DASHBOARD_PROXY_CONF" ]; then
    $SS_BIN -H -t -l -n 'sport = :8081' | grep -q . || fail "dashboard proxy is unavailable; restart the package and check Logs"
fi

if [ -s /tmp/interfold-rpc-proxy.conf ]; then
    $SS_BIN -H -t -l -n 'sport = :8550' | grep -q . || fail "execution RPC proxy is unavailable; restart the package and check Logs"
fi

# Chain ingestion: every heartbeat present must be fresh, and its reader must still progress.
now="${HEALTHCHECK_NOW:-$(date +%s)}"
heartbeats=0
for heartbeat in "$INGESTION_DIR"/chain-*.heartbeat; do
    [ -e "$heartbeat" ] || continue
    heartbeats=$((heartbeats + 1))
    polled_at=$(sed -n 's/^polled_at=//p' "$heartbeat")
    progressed_at=$(sed -n 's/^progressed_at=//p' "$heartbeat")
    case "$polled_at" in ''|*[!0-9]*) fail "invalid health-check setting or heartbeat timestamp" ;; esac
    case "$progressed_at" in ''|*[!0-9]*) fail "invalid health-check setting or heartbeat timestamp" ;; esac
    [ $((now - polled_at)) -le "$INGESTION_MAX_AGE_SECS" ] || fail "chain reader stopped polling; check RPC access and Logs"
    [ $((now - progressed_at)) -le "$INGESTION_STALL_MAX_SECS" ] || fail "chain ingestion stalled; check RPC head and sync Logs"
done

# After the startup grace, every enabled chain must have a heartbeat. The node writes the
# expectation before it starts any reader, so a heartbeat without it means the expectation was lost.
expected="$INGESTION_DIR/expected"
if [ ! -e "$expected" ] && [ "$heartbeats" -gt 0 ]; then
    fail "ingestion expectation is missing; check node Logs"
fi
if [ -e "$expected" ]; then
    chains=$(sed -n 's/^chains=//p' "$expected")
    started_at=$(sed -n 's/^started_at=//p' "$expected")
    case "$chains" in ''|*[!0-9]*) fail "invalid health-check setting or heartbeat timestamp" ;; esac
    case "$started_at" in ''|*[!0-9]*) fail "invalid health-check setting or heartbeat timestamp" ;; esac
    if [ $((now - started_at)) -gt "$INGESTION_START_GRACE_SECS" ]; then
        [ "$heartbeats" -ge "$chains" ] || fail "a chain reader did not start within the startup grace; check RPC access"
    fi
fi

if [ "$heartbeats" -eq 0 ] || { [ -e "$expected" ] && [ "$heartbeats" -lt "$chains" ]; }; then
    printf 'STARTING: waiting for chain ingestion; inspect Logs for sync progress\n'
else
    printf 'HEALTHY: local process and chain ingestion are live; check operator activation in the dashboard\n'
fi
