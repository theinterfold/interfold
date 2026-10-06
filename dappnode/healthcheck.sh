#!/bin/sh
# Local health signal for the Interfold ciphernode image. The node has no readiness
# HTTP/control endpoint, so require the expected PID 1, its exact start/config
# arguments, protected local credential/config files, the QUIC listener, and a
# fresh chain-ingestion heartbeat. The node writes one heartbeat file per chain
# under INGESTION_DIR after every successful read of the chain head (key=value
# lines: chain_id, head, cursor, polled_at, progressed_at, in Unix seconds).
# A heartbeat older than INGESTION_MAX_AGE_SECS means the reader stopped polling;
# a head and cursor that did not move for INGESTION_STALL_MAX_SECS mean an RPC
# endpoint that stopped following the chain, or a sync that stopped advancing.
# No heartbeat at all means the node is still starting: the node removes the
# files of an earlier run at startup and fails to start when it cannot write
# them. At startup the node also writes INGESTION_DIR/expected (chains=<enabled
# chains>, started_at=<Unix seconds>); once INGESTION_START_GRACE_SECS have
# passed since then, every enabled chain must have a heartbeat, so a reader
# that never reaches its first read fails. This is not a protocol-readiness
# guarantee.
set -eu

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
STAT_BIN="${STAT_BIN:-stat}"

case "$QUIC_PORT" in
    ''|*[!0-9]*) exit 1 ;;
esac
case "$INGESTION_START_GRACE_SECS" in
    ''|*[!0-9]*) exit 1 ;;
esac
[ "$QUIC_PORT" -ge 1 ] && [ "$QUIC_PORT" -le 65535 ] || exit 1

[ -r "$PROC_ROOT/1/cmdline" ] || exit 1
[ "$(basename "$(readlink "$PROC_ROOT/1/exe")")" = "interfold" ] || exit 1

cmdline=$(tr '\000' '\n' < "$PROC_ROOT/1/cmdline")
printf '%s\n' "$cmdline" | grep -Fxq 'start' || exit 1
printf '%s\n' "$cmdline" | grep -Fxq "$CONFIG_FILE" || exit 1

[ -s "$CONFIG_FILE" ] || exit 1
[ -s "$PASSWORD_FILE" ] || exit 1
[ -d "$DB_PATH" ] || exit 1
[ -d "$EVENT_LOG_PATH" ] || exit 1

config_mode=$($STAT_BIN -c '%a' "$CONFIG_FILE")
password_mode=$($STAT_BIN -c '%a' "$PASSWORD_FILE")
case "$config_mode" in 400|600) ;; *) exit 1 ;; esac
case "$password_mode" in 400|600) ;; *) exit 1 ;; esac

$SS_BIN -H -u -l -n "sport = :$QUIC_PORT" | grep -q . || exit 1

# Chain ingestion: every heartbeat present must be fresh, and its reader must still progress.
now="${HEALTHCHECK_NOW:-$(date +%s)}"
heartbeats=0
for heartbeat in "$INGESTION_DIR"/chain-*.heartbeat; do
    [ -e "$heartbeat" ] || continue
    heartbeats=$((heartbeats + 1))
    polled_at=$(sed -n 's/^polled_at=//p' "$heartbeat")
    progressed_at=$(sed -n 's/^progressed_at=//p' "$heartbeat")
    case "$polled_at" in ''|*[!0-9]*) exit 1 ;; esac
    case "$progressed_at" in ''|*[!0-9]*) exit 1 ;; esac
    [ $((now - polled_at)) -le "$INGESTION_MAX_AGE_SECS" ] || exit 1
    [ $((now - progressed_at)) -le "$INGESTION_STALL_MAX_SECS" ] || exit 1
done

# After the startup grace, every enabled chain must have a heartbeat. The node writes the
# expectation before it starts any reader, so a heartbeat without it means the expectation was lost.
expected="$INGESTION_DIR/expected"
if [ ! -e "$expected" ] && [ "$heartbeats" -gt 0 ]; then
    exit 1
fi
if [ -e "$expected" ]; then
    chains=$(sed -n 's/^chains=//p' "$expected")
    started_at=$(sed -n 's/^started_at=//p' "$expected")
    case "$chains" in ''|*[!0-9]*) exit 1 ;; esac
    case "$started_at" in ''|*[!0-9]*) exit 1 ;; esac
    if [ $((now - started_at)) -gt "$INGESTION_START_GRACE_SECS" ]; then
        [ "$heartbeats" -ge "$chains" ] || exit 1
    fi
fi
