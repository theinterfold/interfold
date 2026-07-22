#!/bin/sh
# Fail-closed local and protocol readiness probe for the v0.4 image.
set -eu

PROC_ROOT="${PROC_ROOT:-/proc}"
CONFIG_FILE="${CONFIG_FILE:-/data/config.yaml}"
PASSWORD_FILE="${PASSWORD_FILE:-/run/interfold/key}"
DB_PATH="${DB_PATH:-/data/.interfold/data/_default/db}"
EVENT_LOG_PATH="${EVENT_LOG_PATH:-/data/.interfold/data/_default/log.0}"
QUIC_PORT="${QUIC_PORT:-37173}"
SS_BIN="${SS_BIN:-ss}"
STAT_BIN="${STAT_BIN:-stat}"
CURL_BIN="${CURL_BIN:-curl}"
READINESS_URL="${READINESS_URL:-http://127.0.0.1:50506/health/ready}"

case "$QUIC_PORT" in
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
$CURL_BIN --fail --silent --show-error --max-time 8 "$READINESS_URL" >/dev/null
