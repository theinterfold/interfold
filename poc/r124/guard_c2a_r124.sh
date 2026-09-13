#!/bin/bash
# r124 C2a leg memory guard. Soft-abort on true global OOM risk:
# MemAvailable < 2 GiB AND real swap in use (>1 GiB). No-op when the leg ends.
HERE=/home/dev/interfold-research/interfold/poc/r124
LOG="$HERE/c2a_guard_r124.log"
: > "$LOG"
GO=""
for i in $(seq 1 90); do
  [ -z "$GO" ] && GO=$(pgrep -f 'nargo compile' | head -1)
  if [ -z "$GO" ]; then echo "$(date -u +%H:%M:%S) NARGO-GONE (leg finished/crashed)" >> "$LOG"; exit 0; fi
  AV=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
  SWP=$(awk '/SwapTotal/{t=$2}/SwapFree/{f=$2}END{print (t-f)}' /proc/meminfo)
  echo "$(date -u +%H:%M:%S) avail_kB=$AV swp_used_kB=$SWP" >> "$LOG"
  if [ "$AV" -lt 2097152 ] && [ "$SWP" -gt 1048576 ]; then
    echo "$(date -u +%H:%M:%S) OOM-RISK-ABORT avail=$AV swp=$SWP" >> "$LOG"
    kill "$GO" 2>/dev/null
    exit 8
  fi
  sleep 60
done
echo "$(date -u +%H:%M:%S) GUARD-TIMEOUT-90min" >> "$LOG"