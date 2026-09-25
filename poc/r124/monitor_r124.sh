#!/bin/bash
# Monitor the r124 secure/small build: poll session cgroup + global mem every 60s.
# Abort conditions: (a) nargo gone early (compile crash/abort), (b) global MemAvailable < 2 GiB sustained, (c) swap in use.
LOG=/home/dev/interfold-research/interfold/monitor_r124.log
BASE=/home/dev/interfold-research/interfold
: > $LOG
CMD=""
for i in $(seq 1 400); do
  if [ -z "$CMD" ]; then
    CMD=$(pgrep -f "nargo compile" | head -1)
  fi
  [ -z "$CMD" ] && { echo "$(date -u +%H:%M:%S) NARGO-GONE" >> $LOG; echo "$(date -u +%H:%M:%S) NARGO-GONE" >> $LOG; exit 7; }
  AVAIL=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
  SWPFREE=$(grep SwapFree /proc/meminfo | awk '{print $2}')
  SWPTOT=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
  CS=$(grep '^0::' /proc/self/cgroup | cut -d: -f3)
  CUR=$(cat /sys/fs/cgroup$CS/memory.current 2>/dev/null || echo NA)
  PK=$(cat /sys/fs/cgroup$CS/memory.peak 2>/dev/null || echo NA)
  echo "$(date -u +%H:%M:%S) avail_kB=$AVAIL swp_used_kB=$((SWPTOT-SWPFREE)) session_cur_kB=$CUR session_peak_kB=$PK" >> $LOG
  # abort only if global avail low AND swap being used (system-level OOM risk)
  if [ "$AVAIL" -lt 2097152 ] && [ "$((SWPTOT-SWPFREE))" -gt 1048576 ]; then
    echo "$(date -u +%H:%M:%S) OOM-RISK-ABORT avail=$AVAIL swp_used=$((SWPTOT-SWPFREE))" >> $LOG
    kill $CMD 2>/dev/null
    exit 8
  fi
  sleep 60
done
echo "$(date -u +%H:%M:%S) TIMEOUT-400min" >> $LOG
