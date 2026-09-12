#!/bin/bash
# r125 C2b leg memory + box sampler (cgroup2 flat root = the box session cgroup).
# CANARY-R125-MEM-SAMPLER-B41CD
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
ROOT=/sys/fs/cgroup
OUT=/home/dev/interfold-research/interfold/poc/r125/c2b_mem_samples_r125.csv
{
echo "epoch_since_start_s,mem_cur_kb,mem_peak_kb,mem_avail_kb,swap_used_kb,session_cgroup_peak_kb"
while true; do
  T=$(date +%s)
  CUR=$(cat $ROOT/memory.current 2>/dev/null || echo -)
  PK=$(cat $ROOT/memory.peak 2>/dev/null || echo -)
  AW=$(awk '/^MemAvailable/{print $2}' /proc/meminfo)
  SW=$(awk '/^SwapTotal/{s=$2}/^SwapFree/{f=$2}END{print s-f+0}' /proc/meminfo)
  echo "$(($T-START_S)),$CUR,$PK,$AW,$SW,SESSION_PEAK_JAIL"
  sleep 10
done
} 2>&1