#!/bin/bash
set -uo pipefail
A=/home/dev/interfold-research/interfold/poc/r126/leg_c2a_4rpc_r126.sh
B=/home/dev/interfold-research/interfold/poc/r126/leg_c2b_4rpc_r126.sh
echo "run_c2 start $(date -u +%H:%M:%S) legs: $(ls -d \"$A\" \"$B\" 2>&1)"
[ -f "$A" ] && [ -f "$B" ] || { echo "MISSING LEG ABORT"; exit 98; }
bash "$A"; echo "c2a exit=$? $(date -u +%H:%M:%S)"
sleep 3
bash "$B"; echo "c2b exit=$? $(date -u +%H:%M:%S)"
