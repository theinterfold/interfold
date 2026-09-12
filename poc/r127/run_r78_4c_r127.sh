#!/usr/bin/env bash
# r127 r127a: run the committed r78 19-node E2E leg (node_fold_function_tests_r78)
# 4c-pinned (taskset -c 0-3, RAYON_NUM_THREADS=4) — the SPEC-A shape, directly
# comparable to the r69 4196 s @4c / 90.1 min/node @4c anchors. Exit code = the
# cargo test RC. Tree = the r127 staged 81-file secure-8192/small (part (a) now
# RAN-filled on-box; E3_R78_STAGE_ROOT overrides the repo-path default).
set -uo pipefail
export PATH="/home/dev/.cargo/bin:/home/dev/.local/bin:/home/dev/.nargo/bin:/usr/local/bin:/usr/bin:/bin"
cd /home/dev/interfold-research/interfold
export E3_R78_STAGE_ROOT=/home/dev/interfold-research/poc/r127/stage/root
export RAYON_NUM_THREADS=4
/usr/bin/time -v taskset -c 0-3 cargo test --release -p e3-zk-prover --test node_fold_function_tests_r78 -- --nocapture 2> /home/dev/interfold-research/interfold/poc/r127/status/leg-4c-time-$(date -u +%Y%m%d).log