#!/usr/bin/env bash
# r129: the r78 production 19-node DKG fold E2E (node_fold_function_tests_r78,
# secure-8192/small N=19/T=9/H=10/L=3) at FULL 8c — the 2nd point of the
# 4c-vs-full-core wall curve on the re-provisioned 8c/32 GiB box.
#  4c point (RAN r127): test wall 3959.68 s, peak 14.73 GiB, Swaps 0.
#  8c point (this leg): taskset -c 0-7, NO RAYON cap, fresh E3_R78_STAGE_ROOT.
# RAN only with no other heavy leg co-running (no cross-core contamination).
# Prove-only: the test binary is pre-built (r127), artifacts pre-staged =>
# zero nargo/bb compile, leg wall ~= provenance wall.
set -uo pipefail
export PATH="/home/dev/.cargo/bin:/home/dev/.local/bin:/home/dev/.nargo/bin:/usr/local/bin:/usr/bin:/bin"
cd /home/dev/interfold-research/interfold
export E3_R78_STAGE_ROOT=/home/dev/interfold-research/poc/r129/stage/root
/usr/bin/time -v taskset -c 0-7 cargo test --release -p e3-zk-prover --test node_fold_function_tests_r78 -- --nocapture 2>&1 | tee /home/dev/interfold-research/interfold/poc/r129/status/leg-8c-nocap.log 2> /home/dev/interfold-research/interfold/poc/r129/status/leg-8c-time.log