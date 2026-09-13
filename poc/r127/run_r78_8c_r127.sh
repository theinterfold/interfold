#!/usr/bin/env bash
# r127 r127b: the same r78 19-node E2E leg at 8c — contrast point vs the 4c-pinned
# leg. RAN only with the 4c unit IDLE (no co-run: overlapping shares would
# cross-contaminate both walls; 8c unit = all 8 cores = how r124/r125 + the old
# r45/r46 C2s ran 8c-silent). 2nd point of the @4c-vs-full wall-curve for the
# N=19 table. (The single-prove is inners-serial so 8c vs 4c movement is small;
# the RAN contrast is the datum, the projection of where the parallelization of
# the fold steps lands is the shape.)
set -uo pipefail
export PATH="/home/dev/.cargo/bin:/home/dev/.local/bin:/home/dev/.nargo/bin:/usr/local/bin:/usr/bin:/bin"
cd /home/dev/interfold-research/interfold
export E3_R78_STAGE_ROOT=/home/dev/interfold-research/poc/r127/stage/root
/usr/bin/time -v taskset -c 0-7 cargo test --release -p e3-zk-prover --test node_fold_function_tests_r78 -- --nocapture 2> /home/dev/interfold-research/interfold/poc/r127/status/leg-8c-time-$(date -u +%Y%m%d).log