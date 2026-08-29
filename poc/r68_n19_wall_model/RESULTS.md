# Round 68 - N=19 secure-8192 DKG wall table (committed, RAN-runnable)

One idea: re-establish the N=19 E2E DKG wall table ON DISK (the campaign headline need flagged
since round 30). The *full* 19-node secure-8192 E2E is box-2-gated (leaf set does not compile on
this 7.8 GiB box - 14.7 GiB OOM wall, r45/46). But ONE node's c3-bulk DKG chain is ALREADY fully
RAN on this box class (commit 18463b4, secure-8192/small = C3_SLOTS=57, N=19/fan-out-57), so the
table is anchored to that RAN chain; non-c3 remainder is labeled DRAFT. `python3 model.py` runs it.

## Self-check (reproduces the RAN anchors)
- r66 @4c re-summation 4315.5 s vs logged TOTAL 4315.6 s -> OK
- c3b M7x cut @8c (both RAN) 298.1 vs 449.1 = -33.6% -> OK
- core-ratio 4c:8c (same M7x object, both RAN) = 1.670 -> OK
- P0-vs-P1 inners @4c 3247.0 vs 3437.9 = -5.6% -> schedule-invariance (one code path, box-width class)
## RAN FLOOR - ONE node's c3-bulk DKG chain (per-node = the "hours" pain unit)
Per-node @4c (THIS box class), secure-8192/small, commit 18463b4, RAN:
| lane | wall (s) | % of per-node c3 | label |
|------|---------:|-----:|-------|
| 84 c3 inners (54 c3b SecretKey + 30 c3a SmudgingNoise) | 3437.9 | 79.7% | RAN (r66) |
| c3b M7x fold (8 top-level proves, the I5a production fold) | 497.7 | 11.5% | RAN (r66) |
| c3a serial fold (1 kernel + 29 steps) | 368.1 | 8.5% | RAN (r66) |
| c3ab seam (c3a->c3_fold VK, c3b->M7x VK) | 11.8 | 0.3% | RAN (r66) |
| **per-node c3-bulk total** | **4315.6** | 100% | RAN (r66) |

c3b fold cut: M7x 497.7 s (RAN@4c) vs serial 749.8 s (DRAFT@4c = 449.1 RAN@8c x 1.67) = -33.6%, RAN-anchored.
Schedule-invariance: P0 (anchor=3) inners 3247.0 s vs P1 3437.9 s = -5.6%, one code path (r67 RAN).

## 19-NODE WALL (DKG is per-node independent/parallel)
19 nodes commit in parallel; the ceremony wall ~= ONE node's wall.
- RAN floor (c3-bulk only) ~= 4315.6 s / node ~= 71.9 min.
- @8c reference: per-node c3 DRAFT ~= 2584.9 s (core-ratio 1.67 of the RAN @4c anchor);
  54 c3b inners 1763.5 s + c3b M7x 298.1 s are the RAN @8c subset (r63).

## DRAFT remainder (not RAN at N=19/secure-8192 on this box)
Per-node non-c3 leaves (C0 PkBfv, C1 PkGen, C2 Sk/ESm, C4a/C4b) + node_fold (ZkNodeDkgFold) +
the 19-node comm/parallelism. Grounding RAN facts: C0/C1/C3/C4 committee-invariant (r39-r44),
only the c3a/c3b LANES + C5 scale with committee (C5 H-only). The secure-8192/small FULL leaf
set is not built here (14.7 GiB compile OOM wall) => its RAN wall needs box-2.

## BOX-2 ASK (>=16 GiB) and the exact RAN command
1. recompile the secure-8192/small leaf set (C2a/C2b small arms need >=24 GiB);
2. RAN the full 19-node E2E wall:
   BENCHMARK_MODE=secure BENCHMARK_MULTITHREAD_JOBS=<n> cargo test --release -p e3-tests \
     --test integration test_trbfv_actor   (circuits/bin must carry the secure-8192/small stamp)

## Verdict
N=19 DKG wall table ESTABLISHED ON DISK (committed, RAN-runnable `python3 model.py`). Per-node
c3-bulk is RAN; non-c3 remainder is DRAFT + box-2-gated. The M7x fold cut = RAN-anchored lever.
