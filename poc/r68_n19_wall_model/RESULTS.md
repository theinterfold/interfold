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

## ROUND-69 LANDING APPENDIX (2026-08-29) — production-geometry per-node c3-bulk wall, RAN

The r69 leg (systemd unit `r69_prod_geo`, test `m7x_seam_prod_geo_tests_r69`, 453 lines,
secure-8192/small, commit 017adef) RAN the CORRECTED production per-node chain on this 4c box:
108 inners (54 sk-lane `DkgInputType::SecretKey` + 54 esm-lane `SmudgingNoise`, serial,
scattered W_1) + c3b M7x merge + c3a 54-step sequential fold + c3ab seam (c3b pinned to the
M7x VK, c3a to the c3_fold VK, c3ab artifact UNRECOMPILED). Unit Result=success, RC-TEST=0,
wall 1:28:41, maxrss 7,822,760 kB (7.47 GiB), Swaps 0, 278% CPU. Output: /tmp/r69_prod_geo_out.txt
+ durable copy poc/r69/r69_prod_geo_out.txt. All 7 asserts RAN-green: c3b circuit identity M7x,
c3a circuit identity C3Fold, 175 fields each arm, c3ab verify PASS, pinned key-hash publics ==
VK key_hashes (c3a 0x08fa9e2d…164b / c3b 0x26ed7ef3…3a52), c3ab columns == arm tails all 57 rows
(0 mismatches both columns-sets).

| per-node component | wall (s) @4c | % of node | label | vs r68 model-derived |
|---|---:|---:|---|---|
| 108 inners (54 sk + 54 esm) | 4196.3 | 78.9% | RAN (r69) | 4420.4 (model: 38.85 vs 40.93 s/inner unit) |
| c3b M7x fold (8 top-level proves) | 479.5 | 9.0% | RAN (r69) | 497.7 (r66 as-run; −3.7% new measurement) |
| c3a 54-step sequential fold | 634.4 | 11.9% | RAN (r69) | 614.7 (r66 unit 12.27 s/step × 54) |
| c3ab seam | 11.4 | 0.2% | RAN (r69) | 11.8 |
| **PER-NODE PRODUCTION c3-bulk @4c** | **5321.6** | 100% | **RAN (r69)** | 5592.2 (model was the conservative bound, +5.1% above RAN) |

Headline: **one production node's c3-bulk DKG = 5321.6 s = 88.7 min @4c / 3187.4 s = 53.1 min @8c
[DRAFT, core-ratio 1.670 of the RAN@4c anchor]; the 19-node ceremony wall ~= one node's wall
(nodes independent/parallel) ⇒ ~88.7 min @4c / ~53.1 min @8c c3-bulk, BEFORE the DRAFT non-c3
remainder (C0/C1/C2/C4 leaves + node_fold + comm; the box-2 ask stands ≥16 GiB) that r45/46
establish as not compilable here (14.7 GiB class). Cross-checks: per-inner 38.85 s @4c between
r65 40.93 s/inner @4c and r63 32.66 s/inner @8c — box-width-only wall, no regression. M7x wall
479.5 vs r65 497.7 / r67 484.5 @4c — box-width-only, schedule-invariant (P=1 arm here, as r63/r65).

New lever surfaced by the RAN numbers: the **c3a lane is SERIAL BY PRODUCTION WIRING**
(node_dkg_fold folds c3a always sequential; only c3b was routed to M7x). It is 634.4 s = 11.9% of
the per-node wall vs c3b-M7x 479.5 s. An M7x-routing of the c3a lane is a DRAFT est. of
~155 s/node @4c (479.5-class merge replacing the 634.4 serial) — the box-2 follow-up is the
M7x-on-c3a pole (new idea, p2, filed in STATE). The c3b fold cut re-anchored at the r69 M7x wall:
−36.1% @4c (M7x 479.5 RAN vs serial 749.8 DRAFT@4c = 449.1 RAN@8c × 1.67); −33.6% @8c (both RAN,
r63) remains the headline RAN cut.

Test-doc bug found and fixed this round (REEVAL per the r67 template, doc-only): the committed
r69 test header/const comments claimed the leg runs at P=0 / W_0 (NODE_P doc) while the CODE
runs NODE_P=1 / W_1 — the code is correct (matches the r63/r65 P=1 RAN anchor and the 108-inner
production geometry); the docs were stale r67 template carries. Fixed in the r69-landing commit
(no runtime effect; the leg's RAN numbers stand as printed — they were produced by the code,
which was correct). `cargo check -p e3-zk-prover --tests` RC 0 (14.54 s) — gate met (doc-only change).

**Updated fair prices:** I5a card CLOSED (r67) + r69 RAN put the per-node production c3-bulk on
the ledger as a RAN number (88.7 min @4c / 53.1 min @8c c3-bulk; 108 inners 78.9% = the bulk;
c3a serial = 11.9% = next lever). The box-2 ask unchanged: ≥16 GiB for the full 19-node E2E RAN.

---

## ROUND 70 - I70 PoC: route the c3a lane through the M7x merge (RAN)

The r70 leg (systemd unit `r70_c3a_arm`, test `m7x_c3a_arm_tests_r70`, 453 lines,
secure-8192/small, commit cd2f3df) RAN the I70 PoC on this 4c box: the 108-inner production
baseline + the **c3a lane re-routed through the M7x merge** (8 top-level proves) alongside the
c3a serial oracle, + c3b M7x (unchanged) + a BOTH-ARMS-M7x c3ab seam (c3a AND c3b pinned to the
M7x VK, c3ab artifact UNRECOMPILED). Unit Result=success, RC-TEST=0, wall 1:39:33, maxrss
7,820,144 kB (7.47 GiB), Swaps 0, 277% CPU. Output: /tmp/r70_c3a_arm_out.txt + durable copy
poc/r70/r70_c3a_arm_out.txt. All 9 asserts RAN-green: 54 c3a-lane + 54 c3b-lane secure inners
wall 4348.2 s; c3a arm M7x 495.8 s (175 fields, circuit M7x); c3a arm serial 638.0 s (175 fields,
C3Fold); **c3a M7x tail == c3a serial tail all 57 rows (0 mismatches)**; c3b arm M7x 479.7 s;
c3ab wall 11.5 s verify PASS pinned to the M7x VK both arms (publics
0x26ed7ef3…73a5 both); c3ab columns == arm tails all 57 rows both columns-sets (0 mismatches);
node-ledger; payoff.

| per-node component | wall (s) @4c | label | vs r69 node |
|---|---:|---|---|
| 108 inners (54 sk + 54 esm) | 4348.2 | RAN (r70) | 4196.3 (r69; +3.6% box variance, same geometry) |
| c3a lane — M7x merge (8 top-level proves) | 495.8 | RAN (r70) | was 634.4 serial (r69) |
| c3a lane — serial (oracle) | 638.0 | RAN (r70) | 634.4 (r69) |
| c3b M7x fold (8 top-level proves) | 479.7 | RAN (r70) | 479.5 (r69) |
| c3ab seam (both arms M7x VK) | 11.5 | RAN (r70) | 11.4 (r69) |

**I70 claim — HOLDS RAN.** Routing the c3a lane (node_dkg_fold's always-sequential arm) through
the M7x merge **cuts the c3a lane 142.2 s (22.3%)** — 638.0 serial (IFS compare) vs 495.8 M7x —
byte-identical tails (all 57 rows, 0 mismatches) and the c3ab seam verify-PASSes on the
UNRECOMPILED artifact with both arms pinned to the M7x VK. This extends the r65/r66/r67/r69
c3b=M7x VK-pin precedent to the c3a arm: the M7x key-hashVK is lane-agnostic, so a single
c3ab artifact covers both-arm-M7x.

**Post-I70 per-node c3-bulk @4c, RAN-reconstituted (two consistent figures):**
- (a) r69 node 5321.6 − r69 c3a-serial 634.4 + r70 c3a-M7x 495.8 = **5183.0 s = 86.4 min**
- (b) r70 same-leg (4 components, one state) = **5335.2 s = 88.9 min**
(b) − (a) = 152.2 s is entirely the +3.6% inners variance (4348.2 vs 4196.3), not the lever
(c3ab diff 0.1 s, c3b diff 0.2 s). @8c ref [DRAFT, core-ratio 1.670 of the RAN@4c anchor]:
(a) 3104.4 s / (b) 3195.5 s. Gateway remains the bulk: 108 inners = 79.6% of the node; the
M7x-routed c3a (495.8) + c3b (479.7) folds are now the two equal ~9% arms.

Verdict: the c3a lane was the last serial-by-production-wiring arm and it now pays the same
fold cut as c3b. **Node-level I70 payoff ~139-142 s/node @4c (~2.6% of the r69 c3-bulk node)** —
modest in isolation but it closes the c3-bulk lane-symmetry and removes the last serial fold
arm. The production wiring (node_dkg_fold route c3a arm -> M7x + c3ab arm-routed to the c3a-VK
arm, both arms M7x) is the next on-box step (I70-wiring). c3b fold cut re-anchored: M7x 479.7 RAN
vs serial 749.8 DRAFT@4c = 449.1 RAN@8c x 1.67 (−36.0% @4c; −33.6% @8c both-RAN r63 standalone).
Box-2 ask unchanged (>=16 GiB for the full 19-node E2E RAN).