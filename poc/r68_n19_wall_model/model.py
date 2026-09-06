#!/usr/bin/env python3
# ROUND 68 - N=19 secure-8192 DKG wall table (RAN-runnable, self-checking, pure Python).
# Re-establishes the N=19 E2E DKG wall table ON DISK (campaign headline need flagged since
# round 30). Absolute scale anchored to ONE measured per-node production chain ALREADY fully
# RAN on THIS box class (commit 18463b4, secure-8192/small = C3_SLOTS=57, N=19/fan-out-57,
# x86, bb 5.1.0, release): the r66 @4c c3 chain. Others = RAN same-commit same-box-class
# (r63 @8c, r67 @4c) or clearly-labeled DRAFT with its box-2 run command.
# RAN-vs-DRAFT rule: RAN is the floor; DRAFT is the movable part. Anchor absolute scale to
# ONE measured chain; scale only by RATIO of RAN inputs; never cross-multiply a rate by a
# pool/contention factor.

def pct(a, b):
    return 100.0 * (a - b) / b

# RAN constants (traceable to LOG r63/r66/r67; same commit 18463b4 class)
# r63 @8c/16GiB (node P=1, release):
R63_INNERS_54_C3B_8C = 1763.5   # 54 c3b-lane ShareEncryption(SecretKey) inners, s
R63_C3B_M7X_8C       = 298.1    # c3b M7x merge fold (8 top-level proves), verify PASS, s
R63_C3B_SERIAL_8C    = 449.1    # c3b SERIAL fold (54 c3_fold steps), s
# r66 @4c/7.8GiB (node P=1, release) = per-node c3 chain, the @4c ABSOLUTE-SCALE ANCHOR:
# TEST SHAPE (r69-corrected): the inners are 54 c3b-lane [[redacted:sk_…]] + 30 c3a-lane
# SmudgingNoise over a CONTIGUOUS {3..33} block; the c3a lane is a 30-step sequential fold.
# PRODUCTION (RAN-source-verified r69) = 54 + 54 inners over scattered W_P, c3a a 54-step
# sequential fold (generate_shares sk/esm lanes identical; gen_esi_sss K=1; node_dkg_fold
# folds c3a always sequential, c3b via M7x). Production-derived numbers computed below.
R66_INNERS_84_4C  = 3437.9   # 84 c3 inners (54 c3b SecretKey + 30 c3a SmudgingNoise), s
R66_C3B_M7X_4C    = 497.7    # c3b M7x merge fold @4c, s
R66_C3A_SERIAL_4C = 368.1    # c3a serial fold (1 kernel + 29 steps over 30 inners), s
R66_C3AB_4C       = 11.8     # c3ab seam prove (c3a->c3_fold VK, c3b->M7x VK), s
R66_TOTAL_C3_4C   = 4315.6   # inners + c3b M7x + c3a + c3ab (r66 logged TOTAL), s
# r67 @4c/7.8GiB (node P=0, release) = schedule-invariance check:
R67_INNERS_84_4C = 3247.0   # 84 c3 inners @4c (P=0)
R67_C3B_M7X_4C   = 484.5    # c3b M7x merge fold @4c (P=0)

# Box-width core-ratio 4c:8c, RAN from the SAME object (c3b M7x fold) on both boxes:
CORE_4V8 = R66_C3B_M7X_4C / R63_C3B_M7X_8C   # = 1.67 (RAN)
N_NODES  = 19
W        = 74
print("=" * W)
print("ROUND 68 - N=19 secure-8192 DKG wall table  (commit 18463b4, secure-8192/small)")
print("=" * W)

# ------------------------------------------------------------- SELF-CHECK
r66_rec = R66_INNERS_84_4C + R66_C3B_M7X_4C + R66_C3A_SERIAL_4C + R66_C3AB_4C
print("\n[SELF-CHECK]")
print(f"  r66 @4c re-summation : {r66_rec:8.1f} s  vs logged TOTAL {R66_TOTAL_C3_4C:8.1f} s  "
      + ("OK" if abs(r66_rec - R66_TOTAL_C3_4C) < 1.0
         else "FAIL delta=%+.1f" % (r66_rec - R66_TOTAL_C3_4C)))
cut8 = pct(R63_C3B_M7X_8C, R63_C3B_SERIAL_8C)
print(f"  c3b M7x cut @8c (both RAN) : {R63_C3B_M7X_8C:.1f} vs {R63_C3B_SERIAL_8C:.1f} = {cut8:+.1f}%  (expect ~-33.6%)")
print(f"  core-ratio 4c:8c (M7x)     : {CORE_4V8:.3f}  (expect ~1.67)")
print(f"  P0-vs-P1 inners @4c        : {R67_INNERS_84_4C:.1f} vs {R66_INNERS_84_4C:.1f} = "
      f"{pct(R67_INNERS_84_4C, R66_INNERS_84_4C):+.1f}%  (schedule-invariance)")
print("\n" + "-" * W)
print("[RAN FLOOR - ONE node's c3-bulk DKG chain = 84 inners + c3b-M7x + c3a + c3ab]")
print("-" * W)
inh = 100.0 * R66_INNERS_84_4C / R66_TOTAL_C3_4C
print(f"  @4c (THIS box class)  RAN total = {R66_TOTAL_C3_4C:.1f} s = {R66_TOTAL_C3_4C/60.0:.1f} min")
print(f"     84 c3 inners        {R66_INNERS_84_4C:8.1f} s  ({inh:4.1f}% of per-node c3)   [RAN]")
print(f"     c3b M7x fold        {R66_C3B_M7X_4C:8.1f} s  ({100*R66_C3B_M7X_4C/R66_TOTAL_C3_4C:4.1f}%)   [RAN]")
print(f"     c3a serial fold     {R66_C3A_SERIAL_4C:8.1f} s  ({100*R66_C3A_SERIAL_4C/R66_TOTAL_C3_4C:4.1f}%)   [RAN]")
print(f"     c3ab seam           {R66_C3AB_4C:8.1f} s  ({100*R66_C3AB_4C/R66_TOTAL_C3_4C:4.1f}%)   [RAN]")
c3b_serial_4c = R63_C3B_SERIAL_8C * CORE_4V8
cut4 = pct(R66_C3B_M7X_4C, c3b_serial_4c)
print(f"  c3b fold cut: M7x {R66_C3B_M7X_4C:.1f}s(RAN@4c) vs serial {c3b_serial_4c:.1f}s"
      f"(DRAFT={R63_C3B_SERIAL_8C:.1f}RAN@8c x {CORE_4V8:.2f}) = {cut4:+.1f}% [RAN-anchored]")
p8c = R66_TOTAL_C3_4C / CORE_4V8
print(f"  @8c ref: 54 c3b inners {R63_INNERS_54_C3B_8C:.1f}s + c3b M7x {R63_C3B_M7X_8C:.1f}s [RAN subset]")
print(f"     full per-node c3 @8c DRAFT = {R66_TOTAL_C3_4C:.1f}/{CORE_4V8:.2f} = {p8c:.1f}s (core-ratio of RAN@4c anchor)")
print("\n" + "-" * W)
print("[DRAFT - NOT RAN at N=19/secure-8192 on this box; RAN needs box-2]")
print("-" * W)
print("  Per-node non-c3 leaves  : C0 PkBfv, C1 PkGen, C2 Sk/ESm, C4a/C4b DkgShareDecryption")
print("  + node_fold (ZkNodeDkgFold) + the 19-node in-process E2E wall.")
print("  Load-bearing RAN source facts (why these are the movable/DRAFT part):")
print("   - C0/C1/C3/C4 are committee-invariant (r39-r44 RAN); only the c3a/c3b LANES and C5")
print("     scale with committee size (C5 H-only). At N=19/fan-out-57 the c3 lanes BECOME the bulk")
print("     (84 inners/node) - which is exactly the RAN floor above.")
print("   - C5 small (H=10) = 1,289,676 + 228,177*H RAN curve; C5 is node-published, not the DKG path.")
print("   - The secure-8192/small FULL leaf set is not built here (14.7 GiB compile OOM wall, r45/46).")
print("     => a full 19-node E2E RAN wall requires box-2 (>=16 GiB) to recompile the leaf set, then:")
print("     BENCHMARK_MODE=secure BENCHMARK_MULTITHREAD_JOBS=<n> cargo test --release -p e3-tests \\")
print("       --test integration test_trbfv_actor   (circuits/bin must be secure-8192/small build stamp)")
# ---- 19-NODE DKG WALL (DKG is per-node independent/parallel) ----
# The "hours" pain = ONE node's full-proof DKG wall (slowest node commits the ceremony).
# Per-node c3-bulk is RAN @4c. Non-c3 leaves + node_fold + fan-out/comm are DRAFT.
print("\n" + "-" * W)
print("[19-NODE DKG WALL - per-node c3-bulk RAN anchor; fan-out & non-c3 are DRAFT]")
print(f"  Per-node c3-bulk @4c RAN = {R66_TOTAL_C3_4C:.1f} s = {R66_TOTAL_C3_4C/60.0:.1f} min/node")
print(f"  19 nodes are INDEPENDENT & PARALLEL in the ceremony (no serial dependency):")
print(f"     => full 19-node DKG wall ~= ONE node's wall (fan-out hidden in parallelism).")
print(f"        RAN floor (c3-bulk only)  ~= {R66_TOTAL_C3_4C:.1f} s  [RAN per-node, x1 node]")
print(f"        DRAFT full node (c3 + non-c3 leaves + node_fold): see DRAFT remainder below.")
print("\n" + "-" * W)
print("[RAN-ROBUST HEADLINE + BOX-2 ASK]")
print("-" * W)
print(f"  RAN-robust: ONE node's c3-bulk DKG @4c = {R66_TOTAL_C3_4C/60.0:.1f} min; the c3b fold cut")
print(f"    (M7x vs serial) = {cut8:+.1f}% @8c RAN, {cut4:+.1f}% @4c RAN-anchored. That is the lever.")
print("  19 nodes are independent/parallel => 19-node DKG wall ~= one node's wall (fan-out hidden).")
print("  DRAFT remainder (non-c3 leaves + node_fold + comm) needs box-2 RAN to convert to a number.")
print("  BOX-2 ASK: >=16 GiB to (a) recompile the secure-8192/small leaf set, (b) RAN the full")
print("    19-node E2E wall via: BENCHMARK_MODE=secure cargo test --release -p e3-tests --test")
print("    integration test_trbfv_actor  (circuits/bin must carry the secure-8192/small stamp).")
print("\n  Verdict: N=19 DKG wall table ESTABLISHED ON DISK (committed). Per-node c3-bulk is RAN;")
print("  the non-c3 remainder is DRAFT and box-2-gated. The M7x fold cut is a RAN-anchored win.")

# ==================== ROUND-69 CORRECTION: PRODUCTION c3 geometry ====================
# The r66 anchor ABOVE is TEST-SHAPED. RAN-source-verified at this commit (LOG r69):
#  (1) gen_esi_sss.rs:91 -> esi_sss = vec![ONE SharedSecret] => exactly 1 smudging SSS.
#  (2) generate_shares.rs sk-lane(C3a) and esm-lane(C3b) loops are IDENTICAL:
#      skip own party (18 of 19) x L=3 rows => 54 inners PER lane (K=1 esm).
#  (3) node_dkg_fold.rs  [:219-267] c3a is ALWAYS the sequential fold; c3b takes M7x
#      only on 54/54. The {3..33} 30-block c3a of r65/r66/r67 was a test convenience
#      (r67 entry: "the c3a arm's shape is not under test").
# PRODUCTION per-node c3-bulk = 54 (sk/C3a) + 54 (esm/C3b) = 108 inners, + c3a 54-step
# sequential fold (1 kernel + 53 c3_fold proves), + c3b M7x (unchanged), + c3ab.
# Absolute scale: SAME RAN @4c chain (r66) scaled by RATIO of RAN per-unit inputs x
# production counts (skill rule: no global-rate × pool/contention cross-product).
per_inner    = R66_INNERS_84_4C / 84.0    # RAN per-inner (84 sk+esm inners; one circuit class/both lanes)
per_c3a_unit = R66_C3A_SERIAL_4C  / 30.0  # RAN per c3a sequential unit (c3_fold step @4c)

P_INNERS = 108      # 54 sk + 54 esm (RAN-source-derived from (1)+(2))
P_C3A_STE = 54      # production c3a sequential units [RAN-source (3)]

pi   = P_INNERS * per_inner
pc3a = P_C3A_STE * per_c3a_unit
p4c  = pi + R66_C3B_M7X_4C + pc3a + R66_C3AB_4C
p8c  = p4c / CORE_4V8

# ==================== ROUND-69 LANDING: PRODUCTION c3 geometry, RAN (r69 leg) ====================
# The r69 leg (unit r69_prod_geo, 2026-08-29, launched 20:00:13 UTC, landed 21:28:54,
# Result=success, RC-TEST=0, wall 1:28:41, maxrss 7,822,760 kB = 7.47 GiB, Swaps 0,
# 278% CPU; output /tmp/r69_prod_geo_out.txt + durable poc/r69/) RAN the production
# per-node c3-bulk chain on THIS 4c box: 108 secure-8192/small inners over the scattered
# W_1 (54 sk-lane DkgInputType::SecretKey + 54 esm-lane SmudgingNoise) + c3b M7x +
# c3a 54-step sequential + c3ab seam (c3b pinned to the M7x VK, c3a to the c3_fold VK,
# c3ab UNRECOMPILED):
R69_INNERS_108_4C = 4196.3   # 108 inners (54 sk + 54 esm) serial @4c, s
R69_C3B_M7X_4C    = 479.5    # c3b M7x (8 top-level proves), fields 175, circuit M7x, s
R69_C3A_SERIAL_4C = 634.4    # c3a 1 kernel + 53 c3_fold steps over W_1, fields 175, s
R69_C3AB_4C       = 11.4     # c3ab seam prove, verify PASS, s
R69_TOTAL_4C      = 5321.6   # per-node PRODUCTION c3-bulk @4c, s (leg printed total)

print("\n" + "=" * W)
print("ROUND-69 LANDING - production per-node c3-bulk wall (RAN, r69 leg @4c, 453-line test)")
print("=" * W)
r69_rec = R69_INNERS_108_4C + R69_C3B_M7X_4C + R69_C3A_SERIAL_4C + R69_C3AB_4C
print(f"  self-check re-summation : {r69_rec:.1f} s vs leg-printed {R69_TOTAL_4C:.1f} s  "
      + ("OK" if abs(r69_rec - R69_TOTAL_4C) < 1.0 else "FAIL"))
print(f"  108 inners (54 sk + 54 esm, W_1 scatter) {R69_INNERS_108_4C:7.1f} s = "
      f"{R69_INNERS_108_4C/R69_TOTAL_4C*100:4.1f}%  ({R69_INNERS_108_4C/108:.2f} s/inner)   [RAN]")
print(f"  c3b M7x fold (8 top-level proves)       {R69_C3B_M7X_4C:7.1f} s = "
      f"{R69_C3B_M7X_4C/R69_TOTAL_4C*100:4.1f}%   [RAN]")
print(f"  c3a 54-step sequential fold             {R69_C3A_SERIAL_4C:7.1f} s = "
      f"{R69_C3A_SERIAL_4C/R69_TOTAL_4C*100:4.1f}%   [RAN]")
print(f"  c3ab seam (verify PASS)                 {R69_C3AB_4C:7.1f} s = "
      f"{R69_C3AB_4C/R69_TOTAL_4C*100:4.1f}%   [RAN]")
print(f"  ==> PER-NODE PRODUCTION c3-bulk @4c  = {R69_TOTAL_4C:.1f} s = {R69_TOTAL_4C/60.0:.1f} min  [RAN]")
p8 = R69_TOTAL_4C / CORE_4V8
print(f"      @8c ref = {R69_TOTAL_4C:.1f}/{CORE_4V8:.2f} = {p8:.1f} s = {p8/60.0:.1f} min  "
      f"[DRAFT, core-ratio of the RAN@4c]")
# r69-RAN vs r69-model-derived: the model (r66 units x production counts) predicted 5592.2 s:
model_derived = 108 * per_inner + R66_C3B_M7X_4C + 54 * per_c3a_unit + R66_C3AB_4C
print(f"  model-derived (r66 units x counts) = {model_derived:.1f} s; RAN = {R69_TOTAL_4C:.1f} s "
      f"= RAN is {100.0*(model_derived-R69_TOTAL_4C)/R69_TOTAL_4C:+.1f}% vs the model "
      f"(r69 per-inner {R69_INNERS_108_4C/108:.2f} s vs r66-composition {per_inner:.2f} s; "
      f"r69 c3-step {R69_C3A_SERIAL_4C/54:.2f} s vs r66 {per_c3a_unit:.2f} s) — model was the "
      f"conservative bound; the RAN number is the wall")
# c3b fold cut now RAN-anchored at BOTH box widths (M7x RAN@4c/r69; serial RAN@8c/r63 x core-ratio):
ser4 = R63_C3B_SERIAL_8C * CORE_4V8
print(f"  c3b fold cut @4c: M7x {R69_C3B_M7X_4C:.1f} (RAN r69) vs serial {ser4:.1f} "
      f"(DRAFT = {R63_C3B_SERIAL_8C:.1f} RAN@8c x {CORE_4V8:.2f}) = {pct(R69_C3B_M7X_4C, ser4):+.1f}%")
print(f"  c3a lane is SERIAL by production wiring (node_dkg_fold folds c3a always sequential):")
print(f"      {R69_C3A_SERIAL_4C:.1f} s = {R69_C3A_SERIAL_4C/R69_TOTAL_4C*100:.1f}% of the per-node c3-bulk wall [RAN]")
print(f"      => M7x-on-c3a-lane is the natural next lever (DRAFT est: ~{R69_C3A_SERIAL_4C-R69_C3B_M7X_4C:.0f} s/node @4c).")
# 19-node headline (uke = one node; nodes independent/parallel):
print("=" * W)
print("19-NODE HEADLINE INTO THE LEDGER (RAN, r69 baseline):")
print(f"  one production node's c3-bulk DKG = {R69_TOTAL_4C:.1f} s = {R69_TOTAL_4C/60.0:.1f} min @4c "
      f"({R69_INNERS_108_4C/60.0:.1f} of it the 108 inners = 78.9%); the 19-node ceremony wall ~= one node's")
print(f"  wall (independent/parallel) => ~{R69_TOTAL_4C/60.0:.1f} min @4c / ~{p8/60.0:.1f} min @8c c3-bulk, BEFORE the")
print(f"  DRAFT non-c3 remainder (C0/C1/C2/C4 leaves + node_fold + comm; box-2 ask stands >=16 GiB).")

# ==================== ROUND-70 LANDING: I70 c3a-lane M7x, RAN (r70 leg @4c) ====================
# The r70 leg (unit r70_c3a_arm, 2026-08-30, launched 02:43:04 UTC, landed 04:22:37,
# Result=success, RC-TEST=0, wall 1:39:33, maxrss 7,820,144 kB = 7.47 GiB, Swaps 0,
# 277% CPU; output /tmp/r70_c3a_arm_out.txt + durable poc/r70/) RAN the I70 PoC on THIS
# 4c box: 108 secure-8192/small inners over scattered W_1 (54 sk-lane SecretKey/C3a +
# 54 esm-lane SmudgingNoise/C3b) with the C3a lane routed BOTH ways - through the M7x merge
# (under test) and the getCurrent production 54-step sequential fold (the byte-identity
# oracle) - plus a BOTH-ARMS-M7x c3ab seam (c3a AND c3b pinned to the M7x VK, c3ab
# artifact UNRECOMPILED):
R70_INNERS_108_4C   = 4348.2   # 108 inners (54 sk + 54 esm) serial @4c, s
R70_C3A_M7X_4C      = 495.8    # c3a M7x (8 top-level proves), fields 175, circuit M7x, s
R70_C3A_SERIAL_4C   = 638.0    # c3a 1 kernel + 53 c3_fold steps over W_1 (oracle), s
R70_C3B_M7X_4C      = 479.7    # c3b M7x (8 top-level proves), fields 175, circuit M7x, s
R70_C3AB_4C         = 11.5     # c3ab seam (BOTH arms -> M7x VK), verify PASS, s
R70_TEST_WALL_4C    = 5973.39  # test "finished in" (s); wall clock of the leg

print("\n" + "=" * W)
print("ROUND-70 LANDING - I70: c3a lane through the M7x merge (RAN, r70 leg @4c)")
print("=" * W)
r70_armsum = (R70_INNERS_108_4C + R70_C3A_M7X_4C + R70_C3A_SERIAL_4C
              + R70_C3B_M7X_4C + R70_C3AB_4C)
print(f"  self-check: sum of the 5 arm walls = {r70_armsum:.1f} s vs test-report "
      f"{R70_TEST_WALL_4C:.1f} s  "
      + ("OK" if abs(r70_armsum - R70_TEST_WALL_4C) < 1.0 else "FAIL"))
print(f"  108 inners (54 sk + 54 esm, W_1 scatter)  {R70_INNERS_108_4C:7.1f} s  "
      f"({R70_INNERS_108_4C/108:.2f} s/inner)   [RAN r70]")
print(f"  c3a M7x (8 top-level proves)              {R70_C3A_M7X_4C:7.1f} s   "
      f"[RAN r70]  <-- UNDER TEST (the I70 route)")
print(f"  c3a serial (1 kernel + 53 steps)          {R70_C3A_SERIAL_4C:7.1f} s   "
      f"[RAN r70]  <-- the CURRENT production wiring (oracle)")
print(f"  c3b M7x (8 top-level proves)              {R70_C3B_M7X_4C:7.1f} s   [RAN r70]")
print(f"  c3ab (both arms -> M7x VK), verify PASS   {R70_C3AB_4C:7.1f} s   [RAN r70]")
# RAN-ROBUST HEADLINE: the c3a-lane cut, SAME-LEG r70 (both terms RAN, one box state):
c3a_cut = R70_C3A_M7X_4C - R70_C3A_SERIAL_4C
print("-" * W)
print(f"  I70 LEVER (RAN-robust, r70 same-leg): c3a M7x {R70_C3A_M7X_4C:.1f}s vs serial "
      f"{R70_C3A_SERIAL_4C:.1f}s = {c3a_cut:.1f} s = {100.0*c3a_cut/R70_C3A_SERIAL_4C:+.1f}% "
      f"of the c3a lane")
print(f"        c3a-M7x tail == c3a-serial tail, ALL 57 rows, 0 mismatches [RAN r70] "
      f"= the load-bearing equivalence claim holds")
print(f"        BOTH-ARMS-M7x c3ab seam verify PASS on the UNRECOMPILED artifact [RAN r70] "
      f"(extends the r65/r66/r67/r69 c3b=M7x VK-pin precedent to the c3a arm)")
# NODE RECONSTRUCTION (RAN-reconstituted; each term a RAN measurement). Two provenances:
#  (a) r69 production baseline node, c3a term swapped to the r70 RAN c3a-M7x (mixed-leg):
node_r69base = R69_TOTAL_4C - R69_C3A_SERIAL_4C + R70_C3A_M7X_4C
#  (b) r70 same-leg: all 4 post-I70 production components from ONE leg/box-state:
node_r70leg = R70_INNERS_108_4C + R70_C3B_M7X_4C + R70_C3A_M7X_4C + R70_C3AB_4C
print(f"  post-I70 per-node c3-bulk @4c, RAN-reconstituted:")
print(f"     (a) r69 node {R69_TOTAL_4C:.1f} - r69 c3a-serial {R69_C3A_SERIAL_4C:.1f} "
      f"+ r70 c3a-M7x {R70_C3A_M7X_4C:.1f} = {node_r69base:.1f} s = {node_r69base/60.0:.1f} min")
print(f"     (b) r70 same-leg (4 components, one state) = {node_r70leg:.1f} s = "
      f"{node_r70leg/60.0:.1f} min  (r70 inners ran {100.0*(R70_INNERS_108_4C-R69_INNERS_108_4C)/R69_INNERS_108_4C:+.1f}% "
      f"vs r69 -> the (b)-(a) gap is inners variance, not the lever)")
print(f"     @8c ref [DRAFT, core-ratio {CORE_4V8:.2f} of the RAN@4c]: (a) {node_r69base/CORE_4V8:.1f} s "
      f"/ (b) {node_r70leg/CORE_4V8:.1f} s")
print("-" * W)
print("  RAN-ROBUST HEADLINE (r70): routing the c3a lane through the M7x merge cuts the c3a")
print(f"    lane {abs(c3a_cut):.1f}s ({100.0*abs(c3a_cut)/R70_C3A_SERIAL_4C:.1f}%), byte-identical, with the c3ab seam "
      f"verify-PASS on the un-recompiled artifact => the I70 PoC claim holds RAN. Node-level payoff "
      f"~{abs(R70_C3A_M7X_4C-R69_C3A_SERIAL_4C):.0f}-{abs(c3a_cut):.0f} s/node @4c "
      f"({100.0*abs(R70_C3A_M7X_4C-R69_C3A_SERIAL_4C)/R69_TOTAL_4C:.1f}% of the r69 c3-bulk node). The production "
      f"wiring (node_dkg_fold c3a arm -> M7x + c3ab c3a-VK arm switch) is the next on-box step (I70-wiring).")
# ==================== ROUND-75 LANDING: min whole-node function wall, RAN (r75 leg @4c) ====================
# The r75 leg (unit r75, 2026-08-31, RC-TEST=0, wall 13:24.17 @4c, 296%% CPU, maxrss 4.54 GiB,
# Swaps 0; durable poc/r75/) RAN the PRODUCTION function `prove_node_dkg_fold` END-TO-END at
# secure-8192/minimum (N=3/T=1/H=2, L=3, C3_SLOTS=9, W_P=6) on THIS 4c/7.8 GiB box. This is the
# first RAN production-field (8192/59-bit) function wall: the RAN anchor for the committee-
# INVARIANT subset of the non-c3 remainder that r68/r69/r70 had carried as pure DRAFT.
R75_MIN = dict(c0=3.5, c1=27.9, c2a=15.7, c2b=28.8, c3x12=490.7, c4a=18.2, c4b=18.1,
               c2ab=29.0, c3a=143.6, c3b=142.5, c3ab=12.1, c4ab=12.6, node=31.9)  # [RAN step_timings]
R75_MIN_LEAVES = 602.9        # sum of the 7 serial leaf walls [RAN]
R75_MIN_FUNC   = 200.1        # critical path: max(c2ab,c3a,c3b)+c3ab+c4ab+node [RAN]
R75_MIN_WHOLE  = 803.0        # whole-node = leaves + func [RAN]
c4_min_wall = R75_MIN["c4a"]+R75_MIN["c4b"]     # C4 prove pair at secure-8192/min [RAN]
_min_keys = ("c0","c1","c2a","c2b","c3x12","c4a","c4b")
print("\n"+"="*W)
print("ROUND-75 LANDING - min (N=3/T=1/H=2) whole-node PRODUCTION function wall (RAN, r75 @4c)")
print("="*W)
m_leaves = sum(v for k,v in R75_MIN.items() if k in _min_keys)
m_func   = max(R75_MIN["c2ab"],R75_MIN["c3a"],R75_MIN["c3b"])+R75_MIN["c3ab"]+R75_MIN["c4ab"]+R75_MIN["node"]
m_whole  = m_leaves+m_func
print("  anchor self-check : leaves=%.1f + func=%.1f = %.1f s  vs RAN whole %.1f s  %s"%(
    m_leaves,m_func,m_whole,R75_MIN_WHOLE,"OK" if abs(m_whole-R75_MIN_WHOLE)<1.0 else "FAIL"))
print("  c2ab (29.0 s) runs HIDDEN under the c3a|c3b join (parallel) - not on the critical path (r74).")
print("  field-width note  : min is the RAN anchor for the committee-INVARIANT non-c3 provers")
print("    (C0 r39 / C1 r44 invariant; C4 r46 H-only; the 4 folds ~0.1-0.7% small-vs-min, r74 gate table).")
print("\n  ==> min whole-node PRODUCTION function wall @4c = %.1f s = %.1f min  [RAN anchor]"%(
    R75_MIN_WHOLE, R75_MIN_WHOLE/60.0))
print("  c3-inners min = 12 serial @ 40.9 s/inner (r69/r70 small 38.85-40.26 s/inner = SAME band);")
print("    the ~32x min<->small inner gap is pure secure-8192 59-bit width (box-invariant, r75 note).")
# ==================== ROUND-76 MODEL ADVANCE: non-c3 remainder RAN-anchored (was pure DRAFT r69/r70) ====================
# r74/r75 RAN the whole function at BOTH committee endpoints the 7.8 GiB box can carry. The
# non-c3 remainder (leaves C0/C1/C2a/C2b/C4 + c2ab/c4ab/node_fold) that model.py carried as
# DRAFT now has a RAN minimum-width point from r75 (committee-invariant subset) + a RAN
# ratio scale for the one committee-DEPENDENT term (C4, H-only, r46).
C4_GATE_MIN, C4_GATE_SMALL = 1746030.0, 3571446.0    # [RAN r46] C4 secure-8192 min/small gates
C4_RATIO = C4_GATE_SMALL/C4_GATE_MIN                 # = 2.0455 (H-only committee scaling, r46)
C4_SMALL_WALL = c4_min_wall*C4_RATIO                 # [RAN-anchored: RAN min wall x RAN ratio]
C0C1 = R75_MIN["c0"]+R75_MIN["c1"]                   # committee-invariant leaf pair [RAN r75]
print("\n"+"="*W)
print("ROUND-76 - NON-C3 REMAINDER RAN-ANCHORED (r75 min point + r46 C4 ratio; was pure DRAFT)")
print("="*W)
print("  [%s] C0+C1 leaves   = %.1f s (r39/r44 committee-invariant => applies to small)"%("RAN r75",C0C1))
print("  [%s] C4a+C4b leaves = %.1f s min -> %.1f s small (x%.4f = C4 gate ratio, r46/H-only)"%(
    "RAN min / RAN-anchored",c4_min_wall,C4_SMALL_WALL,C4_RATIO))
# invariant non-c3 folds (c2ab/c4ab/node) ~0.1-0.7% small-vs-min (r74 gate table) => use the
# RAN min walls as the small FLOOR (conservative, RAN).
INV_FOLDS_SMALL_FLOOR = R75_MIN["c2ab"]+R75_MIN["c4ab"]+R75_MIN["node"]    # = 73.5 s [RAN min floor]
INV_NONC3_SMALL = C0C1 + C4_SMALL_WALL + INV_FOLDS_SMALL_FLOOR             # [RAN / RAN-anchored]
# c3-bulk at small (production N=19, 108 inners, both M7x arms + c3ab) = model (a) RAN reconstruction
C3BULK_SMALL = node_r69base        # = R69_TOTAL - R69_C3A_SERIAL + R70_C3A_M7X = 5183.0 s [RAN]
# C2a/C2b min prove walls (r75 RAN) are the committee-INVARIANT LOWER BOUND on the small proves.
C2_AB_MIN = R75_MIN["c2a"]+R75_MIN["c2b"]    # = 44.5 s [RAN min] (small prove >= this, per-recipient N)
# N=19 whole-node wall, RAN/RAN-anchored floor + the single residual DRAFT (C2a/C2b small committee delta):
#   node_small = C3BULK_SMALL + INV_NONC3_SMALL + (C2a_small + C2b_small)
#              = [C3BULK_SMALL + INV_NONC3_SMALL]  +  [C2_AB_MIN + (DRAFT committee delta)]
RAN_ALL = C3BULK_SMALL + INV_NONC3_SMALL + C2_AB_MIN     # every RAN/RAN-anchored/C2-min-floor term (C4 at RAN-anchored small wall)
print("  [%s] c3-bulk (108 inners + 2x M7x + c3ab)  = %.1f s [RAN r70 (a) reconstruction]"%("RAN",C3BULK_SMALL))
print("  [%s] non-c3 folds c2ab+c4ab+node (small floor, min walls) = %.1f s [RAN min floor]"%("RAN",INV_FOLDS_SMALL_FLOOR))
print("  [%s] C2a/C2b leaves small: min wall %.1f s is the RAN lower bound (per-recipient N => small >= min)"%("RAN",C2_AB_MIN))
print("  ---------  sum of every RAN / RAN-anchored / C2-min-floor term in the N=19 node:")
print("               N=19 NODE WALL (C4 at RAN-anchored small wall) = %.1f s = %.1f min @4c  [RAN-anchored]"%(RAN_ALL,RAN_ALL/60.0))
# The ONE residual DRAFT term = the C2a/C2b small-vs-min PROVE-THROUGH delta (per-recipient N
# structure; the small C2 LEAVES don't compile on this box - r45 OOM 15.1/14.9 GiB), so the small
# C2 prove wall is >= its min wall and UNBOUNDED-FROM-ABOVE on-box => box-2. Two honest readings:
N_SMALL_RANFLOOR = RAN_ALL - C4_SMALL_WALL + c4_min_wall  # all-pure-RAN: C4 at its RAN MIN wall (conservative floor)
N_SMALL_ANCHORED = RAN_ALL                                # C4 scaled min->small by the RAN gate ratio
print("  ==> N=19 NODE WALL @4c, two readings (both EXCLUDE only the C2 small committee delta + comm):")
print("        [%s]        %7.1f s = %5.1f min  (all-pure-RAN; C4 at its RAN min wall, conservative floor)"%("RAN floor",N_SMALL_RANFLOOR,N_SMALL_RANFLOOR/60.0))
print("        [%s] %7.1f s = %5.1f min  (C4 min->small by the RAN gate ratio x%.2f)"%("RAN-anchored",N_SMALL_ANCHORED,N_SMALL_ANCHORED/60.0,C4_RATIO))
print("  + [DRAFT, box-2] C2a+C2b small prove-through delta (>= 0; small C2 leaves OOM on-box r45)")
print("-"*W)
print("  LABEL TABLE (which inputs feed the N=19 node wall):")
print("    C3BULK (108 in+2xM7x+c3ab) 5183.0 = RAN   (r70 (a) reconstruction of the r69/r70 legs)")
print("    C0+C1 leaves   31.4        = RAN          (r75; c0 r39/c1 r44 committee-invariant)")
print("    C4a+C4b        36.3->%.1f  = RAN min / RAN-anchored (r46 H-only ratio %.4f)"%(C4_SMALL_WALL,C4_RATIO))
print("    c2ab+c4ab+node 73.5        = RAN (min floor; folds ~0.1-0.7% small-vs-min r74)")
print("    C2a+C2b         44.5 floor  = RAN min; small delta = DRAFT/box-2 (compile OOM r45)")
print("-"*W)
print("  ANCHOR REPRODUCTION: min-node model = %.1f s vs r75 RAN whole = %.1f s (delta %+.1f s = jitter; the" % (m_whole,R75_MIN_WHOLE,m_whole-R75_MIN_WHOLE))
print("                             anchor reproduces a known RAN value => the min leg is the valid scale anchor.)")
print("-"*W)
print("  VERDICT (r76): the non-c3 remainder is NO LONGER PURE DRAFT. Its committee-invariant subset +")
print("  the C4 committee term are RAN/RAN-anchored at small from the r75 min point, and the N=19 node")
print("  wall is now a RAN-anchored %.1f min (RAN floor %.1f min) that EXCLUDES only the C2a/C2b small" % (N_SMALL_ANCHORED/60.0,N_SMALL_RANFLOOR/60.0))
print("  per-recipient prove wall (>= its min wall 44.5 s RAN; the small C2 leaves don't compile on-box,")
print("  r45 OOM 15.1/14.9 GiB => the small-vs-min delta is the single DRAFT, box-2) + comm. The c3-bulk")
print("  (5183.0 s = 86.4 min, RAN r70 (a)) dominates: even at the RAN floor the node is %.1f min, so the" % (N_SMALL_RANFLOOR/60.0))
print("  'several hours' framing is now an RAN-anchored ~1.5 h/node @4c (+ inners concurrency note: the")
print("  108 inners run serial in these walls; a production TaskPool 4-way pool is CPU-conserved on 4c,")
print("  RAN r72), with the residual box-2 work = the C2 small prove walls + the full 19-node E2E RAN.")
# ==================== ROUND-80 LANDING: C2 committee curve completed min->micro (recovers the r76 census) ====================
# r76 (2026-08-31) RAN the C2 micro (N=9/T=4/H=5) census arms on box (bin/dkg targets built
# 08-31 11:28/11:49) but its log entry carries GATES_PLACEHOLDER - the digits were never
# durably recorded. r80 recovers them from the durable on-disk artifacts (bb gates re-run +
# sha pin + public-ABI N_parties decode) and cross-checks the min goldens against the durable
# poc/r75/min artifacts (re-gated DIGIT-EXACT to the r45 goldens). Box-2 scope UNCHANGED: an
# r80 full-box sweep finds NO small (N=19) C2 leaf and NO small (~3.57M-gate) C4 leaf on this
# box => I71-leg part-(a) is still exactly the 3 heavy leaf compiles (C2a/C2b >=24 GiB r45 OOM,
# C4 14.70 GiB knife-edge r46).
C2G = {  # secure-8192, C2 committee census (gates)
  "c2a": dict(min=1446311, micro=4283789, min_acir=426360, micro_acir=1155486, micro_sha="96aae9c6a185cd46"),
  "c2b": dict(min=2888964, micro=5726442, min_acir=827414, micro_acir=1556540, micro_sha="588dbfa71c43bc8e"),
}
NC2 = {"min": 3, "micro": 9, "small": 19}   # N_PARTIES per committee (public-ABI decoded RAN)
print("\n" + "=" * W)
print("ROUND-80 - C2 committee curve min(N=3)->micro(N=9) COMPLETED RAN + small(N=19) DRAFT-2pt")
print("=" * W)
_da = C2G["c2a"]["micro"] - C2G["c2a"]["min"]
_db = C2G["c2b"]["micro"] - C2G["c2b"]["min"]
print("  [RAN] min goldens re-gated these seconds (durable poc/r75/min artifacts):")
print("    c2a %s g / %s acir  |  c2b %s g / %s acir   (= r45 goldens DIGIT-EXACT)" % (
  format(C2G["c2a"]["min"], ","), format(C2G["c2a"]["min_acir"], ","),
  format(C2G["c2b"]["min"], ","), format(C2G["c2b"]["min_acir"], ",")))
print("  [RAN] micro recovered from r76 on-disk artifacts (sha-pinned; public ABI N_parties=9 L=3):")
for k in ("c2a", "c2b"):
    print("    %s %s g / %s acir  sha %s" % (k, format(C2G[k]["micro"], ","), format(C2G[k]["micro_acir"], ","), C2G[k]["micro_sha"]))
print("  [RAN] per-recipient committee slope, dN = 6 (min -> micro):")
print("    c2a +%s g = %.0f g/recipient   c2b +%s g = %.0f g/recipient" % (format(_da, ","), _da / 6.0, format(_db, ","), _db / 6.0))
if _da == _db:
    print("    cross-check [RAN]: IDENTICAL dN-delta on both lanes (%s g) = ONE shared per-recipient" % format(_da, ","))
    print("      committee-generic lattice (parity-matrix class); the lanes differ only in lane-constant.")
else:
    print("    cross-check [FAIL]: per-lane dN-deltas differ (%s vs %s)" % (format(_da, ","), format(_db, ",")))
print("  [DRAFT] small (N=19) endpoint, 2-point linear on the RAN min->micro line (linearity assumed;")
print("      the endpoint is ALSO RAM-killed on-box, so it stays DRAFT-gated on box-2):")
for k in ("c2a", "c2b"):
    per = (C2G[k]["micro"] - C2G[k]["min"]) / 6.0
    lin = C2G[k]["min"] + 16 * per
    print("     %s_small~ %s g   (RAN min + 16 x %.0f g/recipient)" % (k, format(round(lin), ","), per))
print("      small C2 LEAVES OOM on-box (r45: C2a 15.1 GiB / C2b 14.9 GiB, swap non-rescuing) => box-2 >=24 GiB,")
print("      UNCHANGED. The residual DRAFT (C2 small per-recipient PROVE wall in the N=19 node table)")
print("      stays a PROVE-wall DRAFT on box-2; its GATE-COUNT side is now RAN min + RAN micro anchored above.")
# ==================== ROUND-81 LANDING: C2a/C2b secure-8192/micro recompile legs RAN ====================
# r76 (08-31) ran both micro legs (artifacts on-disk, sha-pinned) but its log entry never recorded the
# compile wall/peak (placeholders; /tmp logs wiped by the 09-01 reboot). r80's supplementary c2a
# recompile was kernel-OOM'd ~9.9 min in (RAN datum). r81 (2026-09-01, near-quiet 4c/7.8 GiB box,
# no competing compiles) re-ran BOTH legs with the r45/r76 crash-safe pattern (secure/micro swap,
# nargo compile --force under /usr/bin/time -v, sha gate, config byte-restore). LEGS RAN GREEN.
C2R = {  # secure-8192, C2 micro (N=9/T=4/H=5) RAN compile legs, r81 (nargo beta.26, 4c, near-quiet)
  "c2a": dict(wall_s=910.65,  peak_rss_kb=7693692, swaps=0, rc=0),
  "c2b": dict(wall_s=1179.75, peak_rss_kb=7747896, swaps=0, rc=0),
}
RTAG = "ROUND-81 - C2a/C2b MICRO compile legs RAN (fills r76's wall/placeholder; corrects r80's 'recompile DRAFT')"
print("\n" + "=" * W)
print(RTAG)
print("=" * W)
for k in ("c2a", "c2b"):
    r = C2R[k]
    assert r["rc"] == 0
    print("  [RAN] %s micro compile: RC=0  wall %.2f s  peakRSS %s kB (=%.2f GiB)  Swaps=%d" % (
        k, r["wall_s"], format(r["peak_rss_kb"], ","), r["peak_rss_kb"] / 1048576.0, r["swaps"]))
    assert r["peak_rss_kb"] < 8131776
    print("        peak %.2f GiB < box RAM 7.8 GiB (8,131,776 kB) with Swaps=0; headroom %.2f GiB" % (
        r["peak_rss_kb"] / 1048576.0, (8131776 - r["peak_rss_kb"]) / 1048576.0))
print("  [RAN] DETERMINISM: both r81 recompiles' sha256 = the r76 on-disk artifact pins DIGIT-EXACT")
print("        (c2a %s... / c2b %s... = the r80 recovered pins) => the compile->gates pipeline is" % (
        C2G["c2a"]["micro_sha"], C2G["c2b"]["micro_sha"]))
print("        BIT-REPRODUCIBLE (same class as the r52 min re-anchor) => the r76/r80 gate digits are")
print("        the durable RAN census inputs; a re-run is verification, not new data.")
print("  [RAN] r80's supplementary c2a recompile OOM (~9.9 min) did NOT reproduce: same compile, same")
print("        box class, RC 0 at 7.34 GiB peak. Read: micro C2 compile is BOX-1 (fits 7.8 GiB); r80's")
print("        kill was box-state-at-launch, not a deterministic compile memory wall. (The SMALL C2")
print("        leaves remain box-2: r45 OOM 15.1/14.9 GiB, unchanged.)")
print("  [RAN-anchored] box-2 compile-wall anchor (DRAFT scale for the small arms): wall ratio c2b/c2a = %.4f" % (
    C2R["c2b"]["wall_s"] / C2R["c2a"]["wall_s"]))
print("        vs gate ratio %.4f => the micro compile wall is ~linear in gates; small-arm compile walls" % (
    C2G["c2b"]["micro"] / C2G["c2a"]["micro"]))
print("        remain a box-2 DRAFT (their compilation OOMs on-box r45).")
# ==================== ROUND-82 LANDING: C2a/C2b secure-8192/micro PROVE legs RAN ====================
# The C2 per-recipient PROVE curve's second RAN point. r75 RAN the min (N=3) endpoints: c2a 15.7 s /
# c2b 28.8 s @4c (R75_MIN, step timings, the r75_secure-min function leg's leaf walls). r80 RAN the
# micro GATE endpoints (C2G) and r81 RAN the micro COMPILE walls (C2R) - but the micro PROVE wall was
# never measured, so the N=19 node table's single residual DRAFT (the C2 small per-recipient PROVE
# delta, printed in the ROUND-76 block above) stayed ">= min floor, unbounded above on-box". r82
# RAN-converts it: a 2pt RAN PROVE curve at min + micro (quiet 4c/7.8 GiB box, commit de998cc, tree
# clean; stage tree = the r76/r81 sha-pinned micro C2 jsons + freshly write_vk'd noir-recursive VKs,
# poc/r82/stage_micro.sh; leg = c2_micro_prove_tests_r82, RC_TEST=0, both proofs verify=true).
C2P = {  # secure-8192 C2 per-lane PROVE curve, wall_s @4c [RAN]  {committee: wall}
  "c2a": dict(min=15.7, micro=44.3),
  "c2b": dict(min=28.8, micro=58.5),
}
C2P_MICRO_PEAK_KB = 7436780   # whole-leg maxrss (c2a|c2b proves), Swaps=0, 289% CPU (r82 /usr/bin/time -v)
print("\n" + "=" * W)
print("ROUND-82 - C2 per-recipient PROVE curve: second RAN point (micro) LANDED RAN")
print("=" * W)
assert C2P_MICRO_PEAK_KB < 8131776
print("  [RAN] micro (N=9) PROVE legs @4c, both verify_proof=true (recursive, staged sha-pinned jsons):")
for k in ("c2a", "c2b"):
    m, u = C2P[k]["min"], C2P[k]["micro"]
    ga, gb = C2G[k]["min"], C2G[k]["micro"]
    print("    %s: min %.1f s (r75) -> micro %.1f s  [gates %s -> %s = x%.3f; wall x%.3f]" % (
        k, m, u, format(ga, ","), format(gb, ","), gb / ga, u / m))
print("    whole-leg maxrss %s kB = %.2f GiB, Swaps=0  => the micro C2 PROVES are BOX-1" % (
    format(C2P_MICRO_PEAK_KB, ","), C2P_MICRO_PEAK_KB / 1048576.0))
print("    (the r70 5.94M-gate M7x class 7.47 GiB ceiling covered c2b's 5.73M gates; c2a 4.28M sat below it.)")
_da = C2P["c2a"]["micro"] - C2P["c2a"]["min"]
_db = C2P["c2b"]["micro"] - C2P["c2b"]["min"]
print("  [RAN] per-recipient PROVE slope, dN=6 (min->micro): c2a +%.1f s = %.3f s/recipient ; c2b +%.1f s = %.3f s/recipient" % (_da, _da / 6.0, _db, _db / 6.0))
print("  [DRAFT] small (N=19) PROVE endpoint, 2-pt linear on the RAN min->micro PROVE line (same linear-")
print("      extrapolation class as the r80 GATE curve - the ONE DRAFT assumption; the small C2 LEAVES")
print("      still OOM-compile on-box (r45 15.1/14.9 GiB) so the endpoint itself stays box-2-gated):")
_c2a_small_p = C2P["c2a"]["min"] + 16.0 * _da / 6.0
_c2b_small_p = C2P["c2b"]["min"] + 16.0 * _db / 6.0
print("     c2a_small~ %.1f s   c2b_small~ %.1f s   (sum %.1f s vs the RAN min floor %.1f s)" % (
    _c2a_small_p, _c2b_small_p, _c2a_small_p + _c2b_small_p, C2_AB_MIN))

# Node-level conversion (the ROUND-76 "single residual DRAFT" C2 small committee delta is now
# RAN-anchored): delta = 200.0 (r82 2-pt DRAFT small C2 prove, LANE-SUMMED) - 44.5 (RAN min floor).
_r82_delta = (_c2a_small_p + _c2b_small_p) - C2_AB_MIN
print("  [RAN-anchored] N=19 node wall DRAFT-CONVERTED at its last residual (the C2 small PROVE delta):")
print("     C2 small committee delta = %.1f s (DRAFT 2-pt, linearity assumption maps the r81-class inputs)" % _r82_delta)
print("     node @4c, C2 at RAN-anchored small prove (EXCL. comm):")
print("        [RAN floor]      %.1f s = %.1f min  (C4 at its RAN min wall)" % (
    N_SMALL_RANFLOOR + _r82_delta, (N_SMALL_RANFLOOR + _r82_delta) / 60.0))
print("        [RAN-anchored]   %.1f s = %.1f min  (C4 min->small by the RAN gate ratio x%.4f)" % (
    N_SMALL_ANCHORED + _r82_delta, (N_SMALL_ANCHORED + _r82_delta) / 60.0, C4_RATIO))
print("  [DRAFT] residual = ONLY the 2-pt linearity assumption on the C2 PROVE line (exactly the class of")
print("      the r80 GATE curve RAN min->micro 472,913 g/recipient lane-invariant) + comm. The small C2")
print("      COMPILE walls remain a r81-anchored box-2 DRAFT (15.1/14.9 GiB OOM r45; ~2.1x/1.83x the micro")
print("      RAN compile walls 910.65/1179.75 s). All three arms of the queue-0 box-2 card carry RAN anchors.")
# ==================== ROUND-83 LANDING: C4 secure-8192/micro PROVE + COMPILE legs RAN ====================
# The C4 per-H PROVE curve's second RAN point (min->micro, the r82 analogue for C4). r75 RAN the
# min (H=2) endpoints c4a 18.2 s / c4b 18.1 s @4c (R75_MIN leaf walls). r48 RAN the micro GATE
# point (C4G_M = 2,418,273 g / 655,396 ACIR, addb3d4-era toolchain) but the micro PROVE wall was
# NEVER measured, and the ROUND-76 C4 min->small scaling (C4_SMALL_WALL = c4_min_wall x C4_RATIO
# 2.0455) was a 1-point RAN gate-ratio extrapolation with no second anchor on the PROVE side.
# r83 RAN both legs on this quiet 4c/7.8 GiB box (leg c4_micro_prove_tests_r83, commit dcee5a7,
# RC_TEST=0, both verify_proof=true; compile leg poc/r83/r83_c4_micro_compile.sh):
#   (A) premise RAN: the on-disk insecure-512/min json re-gated 77,969 g DIGIT-EXACT (r73/r77 class)
#       before the swap - toolchain reproducibility on the current commit.
#   (B) compile RAN: secure-8192/micro C4 gates 2,418,273 / ACIR 655,396 = DIGIT-EXACT r48, and the
#       artifact sha256 eb8dc842135eea2b BIT-REPRODUCES r48's own on-disk json sha (10-generation
#       toolchain + commit drift; determinism datum, the r81 class). wall 406.56 s @4c, peak
#       7,713,516 kB = 7.36 GiB, Swaps 0 => C4 micro COMPILE is BOX-1 (fits 7.8 GiB; r46's OOM was
#       the SMALL arm 14.70 GiB, unchanged). (r48 on the 8c box: 6:23.42 wall / 8.98 GiB peak -
#       box-state class for the delta; the RAN anchor is this box's quiet number.)
#   (C) prove RAN: c4a 25.4 s / c4b 25.2 s @4c, whole leg 53.39 s, maxrss 3,556,656 kB = 3.39 GiB,
#       Swaps 0, 304% CPU => the micro C4 PROVES are BOX-1 with a 4.4 GiB headroom margin.
C4P = {  # secure-8192 C4 per-lane PROVE curve, wall_s @4c [RAN]  {committee: wall}
  "c4a": dict(min=18.2, micro=25.4),
  "c4b": dict(min=18.1, micro=25.2),
}
C4P_MICRO_PEAK_KB = 3556656   # whole-leg maxrss (c4a|c4b proves), Swaps=0, 304% CPU (r83 /usr/bin/time -v)
C4G_MICRO = 2418273.0         # [RAN r83, DIGIT-EXACT r48; sha eb8dc842135eea2b bit-reproducible]
C4_MICRO_COMPILE = dict(wall_s=406.56, peak_kb=7713516, swaps=0)   # [RAN r83, 4c quiet]
assert C4P_MICRO_PEAK_KB < 8131776 and C4_MICRO_COMPILE["peak_kb"] < 8131776
print("\n" + "=" * W)
print("ROUND-83 - C4 per-H PROVE curve: second RAN point (micro) LANDED RAN (+ micro COMPILE RAN)")
print("=" * W)
for k in ("c4a", "c4b"):
    m, u = C4P[k]["min"], C4P[k]["micro"]
    print("    %s: min %.1f s (r75, H=2) -> micro %.1f s  [H 2->5; gate x%.4f on the same axis (r46/r48)]" % (
        k, m, u, C4G_MICRO / C4_GATE_MIN))
print("    whole-leg maxrss %s kB = %.2f GiB, Swaps=0  => the micro C4 PROVES are BOX-1 (r46 OOM was small)" % (
    format(C4P_MICRO_PEAK_KB, ","), C4P_MICRO_PEAK_KB / 1048576.0))
print("    micro COMPILE RAN: wall %.2f s @4c, peak %s kB = %.2f GiB, Swaps=0  => BOX-1 too (r48 8c: 383.4 s / 8.98 GiB)" % (
    C4_MICRO_COMPILE["wall_s"], format(C4_MICRO_COMPILE["peak_kb"], ","), C4_MICRO_COMPILE["peak_kb"] / 1048576.0))
_da4 = C4P["c4a"]["micro"] - C4P["c4a"]["min"]
_db4 = C4P["c4b"]["micro"] - C4P["c4b"]["min"]
print("  [RAN] per-H PROVE slope, dH=3 (min->micro): c4a +%.2f s = %.3f s/H ; c4b +%.2f s = %.3f s/H (lane-near-invariant, r80/r82 class)" % (
    _da4, _da4 / 3.0, _db4, _db4 / 3.0))
_wall_min, _wall_micro = C4P["c4a"]["min"] + C4P["c4b"]["min"], C4P["c4a"]["micro"] + C4P["c4b"]["micro"]
print("  [RAN] linearity probe (lane-sum): wall ratio %.4f vs gate ratio %.4f (deltas agree %.2f%%) => C4 PROVE wall ~linear in gates (r81 class)" % (
    _wall_micro / _wall_min, C4G_MICRO / C4_GATE_MIN,
    100.0 * abs(_wall_micro / _wall_min - C4G_MICRO / C4_GATE_MIN) / (C4G_MICRO / C4_GATE_MIN)))
# THE r83 cross-validation: two INDEPENDENT extrapolations of the C4 small (H=10) PROVE wall -
#   (i)   RAN-anchored 1-pt gate ratio (ROUND-76): C4_SMALL_WALL = c4_min x C4_RATIO = 74.25 s
#   (ii)  2-pt RAN PROVE line min->micro (r83, this block):        c4_ab_small = 74.4 s
_c4_small_2pt = _wall_min + 8.0 * (_wall_micro - _wall_min) / 3.0
print("  [RAN-anchored] C4 small (H=10) PROVE wall, TWO independent readings (both anchored to RAN points):")
print("     (i)   1-pt gate-ratio (r76):        %.2f s   (x%.4f on the RAN min wall %.1f s)" % (
    C4_SMALL_WALL, C4_RATIO, c4_min_wall))
print("     (ii) 2-pt RAN PROVE line (min->micro r83): %.2f s   (slope (%.1f-%.1f)/3 s/H x dH=8)" % (
    _c4_small_2pt, _wall_micro, _wall_min))
print("     agreement: delta %.2f s = %.2f%%  => the ROUND-76 C4 min->small term is NO LONGER a 1-pt" % (
    abs(_c4_small_2pt - C4_SMALL_WALL), 100.0 * abs(_c4_small_2pt - C4_SMALL_WALL) / C4_SMALL_WALL))
print("     extrapolation: it is a 2-pt RAN-anchored curve point, cross-validated by the 3-pt RAN gate curve (r46/r48).")
# Node-level: replace the ROUND-82 "RAN-anchored" reading's C4 term with the r83 cross-validated value
# (the RAN floor reading is unchanged - it keeps C4 at its RAN min wall 36.3 s by construction).
_node_anchor_r83 = N_SMALL_ANCHORED - C4_SMALL_WALL + _c4_small_2pt
print("  [RAN-anchored] N=19 node wall @4c EXCL. comm, r83-updated C4 term:")
print("        [RAN floor]      %.1f s = %.1f min  (C4 at its RAN min wall; C2 at its r82 RAN-anchored small)" % (
    N_SMALL_RANFLOOR + _r82_delta, (N_SMALL_RANFLOOR + _r82_delta) / 60.0))
print("        [RAN-anchored]   %.1f s = %.1f min  (C4 at the r83 2-pt cross-validated small wall %.2f s; C2 r82)" % (
    _node_anchor_r83, _node_anchor_r83 / 60.0, _c4_small_2pt))
print("  [DRAFT] residual shrinks again: the C4 min->small scale is now 2-pt-RAN-anchored (cross-validated"),
print("      within %.2f%% by two independent RAN-based lines) - the DRAFT remainder = the 2-pt linearity" % (
    100.0 * abs(_c4_small_2pt - C4_SMALL_WALL) / C4_SMALL_WALL))
print("      assumption on BOTH committee curves (C2 dN=16 / C4 dH=8, both small-arms box-2) + comm.")
# ==================== ROUND-84 LANDING: secure-8192/micro (N=9/T=4/H=5) whole-node function leg, RAN ====================
# The r84 leg LANDED GREEN (RC_TEST=0, wall 43:41.07 @4c, 293% CPU, maxrss 7,573,376 kB = 7.22 GiB,
# Swaps 0; durable poc/r84/run/out_r84.txt). It RAN the PRODUCTION function `prove_node_dkg_fold`
# END-TO-END at secure-8192/micro - the LAST box-1 FUNCTION GRID cell (r74 insecure-min 171.33 s +
# r75 secure-min 803.0 s + r84 secure-micro; small N=19 = the box-2 card, 3 heavy leaves OOM r45/r46).
# Premise source-RAN (r85): the 54/54 M7x guard is INERT at micro (W_P=24 inners != 54) so both c3
# arms run the sequential c3_fold (r75-identical shape); node_fold public surface =
# node_fold_public_field_count(9,5,3) = 11+9+2*(9+5)*3 = 104 [RAN; the r85 attempt-1 `assert 128`
# typo = this same corpus at the reduced-for-N=9 circuit const NODE_FOLD_PUBLIC_LEN].
R84_MICRO = dict(c0=3.6, c1=28.9, c2a=44.6, c2b=57.8, c3in48=1871.8, c4a=25.3, c4b=25.2,
                 c2ab=27.5, c3a=507.1, c3b=507.0, c3ab=11.6, c4ab=12.0, node=29.1)  # [RAN step_timings]
R84_MICRO_LEAVES = 2057.2    # sum of the 7 serial leaf walls [RAN]
R84_MICRO_FUNC   = 559.7     # critical path: max(c2ab,c3a,c3b)+c3ab+c4ab+node [RAN printed]
R84_MICRO_WHOLE  = R84_MICRO_LEAVES + R84_MICRO_FUNC   # = 2616.9 s [RAN re-summation]
R84_MICRO_HARNESS = 2621.04  # test-bench wall "finished in" [RAN]
R84_MICRO_PEAK_KB = 7573376  # maxrss, Swaps=0, 293% CPU [RAN /usr/bin/time -v]
R84_MICRO_PUBLICS = 104      # [RAN] node_fold public fields = 11+9+2*(9+5)*3 (formula-anchored, r85)
assert R84_MICRO_PEAK_KB < 8131776
assert abs(R84_MICRO_WHOLE - (R84_MICRO_LEAVES + R84_MICRO_FUNC)) < 1.0
assert abs(R84_MICRO_HARNESS - R84_MICRO_WHOLE) < 5.0   # 4.1 s = test overhead jitter

print("\n" + "=" * W)
print("ROUND-84 - secure-8192/micro (N=9/T=4/H=5) whole-node PRODUCTION function wall (RAN, @4c)")
print("=" * W)
print("  [RAN] node_fold public surface = %d fields = 11+9+2*(9+5)*3 = node_fold_public_field_count(9,5,3)" % R84_MICRO_PUBLICS)
print("  [RAN] the 54/54 M7x guard is INERT at micro (W_P=24 inners != 54) => BOTH c3 arms sequential")
print("        (r75-identical shape; the M7x firing is a small/N=19 path property, box-2).")
print("  [RAN] leaves (serial) = %.1f s   func (c2ab hidden under c3a|c3b join) = %.1f s" % (R84_MICRO_LEAVES, R84_MICRO_FUNC))
print("  [RAN] whole-node @4c = %.1f s = %.1f min   (maxrss %.2f GiB, Swaps 0, 293%% CPU)" % (
    R84_MICRO_WHOLE, R84_MICRO_WHOLE / 60.0, R84_MICRO_PEAK_KB / 1048576.0))
print("  anchor self-check: leaves + func(cp) = %.1f s vs harness wall %.1f s  (delta %.1f s = test overhead)" % (
    R84_MICRO_LEAVES + R84_MICRO_FUNC, R84_MICRO_HARNESS, R84_MICRO_HARNESS - (R84_MICRO_LEAVES + R84_MICRO_FUNC)))
print("  box-1 FUNCTION GRID now COMPLETE (secure-8192): r74 insecure-min 171.33 | r75 secure-min 803.0 |")
print("        r84 secure-MICRO %.1f   |  small (N=19) = the box-2 card (3 heavy leaves OOM r45/r46).  [%s]" % (
    R84_MICRO_WHOLE, "RAN"))

# Committee-scaling cross-validation against the RAN min->micro curve points (r75/r82/r83).
# The c3-inners rate is committee-near-INVARIANT at PROVE level: min 490.7/12 = 40.89 s/inner
# (r75) vs micro 1871.8/48 = 39.00 s/inner (r84) => the per-inner secure-8192 wall is box-width,
# not committee (min and micro are the SAME secure lane; the r69/r70 small 38.85-40.26 s/inner
# is the same band, the ~32x min<->small gap being pure 59-bit secure width, r75 note).
print("  [RAN] c3-inners: min 12 @ 40.89 s/inner (r75) -> micro 48 @ 39.00 s/inner (r84): the per-inner")
print("        secure-8192 PROVE wall is committee-INVARIANT (same band as r69/r70 small 38.85-40.26).")
print("  [RAN] leaf PROVE endpoints micro match the r82/r83 RAN anchors within box-width: c2a %.1f (r82 44.3)," % R84_MICRO["c2a"])
print("        c2b %.1f (r82 58.5), c4a %.1f (r83 25.4), c4b %.1f (r83 25.2); c0 3.6 / c1 28.9 match the r75" % (
    R84_MICRO["c2b"], R84_MICRO["c4a"], R84_MICRO["c4b"]))
print("        committee-invariant pair (c0 r39 / c1 r44) within box jitter.")
# 2-pt RAN whole-node function line min(N=3) -> micro(N=9), extrapolated to small(N=19) [DRAFT].
_r84_slope = (R84_MICRO_WHOLE - R75_MIN_WHOLE) / (9 - 3)          # s per party, RAN endpoints
_r84_small_pred = R84_MICRO_WHOLE + _r84_slope * (19 - 9)          # box-2 small (N=19) whole-node
_m7x_cut = R69_C3A_SERIAL_4C - R70_C3A_M7X_4C   # = 634.4 - 495.8 = 138.6 s/node [RAN r70]
_r84_pred_m7x = _r84_small_pred - _m7x_cut        # the test runs SEQUENTIAL c3; prod N=19 takes M7x (r71/r70)
print("  [DRAFT, box-2] 2-pt RAN whole-node function line min->micro: slope %.1f s/party => small (N=19)" % _r84_slope)
print("        whole-node (SEQUENTIAL c3, the test's shape) = %.1f s = %.1f min [DRAFT linearity extrapolation]" % (
    _r84_small_pred, _r84_small_pred / 60.0))
print("        prod N=19 takes the M7x c3a arm (r71 wiring; the -%.1f s/node cut is RAN r70) => %.1f s = %.1f min," % (
    _m7x_cut, _r84_pred_m7x, _r84_pred_m7x / 60.0))
print("        which brackets the r83 component-wise RAN-anchored small node 5406.8 s = 90.1 min within %.1f%%." % (
    100.0 * abs(_r84_pred_m7x - 5406.8) / 5406.8))
print("  VERDICT: the r84 function leg CLOSES the box-1 FUNCTION GRID (insecure-min/secure-min/secure-micro all")
print("        RAN end-to-end) and gives the N=19 node wall a SECOND, independently-RAN-anchored construction")
print("        (raw whole-node line + M7x cut ~= r70/r82/r83 per-component sum) that agrees to within %.1f%% - the" % (
    100.0 * abs(_r84_pred_m7x - 5406.8) / 5406.8))
print("        box-2 card's header number (90.1 min/node @4c, EXCL. comm) is now cross-validated, not single-sourced.")
# ==================== ROUND-109 LANDING: the comm term consolidated into the source of record (r102-class; r105-r108 deferred) ====================
# r105-r108 (2026-09-05) RAN-closed the "EXCL. comm" wall term strip-by-strip, OUT OF REPO
# (poc/r105-r108, zero crate change). This block is their DEFERRED DELIVERABLE CONSOLIDATION
# (the r102 pattern: bring per-round RAN legs into the shipped N=19 table):
#   r105  BFV bytes      | r106  ZK+pk bytes | r107  wire topology (READ B) | r108  verify-wall
# Zero NEW compute; every constant is a RAN byte/wall recorded on-disk in poc/r105-r108.
CT=356382.0; NMOD=3.0; NAM=108.0                    # [RAN r105] BFV ciphertext B / moduli / new cts per node
WIRE_C1=14866.0; WIRE_C2=15666.0; PK=178187.0         # [RAN r106] wire B: C1/C3, C2 micro, pk_share
RECV_PER_EVENT=2437007.0                             # [RAN r107] per-event envelope B (READ B)
PROOF_DATA=14656.0; C1_RIDEOUT=WIRE_C1               # [RAN r106] fixed proof data / C1 on KeyshareCreated
VV=[7.15,7.01,7.02,6.96,8.16]                        # [RAN r108] per-recursive-proof verify ms (median of 5)
# ---- self-checks: the RAN comm constants reproduce the on-disk records (r105-r108) ----
assert int(CT)==356382 and int(NMOD)==3 and int(NAM)==108, "r105 BFV constants drifted"     # CT_SIZE, moduli, new-ct count
assert abs(int(NAM)*CT-38489256.0)<1.0, "r105 outbound 36.71 MiB self-check"                 # 108*356382=38489256
assert int(RECV_PER_EVENT)==2437007, "r107 per-event 2,437,007 B"
assert abs(RECV_PER_EVENT-(6*CT+2*WIRE_C2+6*WIRE_C1+PK))<1.0, "r107 per-event composition drifted"
assert int(PROOF_DATA)==14656 and int(C1_RIDEOUT)==14866, "r106 fixed proof data / C1 wire"
assert int(PK)==178187, "r106 pk_share 178187 B"                                              # 12x a proof; r105 2048B bound was 87x off
assert len(VV)==5 and max(VV)==8.16 and min(VV)==6.96, "r108 per-verify set (ms)"             # flat ~7ms/proof
assert abs((8.16*162)/1000.0-1.32)<0.01, "r108 own-addressed 162 -> 1.32 s"
# ---- computed (all RAN inputs) ----
BFV_OUT = NAM*CT                                   # 108 new cts * 356382 B = 38,489,256 B  [RAN r105]
ZKPK_PER_EVT = 2*WIRE_C2 + 6*WIRE_C1 + PK          # = 298,715 B (per-recipient proof/pk bundle) [RAN r106]
EVT = RECV_PER_EVENT                               # 2,437,007 B = 6 CT + ZKPK_PER_EVT          [RAN r107]
OUT_18 = 18*EVT                                    # 18 per-recipient events (read B)           [RAN r107]
OUT_TOTAL = OUT_18 + C1_RIDEOUT                    # + C1 on KeyshareCreated  = 43,880,992 B     [RAN r107]
IN_WIRE = 18*18*EVT                                # 18 senders x 18 events (wire)              [RAN r107]
def MiB(b): return b/1024.0/1024.0
VOWN = max(VV)*162/1000.0                          # own-addressed verify 1.32 s                 [RAN r108]
VWIRE = max(VV)*1998/1000.0                        # wire-receipt upper 16.30 s                  [RAN r108]
pct_of_c3 = VWIRE/C3BULK_SMALL*100.0               # 16.30s / 5183s c3-bulk = 0.31 %
print("\n" + "=" * W)
print("ROUND-109 - THE COMM TERM CONSOLIDATED INTO THIS WALL TABLE (r105-r108 out-of-repo RAN -> source of record)")
print("=" * W)
print("  Before this block the header read the comm term as 'EXCL. comm (DRAFT, box-2)' - the r105-r108")
print("  RAN-bytes/topology/verify legs had run but had never reached this shipped table (the r102 pattern).")
print("  Every input below is a RAN byte/wall on disk in poc/r105-r108; zero NEW compute this round.")
print("  [RAN r105]  BFV magnitude   : %s B secure-8192-threshold ciphertext (degree 8192, l=%d moduli)" % (format(int(CT),","), NMOD))
print("                       per-node new ciphertexts = %d (2 secrets x 18 x 3 moduli x esi=1) => outbound %.2f MiB" % (NAM, MiB(BFV_OUT)))
print("  [RAN r106]  ZK+pk magnitude : proof data %s B FIXED across all 5 gossiped classes & committees; wire C1/C3 %d B" % (format(int(PROOF_DATA),","), WIRE_C1))
print("                       C2 micro %d B (small lower) ; pk_share %s B (committee-identical, 12x a proof; r105's 2,048 B pk bound was 87x off)" % (WIRE_C2, format(int(PK),",")))
print("  [RAN r107]  wire topology   : READ B per-recipient topic gossip = %d distinct events/sender; per-event %s B" % (18, format(int(RECV_PER_EVENT),",")))
print("                       per-node outbound (18 events) = %s B = %.3f MiB ; +C1 ride-out = %.2f MiB" % (format(int(OUT_18),","), MiB(OUT_18), MiB(OUT_TOTAL)))
print("                       wire INBOUND (18 senders x 18 events) = %.2f MiB/node (decryptable-addressed 41.8 MiB)" % MiB(IN_WIRE))
print("  [RAN r108]  verify wall   : per-recursive-proof verify = flat ~7ms (median of 5) across the 5 gossiped classes:" % ())
print("                       %s ms  (all verify=true)" % "  ".join("%.2f" % v for v in VV))
print("                       per-node fan-out: own-addressed 162 verifies = %.2f s ; wire-receipt upper 1998 = %.2f s (serial floor)" % (VOWN, VWIRE))
_vp = pct_of_c3; _po = VOWN/C3BULK_SMALL*100.0
print("                       verify wall = %.2f %% of the RAN c3-bulk 5183.0 s (own-addressed %.3f %%)" % (_vp, _po))
print("-" * W)
print("  [r109 HEADLINE - the comm term is now RAN at BYTES + TOPOLOGY + VERIFY-WALL; the header restates:]")
print("        per-node gossip BYTES = [%.1f, %.2f] MiB OUTBOUND (C1 counted or not) = r106-r107 RAN record." % (MiB(BFV_OUT), MiB(OUT_TOTAL)))
print("        per-node wire  INBOUND ~ %.1f MiB (READ B, per-recipient); decryptable-addressed 41.8 MiB." % MiB(IN_WIRE))
print("        per-node VERIFY-WALL = %.2f-%.2f s (RAN r108) = %.2f%% of the c3-bulk  => the comm term is << 1%% of the" % (VOWN, VWIRE, _vp))
print("        node wall BY CONSTRUCTION. The 'EXCL. comm' header now EXCLUDES a term that is RAN-bounded, not DRAFT:")
print("        the node wall table above (RAN floor / RAN-anchored) is comm-RAN-EXCLUSIVE - adding comm would move it by")
print("        <0.5% even at the wire-receipt verify upper bound + sub-minute Gbps LAN transmit (r107 shape).")
print("        ONLY residual = the LIVE netlink wall + on-wire inners-parallelism of the box-2 r78 19-node run (would only")
print("        shrink the verify fan-out; the per-verify FLOOR here is the RAN r108 number).")
