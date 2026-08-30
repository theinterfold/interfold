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
