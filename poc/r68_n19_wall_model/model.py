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