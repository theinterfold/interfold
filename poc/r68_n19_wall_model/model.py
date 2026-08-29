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

print("\n" + "=" * W)
print("ROUND-69 CORRECTION - production c3 geometry (source RAN; walls RAN-derived)")
print("=" * W)
print(f"  Test-shape anchor (r66 as run)   : 84 inners + c3a 30-step + c3b M7x + c3ab = {R66_TOTAL_C3_4C:.1f} s @4c = {R66_TOTAL_C3_4C/60.0:.1f} min  [RAN]")
print(f"  Production (source RAN/[RAN-der]): {P_INNERS} inners + c3a {P_C3A_STE}-step serial + c3b M7x + c3ab")
print(f"     per-inner  = {R66_INNERS_84_4C:.1f}/84 = {per_inner:.3f} s   [RAN unit]")
print(f"     per c3 step = {R66_C3A_SERIAL_4C:.1f}/30 = {per_c3a_unit:.3f} s   [RAN unit]")
print(f"  PRODUCTION per-node c3-bulk @4c  : {pi:.1f}(inners) + {R66_C3B_M7X_4C:.1f}(c3b M7x,RAN) + {pc3a:.1f}(c3a serial) + {R66_C3AB_4C:.1f}(c3ab,RAN) = {p4c:.1f} s = {p4c/60.0:.1f} min")
print(f"     @8c ref = {p8c:.1f} s = {p8c/60.0:.1f} min  (core-ratio {CORE_4V8:.2f})")
print(f"  c3b fold cut (M7x vs serial) UNCHANGED: {cut8:+.1f}% @8c [RAN] / {cut4:+.1f}% @4c [RAN-anchored]")
print(f"  VERDICT: committed 71.9 min/node was TEST-shaped (54+30); production = {p4c/60.0:.1f} min/node @4c ({100*(p4c-R66_TOTAL_C3_4C)/R66_TOTAL_C3_4C:+.1f}%) -")
print(f"    the c3a lane runs 54 sequential steps (not 30) and the esm lane runs 54 inners (not 30).")
print(f"    Same 19-node parallelism: wall ~= one node ~= {p4c/60.0:.1f} min c3-bulk @4c / ~{p8c/60.0:.1f} min @8c (before DRAFT non-c3 leaves).")
# The production number is RAN-derived (ratio of RAN per-unit inputs); the r69 leg
# (test m7x_seam_prod_geo_tests_r69) RAN-confirms it on this box (108 inners + arms).
