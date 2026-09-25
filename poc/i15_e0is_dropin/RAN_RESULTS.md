# I15 RAN results (round 33, 2026-08-22, box 1: 4c/7.8GB, nargo 1.0.0-beta.26, bb 5.1.0)

## What
C3 (share_encryption) dropped the per-limb e0 CRT auxiliaries `e0is`/`e0_quotients`
(2·L·N unbounded-coefficient witness polys + the L·N CRT-consistency assert block).
The CT0 relation at gamma now uses the range-checked global `e0.eval(gamma)`.

## Why sound (tightening, not weakening)
- `e0` is range-checked: insecure E0 bound 6 / secure 20, while every q_i ~ 2^61
  (secure DKG moduli 0x0800000000004001 / 0x0800000000044001, insecure
  2251799813554177). Honest witness: e0is[i] = e0, e0_quotients[i] = 0 (exact
  division asserted in the Rust generator).
- Old CT0 row used e0is[i].eval(gamma) which was an ARBITRARY FR field value
  (free witness; e0is is NOT absorbed in the SAFE payload, NOT range-checked).
- New CT0 row binds it to the range-checked e0. Any witness valid under the new
  circuit was also valid under the old one (set inclusion), and every new witness
  satisfies the honest e0is==e0 relationship => same decryption class.
- No digest/transcript change: neither e0is nor e0_quotients was in the payload;
  SAFE challenge bytes unchanged for every existing witness.
- r1is bound unchanged (the q_l * r1is[i] term absorbs any cross-limb slack exactly
  as before; it only had to be consistent per l, which it still is, via e0).

## Gate measurement (bb gates -t noir-recursive-no-zk, insecure-512, this box)
- pre  (I14 basis, commit 611bbc9): circuit_size 100,697 / 44,523 ACIR opcodes
- post (I15, this round):          circuit_size 100,185 / 44,011 ACIR opcodes
- DELTA: -512 gates / -512 ACIR opcodes; named ABI params 16 -> 14
  (e0is + e0_quotients removed; public pub-inputs of main() are pkC, msgC — unchanged)
  = -0.51% of C3.
- The delta is SMALLER than a naive 2·N·L-coeff removal estimate because bb's
  witness-hoisting/cancellation removed most of the linear witness-read cost and
  the e0is·q_l·cyclo_at_gamma multiply chain. IN Interpretation (not independently
  probed): the dropped L·N CRT-consistency assert block (512 asserts in the
  insecure-512 L=1/N=512 config) plus the per-limb Horner-redo accounts for most
  of it; the exact 512 = L·N match is suggestive but I do NOT claim a clean 1:1
  attribution (isolate it with a second arm if it matters). What IS a hard RAN
  fact: -512 gates = -0.51% of C3, and the circuit still proves + verifies end-to-end.

## E2E (commit-smoke gate, same box)
- VKs regenerated for all 3 targets (evm / noir-recursive-no-zk / noir-recursive),
  installed per repo convention (target/*.vk*, gitignored build artifacts).
- `cargo test -p e3-zk-prover --test local_e2e_tests share_encryption
   -- --test-threads=1` -> **2 passed, 0 failed, 6.28 s** (real bb prove + verify).
- `cargo check -p e3-zk-helpers` clean; `cargo check --workspace` run post-commit.

## Secure-8192 (DRAFT — box >= 16 GB)
Skip the e0is/e0_quotients Marquee plumbing in `crates/zk-helpers/src/circuits/dkg/
share_encryption/computation.rs` (already done here) and rebuild secure C3:
  pnpm build:circuits --preset secure-8192 --committee small   (>= 16 GB box)
  bb gates -t noir-recursive-no-zk target/share_encryption.json
Expected -0.51% at L=2 (e0is/e0_quotients are 2 polys each of N coeffs; the gate
delta scales roughly linearly with the CRT-consistency assert block = L·N asserts).
Also re-runs the I4 secure split + I14 secure A/B on the same build (see RUNBOOK).
