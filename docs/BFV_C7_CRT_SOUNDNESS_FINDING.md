# BFV C7 soundness finding — DO NOT FIX ON THE CKKS BRANCH

**Status:** recorded 2026-09-05 during the threshold-CKKS audit. Deliberately NOT fixed here
(user instruction: do not touch BFV). Ships on `origin/main` today. Needs its own change, its own
verifier regeneration, and cryptographer sign-off as a numbered claim.

## The finding

`circuits/lib/src/core/threshold/decrypted_shares_aggregation.nr:280-304`
(`verify_crt_reconstruction`) asserts, coefficient-wise and over raw BN254 field arithmetic:

```
u_crts[l] + crt_quotients[l] * q_l == u_global        for every limb l
```

`crt_quotients` is a **private witness with no range constraint anywhere** in the library
(`grep -rn crt_quotients circuits/lib/src` returns only struct/plumbing lines; `Polynomial::add`
and `mul_scalar` in `math/polynomial.nr` are unreduced field ops).

Because `q_l` is invertible in the scalar field, for **any** target `u*` a prover sets
`r_l = (u* − u_crts[l]) · q_l⁻¹ mod p` and the assertion passes. The CRT "glue" therefore
constrains nothing: `u_global` is a free choice of the prover.

Empirically confirmed (audit, `nargo` against the real lib): honest reconstruction `42`, claimed
`u_global = 1000000`, **accepted**; repeated at L=2 with the real ps0 moduli
`[68719403009, 68719230977]`, claimed `u_global = 123456789012345678`, **accepted**.

## Blast radius on BFV

Less than total, because on BFV `verify_decoding` follows the CRT step (`:103-108` region) and
enforces `m = round(t · u_global / Q) mod t` against the public plaintext. That is many-to-one:
the prover can pick a *different* `u_global` in the same decode class, but cannot pick an
arbitrary plaintext. So today's BFV C7 proves "the published plaintext is *a* decode of *some*
`u_global`," not "the published plaintext is the decode of the reconstruction of these shares."

Whether that residual freedom is exploitable depends on what else binds `u_global` downstream
(nothing on-chain does). Treat as **high**, not critical, for BFV; **critical** for CKKS, where
no decode step follows (fixed on the CKKS branch, see below).

## The fix (when authorised)

Range-constrain every `crt_quotients[l]` coefficient so the field identity implies the integer
identity. Honest quotients satisfy `|r_l| < Q / q_l · (something small)`; a bound of
`BIT_R = ceil(log2(Q_max)) + 2` bits, applied via the existing `range_check` gadget the other
circuits already use, is sufficient and cheap (L · MAX_COEFFS range checks). Then the equation
`u_crts + r·q = u_global` over integers with `|r|` bounded and `u_crts ∈ [0,q)` pins `u_global`
to the unique CRT lift.

**Consequences:** the BFV C7 VK changes → `DecryptionVerifier` on-chain must be regenerated and
redeployed; every staged `decrypted_shares_aggregation` artifact must be rebuilt. That is why this
is not done on the CKKS branch.

## How the CKKS branch handled its copy

`decrypted_shares_aggregation_ckks.nr` shared this body. On the CKKS branch the quotients are
range-constrained in the CKKS circuit only (see `ckks_c7_soundness_*` tests). The BFV circuit
is left byte-identical to `origin/main`.

## Claim for cryptographers

**C-6.** *An unconstrained CRT quotient witness in `verify_crt_reconstruction` makes the
reconstruction identity vacuous over the scalar field; on BFV the downstream `verify_decoding`
caps the damage to "some `u_global` in the decode class of the published plaintext", on CKKS
nothing caps it.* Confirm the bound `BIT_R` above is sufficient, and whether the BFV residual
freedom is exploitable given what binds `u_global` elsewhere.
