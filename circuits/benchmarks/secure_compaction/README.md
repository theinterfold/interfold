# Secure circuit compaction benchmarks

These earlier measurements compare standalone candidate leaves with the original circuit
implementations. They are reference results, not new measurements of the current integrated sources.

The branch now applies the arithmetic in the normal circuit files. It keeps existing private
entry-point layouts and derives the compact quotients inside the circuit. These compatibility steps
can change gate counts. Re-measure the normal entry points before quoting the table as this branch's
performance.

## Review map

All paths below are relative to `circuits/lib/src/`.

| Circuit           | File                                                                        | Change                                                                     |
| ----------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| C1                | `core/threshold/pk_generation.nr`                                           | Reduced-product checks and bounded quotient transcript                     |
| C2a/C2b           | `core/dkg/share_computation.nr`                                             | Consecutive-coordinate finite differences                                  |
| C3                | `core/dkg/share_encryption.nr`                                              | Message-scaling identities and smaller quotient checks                     |
| C4                | `core/dkg/share_decryption.nr`                                              | Bounded carry reduction, secure minimum committee only                     |
| C6                | `core/threshold/share_decryption.nr`                                        | Reduced decryption equation with all public bindings                       |
| C7                | `core/threshold/decrypted_shares_aggregation.nr`                            | Bounded interpolation, Garner reconstruction, rounded decoding             |
| P3 ct0/ct1        | `core/threshold/user_data_encryption_ct0.nr`, `user_data_encryption_ct1.nr` | Reduced encryption equations with the original error bounds                |
| Shared arithmetic | `math/secure_arithmetic.nr`, `math/share_encryption_arithmetic.nr`          | Range checks, quotient reduction, product evaluation, and regression tests |

The normal C6 entry point also forwards its existing public domain limbs into the new checking
transcript. C0 and C5 are unchanged. Insecure parameters and larger-committee C4 retain their
original implementation. The fixed-CRP ct1 specialization is not enabled for the generic encryption
entry point.

This is a cryptographic review branch. No Rust/SDK source, generated circuit configuration, release
artifact, verification key, or Solidity verifier is updated by this change.

## Current integration checks

On 2026-09-08:

- `pnpm noir:test` passed all 190 library tests. The C7 valid/invalid message tests now call the
  normal circuit type, so they also check selection of its secure path.
- `nargo check --workspace` passed for the normal DKG and threshold workspaces with the default
  insecure-512/minimum selection.
- All nine changed leaves passed type-checking in a temporary secure-8192/minimum harness. It used
  copies of the normal entry points with only their parameter imports changed to the existing secure
  modules. No generated configuration was edited.

These checks do not generate or verify full-size proofs for the integrated entry points. The secure
proof comparisons, new gate counts, larger-committee integration, and recursive rebuild remain
pending. Do not treat the historical results below as those missing checks.

## Method

Each pair uses the same Rust-generated secure-8192 inputs. Both proofs must verify, and their public
inputs must match byte for byte. Compilation uses the default compiler constraint checks.
Barretenberg uses `--verifier_target noir-recursive` for gate counts, keys, proofs, and
verification.

The tools are Nargo `1.0.0-beta.26` and Barretenberg `5.1.0`. The Linux machine has an AMD Ryzen 9
9950X, eight available logical CPUs, and 47 GiB of RAM. Each timing is one observation, not an
average or a latency guarantee. Proving time excludes compilation, witness generation, key
generation, recursion, and network work.

## Three-node committee

The minimum committee has three members, degree-one shares, and two aggregation participants.

| Circuit                     | Original gates | Candidate gates | Gate reduction | Original proof time | Candidate proof time |
| --------------------------- | -------------: | --------------: | -------------: | ------------------: | -------------------: |
| C1: key generation          |      2,223,114 |       1,493,494 |         32.82% |              9.89 s |               6.74 s |
| C2a: secret-key shares      |      1,446,311 |       1,379,035 |          4.65% |              6.52 s |               6.41 s |
| C2b: noise shares           |      2,888,964 |       2,360,858 |         18.28% |             14.18 s |              12.16 s |
| C3: share encryption        |      3,475,203 |       1,732,025 |         50.16% |             14.96 s |               7.65 s |
| C4: share aggregation       |      1,746,030 |       1,277,346 |         26.84% |              7.65 s |               5.57 s |
| C6: decryption share        |      2,977,228 |       2,453,651 |         17.59% |             13.42 s |              11.63 s |
| C7: reconstruction          |        108,461 |          25,029 |         76.92% |              0.67 s |               0.34 s |
| P3 ct0: input encryption    |      1,688,639 |       1,309,851 |         22.43% |              7.73 s |               6.32 s |
| P3 ct1: input encryption    |      1,398,622 |       1,103,025 |         21.13% |              7.62 s |               5.82 s |
| P3 ct1: fixed committee CRP |      1,398,622 |         680,438 |         51.35% |              7.44 s |               3.92 s |

C3 and C4 also passed separate proof comparisons with smudging-noise-share inputs. Their gate counts
are identical to the corresponding secret-key-share cases. All listed candidate proofs are 14,656
bytes. Fewer gates do not reduce this proof format's byte length.

The fixed-CRP variant uses a genuine committee-generated key and its existing configuration
constant. It is not a replacement for encryption under arbitrary public keys.

For the earlier standalone experiment, the library suite passed 190 Noir tests. The selected
candidates passed 58 negative checks on witnesses and proof public inputs. These counts exclude the
rejected C0 and C5 candidates.

In that experiment, clean-source compilation passed for every selected package. All 12 comparison
cases had identical bytecode, ABI, and freshly generated verification keys after cleanup. Their
proofs verify with those keys. The C6 proof was regenerated because its saved proof files were
empty. The table uses the new C6 timing. The negative-test runner now verifies each unmodified proof
before testing rejection of altered public inputs.

[Machine-readable results](results.json) include hashes and exact measurements. Artifact JSON hashes
can differ because they include source maps. The bytecode and verification keys match. The nine-node
checks found 78.02% fewer C7 gates, but 4.59% more C4 gates. C4 is therefore a minimum-committee
optimization only. Retain the original larger-committee C4 implementation when integrating these
candidates. Further larger-committee results are pending.

## Excluded candidates

The C0 candidate increased gates from 287,727 to 544,433. The C5 candidate increased gates from
754,560 to 1,277,110. Neither candidate is included in this branch. Their proposed checks on
canonical commitment openings need a separate security review. Key serialization and transport
changes are also excluded.

## Security and integration limits

The BFV degree, primes, plaintext modulus, committee thresholds, and configured noise bounds remain
unchanged. In particular, P3 ct0 retains its large global error bound. It does not substitute the
smaller C3 error bound. The public commitment functions remain unchanged, and C7 checks every
claimed output coefficient, including zero.

Tests cover valid full-size inputs and selected invalid witnesses. Independent integer models check
arithmetic bounds and identities. These checks do not establish soundness against every malicious
prover. An independent cryptographic review remains necessary, especially for hint constraints and
Fiat-Shamir transcripts.

The standalone candidates had different private interfaces. The current integration retains the
normal entry-point interfaces, including the checked f(0), C6 native-tail, and P3
error-decomposition witnesses. It does not retain the old checking transcripts or verification keys.
Recursive integration tests, regenerated release artifacts, and matching on-chain verifiers remain
required. These leaf results do not measure complete DKG latency or prove end-to-end compatibility.

## Reproduction

The [arithmetic review](ARITHMETIC_REVIEW.md) explains the transformations and their assumptions.
The machine-readable results retain the original artifact hashes and measurements.

Run the local arithmetic tests with `pnpm noir:test`. Use the normal build pipeline on a capable
machine to generate and measure the integrated leaves, for example:

```bash
pnpm build:circuits --preset secure-8192 --committee minimum
```

Compare the optimized and original entry points using the same Rust-generated inputs. Verify both
proofs with their own keys and compare public inputs byte for byte. Cover minimum, micro, and small
committees; valid and altered witnesses; the generic encryption path; recursive folds; and
insecure-512 regressions. Do not reuse old VKs or describe a successful proof as a soundness audit.
Keep generated private inputs, proof witnesses, and raw logs outside the repository.
