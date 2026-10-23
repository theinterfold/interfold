# Bid proof circuits

This directory holds the Noir circuits that prove one claim about a bid:

> The SIMD plaintexts of my bid ciphertexts come from one bid `b` with `0 <= b < B`.

The circuits cover the `vickrey` and `vickrey-compact` designs of the auction crate. They run on top
of the `user_data_encryption` proofs. They do not replace them.

## Statement

| Item                           | Value                                                                                   |
| ------------------------------ | --------------------------------------------------------------------------------------- |
| Private input                  | The bid `b`, and the `k1` polynomial of each bid ciphertext.                            |
| Public output                  | One `k1` commitment for each bid ciphertext.                                            |
| Ciphertexts                    | `vickrey`: 2 (`[b >= l]` and `[b > l]`). `vickrey-compact`: 1 (`2 [b >= l] - [b > l]`). |
| Constraint 1                   | `b < B`.                                                                                |
| Constraint 2                   | The SIMD slots of each plaintext `m` have the layout of the design for this `b`.        |
| Link to `user_data_encryption` | The commitment is computed exactly as that circuit computes its `k1` commitment.        |

`k1 = reverse([Q_MOD_T · m]_t)`. `Q_MOD_T` is the product of the ciphertext moduli mod `t`. The
reversal and the scale are the ones of `crates/zk/witness/src/threshold/user_data_encryption.rs`.

The slot layout is `slot = copy · n · B + region · B + level`. Every region of every copy holds the
same value for a level. Slots beyond the last copy hold 0. The mask ciphertext needs no shape proof
and is not covered.

The commitment is
`compute_single_polynomial_commitment_checked::<N, BIT_K>(k1, DS_USER_DATA_ENCRYPTION_COMMITMENT)`.
It has the same value as the plain version that `user_data_encryption` uses. The checked version
adds one digit assert for each coefficient. The asserts make the packing injective, so a commitment
has one opening. The encryption circuit already range-checks `k1` to `[0, t - 1]`. An equal
commitment in both proofs gives the same `k1`, so the bound transfers. A second range check in this
circuit would cost about twice as much as the digit assert. For this reason the circuits use the
checked commitment. A standalone run of this circuit alone does not prove that `k1` is in
`[0, t - 1]`. It proves it only with the equality check.

`BIT_K` is the bit width of `t - 1`. It must match the `BIT_K` of the encryption circuit.

## Strategies

All strategies prove the same statement. Each has its own bin package.

| Package   | Strategy                                                                                                     |
| --------- | ------------------------------------------------------------------------------------------------------------ |
| `ntt/`    | A forward negacyclic NTT of `k1` in the circuit. Cost `O(N log N)`. It does not depend on `B`.               |
| `table/`  | `k1 = sum_l expected(l) · D[l] mod t`. `D[l]` are public polynomials. Cost `O(N · B)` at most.               |
| `sparse/` | `k1` has non-zero coefficients only at `2B - 1` public positions. The circuit takes only those coefficients. |
| `lib/`    | The shared Noir library (`bid_lib`) and its tests.                                                           |

### NTT

The circuit does the Cooley-Tukey NTT of Longa and Naehrig. The butterfly is
`(a, b) -> (a + w·b, a + (t - w)·b)`, so no value is negative.

- The circuit does not reduce between layers. Each output is one witness, so no expression grows.
- After `L = log2 N` layers every value is below `t^(L + 1)`. The generator asserts
  `t^(L + 1) < 2^253`. Then no value wraps mod the field prime. At `N = 16384` and `t = 65537`,
  `t^(L + 1)` has 241 bits.
- The last layer reduces. Each output `v` must satisfy `v - target = t · q`. The range check
  `q < 2^QBITS` makes the equation hold over the integers. `QBITS = bit_length(t^L)` (225 at
  `N = 16384`).
- One reduction of `N` values costs `N` range checks. A reduction between layers costs the same
  number of quotient bits in total. Thus the single final reduction is the cheapest schedule.
- The generator maps each NTT output index to a slot, and each slot to a level, with the real slot
  points of fhe.rs. The circuit never needs the slot order of fhe.rs.

The bound argument is in the comments of `lib/src/ntt.nr`.

### Table

The SIMD map is linear. The plaintext of a bid is the sum of the level plaintexts, weighted by
`expected(l)`. The generator writes `D[l] = Q_MOD_T · INTT(indicator of level l)` for each level.
The table has `B` rows of `N` constants. Most are zero (see below), and Noir drops those terms. The
generator output is a dense table, so its file is large at `B = 64`.

### Sparse

When `N` is a multiple of `n · B`, the slots have the period `B`. Then `m(X)` is a polynomial in
`X^(N / 2B)`. The generator finds the support from the real fhe.rs data: it is every position where
some `D[l]` is non-zero. At `N = 1024` and `N = 16384` it has `2B - 1` positions (31 for `B = 16`,
127 for `B = 64`).

- The statement does not change. A polynomial is determined by its slots. A `k1` with the right
  slots has no coefficient outside the support.
- The circuit takes only the support coefficients. It puts the constant 0 at all other positions and
  computes the commitment on the whole polynomial.
- Slots with equal weights on the support have equal values. The generator groups the slots in
  classes (about `2B`). One weighted sum per class checks all slots of the class. The generator
  asserts that no class has 2 levels.
- If `N` is not a multiple of `n · B`, some slots lie beyond the last copy. They break the period,
  `k1` is dense, and the generator refuses the sparse strategy. Use `table` or `ntt` then.

## Files

| File                                  | Content                                                                       |
| ------------------------------------- | ----------------------------------------------------------------------------- |
| `lib/src/{bid,ntt,table,sparse}.nr`   | The circuit logic.                                                            |
| `lib/src/tests.nr`                    | Tests on a tiny fixture (see Correctness).                                    |
| `lib/src/fixture*.nr`                 | GENERATED fixtures: `N = 16`, `t = 97`, `n = 2`, `B = 4`.                     |
| `{ntt,table,sparse}/src/main.nr`      | The bin packages.                                                             |
| `{ntt,table,sparse}/src/constants.nr` | GENERATED constants. Committed for toy, `vickrey`, `n = 16`, `B = 16`, bid 5. |
| `{ntt,table,sparse}/Prover*.toml`     | GENERATED inputs from real fhe.rs plaintexts.                                 |
| `bench.sh`                            | Generates, executes, counts gates, and optionally proves.                     |
| `../../src/bin/bid_circuit.rs`        | The generator.                                                                |

## Regenerate and run

Run all commands from `examples/auction`.

```sh
# Constants and Prover files into one package. --cases also writes the tampered inputs.
cargo run --release --bin bid_circuit -- --params toy --bidders 16 --levels 16 \
  --variant vickrey --strategy sparse --bid 5 --out-dir circuits/bid/sparse --cases

# Run the honest input, then a tampered input (the second command must fail).
(cd circuits/bid/sparse && nargo execute)
(cd circuits/bid/sparse && nargo execute --prover-name Prover_bid-plus-one)

# Tests of the Noir library.
(cd circuits/bid/lib && nargo test)

# One configuration in a scratch package: gates, tampered cases, proof.
CASES=1 PROVE=1 circuits/bid/bench.sh demo vickrey ntt 16 16 5
```

Generator options:

| Option                  | Values                                                                                                | Default   |
| ----------------------- | ----------------------------------------------------------------------------------------------------- | --------- |
| `--params`              | `toy` (N=1024), `demo` (N=16384), `mid` (N=4096, t=40961, no security), `tiny` (N=16, t=97, fixtures) | `toy`     |
| `--variant`             | `vickrey`, `compact`                                                                                  | `vickrey` |
| `--strategy`            | `ntt`, `table`, `sparse`                                                                              | `ntt`     |
| `--bidders`, `--levels` | `n` and `B`                                                                                           | 16, 16    |
| `--bid`                 | The honest bid                                                                                        | 5         |
| `--out-dir`             | A bin package directory                                                                               |           |
| `--cases`               | Also write `Prover_<case>.toml`                                                                       |           |
| `--fixture`             | Write the fixture of the library tests                                                                |           |

The generator takes the plaintexts from `Vickrey::bid_slots` and `VickreyCompact::bid_slots`. These
are the vectors that `submit` encrypts. It encrypts and decrypts them under a throwaway key and
reads the polynomial `m` that fhe.rs holds. Before it writes a file, it checks that:

1. the NTT of `m` equals the slot vector, through the map from output to slot;
2. every slot equals `A · [b >= l] + B · [b > l]` for the design;
3. the public table reproduces `k1` for the honest bid and for bids 0 and `B - 1`;
4. (sparse) `k1` is zero outside the support, and every class has the right value.

## Correctness evidence

Honest inputs execute at toy and demo size for all 3 strategies and both variants. The same `k1`
gives the same commitment in all 3 strategies. It also equals the output of the plain
`compute_single_polynomial_commitment` (checked with an ad hoc probe circuit).

These tampered inputs fail in every strategy and variant, at toy and demo size
(`CASES=1 circuits/bid/bench.sh ...`). `mismatched-pair` exists for `vickrey` only.

| File                      | Content                                   | Result                                     |
| ------------------------- | ----------------------------------------- | ------------------------------------------ |
| `Prover_bid-plus-one`     | `k1` of bid `b + 1`, claim `b`            | `Failed assertion` (`assert_max_bit_size`) |
| `Prover_non-thermometer`  | A hole in the thermometer of ciphertext 0 | `Failed assertion`                         |
| `Prover_mismatched-pair`  | Ciphertext 1 encodes `b + 1`              | `Failed assertion`                         |
| `Prover_bid-out-of-range` | Claim `b = B`                             | `Failed constraint` (no one-hot vector)    |

Example:

```text
$ (cd circuits/bid/ntt && nargo execute --prover-name Prover_bid-plus-one)
...
     4: Field::assert_max_bit_size
             at std/field/mod.nr:17:9

Failed assertion
```

`nargo test` in `lib/` runs 26 deterministic tests on the tiny fixture. The fixture comes from real
fhe.rs plaintexts. The tests check, for each strategy and design:

- every honest bid passes, and all strategies return the same commitments;
- a `k1` of bid `b + 1` with a claim `b` fails;
- a slot vector that is not a thermometer fails;
- 2 valid thermometers of 2 different bids fail (`vickrey`);
- a claim `b = B`, `b > B`, and `b = -1` fail.

## Measured gates and prove time

Conditions: `bb gates` (`circuit_size`) of `nargo 1.0.0-beta.26` bytecode with `bb 5.2.0`. `n = 16`
bidders. Gates cover both ciphertexts for `vickrey` and the one ciphertext for `vickrey-compact`.
Prove times use `bb prove` with `--verifier_target noir-recursive` (ZK, Poseidon2) on an Apple
M-series machine with 11 threads and 36 GiB of RAM. Every proof verified with `bb verify`.

Gates, `B = 16`:

| `N`          | Variant           | `ntt`   | `table` | `sparse` |
| ------------ | ----------------- | ------- | ------- | -------- |
| 1024 (toy)   | `vickrey`         | 46,993  | 17,806  | 8,192    |
| 1024 (toy)   | `vickrey-compact` | 24,994  | 10,382  | 5,511    |
| 4096 (mid)   | `vickrey`         | 211,297 | 61,959  | 20,675   |
| 4096 (mid)   | `vickrey-compact` | 107,061 | 32,459  | 11,761   |
| 16384 (demo) | `vickrey`         | 972,503 | 251,788 | 84,519   |
| 16384 (demo) | `vickrey-compact` | 487,744 | 127,461 | 43,763   |

Gates, `B = 64`:

| `N`          | Variant           | `ntt`   | `table` | `sparse` |
| ------------ | ----------------- | ------- | ------- | -------- |
| 1024 (toy)   | `vickrey`         | 47,153  | 20,572  | 19,443   |
| 1024 (toy)   | `vickrey-compact` | 25,154  | 13,101  | 11,224   |
| 4096 (mid)   | `vickrey`         | 211,457 | 64,726  | 32,426   |
| 4096 (mid)   | `vickrey-compact` | 107,221 | 35,178  | 17,748   |
| 16384 (demo) | `vickrey`         | 972,663 | 254,540 | 97,791   |
| 16384 (demo) | `vickrey-compact` | 487,904 | 130,165 | 50,511   |

`mid` uses `t = 40961` and 56-bit moduli. It is not a profile of the crate. It gives a size between
toy and demo, for gate counts only.

Prove time and peak memory, `B = 16`:

| `N`          | Variant           | Strategy | Prove (s) | Peak RAM (GiB) |
| ------------ | ----------------- | -------- | --------- | -------------- |
| 1024 (toy)   | `vickrey`         | `ntt`    | 0.35      | 0.12           |
| 1024 (toy)   | `vickrey`         | `table`  | 0.19      | 0.05           |
| 1024 (toy)   | `vickrey`         | `sparse` | 0.13      | 0.02           |
| 4096 (mid)   | `vickrey`         | `ntt`    | 1.35      | 0.58           |
| 4096 (mid)   | `vickrey`         | `table`  | 0.46      | 0.15           |
| 4096 (mid)   | `vickrey`         | `sparse` | 0.24      | 0.04           |
| 16384 (demo) | `vickrey`         | `ntt`    | 4.94      | 2.38           |
| 16384 (demo) | `vickrey`         | `table`  | 1.56      | 0.61           |
| 16384 (demo) | `vickrey`         | `sparse` | 0.68      | 0.16           |
| 16384 (demo) | `vickrey-compact` | `ntt`    | 2.85      | 1.21           |
| 16384 (demo) | `vickrey-compact` | `table`  | 0.87      | 0.31           |
| 16384 (demo) | `vickrey-compact` | `sparse` | 0.39      | 0.08           |

Observations:

- The `ntt` cost does not depend on `B`. It is `N log N` butterflies plus `N` quotient range checks
  of 225 bits (about 10 gates each at demo size).
- The `table` and `sparse` costs depend on `B` only through the non-zero entries of the table.
- The commitment is the floor. A probe circuit with `N = 16384` and `BIT_K = 17` needs about 43,000
  gates for one commitment when only 31 coefficients are witnesses. It needs about 90,000 when all
  16384 coefficients are witnesses with digit asserts. The `sparse` circuit is mostly 2 such
  commitments.

Existing numbers for the encryption proof (`circuits/benchmarks/results_secure_*`, committee
`micro`, `N = 8192`, `t = 17,000,000`, not the auction parameters):

| Circuit                | Gates     | Prove (s) | Proof (KB) |
| ---------------------- | --------- | --------- | ---------- |
| `user_data_encryption` | 1,688,676 | 5.7       | 15.88      |

The insecure preset (`N = 64`) has 53,695 gates. No benchmark exists for `N = 16384` and
`t = 65537`.

## Limits and open risks

- **The commitment is not blinded.** It is a hash of `k1`, and `k1` is a function of the bid. A
  party that sees the commitment can compute it for each of the `B` bids and find the bid. This
  holds for the encryption proof too. Check who sees the public outputs of the encryption proof.
- **The link is outside these circuits.** The soundness of the commitment link needs 3 things: an
  equality check between the commitments of both proofs, the same `BIT_K`, and the same domain
  separator.
- **`k1` range.** The circuits do not range-check `k1` to `[0, t - 1]`. They rely on the encryption
  proof (see Statement).
- **`b` is private and free.** No circuit binds `b` to another commitment, for example a deposit.
- **Parameters.** `BIT_K` and the table depend on `t`, `N`, and the moduli. A change of the
  encryption parameters needs a new generator run.
- **Sparse.** It needs `N` to be a multiple of `n · B`. The `ntt` and `table` strategies do not.
- **Table size.** The `table` constants file has `N · B` entries. At `N = 16384` the file is 0.9 MB
  for `B = 16` and 3.4 MB for `B = 64` (1,048,576 numbers, most of them 0).
- **Memory and time.** The `ntt` strategy at `N = 16384` needs 2.4 GiB to prove. `nargo execute`
  (compile and solve) needs 4.5 GiB and 43 s. The `table` and `sparse` strategies need less.
