# Sealed negotiation: design note

This note explains why the negotiation uses the construction it uses, what the output leaks, and how
close the agreed price is to the ideal one. `README.md` has the usage. The encoding in this note is
the contract between the circuit, the FHE program, the contract and the SDK (`sdk/src/layout.ts`).

## The ideal mechanism

A seller has a private minimum price `s`. A buyer has a private maximum price `b`. Both are levels
of a public price grid. If `b >= s`, the mechanism picks one level `p` uniformly in `[s, b]`. If
`b < s`, it outputs "no match". The ideal output is the match bit and `p`.

The ideal leak is small. Given `p`, the seller learns `b >= p`. Given `p`, the buyer learns
`s <= p`. For a uniform `p`, the likelihood of `p` is `1/(b - s + 1)`. So the seller learns nothing
more about `b` than that bound, and a high `b` does not make a high `p` more likely. The no-match
output leaks only `b < s`.

## What a program can compute

The platform sets these limits:

- A program works slot by slot. It has no rotation key. Every non-zero slot of the decrypted output
  is public, and a slot cannot read another slot.
- One output ciphertext and one decryption for each E3. The multiplication depth is at most 3.
- No randomness inside a program. A party can add secret random inputs. The committee and the runner
  must not know the random value.
- Each extra ciphertext that a party sends adds a full encryption-proof tree (about 6.5M gates).

Four facts follow, and they decide the design.

1. **A public random value leaks.** Let `u` be a random pointer that anyone can read (for example
   from an earlier E3), and let `p = f(u, s, b)`. The pair `(u, p)` fixes a rectangle of `(s, b)`
   pairs. The output shows more than the ideal one. So the pointer must stay secret, and the one-hot
   output must be computed inside the program.
2. **The output of a slot is a function of two numbers.** Slot `i` of the output is a polynomial of
   one value of the seller and one value of the buyer in that slot. The seller can put any function
   of its private data in its value, so the question is the rank of the matrix
   `M_i[(s, a), (b, c)]`, with the private data of the seller (`s`, its random share `a`) as rows
   and that of the buyer as columns. One ciphertext multiplication gives a rank-1 term. Lanes (the
   groups of 16 slots) give more terms: the program computes one product for each lane, and the
   **public** adds the lanes after the decryption.
3. **Lanes need a mask.** The lane values of the output are public. If they show which lane is
   non-zero, they show the secret pointer. Each party adds a mask: random lane values with sum 0
   over the lanes (the mask is one more ciphertext). The 8 lane values are then uniform subject to
   their sum.
4. **A comparison of a joint secret with a private threshold is expensive.** It has rank equal to
   the size of the domain of the secret. This kills every design that picks `p = s + v (b - s)` or
   `p = s + (V mod (b - s + 1))` with a joint random `V`: the first leaks `v (b - s)`, which has few
   divisors, so `b` is nearly known. The second needs `ceil(R / n)` equality tests for a pointer in
   `[0, R)`, with `R` large for uniformity and `n = b - s + 1` small. Equality of two secrets is
   cheap (a ciphertext subtraction), but a window or a threshold is not.

### Alternatives that the study rejected

| Alternative                                             | Why not                                                                                                                             |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Public coin from an earlier E3                          | Leaks `(u, p)`, which bounds `s` and `b` on both sides (fact 1).                                                                    |
| Cyclic pointer: `p` = first level of `[s, b]` after `u` | The slot cannot test that `u` is outside `(s, b]` (fact 4). If it could, `p = s` has probability `(L - n + 1)/L`: a leak of `s`.    |
| `p = s + v (b - s)`                                     | Leaks the product `v (b - s)` (fact 4).                                                                                             |
| `p = s + (V mod n)`, one pointer `V`                    | Needs `R / n` factors: depth `log(R / n)` and an exact uniform `V` only if `n` divides `R` (`R` = lcm of all `n`).                  |
| Several trials, first accepted pointer                  | Cross-slot "first" logic needs a sum over slots. All accepted trials in the output show the range. The count of failures shows `n`. |
| One party draws the random value                        | That party chooses `p`. The task needs a joint value.                                                                               |
| Min-wise independent family (affine, golden-ratio)      | Best uniformity, but the rank is the size of the family, hundreds (table below).                                                    |
| **Trie priorities, pointer `u = a xor c` (chosen)**     | Rank 16, depth 1, 3 ciphertexts for each party, exact leak analysis.                                                                |

## The chosen construction

The grid has `L` levels, `2 <= L <= 16`. Level `i` has 4 bits.

**Random priorities.** For a pointer `u` of 4 bits, the priority of the level `l` is `l xor u`. The
agreed level is the one of the least priority in `[s, b]`. This is a permutation of the levels for
each `u`. For a permutation, the winner factorises:

```text
[p == i] = [s <= i] * [i <= b]
         * prod over the 1-bits k of i:  (1 - z_k * [u_k = 0])      z_k = [s <= left_k(i)]
         * prod over the 0-bits k of i:  (1 - w_k * [u_k = 1])      w_k = [b >= right_k(i)]
```

`left_k(i)` is `i` with bit `k` cleared and every lower bit set: the largest level below `i` that
beats `i` when `u_k = 0`. `right_k(i)` is `i` with bit `k` set and every lower bit cleared: the
smallest level above `i` that beats `i` when `u_k = 1`. The seller can compute the first product (it
depends on `s` and on `u` at the 1-bits of `i`). The buyer can compute the second (it depends on `b`
and on `u` at the 0-bits). The two bit sets of a level are disjoint.

**Joint pointer.** `u = a xor c`. The seller draws `a`, the buyer draws `c`, each 4 uniform bits. If
one party draws honestly, `u` is uniform and neither party knows it. Neither can bias it.

**Lane tensor.** Write `[u_k = 0]` as a sum over the unknown bit of the other party. For the lane
`theta` in 0..15, the seller holds `X(theta, i)` and the buyer holds `Y(theta, i)`:

```text
X(theta, i) = [s <= i] * prod over 1-bits k of i: A_k(a_k xor theta_k)   * prod over 0-bits k: [a_k = theta_k]
Y(theta, i) = [i <= b] * prod over 1-bits k of i: [c_k = theta_k]        * prod over 0-bits k: B_k(c_k xor theta_k)
A_k(0) = 1 - z_k, A_k(1) = 1        B_k(0) = 1, B_k(1) = 1 - w_k
```

The lane `theta` that counts at the level `i` is `theta_k = c_k` on the 1-bits of `i` and
`theta_k = a_k` on the 0-bits. So `sum over theta of X * Y = [p == i]` (checked for every
`s, b, a, c` by `sdk/src/layout.test.ts`). The sum is 0 for every level if `b < s`, because of the
factors `[s <= i]` and `[i <= b]`.

**Ciphertexts.** A party sends 3 ciphertexts, each with 128 SIMD slots. Slot `g * 16 + i` is group
`g` (0..7), level `i`.

| Ciphertext | Slot `g * 16 + i` holds                                                       |
| ---------- | ----------------------------------------------------------------------------- |
| 0          | `X(g, i)` (or `Y(g, i)`): the lanes 0 to 7                                    |
| 1          | `X(g + 8, i)` (or `Y(g + 8, i)`): the lanes 8 to 15                           |
| 2          | A random mask: for each level `i`, the sum over `g` of the slots is 0 mod `t` |

**Program.** `out = X0 * Y0 + X1 * Y1 + M_seller + M_buyer`, slot by slot. It has two ciphertext
multiplications of depth 1, and needs the relinearization key. After the decryption, the public
computes `S_i = sum over g of out[g * 16 + i] mod 257`. `S` is the one-hot vector of `p`, or zero
for no match.

## What is public, and what each party learns

| Item                             | Visible to                                                                                          |
| -------------------------------- | --------------------------------------------------------------------------------------------------- |
| `s`, `b`, the shares `a`, `c`    | Only the party that owns it. Never decrypted.                                                       |
| The three ciphertexts of a party | Everyone, encrypted under the committee key.                                                        |
| The 128 output slots             | Everyone. The 8 group values of each level are uniform subject to their sum, so they show only `S`. |
| `S`: match bit and `p`           | Everyone. This is the ideal output.                                                                 |
| `u`, the lane, the other mask    | Nobody.                                                                                             |

The privacy argument is in two parts.

1. **The output slots carry only `S`.** Each output slot is `(X Y terms) + m^A + m^C`. Fix the
   secrets of the two parties. For each level, the vector of the 8 group values is the vector of the
   products plus `m^A + m^C`. If one party draws its mask uniformly from the zero-sum vectors,
   `m^A + m^C` is uniform on the zero-sum space whatever the other party does. So the group vector
   is uniform on the vectors with sum `S_i`. The circuit checks the zero-sum constraint of each
   mask: a party cannot add a non-zero offset and break the sum. So the output slots are a function
   of `S` and of fresh uniform values.
2. **`S` has the law of the mechanism.** Given `(s, b)`, `u` is uniform. It does not depend on `a`
   alone or `c` alone. So the posterior of a party about the other, after seeing `S` and knowing its
   own `a`, is the posterior from the likelihood `ell(p; s, b) = Pr_u[winner = p]`. The seller's
   knowledge of `a` adds nothing, because `c` is uniform.

The output leaks exactly `ell`. The mechanism differs from the ideal one only by `ell`.

### How close `ell` is to uniform

The law is exact. `sdk/src/uniformity.ts` computes it, and `pnpm -C sdk uniformity` prints the
tables. The priorities `l xor u` are a trie: they rank the levels first by bit 3, then bit 2, and so
on, with a random order of the two children at each depth. A level in a small subtree wins more
often. All 136 intervals of 16 levels, uniform prior on `(s, b)`:

| Family (16 levels)           | `K` | Max TV | Mean TV | Excess information | Overweight / underweight | Rank (per level)           |
| ---------------------------- | --- | ------ | ------- | ------------------ | ------------------------ | -------------------------- |
| Ideal                        | -   | 0      | 0       | 0                  | 1 / 1                    | -                          |
| **Trie, `l xor u` (chosen)** | 16  | 0.417  | 0.144   | 0.120 bits         | 4.5 / 0.375              | 16                         |
| Cyclic shift of the levels   | 16  | 0.562  | 0.383   | 0.644 bits         | 4.5 / 0.125              | 2K                         |
| Golden-ratio cyclic shift    | 128 | 0.151  | 0.105   | 0.037 bits         | 1.78 / 0.44              | hundreds                   |
| Affine `(a l + b) mod 17`    | 272 | 0.071  | 0.039   | 0.016 bits         | 1.21 / 0.79              | full (126/252 at 6 levels) |

`research/alternatives.py` computes the rows (add `--rank` for the measured ranks at 8 levels). The
trie never excludes a level: every level of `[s, b]` has a positive probability, so the output never
proves that a level is impossible. A probability is a multiple of 1/16, so the family cannot do
better than a granularity of 1/16 for any family of 16 members.

Two examples. For `s = 2` and `b = 12` (11 levels) the exact law is, in sixteenths:
`2:2 3:2 4:1 5:1 6:1 7:1 8:1 9:1 10:1 11:1 12:4`. The ideal is 1.45 on each level, so the top level
`b` is 2.9 times too likely. After the output `p = 7`, the seller (`s = 2`) holds a posterior on `b`
of 0.2 on `b = 7` and 0.1 on each of `8..15` (the ideal mechanism gives the same support with a
different weight on `b = 7`). After the same output, the buyer (`b = 12`) holds a posterior on `s`
of 0.05 on each of `0..3`, 0.1 on `4` and `5`, 0.2 on `6` and 0.4 on `7`: a lower `s` is less likely
than `s = p`. Both posteriors have the full support allowed by the bound, so no level is excluded.
`pnpm -C sdk uniformity` prints these numbers. The excess mutual information of the whole mechanism
over the ideal one is 0.12 bits.

An interval that is a power-of-2 aligned block (`[0, 7]`, `[8, 15]`, `[0, 15]`, `[4, 7]`) has an
exactly uniform law. The worst interval is `[3, 8]` (total variation 0.417): the law is 4/16, 1/16,
1/16, 1/16, 1/16, 8/16, so the level 8 wins half of the time. `[0, 2]` gives 1/4, 1/4, 1/2.

### What is exact, and what is not

- **Exact:** the match bit. It is `[b >= s]`, with no error.
- **Exact:** the joint, secret pointer. Neither party, the committee or the runner knows it.
- **Exact:** the output slots reveal nothing but `S`, if one party masks honestly.
- **Not exact:** the law of `p`. It has total variation distance up to 0.42 from the uniform law.
  This gap is the only extra leak.

## Cost

| Item                       | Value                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------ |
| Ciphertexts for each party | 3 (lanes 0..7, lanes 8..15, mask)                                                          |
| Multiplicative depth       | 1 (two ciphertext multiplications, then additions)                                         |
| Slots                      | 128 of 128: 8 groups of 16 levels                                                          |
| Browser proof              | One encryption-proof tree for each ciphertext, one proof of the encoding (see `circuits/`) |
| Output                     | One ciphertext, decoded on chain: the contract sums the 8 groups of each level             |

## Open decisions

- The family is a trie. A family with a smaller distance has a larger rank (table above). Earlier
  trials with shifted, mirrored and k-ary tries did not lower the maximum distance of the trie; they
  are not in this repository.
- A negotiation allows one offer of each party and no update. An update needs a version rule like
  the one of `examples/sealed-cca`.
- A party that does not send its offer stops the negotiation. Nothing leaks. There is no deposit, so
  there is nothing to refund.
