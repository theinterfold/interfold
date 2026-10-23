# Sealed-bid auction designs

This crate compares sealed-bid auction designs for Interfold with l-BFV keys. Each design is one E3
program:

1. Each bidder encrypts its bid under one public key.
2. The program evaluates the auction with the l-BFV relinearization key.
3. The program returns one ciphertext.

Interfold decrypts that ciphertext and publishes the full plaintext. Thus, the plaintext must
contain the auction result and no other information about the bids.

One party creates the keys and decrypts. A threshold committee changes who holds the secret key. It
does not change the program or the plaintext that the program makes public.

## Designs

A tie goes to the bidder with the higher index. There are two exceptions. `vickrey` and
`vickrey-compact` give a tie to a random tied bidder (see [Ties](#ties)). `rl-first-price` and
`rl-second-price` show the tie set, and a random value in the output picks the winner (see
[The ratio-lane designs](#the-ratio-lane-designs)).

| Design               | Public result                  | Other disclosure                                                    | Ciphertexts for each bidder | Depth          | ct×ct products |
| -------------------- | ------------------------------ | ------------------------------------------------------------------- | --------------------------- | -------------- | -------------- |
| `rank`               | Winner                         | Each bidder can read its own rank with its secret.                  | 4                           | 2              | `2n`           |
| `rank-batched`       | Winner                         | A tie for the highest bid. Each bidder can read its own rank.       | 4                           | 2              | 2              |
| `first-price`        | Winner and winning bid         | None                                                                | 1                           | `⌈log2 n⌉`     | `n - 1`        |
| `first-price-blind`  | Winner and winning bid         | None, if the mask of 1 bidder is honest                             | 2                           | 1              | 1              |
| `second-price`       | Winner and second-highest bid  | None, if the mask of 1 bidder is honest                             | 3                           | `⌈log2 n⌉ + 1` | `5(n - 1)`     |
| `second-price-blind` | Winner and second-highest bid  | The winning bid. The other disclosure is none, if 1 mask is honest. | 2                           | 2              | 2              |
| `vickrey`            | Winner and second-highest bid  | None, if the mask of 1 bidder is honest                             | 3                           | 3              | 4              |
| `vickrey-compact`    | Winner and second-highest bid  | None, if the mask of 1 bidder is honest                             | 2                           | 4              | `n + 4`        |
| `rl-first-price`     | Winning bid and tie set        | The tie set, and a random value that picks the winner               | 3                           | 1              | 1              |
| `rl-second-price`    | Second-highest bid and tie set | The tie set, and a random value that picks the winner               | 4                           | 3              | 6              |

- `rank` puts bids in the exponent (`X^b`). The program publishes a blinded score for each bidder.
  The score of the winner is 0. A loser score is a random non-zero value. The design does not
  compute a price. The winner must open a bid commitment.
- `rank-batched` computes the same scores with 2 products for all bidders:
  1. Each bidder puts its bid in its own window: `X^(3B·i + 2B + b_i)`.
  2. One product with `Σ X^-b_j` gives the score of each bidder at the center of its window.
  3. A second product with `Σ ρ_k · X^(3Bn·k)` applies each blinding to one score only.

  The cost is `3 · n² · B` coefficients. A tie for the highest bid shows a zero for each tied
  bidder. Ranks are competition ranks: `1 + the number of higher bids`.

- `first-price` encodes each bid as a SIMD thermometer of `bid · n + index`. The program computes
  the OR of all thermometers. The output is a function of the winner and the winning bid only.
- `first-price-blind` adds the thermometers instead. Slot `p` then holds `c[p]`, the number of bids
  above `p`. One product with the sum of the bidder masks makes each slot 0 or a random non-zero
  value. Only the length of the non-zero prefix is visible: the largest `bid · n + index`.
- `second-price` adds a second thermometer region for the plain bids. The program keeps the slots
  where two or more bids are above the slot. Coefficient 0 of the output holds
  `n · second_price + winner`. Bidder masks hide all other coefficients.
- `second-price-blind` computes `c · (c - 1)` in the plain-bid region and `c · c` in the folded
  region, then blinds with the masks. The plain-bid region is non-zero where 2 or more bids are
  above the slot. The folded region shows the winner and also the winning bid.
- `vickrey-compact` is the recommended second-price design. Each bidder sends 2 ciphertexts, thus 2
  encryption proofs, and the encryption proofs are the largest part of the bidder cost. `vickrey`
  sends 3 ciphertexts and uses fewer products. See [The `vickrey` design](#the-vickrey-design).

- `rl-first-price` and `rl-second-price` are the ratio-lane designs. They keep the price range
  independent of the number of bidders. See [The ratio-lane designs](#the-ratio-lane-designs).

### Blind designs

The blind designs (`first-price-blind`, `second-price-blind`, `vickrey`, and `vickrey-compact`) use
a fixed number of products for any number of bidders, except `vickrey-compact`. They have these
costs:

- The result is a pattern of zero slots, not a value in coefficient 0. A contract cannot decode all
  slots at an acceptable cost. Thus, a party claims the result, and the contract checks it. The
  contract evaluates the published plaintext at some slot points. Each evaluation is N
  multiplications mod t. `first-price-blind` needs 2 evaluations, `vickrey` needs 3, and
  `second-price-blind` needs 4.
- A slot where the mask sum is 0 shows as zero by error. The probability is `1/t` for each slot.
- One bidder mask must be honest. A bid circuit must prove that the other ciphertexts are well
  formed. The masks need no proof.

### The `vickrey` design

The output shows the winner and the second-highest bid `s`, and no other information. It does not
show the winning bid, the runner-up, the number of bids at a level, or a tie.

[ENCODING.md](ENCODING.md) shows the encoding and the calculation step by step on small auctions.

The slots hold one region of `B` slots for each candidate winner. Region `k` belongs to the bidder
with tie priority `k`, and `b_k` is the bid of that bidder. Slot `p` of region `k` holds this test
value:

```text
g_k[p] = #{j ≠ k : b_j > p} + [b_k < p] + [b_k = p] · #{j > k : b_j = p}
```

The value is 0 only when bidder `k` beats all other bidders at level `p`. A tie goes to the higher
priority. The program outputs `g · c'(c' - 1) · r`, where `c'[p]` is the number of bids at or above
`p`, and `r` is the sum of the bidder masks:

| Slot `p` | Winner region | Other regions | Reason                                                     |
| -------- | ------------- | ------------- | ---------------------------------------------------------- |
| `p < s`  | Random        | Random        | Two or more bids are above `p`. Thus `g ≥ 1` and `c' ≥ 2`. |
| `p = s`  | 0             | Random        | Only the winner beats all other bidders at `s`.            |
| `p > s`  | 0             | 0             | One bid or none is at or above `p`. Thus `c'(c' - 1) = 0`. |

The output is a function of the winner and `s` only, plus random values. The test
`vickrey_output_depends_only_on_the_winner_and_the_price` checks this property on bid sets with
different winning bids, runner-ups, and ties.

Each bidder sends 3 ciphertexts: the thermometers `[b ≥ p]` and `[b > p]`, copied into every region,
and a mask. The ciphertexts do not depend on the index of the bidder. The difference of the two
thermometers is the one-hot `[b = p]`. The program knows the index of each submission. It selects
the own-region terms and the tie-break terms with plaintext selectors (`3n` ct×pt products). Then it
uses 4 ct×ct products at depth 3, which fits 5 moduli for any number of bidders.

The input proofs are small for this reason:

- The bid proof shows that the two thermometers come from one bid `b < B`. The bidder cannot put its
  bid in the wrong region or claim a different index, because the program applies the index. The
  Noir circuits and measured gate counts of this proof are in
  [`circuits/bid`](circuits/bid/README.md). The proof costs 84,519 gates (`vickrey`) or 43,763 gates
  (`vickrey-compact`) at N = 16384, B = 16, with the `sparse` strategy.
- The mask needs no shape proof. Any mask is safe when one other mask is honest.

`vickrey-compact` sends 2 ciphertexts: one bid ciphertext that holds `[b ≥ p] + [b = p]` (values 0,
1, or 2), and a mask. The program squares each bid ciphertext `v` and gets both thermometers with
`[b ≥ p] = v(3 - v)/2` and `[b > p] = v(2 - v)`. The rest of the program is the same as `vickrey`.
The squares cost `n` more products and one more level of depth (6 moduli at N = 16384):

| Bidders | `vickrey` program | `vickrey-compact` program | Upload, `vickrey` | Upload, `vickrey-compact` |
| ------- | ----------------- | ------------------------- | ----------------- | ------------------------- |
| 4       | 106 ms            | 271 ms                    | 3.44 MB           | 2.70 MB                   |
| 16      | 132 ms            | 642 ms                    | 3.44 MB           | 2.70 MB                   |
| 64      | 281 ms            | 2.22 s                    | 3.44 MB           | 2.70 MB                   |
| 256     | 839 ms            | 8.50 s                    | 3.44 MB           | 2.70 MB                   |

These values are from `--params demo --levels 16 --sweep 4,16,64,256` on one machine.

Spare slots hold copies of the regions. Each copy gets independent mask values, so a slot reads as
zero by error only with probability `t^-copies`. The winner is wrong only if the slot `s` of a loser
reads as zero. Without copies, that probability is about `(n - 1)/t`.

A contract checks a claim `(w, s)` with 3 evaluations. Region `w` is the region of bidder `w`, at
its tie priority:

1. Slot `s` of region `w` is 0.
2. Slot `s - 1` of region `w` is not 0, if `s > 0`. This check refuses a price that is too high.
3. Slot `s` of one other region is not 0. This check refuses a loser that claims `s + 1`.

#### Ties

The tie priority is a random order of the bidders. It must come from public randomness that is fixed
after the bids close, for example a randomness beacon. Thus no bidder can know or change its
priority when it bids. A tie for the highest bid goes to a random tied bidder.

The order costs nothing. The ciphertexts do not depend on the bidder index, and the program puts
each bidder in its region with plaintext selectors. The output does not show the tie. A tie does not
change the price: the price is the tied bid.

A tie that starts a new auction is not used. That output must show the tied bidders, thus it shows
that they bid `s`. Bidders that bid their value can tie again. The new auction also starts with the
information that the first auction made public.

## The ratio-lane designs

The `vickrey` design needs one region of `B` slots for each bidder, so `n · B ≤ N`. The ratio-lane
(RL) designs give the winner as a value at one slot of the price level. They need
`B · lanes + 1 ≤ N`. The number of lanes grows with `⌈n / W⌉` only. With one weight group (up to 16
bidders at `t = 65537`), the price range is `N - 1` levels for the first price and `⌊(N - 1)/2⌋`
levels for the second price. With 64 bidders, it is 4095 and 3276 levels.

- **Weights.** `W` is the largest number with `2^W ≤ t`: 16 at `t = 65537`. Bidder `k` is in weight
  group `⌊k / W⌋` and has the weight `2^(k mod W)`. A group sum shows a set of bidders, bit by bit.
  There are `⌈n / W⌉` groups, and one lane for each group.
- **First price.** Each level has one lane per group: `Σ w_k [b_k ≥ p] + m · #{b > p}`. The lane is
  0 above the top bid, the sum of the weights of the tied top bidders at the top bid, and uniform
  below. 1 ct×ct product, depth 1, no error probability.
- **Second price.** Each level has a `y` lane and one `z` lane per group. At the second-highest bid
  `s`, the ratio `z / y` shows the winner set. Below `s` the lanes are uniform. 6 ct×ct products,
  depth 3. Spare slots hold copies under independent masks: the error is `t^-copies`.
- **Random lane.** One more slot holds the sum of the bidder masks. The winner is
  `T[random mod |T|]`, with `T` the tie set sorted by index. No bidder can predict or grind it.
- **Disclosure.** The output shows the price, the tie set, and the random value. A tie set with 1
  bidder is the winner. A tie shows which bidders tied, and that their bid equals the price.
- **Setup limits.** The first price needs `n < t`. The second price needs `n (n - 1) < t`, so that
  `A (A - 1)` is not zero mod `t`.

[ENCODING.md](ENCODING.md) section 8 shows the lanes on small auctions. [REPORT.md](REPORT.md)
sections 6 to 8 have the construction, the ties, and the measured costs.

The output of `cargo run --release -- --design rl-second-price --bids 3,9,9,2,5 --seed 1` shows the
tie set and the random lane:

```text
public       winner 1, price 9
ties         tie set [1, 2], random lane 1658, winner = tie set[1658 mod 2]
```

## Parameters

Both profiles use a prime plaintext modulus `t ≡ 1 (mod 2N)`. This modulus permits SIMD slots, and
every non-zero value has an inverse mod `t`.

| Profile | N     | t     | Use                               |
| ------- | ----- | ----- | --------------------------------- |
| `toy`   | 1024  | 12289 | Tests and quick runs. Not secure. |
| `demo`  | 16384 | 65537 | Sizes of a secure preset.         |

The number of ciphertext moduli follows the depth of the design. The size comes from the
`search_params` results for a committee of 20 nodes at λ = 31. That bound includes the threshold
smudging noise, so a run with one party has a large noise budget left.

Each design has a capacity limit:

| Design               | Slots needed          | Value limit     |
| -------------------- | --------------------- | --------------- |
| `rank`               | `3 · n · B`           | -               |
| `rank-batched`       | `3 · n² · B`          | -               |
| `first-price`        | `n · B`               | `n · B ≤ t`     |
| `first-price-blind`  | `n · B`               | `n < t`         |
| `second-price`       | `(n + 1) · B`         | `n · B ≤ t`     |
| `second-price-blind` | `(n + 1) · B`         | `n < t`         |
| `vickrey`            | `n · B`               | `2n ≤ t`        |
| `vickrey-compact`    | `n · B`               | `2n ≤ t`        |
| `rl-first-price`     | `⌈n/W⌉ · B + 1`       | `n < t`         |
| `rl-second-price`    | `(1 + ⌈n/W⌉) · B + 1` | `n (n - 1) < t` |

`B` is the number of bid levels. The program refuses an auction that is larger than the limit.

## Run the demo

1. Go to the crate directory:

   ```bash
   cd examples/auction
   ```

2. Run all designs on the toy profile with random bids:

   ```bash
   cargo run --release
   ```

3. Run all designs with your bids:

   ```bash
   cargo run --release -- --bids 7,3,9,9
   ```

4. Run all designs at the secure ring size:

   ```bash
   cargo run --release -- --params demo --bidders 16 --levels 300
   ```

Use `--design <name>` to run one design, for example `--design rank-batched`. Use `--seed` to repeat
a run.

To see how the cost changes with the number of bidders, use `--sweep`. The command runs all designs
on random bids for each bidder count and prints one table:

```bash
cargo run --release -- --params demo --levels 16 --sweep 2,4,8,16,32,64
```

The sweep does not apply the 16 MiB cap on the relinearization key. A design with depth 6 or more
needs 8 or more moduli, and its key is larger than the cap.

The output shows these items for each design:

- The parameters and the depth
- The key size and the upload size for each bidder
- The number of ct×ct and ct×pt products, and the program time
- The noise budget that is left after the program
- The public result, and the own rank of each bidder for `rank`
- A check against the result on plaintext bids

## Run the tests

```bash
cargo test --release
```
