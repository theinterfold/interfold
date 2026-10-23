# The `vickrey` encoding by example

This document shows the `vickrey` and `vickrey-compact` designs on small auctions. Section 8 shows
the ratio-lane designs `rl-first-price` and `rl-second-price`. All patterns in this document are
output of the real program (toy parameters, 3 bidders, 5 bid levels).

Notation:

- `n` is the number of bidders, and `B` is the number of bid levels. A bid `b` is in `0..B`.
- `[x]` is 1 when `x` is true, and 0 when `x` is false.
- `R` is a random non-zero value. `0` is zero.

## 1. Slots, regions, and copies

A plaintext has `N` slots. The program multiplies and adds ciphertexts slot by slot. The design cuts
the slots into `n` regions of `B` slots. Each bidder has one region, at its tie priority. Slot `p`
of a region is bid level `p`.

The tie priority is a random order of the bidders, drawn after the bids close (see the README
section "Ties"). To keep the examples simple, the priority in this document is the bidder index.
Thus region `k` is the region of bidder `k`, and a bidder with a higher index wins a tie.

```
            region 0          region 1          region 2
         ┌──┬──┬──┬──┬──┐  ┌──┬──┬──┬──┬──┐  ┌──┬──┬──┬──┬──┐
level p  │0 │1 │2 │3 │4 │  │0 │1 │2 │3 │4 │  │0 │1 │2 │3 │4 │   copy 0
         └──┴──┴──┴──┴──┘  └──┴──┴──┴──┴──┘  └──┴──┴──┴──┴──┘
         then the same 15 slots again (copy 1), again (copy 2), ... until N slots are full
```

The slots after the first `n · B` slots hold copies of the regions. The copies get different random
values, which makes a zero-by-error less likely (see section 6). The examples show copy 0 only.

## 2. What a bidder encrypts

A bid becomes two thermometers:

- `[b ≥ p]` is 1 at levels `0..=b`.
- `[b > p]` is 1 at levels `0..b`.

The difference `[b ≥ p] - [b > p]` is a one-hot: 1 only at level `b`.

| Bid   | `[b ≥ p]`, levels 0 to 4 | `[b > p]`, levels 0 to 4 | One-hot `[b = p]` |
| ----- | ------------------------ | ------------------------ | ----------------- |
| `b=1` | `1 1 0 0 0`              | `1 0 0 0 0`              | `0 1 0 0 0`       |
| `b=4` | `1 1 1 1 1`              | `1 1 1 1 0`              | `0 0 0 0 1`       |
| `b=2` | `1 1 1 0 0`              | `1 1 0 0 0`              | `0 0 1 0 0`       |

Each bidder puts the same thermometer in every region. Thus, the ciphertext does not depend on the
index of the bidder. For example, the bidder with `b=1` encrypts this `[b ≥ p]` plaintext:

```
   region 0     region 1     region 2
  1 1 0 0 0    1 1 0 0 0    1 1 0 0 0
```

The bidder also encrypts a mask: a random value in each slot.

| Design            | Ciphertexts of one bidder                  |
| ----------------- | ------------------------------------------ |
| `vickrey`         | `[b ≥ p]`, `[b > p]`, mask                 |
| `vickrey-compact` | `[b ≥ p] + [b = p]` (values 0, 1, 2), mask |

The `vickrey-compact` bid ciphertext holds 1 below the bid, 2 at the bid, and 0 above the bid. For
`b=2`, it is `1 1 2 0 0` in each region. The program gets the two thermometers back with one square
per bidder:

| Slot value `v` | `v(3 - v)/2` = `[b ≥ p]` | `v(2 - v)` = `[b > p]` |
| -------------- | ------------------------ | ---------------------- |
| 0 (above)      | 0                        | 0                      |
| 1 (below)      | 1                        | 1                      |
| 2 (at)         | 1                        | 0                      |

After this step, the two designs do the same calculation.

## 3. What the program calculates

Example 1: the bids are `b0=1`, `b1=4`, `b2=2`. The winner is bidder 1. The second-highest bid is
`s=2`.

**Step 1. Count the bids at or above each level.** The program adds the `[b ≥ p]` ciphertexts of all
bidders. Every region gets the same count `c'`:

| Level `p`         | 0   | 1   | 2   | 3   | 4   |
| ----------------- | --- | --- | --- | --- | --- |
| `c'` = `#{b ≥ p}` | 3   | 3   | 2   | 1   | 1   |
| `c'(c' - 1)`      | 6   | 6   | 2   | 0   | 0   |

`c'(c' - 1)` is 0 when fewer than 2 bids are at or above `p`. Thus, it is 0 above the second-highest
bid. This product hides the winning bid.

**Step 2. Count, in region `k`, why bidder `k` does not win at level `p`.** The program uses
plaintext selectors to apply the index of each bidder:

```
g_k[p] = #{j ≠ k : b_j > p}         another bidder is strictly above p
       + [b_k < p]                  bidder k is below p
       + [b_k = p] · #{j > k : b_j = p}   tie at p, and a bidder with a higher priority wins the tie
```

`g_k[p]` is 0 only if bidder `k` bids at least `p`, and no other bidder beats bidder `k` at `p`.

| Region (bid) | `g` at p = 0 | 1   | 2   | 3   | 4   |
| ------------ | ------------ | --- | --- | --- | --- |
| 0 (`b0=1`)   | 2            | 2   | 2   | 2   | 1   |
| 1 (`b1=4`)   | 2            | 1   | 0   | 0   | 0   |
| 2 (`b2=2`)   | 2            | 1   | 1   | 2   | 1   |

**Step 3. Multiply and mask.** The output is `g · c'(c' - 1) · r`. Here `r` is the sum of all masks,
so it is random if one mask is honest.

| Region (bid) | `g · c'(c' - 1)` | Public output |
| ------------ | ---------------- | ------------- |
| 0 (`b0=1`)   | `12 12  4  0  0` | `R R R 0 0`   |
| 1 (`b1=4`)   | `12  6  0  0  0` | `R R 0 0 0`   |
| 2 (`b2=2`)   | `12  6  2  0  0` | `R R R 0 0`   |

Only the public output column becomes public. The masks remove all numbers. Only the zero pattern
stays.

## 4. How to read the output

```
region 0:  R R R 0 0     last R at level 2
region 1:  R R 0 0 0     last R at level 1    ← zero at level s: the winner
region 2:  R R R 0 0     last R at level 2
                ↑
                s = 2 = the highest "last R"
```

1. In each region, find the last level with `R`.
2. The price `s` is the highest of these levels.
3. The winner is the region that is `0` at level `s`.

The pattern of every region is fixed by the winner and `s` only:

| Region | Levels `0..s` | Level `s` | Levels above `s` |
| ------ | ------------- | --------- | ---------------- |
| Winner | `R`           | `0`       | `0`              |
| Loser  | `R`           | `R`       | `0`              |

Thus, the output does not show the winning bid (4), or the bids of the losers (1 and 2). In example
1, the bidders with `b=1` and `b=2` have the same pattern.

## 5. A tie

Example 2: the bids are `b0=3`, `b1=1`, `b2=3`. Two bidders tie at the top. The bidder with the
higher priority (here, the higher index) wins the tie, so the winner is bidder 2. The price is
`s=3`. With a different random priority, bidder 0 can win the tie. The price does not change.

Example 3: the bids are `b0=3`, `b1=1`, `b2=4`. There is no tie. The winner is bidder 2, and the
price is `s=3`.

| Region | Example 2 (tie) | Example 3 (no tie) |
| ------ | --------------- | ------------------ |
| 0      | `R R R R 0`     | `R R R R 0`        |
| 1      | `R R R R 0`     | `R R R R 0`        |
| 2      | `R R R 0 0`     | `R R R 0 0`        |

The two outputs have the same pattern. Thus, the output does not show the tie. The `R` values are
different random values.

The tie term in example 2, region 0, level 3: `[b0 = 3] · #{j > 0 : b_j = 3} = 1 · 1 = 1`. Thus,
`g_0[3]` is not 0, and bidder 0 loses the tie. In region 2, no bidder with a higher priority is at
level 3, so `g_2[3] = 0`.

## 6. Copies

A slot can be zero by error when the random value `r` is 0 there. The probability is `1/t` for each
slot. Each copy of the regions gets independent random values. The decoder reads a slot as `R` when
one or more copies are not zero. For a loser slot to read as zero, all copies must be zero. The
probability is `t^-copies`.

## 7. Slots and coefficients

The slot values are not the coefficients of the plaintext polynomial. The plaintext polynomial
`m(X)` has `N` coefficients. Slot `i` holds `m(α_i) mod t`, where `α_i` is one of the `N` roots of
`X^N + 1` mod `t`. The encoder makes the coefficients from the slot values with an inverse NTT.
Thus, a thermometer in the slots looks like random numbers in the coefficients:

```
slots         1 1 0 0 0 | 1 1 0 0 0 | 1 1 0 0 0 | ...      (structured)
                         inverse NTT mod t
coefficients  N values spread over 0..t-1                (no visible structure)
```

The BFV encryption proof works on the coefficients. A bid proof must show that the slots are a
thermometer. Thus, the bid circuit calculates the forward NTT of the coefficients and compares each
slot with the thermometer of the bid.

## 8. The ratio-lane encoding

The `rl-first-price` and `rl-second-price` designs do not use one region for each bidder. They use
one **lane** of `B` slots for each weight group. A lane has one slot for each level `p`. The number
of lanes does not depend on the number of bidders, only on the number of weight groups (see
[REPORT.md](REPORT.md), section 6). The examples below use 3 bidders, which fit one weight group.

The bidder with index `k` has the weight `w_k = 2^k`: 1, 2, and 4 for bidders 0, 1, and 2. The
program adds the weights of a set of bidders. The sum shows that set, bit by bit: the value 5 is
`1 + 4`, thus bidders 0 and 2.

The ciphertexts of a bidder are the same two thermometers as in section 2, copied into every lane,
and a mask. The second price also uses a pair mask. The program applies the weights with plaintext
selectors, so the ciphertexts do not depend on the index of the bidder.

### First price

Per level, the program outputs `Σ w_k [b_k ≥ p] + m · A`. Here `A[p] = #{b > p}`, and `m` is the sum
of the masks.

Example 4: the bids are `b0=1`, `b1=4`, `b2=2`. The price is 4, and bidder 1 is the only bidder at
the top.

| Level `p`         | 0   | 1   | 2   | 3   | 4   |
| ----------------- | --- | --- | --- | --- | --- |
| `Σ w_k [b_k ≥ p]` | 7   | 7   | 6   | 2   | 2   |
| `A` = `#{b > p}`  | 3   | 2   | 1   | 1   | 0   |
| Public output     | `R` | `R` | `R` | `R` | 2   |

The mask term `m · A` is 0 where `A = 0`: at the top level and above. At every lower level, `A` is
not zero, and the term makes the slot uniform. The highest non-zero slot is the price. Its value is
the sum of the weights of the tied top bidders. Here the value 2 shows bidder 1.

Example 5: the bids are `b0=3`, `b1=1`, `b2=3`. Two bidders tie at the top. The output at level 3 is
`1 + 4 = 5`. Thus the tie set is bidders 0 and 2, and the price is 3. The output does not hide the
tie set.

### Second price

Per level, the program makes two lanes: `y` and `z`. With `C[p] = #{b ≥ p}` and `A[p] = #{b > p}`:

```text
c = C (C - 1)        u = A (A - 1)        L = Σ w_k [b_k > p] + (1 - A) · Σ w_k [b_k = p]
y = R · c       + m_y · u
z = R · c · L   + m_z · u
```

`R` is the sum of the pair masks. It has the same value in `y` and `z` at one level. The masks `m_y`
and `m_z` are independent.

Example 6: the bids are `b0=1`, `b1=4`, `b2=2`. The second-highest bid is `s=2`.

| Level `p` | 0   | 1   | 2     | 3   | 4   |
| --------- | --- | --- | ----- | --- | --- |
| `c`       | 6   | 6   | 2     | 0   | 0   |
| `u`       | 6   | 2   | 0     | 0   | 0   |
| `L`       | 7   | 5   | 2     | 2   | 2   |
| `y`       | `R` | `R` | `R`   | 0   | 0   |
| `z`       | `R` | `R` | `R`   | 0   | 0   |
| `z / y`   | `R` | `R` | **2** | 0   | 0   |

- At level `s = 2`, `u = 0`. The mask term disappears. Then `y = R · c` and `z = R · c · L`. The
  ratio `z / y` is `L = 2`: the weight of bidder 1, the top bidder.
- Below `s`, `u` is not zero (it needs `n (n - 1) < t`). Both lanes are uniform and independent. The
  ratio is a random value there.
- Above `s`, `c = 0` and `u = 0`. Both lanes are 0.

The ratio removes the factor `R · c`. This factor hides the number of bids at or above `s`.

Example 7: the bids are `b0=3`, `b1=1`, `b2=3`. At level 3, `A = 0`, so `L` is the sum of the
weights of the tied top bidders: `1 + 4 = 5`. The ratio `z / y` is 5. The price is 3, and the tie
set is bidders 0 and 2.

### Random lane and the winner

One slot outside all lanes holds `m` at that slot. It is a uniform value if one mask is honest. It
is fixed by the encrypted masks, so a bidder cannot predict it. The result is public with the price.

The winner is `T[random mod |T|]`. `T` is the tie set, sorted by bidder index. In example 5, `T` is
`[0, 2]`. A random value of 3 gives `T[3 mod 2] = T[1]`: bidder 2.

### Copies

The second price has a zero-by-error when `R` is 0 at level `s`. The probability is `1/t`. The spare
slots hold copies of the `y` and `z` lanes with independent pair masks. The decoder takes the
highest price over the copies. The probability of an error is `t^-copies`. The first price has no
error and needs one copy.
