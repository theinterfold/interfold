# Auction designs in TypeScript

This package is a plaintext simulation of the sealed-bid auction designs in the Rust crate
(`../src`). It uses the same slot encodings, the same sequence of operations, and the same decoding.
Nothing is encrypted. A "ciphertext" here is the list of plaintext slots plus a depth counter. Thus
you can print and test each step of the tally.

Use it to read the encodings and to test an idea fast. Do not use it to hide bids.

The package is standalone. It is not in the root pnpm workspace, as the Rust crate is not.
`../ENCODING.md` explains the `vickrey` encoding in detail. This README does not copy it. `../viz`
is a small web app that runs this simulation in the browser and draws each step.

## Install, test, and run

All commands run in this directory (`examples/auction/ts`). You need Node 18 or later.

```sh
pnpm install                     # or: npm install
pnpm test                         # or: npx vitest run
npx tsc --noEmit                  # type check
npx tsx src/cli.ts --design vickrey-compact --bids 1,4,2 --levels 5
npx tsx src/cli.ts --design vickrey --bids 1,4,2 --levels 5 --trace
```

The only dependencies are `typescript`, `vitest`, and `tsx`.

The file `pnpm-workspace.yaml` in this directory makes it a separate pnpm root, so `pnpm install`
does not touch the root workspace. `pnpm install --ignore-workspace` gives the same install. With
pnpm 11, it also prints a warning about the build script of `esbuild` and exits with code 1. The
install is complete. The tests and the CLI do not need that build script.

### CLI options

| Option                  | Meaning                                                                                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--design <name>`       | A design name from the table below, or `all` (default).                                                                                                 |
| `--params <profile>`    | `toy` (N=1024, t=12289, default) or `demo` (N=16384, t=65537).                                                                                          |
| `--bids <list>`         | Comma-separated bids, one for each bidder. Random bids when not set.                                                                                    |
| `--bidders <n>`         | Number of bidders for random bids. Default 4.                                                                                                           |
| `--levels <B>`          | Bids are in `0..B`. Default 16.                                                                                                                         |
| `--seed <n>`            | Seed for the bids, the masks, and the tie draw. Random when not set.                                                                                    |
| `--tie-priority <list>` | A tie priority (a permutation of `0..n`) for `vickrey` and `vickrey-compact`. The `rl-` designs have no tie priority: the random lane picks the winner. |
| `--sweep <list>`        | Comma-separated bidder counts. Prints one table of the costs.                                                                                           |
| `--trace`               | Prints each intermediate slot vector, by region and level.                                                                                              |

The CLI prints the same summary as the Rust binary `auction-designs`. It does not print key sizes,
timings, or noise budgets, because nothing is encrypted.

## Designs

Names are the same as `Design::name()` in Rust. The counts are for `n` bidders. The last column is
for `n = 4`. The tests check all counts against the Rust crate.

| Design               | What the output reveals                                                           | ct×ct      | ct×pt    | Depth          | `n = 4` (ct×ct / ct×pt / depth) |
| -------------------- | --------------------------------------------------------------------------------- | ---------- | -------- | -------------- | ------------------------------- |
| `rank`               | The winner. Each bidder can read its own rank.                                    | `2n`       | `3n - 2` | 2              | 8 / 10 / 2                      |
| `rank-batched`       | The winner and a tie for the highest bid. Each bidder reads its own rank.         | 2          | 1        | 2              | 2 / 1 / 2                       |
| `first-price`        | The winner and the winning bid.                                                   | `n - 1`    | 0        | `⌈log2 n⌉`     | 3 / 0 / 2                       |
| `first-price-blind`  | The winner and the winning bid.                                                   | 1          | 0        | 1              | 1 / 0 / 1                       |
| `second-price`       | The winner and the second-highest bid.                                            | `5(n - 1)` | `n`      | `⌈log2 n⌉ + 1` | 15 / 4 / 3                      |
| `second-price-blind` | The winner, the second-highest bid, and the winning bid.                          | 2          | 0        | 2              | 2 / 0 / 2                       |
| `vickrey`            | The winner and the second-highest bid.                                            | 4          | `3n`     | 3              | 4 / 12 / 3                      |
| `vickrey-compact`    | The winner and the second-highest bid.                                            | `n + 4`    | `4n`     | 4              | 8 / 16 / 4                      |
| `rl-first-price`     | The winning bid, the tie set, and a random value that picks the winner.           | 1          | `n`      | 1              | 1 / 4 / 1                       |
| `rl-second-price`    | The second-highest bid, the winner set, and a random value that picks the winner. | 6          | `2n`     | 3              | 6 / 8 / 3                       |

Each design that uses masks (all designs except `first-price`) reveals only the values in the table,
if the mask of one bidder is honest.

A tie goes to the bidder with the higher index. `vickrey` and `vickrey-compact` are the exception.
They draw a random tie priority after the bids close. The priority is a permutation of `0..n`, and
the tied bidder with the highest priority wins.

The two `rl-` designs (ratio lanes) are the other exception. They also have no region for each
bidder. Bidder `k` has the weight `2^(k mod W)` in the weight group `⌊k / W⌋`, with `W = ⌊log2 t⌋`
(13 on the toy profile, 16 on the demo profile). A lane holds the sum of the weights of some
bidders, and the bits of that sum name the bidders. Thus the output needs `⌈n / W⌉` lanes for each
price level, and not `n`. The output also holds the sum of the masks in one extra slot, the random
lane. The winner of a tie is `tie set[random mod |tie set|]`. The output shows the tie set (all its
bids equal the price) and the random value, and nothing else.

- `rl-first-price`: one block of `B` slots for each weight group. Slot `p` is `Z + m · A`. It is 0
  above the highest bid, the weights of the tied bidders at it (no mask, no error), and uniform
  below it.
- `rl-second-price`: one copy is the lane `y` and one lane `z` for each weight group. Both lanes are
  0 above the second-highest bid `s`, and uniform below it. At `s`, `y = R · c` and `z = R · c · L`.
  The ratio `z / y = L` is the sum of the weights of the winner set in that group. `R` is the sum of
  the pair masks: a pair mask has the same value in `y` and in every `z` of a copy. A copy reads `s`
  too low with probability `1/t`, the reader takes the highest `s` over the copies, and the ring
  holds as many copies as fit. The condition is `n (n - 1) < t`.

With `--trace`, the layout shows copy 0 and the random lane. `isCorrect` compares the tie set and
the random lane too: the expected random value is the sum of the plaintext masks.

## Files

| File                         | Content                                                                            |
| ---------------------------- | ---------------------------------------------------------------------------------- |
| `src/field.ts`               | Slot arithmetic mod `t`, the toy and demo profiles, and the ring `Z_t[X]/(X^N+1)`. |
| `src/evaluator.ts`           | `Ciphertext` (slots and depth) and `Evaluator` (counts ct×ct and ct×pt).           |
| `src/designs/<name>.ts`      | One file for each design: `encodeBid`, `evaluate`, and `decode`.                   |
| `src/designs/design.ts`      | `Setup`, `PublicResult`, the tie `ranking`, and the `Design` interface.            |
| `src/designs/*-common.ts`    | Code that two designs share (`blind-common`, `vickrey-common`, `ratio-common`).    |
| `src/index.ts`               | The registry `designs`, and `run(...)`.                                            |
| `src/cli.ts`, `src/trace.ts` | The command line and the trace printer.                                            |
| `test/*.test.ts`             | The tests.                                                                         |

Start with `src/designs/vickrey.ts`. The `encodeBid` comment shows the slot layout, and `evaluate`
follows the Rust program step by step. The long comment in `src/designs/vickrey-common.ts` shows why
the output hides everything except the winner and the price.

### Use as a library

```ts
import { run, seededRng } from './src'

const { result, expected, opCounts, depth, outputSlots } = run(
  'vickrey', // a design name or a design object
  'toy', // the profile
  [1, 4, 2], // the bids
  5, // the number of levels
  [0, 1, 2], // the tie priority (optional)
  seededRng(1), // the random source (optional)
)
```

`run` returns:

- `result`: the public result that `decode` reads from the output.
- `expected`: the result of the plain rule on the bids.
- `opCounts`: the number of ct×ct and ct×pt products.
- `depth`: the multiplicative depth of the output, measured.
- `outputSlots`: the output that Interfold publishes.

## How the simulation works

A plaintext is a polynomial with `N` coefficients mod `t`. The prime `t` is 1 mod `2N`. Thus the
ring splits into `N` independent slots. A sum or a product acts on each slot alone.

- A slot design (`first-price`, `vickrey`, ...) puts one value in each slot.
- A coefficient design (`rank`, `rank-batched`) puts a bid in an exponent: `X^b`. A product of
  polynomials is a slot-wise product. The design reads coefficients.

This package keeps every value as its `N` slots. `Ring.toSlots` and `Ring.toCoefficients` move
between the two views. A test checks that the slot-wise product equals the polynomial product mod
`X^N + 1`.

The slot order here is not the slot order of fhe.rs. A design uses the order only to put values in
slots, so the order changes no result.

`Evaluator.mul` counts a ct×ct product, and adds 1 to the depth. `Evaluator.mulPlain` counts a ct×pt
product. Sums and differences are free. The depth that `run` returns is measured. The Rust crate
reports the formula of the design. The tests check that the two are equal.

## Worked example: `vickrey`

Three bidders bid 1, 4, and 2. There are 5 levels. We use the identity tie priority, so region `k`
belongs to bidder `k`. This is the setup of `../ENCODING.md`.

```sh
npx tsx src/cli.ts --design vickrey --bids 1,4,2 --levels 5 --seed 1 --tie-priority 0,1,2 --trace
```

The summary comes first:

```text
== vickrey ==
program      4 ct×ct, 9 ct×pt
public       winner 1, price 2
check        OK (expected winner 1, price 2)
```

The trace shows copy 0 of the slots. A `.` is 0. Each region has `B = 5` slots, one for each level.
This is the input of bidder 0 (bid 1). The thermometer `[b >= p]` is 1 at levels 0 and 1. It is the
same in every region, so it does not depend on the bidder index.

```text
  bidder 0, bid 1
   [b >= p]
    level p             0 1 2 3 4
    region 0 (bidder 0) 1 1 . . .
    region 1 (bidder 1) 1 1 . . .
    region 2 (bidder 2) 1 1 . . .
```

The program adds the thermometers of all bidders. This gives `c'[p]`, the number of bids at or above
level `p`. Then it computes `c'(c' - 1)`. This is 0 where one bid or none is at or above `p`. Thus
it is 0 above the second-highest bid, which is 2.

```text
  step: c' = #{j : b_j >= p}  (depth 0)
    level p             0 1 2 3 4
    region 0 (bidder 0) 3 3 2 1 1
    region 1 (bidder 1) 3 3 2 1 1
    region 2 (bidder 2) 3 3 2 1 1

  step: c'(c' - 1)  (depth 1)
    level p             0 1 2 3 4
    region 0 (bidder 0) 6 6 2 . .
    region 1 (bidder 1) 6 6 2 . .
    region 2 (bidder 2) 6 6 2 . .
```

The test `g` is 0 in region `k` at level `p` only when bidder `k` beats all other bidders at `p`.
Bidder 1 bid 4. Thus region 1 is 0 from level 2 up. The other regions are not 0 at level 2.

```text
  step: g = #{j ≠ k : b_j > p} + [b_k < p] + ties  (depth 1)
    level p             0 1 2 3 4
    region 0 (bidder 0) 2 2 2 2 1
    region 1 (bidder 1) 2 1 . . .
    region 2 (bidder 2) 2 1 1 2 1
```

The program multiplies `g`, `c'(c' - 1)`, and the sum of the masks `r`. The mask makes each non-zero
slot uniform. The output has this zero pattern:

```text
  step: output = g · c'(c' - 1) · r  (depth 3)
    level p                0    1    2    3    4
    region 0 (bidder 0) 7950 6160 1786    .    .
    region 1 (bidder 1) 2818 1905    .    .    .
    region 2 (bidder 2) 3106  382 2994    .    .
```

`decode` reads the pattern:

1. The price is the last level where a region is non-zero. This is level 2.
2. The winner is the one region that is 0 at that level. This is region 1, which is bidder 1.

The non-zero values change with the seed. The zero pattern does not.

## Cross-check against Rust

The Rust binary and this CLI must give the same public result and the same operation counts for the
same bids. The Rust binary prints timings, so the `sed` command removes them. Run both commands from
`examples/auction`. The seeds, and thus the masks and random tie priorities, differ between the two
programs. The result does not depend on them, if no two bids tie.

```sh
cd examples/auction
for design in vickrey vickrey-compact second-price rank; do
  echo "== Rust $design"
  cargo run --release --bin auction-designs -- --design $design --bids 1,4,2 --levels 5 --seed 1 \
    | grep -E '^(public|program)' | sed -E 's/, [0-9.]+(ms|µs|s)$//'
  echo "== TS $design"
  (cd ts && npx tsx src/cli.ts --design $design --bids 1,4,2 --levels 5 --seed 1 \
    | grep -E '^(public|program)')
done
```

Output of this command:

```text
== Rust vickrey
program      4 ct×ct, 9 ct×pt
public       winner 1, price 2
== TS vickrey
program      4 ct×ct, 9 ct×pt
public       winner 1, price 2
== Rust vickrey-compact
program      7 ct×ct, 12 ct×pt
public       winner 1, price 2
== TS vickrey-compact
program      7 ct×ct, 12 ct×pt
public       winner 1, price 2
== Rust second-price
program      10 ct×ct, 3 ct×pt
public       winner 1, price 2
== TS second-price
program      10 ct×ct, 3 ct×pt
public       winner 1, price 2
== Rust rank
program      6 ct×ct, 7 ct×pt
public       winner 1, price -
== TS rank
program      6 ct×ct, 7 ct×pt
public       winner 1, price -
```

To compare a tie, take the priority that the Rust binary draws, and give it to the TS CLI. Rust
draws the priority `[1, 3, 2, 0]` for this seed. The tied bidders are 0, 2, and 3. Bidder 2 has the
highest priority of the three.

```sh
cargo run --release --bin auction-designs -- --design vickrey-compact --bids 9,3,9,9 --levels 16 --seed 3 \
  | grep -E '^(public|ties)'
(cd ts && npx tsx src/cli.ts --design vickrey-compact --bids 9,3,9,9 --levels 16 --tie-priority 1,3,2,0 \
  | grep -E '^(public|ties)')
```

```text
public       winner 2, price 9
ties         random priority [1, 3, 2, 0] (higher wins a tie)
public       winner 2, price 9
ties         given priority [1, 3, 2, 0] (higher wins a tie)
```

To compare the costs of all designs, run the sweep in both programs. Rust prints a table with more
columns. The columns `depth`, `ct×ct`, and `ct×pt` are the same:

```sh
cargo run --release --bin auction-designs -- --sweep 2,3,4,5,8 --levels 8 --seed 3
(cd ts && npx tsx src/cli.ts --sweep 2,3,4,5,8 --levels 8 --seed 3)
```

`test/op-counts.test.ts` holds the Rust numbers of this sweep.

## What the tests check

| Test file                 | What it checks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test/designs.test.ts`    | Port of `tests/designs.rs`, and more. Each design reveals what its rule says, on fixed and random bid sets with ties and the bids 0 and `B - 1`.                                                                                                                                                                                                                                                                                                                                                        |
|                           | The output depends only on the public result: bid sets with the same result give the same zero pattern.                                                                                                                                                                                                                                                                                                                                                                                                 |
|                           | The `vickrey` tie priority: bids `[9, 3, 9, 9]` with priorities `[3, 0, 1, 2]`, `[0, 3, 2, 1]`, and `[1, 2, 0, 3]` give winners 0, 2, and 3.                                                                                                                                                                                                                                                                                                                                                            |
|                           | The claim checks of the blind designs and `vickrey` accept only the true result.                                                                                                                                                                                                                                                                                                                                                                                                                        |
|                           | Each design runs at its slot limit, and refuses one more level.                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `test/rl-designs.test.ts` | The `rl-` designs: the price, the tie set, and a winner from the set, on bid sets with ties and on tie sets across weight groups. The winner of a tie comes from the whole set. The lanes are 0 above the price and uniform below it. Bids with the same result and the same masks give the same readout. Copies fix the price when the pair mask is 0 in other copies, and a pair mask that is not equal in `y` and `z` gives a wrong result. The capacity limits: `n (n - 1) < t` and the slot limit. |
| `test/bid-slots.test.ts`  | Port of `tests/bid_slots.rs`. Each slot of a `vickrey` bid depends on its level only.                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `test/op-counts.test.ts`  | The counts and the depth equal the Rust numbers, for 2 to 8 bidders.                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `test/field.test.ts`      | Slots are the polynomial at the roots of `X^N + 1`. The slot-wise product is the polynomial product mod `X^N + 1`.                                                                                                                                                                                                                                                                                                                                                                                      |

All tests use a seeded generator (`seededRng`), so a run is repeatable. This generator is not a
secure generator.

## Differences from the Rust crate

- No keys, no encryption, and no noise. The program shows only the arithmetic.
- No parameter search. `run` refuses a depth that the demo profile cannot hold, with the same
  numbers as Rust.
- The random source is a seeded generator. The same seed gives other masks than Rust.
- The slot order differs. See "How the simulation works".
