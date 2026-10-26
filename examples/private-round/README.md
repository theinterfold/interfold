# Private round: a sealed OTC and strategic sale for up to 13 bidders

A creator sells a few lots of an ERC-20 token to up to 13 bidders. Each bidder wants one lot and
encrypts the highest price that it accepts. The committee decrypts one thing: **whether the reserve
was met, and at which price step the round clears**. It never decrypts a bid, a demand curve or a
count. If the reserve is not met, nothing about the bids becomes public.

This app is a variant of `examples/sealed-cca`. The sealed-cca sale reveals the whole demand curve.
This app reveals the clearing step only, and it needs **ciphertext multiplication** to do so (depth
3, at most 7 products). It uses the `insecure-simd` preset (parameter set 5: degree 128, plaintext
modulus 257, 128 SIMD slots). The parameters are insecure. They give no security.

## The round

| Value                 | Meaning                                                                                      |
| --------------------- | -------------------------------------------------------------------------------------------- |
| `lot`                 | The sale-token amount of one lot. Every bidder buys at most one lot.                         |
| `lots` (`K`)          | The lots for sale, 1 to 12. The creator deposits `K * lot` of the sale token.                |
| `prices`              | 2 to 16 price steps, strictly increasing. A step is a price per whole sale token.            |
| `reserveStep` (`rho`) | The lowest step at which the round can sell. Public.                                         |
| `minLots` (`m`)       | The fewest bidders at or above the reserve step for the round to go ahead, 1 to `K`. Public. |
| `escrow`              | What every bidder deposits once: the price of one lot at the highest step.                   |

A bid is a step `b` (0 to `levels - 1`). A bidder accepts every step up to `b`. With `c_l` the
number of counted bidders with `b >= l`, the round decides:

```text
gate        G   = [ c_rho >= m ]
lane l      A_l = [ c_l   >= K ]      for l = rho .. levels-1     (A_l never rises with l)

NOT_MET           G = 0                       everybody gets the escrow back
UNDERSUBSCRIBED   G = 1, A_rho = 0            every bidder at or above rho gets one lot at p[rho]
SOLD_OUT          A_rho = 1                   l* = max { l : A_l = 1 }; one lot at p[l*] for the bidders
                                              above l*, and for the first bidders at l* (by deposit order)
ABORTED           the output breaks a rule    handled like NOT_MET (full refund)
```

`l*` is the K-th price step: the highest step that `K` bidders still accept. At `l*` more than `K`
bidders may want a lot. The bidders strictly above `l*` get a lot. The lots that are left go to the
bidders **at** `l*`, in the order of their **bidder index** (the order of their deposits). A lot is
never split.

## How a bid works

1. The creator approves `K * lot` of the sale token and requests the E3 with the round parameters.
   `validate` pulls the supply and inserts the configuration as input 0.
2. A bidder calls `deposit` (or a relayer calls `depositFor` with an EIP-2612 permit) and gets the
   bidder index `i` (0 to 12). A 14th deposit reverts with `TooManyBidders`.
3. The bidder encrypts two ciphertexts under the committee key and proves them with **one** proof:
   - **role 0, the bid:** six copies of the thermometer `[l <= b]` (slots 0 to 95), six copies of
     the gate bit `[b >= rho]` (slots 96 to 101), and the version of the bid in the slot `115 + i`.
   - **role 1, the mask:** 128 slots that the bidder chooses uniformly in `0..256`. The proof does
     not constrain them.
4. `publishInput` verifies the proof and inserts **two** consecutive leaves with the same metadata
   (`bidder || uint40 version`). The contract, not the bidder, supplies `i`, the version, the round
   parameters and the committee key to the proof. A bidder cannot count in the slot of another
   bidder or bid outside the grid. A bidder can update a bid twice. A relayer can send a bid with
   the bidder's EIP-712 signature.

The program takes, for each bidder, the **latest bid whose two ciphertexts both open their
commitments** (`select_bids`, in `program/src/lib.rs`). A bidder with no such bid is dropped whole.

## The FHE program

Let `C` be the sum of the bid ciphertexts, `R` the sum of the mask ciphertexts, and `n` the number
of counted bidders. In a lane slot, `C` holds the count `c` of the lane. For each lane the program
computes `R * prod_j (c - z_j)`, where the `z_j` are the zeros of a polynomial that is zero on
exactly one side of the threshold `theta` (`theta = K` for a price lane, `theta = m` for the gate):

```text
direct       { 0, ..., theta-1 }    zero  <=>  c <  theta      theta factors
complement   { theta, ..., n }      zero  <=>  c >= theta      n+1-theta factors (none if theta > n)
```

The program takes the side with fewer factors. The side depends on `n` only, and `n` is public. A
lane with fewer factors than the widest repeats its first zero. One balanced product tree over the
factors and the mask has at most 8 leaves. That is **depth 3 and at most 7 ct x ct products**, all
relinearized with the threshold l-BFV key.

A lane where the test is false is a **uniform** value, because `R` is uniform and a nonzero factor
does not change that. A lane where the test is true is **zero**. After decryption a lane says "zero"
or "nonzero" and nothing else. A lane copy is zero by chance with probability 1/257. The decoder
reads a lane as zero only if all six copies are zero, so a wrong lane has probability
`257^-6 = 3.5e-15`.

The price lanes of the steps below `rho` are zeroed by the lane selector. They are always zero, so
they carry no information. If the reserve is not met, `c_l <= c_rho < m <= K` for every `l >= rho`,
so every price lane has a false test. The output of a failed round shows no step at all.

The output also copies the counted version of each bidder to the slot `115 + i`. The contract needs
it to know which bid counted.

### Why the cap is 13

The depth does not depend on the number of steps: the 16 steps are slot-parallel. It depends on the
factor count `D = min(theta, n + 1 - theta)` of the widest lane. The largest `D` over all `theta` is
`floor((n + 1) / 2)`. With `n <= 13` it is 7, so the tree has 7 factors and the mask: 8 leaves,
depth 3. With `n = 15` it is 8, so the tree has 9 leaves and depth 4. The slot layout (6 copies of
16 steps, 6 gate copies, 13 version slots) uses 115 + 13 = 128 slots. The cap is 13 bidders and 12
lots (`K <= n - 1`: a round with `K = 13` lots cannot sell out). The unit tests check the bound for
every `n`, `K` and `m` (`the_lane_polynomial_has_at_most_seven_factors_for_13_bidders`). [INFERENCE]
The factor bound also holds for `n = 14` (`D = 7`). The cap of 13 comes from the task, not from the
depth.

### Noise

`program/examples/noise.rs` builds a threshold l-BFV committee (one public-key share and one
relinearization-key share per party, as the committee does), runs the exact program (`evaluate`)
over rounds of bids and masks, and measures the noise of the output with the sum of the secret keys.
It also decodes the output and compares the outcome with the one on the plaintext bids. The sweep
covers every `K` and `m` at 13 bidders, and every `n` from 1 to 13 at `K = m = 7` (the worst case).

```sh
CARGO_TARGET_DIR=... cargo run --release -p e3-user-program --example noise -- --parties 3,9 --trials 10
```

Result (fhe.rs `375cfc6`, `insecure-simd`, `log2(q) = 168`, `log2(q/t) = 160`; 910 rounds per
committee size; 0 rounds decoded to a wrong outcome):

| `D` (factors) | Depth | 3 parties: max / mean (bits) | 9 parties: max / mean (bits) |
| ------------- | ----- | ---------------------------- | ---------------------------- |
| 0             | 0     | 32 / 31.6                    | 32 / 31.6                    |
| 1             | 1     | 68 / 67.2                    | 71 / 70.0                    |
| 2             | 2     | 82 / 81.0                    | 86 / 84.7                    |
| 3             | 2     | 82 / 81.6                    | 86 / 85.0                    |
| 4             | 3     | 97 / 95.4                    | 102 / 99.8                   |
| 5             | 3     | 97 / 95.5                    | 101 / 99.7                   |
| 6             | 3     | 97 / 95.7                    | 101 / 100.0                  |
| 7             | 3     | 97 / 96.0                    | 101 / 100.3                  |

At 13 bidders the noise is **97 bits with 3 parties and 102 bits with 9 parties**. Decryption needs
the noise plus the smudging noise to stay below `q/(2t)` (159 bits). The smudging bound of the
preset is `INSECURE_SIMD_E_SM_BOUND`, about `2^142`. The margin is 17 bits or more.

## Clearing and claims

`clear(e3Id)` reads the published plaintext, applies the rules of `RoundOutput` and stores the
outcome. Anyone can call it. An output that breaks a rule clears as `ABORTED`, which refunds
everybody. After `clear`, three windows run:

| Window  | Length  | What happens                                                                                                   |
| ------- | ------- | -------------------------------------------------------------------------------------------------------------- |
| Phase 1 | 2 days  | Bidders **above** `l*` claim their lot. Everybody can claim a refund without a proof if the round was not met. |
| Phase 2 | 2 days  | Bidders **at** `l*` register. Phase 2 starts when phase 1 ends.                                                |
| Claim   | 30 days | Everyone else claims. After this window the creator can `sweep` what is left.                                  |

A claim needs a small proof (`private_round_claim`) of how the private bid `b` compares with the
claim step `k`: `cmp = 0` if `b < k`, `1` if `b = k`, `2` if `b > k`. `k` is `l*` when sold out and
`rho - 1` when undersubscribed (with `rho = 0` nobody needs a proof).
`claimRequirement(e3Id, bidder)` returns `(proofNeeded, k)`.

- **Sold out, `cmp = 2` (above):** claims in phase 1. Gets one lot at `p[l*]` and the rest of the
  escrow.
- **Sold out, `cmp = 1` (at `l*`):** calls `claim` in phase 2 to register. After phase 2,
  `settleMarginal` gives the first `R = K - aboveClaimed` registered bidders, by bidder index, one
  lot. The other registered bidders get the whole escrow back. A registered bidder with a lower
  index than another always has priority. A bidder at `l*` that does not register forfeits the lot
  (the lot goes to the next registered bidder) and can still claim a refund after phase 2.
- **Sold out, `cmp = 0` (below):** claims the refund at any time.
- **Undersubscribed:** every bidder at or above `rho` (`cmp = 2` against `rho - 1`) gets one lot at
  `p[rho]`.
- **Not met, aborted:** every bidder claims the whole escrow back with no proof.

The creator calls `withdrawProceeds` (the payments of the claimed lots), `withdrawSupply` (the whole
supply, only when the round was not met or aborted) and `sweep` (after the claim window: the unsold
supply and the unclaimed escrows). If the E3 failed, `refundEscrow` and `refundSupply` return the
funds.

## What stays hidden and what is public

**Public, for everyone:** the round parameters; who deposited, in which order; who bid and how many
times (the contract logs every bid); which bidders the program **counted**, and the version of the
counted bid (`n` is public); whether the reserve was met; and `l*` when the round sells out.

**Not public, for anyone:** every bid; the demand `c_l` at any step; the number of bidders at or
above any step. The outcome says only this much: a sold-out round at `l*` means that at least `K`
bidders accept `l*` and fewer than `K` accept `l* + 1`. An undersubscribed round means
`m <= c_rho < K`. A round that was not met means `c_rho < m`.

**A failed round leaks nothing else.** With `G = 0` all price lanes decode as "test false". The only
fact that becomes public is `c_rho < m`. A bidder gets the escrow back without a proof, so it never
reveals its class.

**What the claims reveal.** A claim proof reveals the comparison `cmp` of the bidder with `k`. After
the claims, the public knows which bidders were above, at, or below `l*` (sold out) or at or above
`rho` (undersubscribed). A bidder that proves `cmp = 1` reveals that its bid is exactly `l*`. A
bidder that is below `l*` reveals "below" when it claims its refund. This is the price of per-bidder
escrow and private claims. The claim does not reveal `b`, only the class. A bidder can keep its
class private only by not claiming, which forfeits its lot or its refund until the claim window
ends. The research note `mult-private-outcomes.md` (not in this tree) sketches claims that a
verifier cannot link to a bidder (`unl_cmp`, 789 gates). It is not built here.

| Party               | Learns                                                                                        |
| ------------------- | --------------------------------------------------------------------------------------------- |
| Public              | The public facts above. After the claims, the class of each bidder that claimed.              |
| A bidder            | The same, plus its own bid. It learns nothing about another bid.                              |
| The creator         | The same as the public, plus the proceeds. It does not learn any bid.                         |
| The relayer, server | The ciphertexts and the proofs. They are encrypted. The relayer sees who bids and when.       |
| The committee       | The threshold key. A quorum could decrypt any bid: this is the trust assumption of Interfold. |

**One honest bidder (mask assumption).** The sum of the masks `R` hides the counts only if at least
one counted bidder chooses its mask uniformly and keeps it secret. A bidder that is alone (`n = 1`)
knows `R`, so it can learn its own count, which is its own bid. If all bidders collude and share
their masks they can decode the lane values, so they learn the count at every step. That reveals
nothing that they did not already know, because they are the bidders. The proof does not constrain
the mask. A malicious bidder can publish a zero mask. That only removes its own contribution. The
probability that two copies of a mask slot collide is irrelevant: each of the 128 mask slots is
independent.

## What is proven

- **Bid proof (`private_round_bid`, one EVM proof, 1,427,418 gates, below the 2^21 browser limit):**
  both ciphertexts are valid encryptions under the committee key, the bid plaintext has the layout
  above for a step `b < levels`, the reserve step and index and version are in range, and
  `bid_commitment` opens to `(b, salt, bidder, e3Id)`. Details: `circuits/PUBLIC_INPUTS.md`. The
  proof is 10,688 bytes with 11 public inputs. One bid takes about 265 s in Node on an M3 Pro (the
  bid encryption proof about 145 s, the mask encryption proof about 96 s, the EVM proof about 24 s,
  measured while other jobs ran). Each extra ciphertext per input adds a full encryption proof, so a
  bid has exactly two.
- **Claim proof (`private_round_claim`, 2,928 gates):** `bid_commitment` opens to `b`, and `cmp` is
  the comparison of `b` with `k`. 7,232 bytes, 5 public inputs, 0.1 s.
- **Compute proof:** a mock on the local chain and on Sepolia (`TEMPLATE_UNPROVED_TEST`).

## Contracts

| Contract                          | Role                                                                           |
| --------------------------------- | ------------------------------------------------------------------------------ |
| `PrivateRoundProgram`             | The E3 program: round, deposits, bids, clearing, claims, withdrawals.          |
| `libraries/RoundConfig`           | Decodes and checks the request parameters (external library).                  |
| `libraries/RoundOutput`           | Reads the decrypted output and applies the validity rules (external library).  |
| `libraries/RoundClearing`         | The settlement arithmetic.                                                     |
| `libraries/SlotCodec`             | Decodes the published coefficients into SIMD slots.                            |
| `gates/MerkleAllowlistGate`       | An example `IBidderGate`: an allowlist.                                        |
| `verifiers/PrivateRound*Verifier` | The generated Honk verifiers of the bid and claim circuits.                    |
| `mocks/*`                         | The demo tokens (anyone can `mint`), a mock bid verifier and the test harness. |

`PrivateRoundProgram` is 24,558 bytes. The limit is 24,576. Only 18 bytes are free, so any addition
needs more logic in the external libraries. `clear()` costs 1,962,015 gas in the worst case that the
tests build (13 bidders, 39 bids, 16 steps, sold out).

Events: `SaleCreated`, `Deposited`, `BidSubmitted(.., firstLeaf)`,
`SaleCleared(e3Id, outcome, step, pStar, counted)`,
`ClaimWindowOpened(e3Id, phase1End, phase2End, claimDeadline)`, `Claimed`, `MarginalRegistered`,
`ProceedsWithdrawn`, `SupplyWithdrawn`, `Swept`, `EscrowRefunded`, `SupplyRefunded`.

Views: `sale(e3Id)`, `salePrices`, `deposited`, `bidderIndex`, `bidCount`, `clearing(e3Id)`,
`countedVersion`, `claimRequirement`, `previewClaim`, `claimed`, `marginalMask`,
`proceedsAvailable`, `swept`, `supplyReturned`.

## Prerequisites

- Rust, Node, pnpm, `nargo` 1.0.0-rc.3, `bb` 6.0.0 and Foundry (`anvil`).
- An `interfold` CLI built from this checkout. Its `bb` version must be 6.0.0
  (`crates/zk/prover/versions.json`). An older CLI installs `bb` 5.2.0 and the ciphernodes cannot
  prove with the v6 circuits.

## Run it

Run these commands in this order, in the repository root unless it says otherwise.

1. Build the protocol circuits for the insecure SIMD preset:

   ```sh
   pnpm build:circuits --preset insecure-simd --committee minimum
   ```

2. Build the SDK of the repository (`pnpm sdk:build`). It bundles the user-data encryption circuits.
3. Build the CLI from this checkout and put it first in `PATH`:

   ```sh
   cargo build --release -p e3-cli
   export PATH="$PWD/target/release:$PATH"
   ```

4. In `examples/private-round`: set up and start the stack. `pnpm dev:setup` compiles the two
   circuits (`circuits/compile.sh`), writes the two verifiers and `circuits/target/vk_anchor.json`,
   and runs `interfold noir setup`.

   ```sh
   pnpm install
   pnpm dev:setup
   pnpm dev:all
   ```

   If `interfold noir setup` fails with `checksum missing for circuits-<version>.tar.gz`, pack the
   build of this repository:

   ```sh
   STAGE=$(mktemp -d) && mkdir -p "$STAGE/circuits/insecure-simd"
   cp -R ../../dist/circuits/insecure-simd/minimum "$STAGE/circuits/insecure-simd/"
   jq '.files |= with_entries(select(.key | startswith("insecure-simd/minimum/")))' \
     ../../dist/circuits/checksums.json > "$STAGE/circuits/checksums.json"
   COPYFILE_DISABLE=1 tar --no-xattrs -C "$STAGE" -czf /tmp/prd-circuits.tar.gz circuits
   interfold noir setup --circuits-archive /tmp/prd-circuits.tar.gz \
     --circuits-configuration insecure-simd/minimum --allow-unpinned-archive
   ```

`pnpm dev:all` deploys the contracts with `scripts/deploy-local.ts`, starts anvil, five ciphernodes,
the program server and runner (`program/`, `runner/`), the coordination server and the web app
(<http://localhost:3000>). The web app has these pages: the list of rounds, **Create** (token, lot,
number of lots, price grid, reserve step, minimum raise), the round page (status, deposit, bid), the
results page (what is public, your outcome, **Claim** or **Register** and **Settle**, with an
in-browser claim proof) and the creator panel. The **Mint test tokens** button mints the demo
tokens. Do not use the anvil accounts 1 to 5 (ciphernodes) or 9 (the relayer of the server).

## The FHE program, the server and the runner

The program (`program/`, `runner/`, `guest/`) reads input 0, the configuration
`"interfold-private-round-config-v1" || uint8 levels || uint8 reserveStep || uint8 lots || uint8 minLots`.
`validate` inserts its leaf. The metadata of a bid leaf is `bidder || uint40 version` (25 bytes).
The slot layout lives in `program/src/lib.rs` (`layout`), `sdk/src/layout.ts` and the Solidity
library `RoundOutput`. The vectors `sdk/test-vectors/layout.json` (written by the Rust program) and
`slots.json` (the fhe.rs decoder) pin them to each other.

The server (`server/`) watches the committee key, schedules the compute at the end of the input
window, reads the inputs from the chain (two leaves per bid, from `BidSubmitted.firstLeaf`), calls
the runner, and publishes the output. It does not decode the plaintext: anyone calls `clear(e3Id)`.
Its routes are the ones of `examples/sealed-cca` (`POST /relay`, `POST /relay/deposit`,
`GET /health`).

## Test

```sh
pnpm test                # Hardhat: contracts, clearing, decoder, generated verifiers (110 tests)
pnpm test:server         # vitest: the server and the SDK
pnpm test:integration    # the full local stack, all three scenarios
cargo test -p e3-user-program --release                              # the FHE program (29 tests)
cargo run --release -p e3-user-program --example noise               # the noise sweep
cargo run --release -p e3-user-program --example layout_vectors      # writes sdk/test-vectors/layout.json
```

The integration test (`tests/integration.spec.ts`) selects its scenarios with `ROUND_SCENARIO`
(`sold_out`, `undersubscribed`, `not_met`, `all`), the bidders with `ROUND_BIDDERS`, and the number
of bid proofs in parallel with `ROUND_PROOF_CONCURRENCY`.

## Local end-to-end run: status

**The end-to-end smoke run (several bidders, reserve met and not met, clearing, claims) did NOT
complete on this branch.** The stack stopped before the first E3, so there is no recorded output of
a full round. These are the exact commands and what happened:

```sh
# CLI built from this checkout (bb target 6.0.0): cargo build --release -p e3-cli  (7 min 56 s)
export PATH=/tmp/prd-cli/bin:$PATH
cd examples/private-round
interfold noir setup --circuits-archive /tmp/prd-circuits.tar.gz \
  --circuits-configuration insecure-simd/minimum --allow-unpinned-archive   # bb 6.0.0, circuits 0.20.0-dev.2
ROUND_SCENARIO=all ROUND_PROOF_CONCURRENCY=3 ./scripts/test_integration.sh
```

The script stops in `deploy-local.ts` with
`BFV_PARAM_SET=5 does not match the active circuit artifacts (parameter set 0)`. The checked-in
`ACTIVE_BFV_PARAM_SET` of `packages/interfold-contracts/scripts/utils.ts` is 0 (`insecure-64`). The
build step `pnpm build:circuits --preset insecure-simd --committee minimum` patches it to 5 (and
`ActiveCryptoConfig.sol`) and rebuilds `packages/interfold-contracts/dist`. The author of this
branch did not run that build, because a shared machine ran other large circuit builds. Run it as
step 1 of "Run it" and then run `pnpm test:integration`.

What was run and passed on this branch instead:

- `cargo test -p e3-user-program --release --lib`: 29 tests (the FHE program on real l-BFV
  ciphertexts with 1, 3 and 9 parties, the decoder, the input policy).
- the noise sweep (above), 910 rounds per committee size, 0 wrong outcomes.
- `pnpm test` (Hardhat): 110 tests, with the generated verifiers accepting real bid and claim
  proofs.
- `vitest run ./server sdk/src/layout sdk/src/clearing`: 169 tests, including the layout vectors
  that the Rust program wrote.
- A real bid proof (two ciphertexts, one EVM proof, 265 s) and three real claim proofs, verified by
  the generated Solidity verifiers (`sdk/test-vectors/proofs.json`).
- `tests/integration.spec.ts` (three scenarios: `sold_out` with 5 bidders, `undersubscribed` with 3,
  `not_met` with 3) type-checks. It has not run.

## Layout

| Path                                   | What it holds                                                                |
| -------------------------------------- | ---------------------------------------------------------------------------- |
| `contracts/`                           | The program, the libraries, the gate, the generated verifiers and the mocks. |
| `test/`                                | The Hardhat tests.                                                           |
| `deploy/default.ts`                    | `deployTemplate`: the deploy of the program and what it needs.               |
| `circuits/`                            | The Noir circuits (bid, claim), `PUBLIC_INPUTS.md` and the tooling.          |
| `sdk/`                                 | `@interfold/private-round`: layout, provers, clearing mirror, test vectors.  |
| `program/`, `runner/`, `guest/`, `da/` | The FHE program, its runner, the OpenVM guest and the Avail helper.          |
| `server/`                              | The coordination server and the relayer.                                     |
| `client/`                              | The web app.                                                                 |
| `scripts/`, `tests/`                   | The local scripts and the integration test.                                  |

## Limits

- The parameters are insecure (N = 128, t = 257). They give no security.
- A round has at most 13 bidders and 12 lots. Each bidder wants exactly one lot of the same size.
- A bidder bids at most 3 times. The escrow is the same for every bidder.
- The claim reveals the class of the bidder (above, at or below the clearing step).
- The mask must come from at least one honest bidder. The proof does not enforce it.
- The marginal fill order is the deposit order, which is public. A bidder at the clearing step can
  see its rank only after the other bidders register.
- A bidder has 30 days after `clear` to claim. After that, the creator can sweep what is left.
- The sale and payment tokens must be standard ERC-20 tokens. Do not use fee-on-transfer or rebasing
  tokens.
- The compute proof is a mock on the local chain and on Sepolia.
- `PrivateRoundProgram` is 18 bytes below the contract size limit.
