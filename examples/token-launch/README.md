# Token launch: a public sale with sealed bids

A creator sells a fixed supply of a token. Each bidder sends **one bid** with a **private budget** `B`
and a **private maximum price** `b`. This is the bid shape of the Uniswap CCA. The sale clears at
**one uniform price**. The chain never sees a bid in the clear, and the committee never decrypts the
full demand curve. After the clearing, bidders **claim to a fresh address**. Nobody can link a claim to
the bid that paid for it, except in one case that this README names ("Marginal bids").

The app is a full example, like `examples/sealed-cca`: contracts, Noir circuits, an FHE program, a
runner, a server and relayer, a web app, an SDK and a local run. It uses the `insecure-simd` preset
(parameter set 5, degree 128, `t = 257`, 128 SIMD slots). **The parameters give no security.** Read
"Limits".

**Status:** the circuits, the contracts, the program, the server and the web app are built and have
unit tests. The full local run was **not yet run end to end**. See "Local smoke run".

What is new compared with `examples/sealed-cca`:

| Topic          | `sealed-cca`                           | `token-launch`                                                                |
| -------------- | -------------------------------------- | ----------------------------------------------------------------------------- |
| Bid            | a price step and a fixed escrow        | a private budget `B` and a private price step `b`                             |
| Revealed data  | the demand curve (counts per step)     | 6 or 7 budget sums, found by a 2-round probe search (a full curve has 15)     |
| FHE            | one ciphertext per bid                 | two ciphertexts per bid (one per round), one proof, additions only            |
| Claim          | the claim is public per bid            | a ZK proof of a Merkle membership and a nullifier. The recipient is fresh.    |
| Tie at the end | pro rata                               | **first bid wins**, in the order of the bids                                  |

## Contents

- [The sale](#the-sale)
- [How a bid works](#how-a-bid-works)
- [Two rounds: the probe search](#two-rounds-the-probe-search)
- [Clearing](#clearing)
- [Claims](#claims)
- [What each party learns](#what-each-party-learns)
- [What is proven](#what-is-proven)
- [Contracts](#contracts)
- [Prerequisites](#prerequisites)
- [Run it](#run-it)
- [Local smoke run (not yet run end to end)](#local-smoke-run-not-yet-run-end-to-end)
- [Test](#test)
- [Layout](#layout)
- [Limits](#limits)
- [Open decisions](#open-decisions)

## The sale

The creator sets these values at creation:

- The sale token, the supply `S` and the payment token. The creator approves `S` first. The program pulls it.
- `levels` (8 to 16) and a strictly increasing list of prices `p[0..levels)`. The prices are
  payment-token base units for one whole sale token. A bid names a **price step** `b < levels`. The
  bid accepts every price up to `p[b]`.
- `budgetUnit`: the size of one budget unit in payment-token base units. A budget is an integer
  `1 <= B <= 4095` units.
- Up to 4 **escrow tiers** `X` (in budget units, ascending, at most 4095). A bidder escrows the
  public amount `X * budgetUnit` and keeps the real budget `B <= X` private. A tier is the public
  upper bound of the budget. The claim refunds `X*budgetUnit - paid`.
- A title and the input window.

A sale is **two E3 computations**. The creator sends two `Interfold.request` transactions in the same
block window. The first one is round 1. Its E3 id is the **sale id**. The second one is round 2 and it
links to the sale id. Both committees publish a key before the window ends. See
[Two rounds](#two-rounds-the-probe-search).

## How a bid works

The bidder holds a bid secret `(b, B, X, salt)`. The browser makes **one plaintext** and encrypts it
**twice** (once under the key of each round). The two encryptions use independent randomness. One
ZK proof covers both ciphertexts.

### The plaintext (Design A, digit lanes)

The program can only add. So the bid is a *thermometer*: for every price step `l <= b` the plaintext
holds the digits of the budget. The budget `B` has 6 digits in base 4 (`B = sum d_j 4^j`, `0 <= d_j <= 3`).

```text
slot (l*6 + j)     = d_j(B)          if l <= b, else 0     (l = 0..15, j = 0..5)   96 slots
slot (96 + i/8)    = 2^(i mod 8)                            (i = the bid index)     11 slots
every other slot   = 0                                      (slots 107..127)
```

A sum over `n <= 85` bids has digit cells `<= 85 * 3 = 255 < t = 257`. So the cell
`c(l, j) = sum_i d_j(B_i) [b_i >= l]` does not wrap, and `F_l = sum_j 4^j c(l, j)` is the **exact sum
of the budgets of all bids with step `>= l`**. The flag cells add up to a bitmap of the bids that are
counted. A flag cell holds 8 bits, so it is at most 255.

### One proof, two ciphertexts

`token_launch_bid` proves in zero knowledge that both ciphertexts encrypt the same plaintext of the
shape above, for private `(b, B, salt)` and public `(levels, index, X)`. It checks the two user-data
encryption proof trees with `verify_honk_proof_non_zk` (the same wrapper as `examples/auction-e2e`). The
public commitment is `Poseidon2(domain, b, B, X, salt, bidder, saleId)`. The contract stores it in a
claim tree.

### Send a bid

`publishInput(saleId, abi.encode(BidInput))` runs on the sale id. It stores the first ciphertext in the
input tree of round 1, the second one in the input tree of round 2, and the commitment in the claim
tree (depth 7). The bidder pays `X * budgetUnit` payment tokens. The input can be a direct call, or
a relayed call with an EIP-712 signature and an EIP-2612 permit (`POST /relay`).

One bid per address. At most 85 bids.

### The program: which bids count

The FHE program (`program/`) takes input 0 (the configuration) and every bid that opens its
commitment. It adds the ciphertexts and then multiplies the sum by a **keep mask** (a plaintext with a
0 or a 1 in each slot). The mask keeps only the probe levels and all flag cells. The committee
decrypts only this masked sum.

## Two rounds: the probe search

The contract needs only the **clearing step**, not the full curve. A step `m` is *over-demanded* when
`F_m * budgetUnit * 10^decimals > p[m-1] * S`. For a valid output, `A(m)` is monotone, so a search finds
the step. The search is 4-ary and runs in 2 rounds (for 16 levels):

1. **Round 1.** The mask keeps the levels `P1 = {4, 8, 12}`. The contract reads `F_4, F_8, F_12` and
   sets the bracket `(lo, hi)` around the clearing step.
2. `publishProbes(saleId)` replaces input 0 of round 2 with a configuration that lists the interior
   of the bracket, `P2 = {lo+1 .. hi-1}` (and level 0 when `lo = 0`).
3. **Round 2.** The mask keeps `P2` and the flags. The contract reads the 3 sums (4 with level 0) and
   finds the exact step.
4. The counted bitmaps of the two rounds must be equal. If they are not, the sale **aborts**.

The program for round 2 reads its configuration from input 0. The compute proof binds that input
through the input root. The contract rejects a non-monotone or invalid output with `SaleAborted` and
does not revert, so a bad output cannot freeze funds. The creator receives the escrow of bids that
count in only one round. Everyone else uses `refundEscrow`.

The two keys are known before the first bid. So the bidder never waits for round 1.

## Clearing

All amounts are in payment-token base units. `U = 10^saleDecimals`. Divisions round down, except where
`ceil` is written.

- **Capped at step `s`** (demand at `p[s]` is at least the supply):
  - `pStar = p[s]`. Bids above `s` win in full: `tokens = floor(B*unit*U / pStar)`.
  - Bids below `s` lose.
  - Bids **at** `s` share `R = S - floor(above*U/pStar)` **by the order of the bids**: **the first bid
    wins**. An earlier bid takes `min(full, remaining)`. The first bid that does not fit gets the
    remainder. Later bids get `0` and a full refund.
- **Uncapped at step `l`** (the supply is not sold at `p[l]`, but it is sold at lower prices):
  `pStar = ceil(F_l*unit*U / S)`. Every bid with `b >= l` wins in full at this single price.
- **Undersubscribed**: nobody reaches the supply at `p[0]`. `pStar = p[0]`. Every counted bid wins in full.

Every winner pays `ceil(tokens * pStar / U)`, which is at most `B*unit`. The refund is
`X*unit - paid`. These properties hold in the code and in 300 random sales of the tests: the total
tokens are at most `S`, nobody pays more than the budget, there is one price, nobody pays more than
the own maximum price, and every step above the clearing step wins.

## Claims

After `clear`, a bidder claims with a **ZK proof** `token_launch_claim`. The claim proves a
membership in the claim tree and a nullifier. It does not reveal the bid index.

Public inputs: `[root, counted_mask, sale_id, k, nullifier, recipient, escrow_units, budget_units,
reveal_index, cmp, index_plus_one]`. The circuit compares the private step `b` with the public clearing
step `k`: `cmp = 2` (above), `1` (equal) or `0` (below). The claim reveals the tier `X`, the class
`cmp` and (for a winner) the budget `B`. The contract computes `(tokens, paid, refund)` from these
values and sends them to `recipient`. `recipient` is a **fresh address**, and the server **relays the
claim** (`POST /relay/claim`), so the fresh address needs no gas.

The nullifier is `Poseidon2(domain, salt, saleId)`. It makes a claim a single use.

### Marginal bids (the one linkable claim)

The contract cannot order the bids at the clearing step without their positions. So a bid at the
clearing step (`cmp = 1` in a capped sale) uses two steps:

1. **Register.** In the first 3 days after `clear` (`MARGINAL_WINDOW`), the proof reveals the bid
   **index**, the budget and the recipient (`reveal_index = 1`). This **links the bid to its depositor
   address**. The contract stores the registration and pays nothing yet.
2. **Pay.** After the window, anyone calls `payMarginal(saleId, index)` (the keeper does it). The
   contract fills the registered bids in the order of the index. A bid that did not register in time
   still claims: it gets a refund only, and it forfeits the fill (`reveal_index = 0`).

Claims above or below the clearing step are immediate and unlinkable. A bid that was not counted
(the bytes did not open the commitment) uses `refundDropped(saleId, index)` by address.

## What each party learns

| Who                       | Learns                                                                                                                         |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Everyone (the chain)      | The sale parameters. Each deposit: address, **tier**, index, the two ciphertexts, the commitment. The counted set (a bitmap).  |
| Everyone, after round 1   | `F` at the 3 levels `{4, 8, 12}`.                                                                                               |
| Everyone, after round 2   | `F` at 3 more levels in the bracket (4 with level 0). That is 6 or 7 sums in all. The price, the step, the total sold.          |
| Everyone, per claim       | A nullifier, a fresh recipient, the tier `X`, the class `cmp`, and `B` for a winner. **Not** the bid index (except a marginal registration) and not the depositor. |
| A marginal registrant     | The bid index, so the depositor address, the budget and the recipient are public.                                              |
| The committee             | Only the two masked sums. A committee threshold decrypts one ciphertext per E3 and sees nothing else. (A colluding threshold can decrypt any single bid: this is the standard assumption of the platform.) |
| The creator               | The same as everyone. The creator does not learn who claimed what.                                                             |
| The relayer               | The claim payload (the same data as the chain) and the network address of the caller. Use your own gas to hide the network address. |
| Hidden until the claim    | Each `(b, B)`. A loser never reveals `B` or `b`. A winner reveals `B`, and the step only as the class (above, or equal).       |

**Anonymity set.** A claim is hidden in the set of counted bidders with the same tier and class. A
small tier or class gives a small set. The tiers are a product choice: few tiers give larger sets.

### Information against the full curve (estimate)

A sealed bid auction that reveals the full curve gives the 15 sums `F_1 .. F_15`. This design gives
6 or 7. `scripts/leak_entropy.py` estimates the entropy of the revealed sums with a Gaussian
approximation: `n` iid bids, the step a rounded normal (median 8, sigma 3), the budget lognormal
(median 100 units, sigma 1). The resolution is 1 budget unit. This is a **model estimate**, not a
measurement. The ratio is the useful number.

| `n` bidders | Full curve (15 sums) | Round 1 only (3 sums) | Probe search (6 or 7 sums)          | Hidden vs the full curve |
| ----------- | -------------------- | --------------------- | ------------------------------------ | ------------------------ |
| 85          | 167 bits             | 37 bits               | 68 to 71 bits (41 to 43 % of full)   | 96 to 99 bits            |
| 30          | 156 bits             | 35 bits               | 64 to 67 bits (41 to 43 % of full)   | 89 to 92 bits            |

So the probe search reveals a little less than half of the information of the full curve. It reveals
exactly the data that the clearing needs (`F` at the clearing step and the next step) and some
neighbours. Run `python3 scripts/leak_entropy.py` to reproduce it.

## What is proven

| Circuit              | What it proves                                                                                                                | Gates       |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `token_launch_bid`   | Two ciphertexts encrypt the same bid plaintext. Digits, `1 <= B <= X <= 4095`, `b < levels`, `index < 85`, the commitment.   | 1,432,756   |
| `token_launch_claim` | The commitment opens, the membership in the claim tree (depth 7), the counted bit, the nullifier, `cmp`, the index rule.     | 17,206      |

Both are below the browser limit of about `2^21 = 2,097,152` gates. The public inputs are in
`circuits/PUBLIC_INPUTS.md`. `circuits/compile.sh` builds the circuits, writes `vk_anchor.json` and
generates the two Solidity verifiers. The verifiers cost about 3.04 M gas (bid) and 2.60 M gas (claim).
The Node proving time of one bid was about 6.4 minutes on a busy machine (two encryption proof trees of
about 115 s, and the bid proof of about 155 s). A claim proof takes under a second.

## Contracts

| Contract / library    | Role                                                                                                              |
| --------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `TokenLaunchProgram`  | The E3 program of both rounds, the sale, the bids, the claims, the creator functions. 22,875 bytes (the limit is 24,576). |
| `SaleConfig`          | Decodes and validates the creation parameters.                                                                    |
| `SaleOutput`          | Decodes the plaintext of an E3 into the cells and flags. It rejects any impossible value.                         |
| `ProbeSearch`         | The 2-round search (spec in `sdk/src/probes.ts`).                                                                 |
| `SaleClearing`        | The clearing and the amounts of a claim (`sdk/src/clearing.ts` mirrors it).                                       |
| `Settlement`          | The movement of funds. `IncrementalTree` is the claim tree (Poseidon, zk-kit `InternalLazyIMT`).                  |
| `TokenLaunchBidVerifier`, `TokenLaunchClaimVerifier` | Generated Honk verifiers.                                                       |

The public surface is `contracts/interfaces/ITokenLaunch.sol`. The main calls are `publishInput`,
`publishProbes`, `clear`, `claim`, `payMarginal`, `refundDropped`, `refundEscrow`, `refundSupply`,
`withdrawProceeds`, `withdrawUnsold`, `withdrawForfeited` and `sweep`. After `claimDeadline`
(30 days after `clear`), the creator sweeps what is left.

Gas (mock verifiers in the Hardhat test; add the real verifier cost):

| Call                              | Gas       |
| --------------------------------- | --------- |
| `publishInput` (3 tree inserts)   | 521,925   |
| `publishProbes`                   | 760,955   |
| `clear`                           | 878,171   |
| `claim` (immediate)               | 229,799   |
| `claim` (marginal registration)   | 102,204   |
| `payMarginal` (last of 4)         | 140,849   |

A bid costs about 3.56 M gas with the real verifier. A claim costs about 2.83 M gas.

## Prerequisites

- Rust, Node, pnpm, `nargo` 1.0.0-rc.3, `bb` 6.0.0 and Foundry (`anvil`).
- An `interfold` CLI built from this checkout (release build of `e3-cli`). The CLI must match
  `bb` 6.0.0.
- The built circuits of the protocol for the insecure SIMD preset, and a built SDK. See the steps below.

## Run it

Run these commands in this order, from the repository root unless a step says otherwise.

1. Build the Noir circuits of the protocol for the insecure SIMD preset. This also switches the
   generated protocol configuration to the preset. **Do not commit the files that it changes**
   (`circuits/lib/src/configs/*`, `packages/interfold-contracts/scripts/utils.ts`,
   `packages/interfold-contracts/contracts/lib/ActiveCryptoConfig.sol`).

   ```sh
   pnpm build:circuits --preset insecure-simd --committee minimum
   pnpm -C packages/interfold-contracts build
   ```

2. Build the SDK of the repository (`pnpm sdk:build`). It bundles the user-data encryption circuits.

3. Set up the example. It compiles the two circuits and writes the two verifiers and
   `circuits/target/vk_anchor.json`:

   ```sh
   cd examples/token-launch
   pnpm install
   pnpm dev:setup
   ```

   If `interfold noir setup` fails with `checksum missing`, pack the build of this repository. The
   steps are in `examples/auction-e2e/README.md` (`--circuits-archive`, `--circuits-configuration
   insecure-simd/minimum`, `--allow-unpinned-archive`).

4. Start the stack: anvil, the ciphernodes, the program server, the program runner and the web app:

   ```sh
   pnpm dev:all
   ```

`pnpm dev:all` deploys the contracts with `scripts/deploy-local.ts` (`deploy/default.ts`). The deploy
records `TokenLaunchProgram`, the two verifiers, the eight libraries, `MockSaleToken` (18 decimals) and
`MockPaymentToken` (6 decimals, with EIP-2612) in `deployed_contracts.json`.

The web app (<http://localhost:3000>) has these pages: the list of sales, **Create** (token, supply, a
price grid, `budgetUnit`, tiers, window; it sends the two requests), the sale page (the timeline
Bidding, Round 1, Probing, Round 2, Cleared; the bid panel with a budget, a tier and a maximum price;
the partial curve with the revealed sums; the claim panel with a fresh recipient; the creator panel),
and **About**. The **Mint test tokens** button mints the demo tokens. Use the anvil keys 6 to 8 for
bidders. Accounts 1 to 5 are the ciphernodes and account 9 is the relayer.

## The FHE program, the server and the runner

`program/src/lib.rs` is the only source of the layout (`layout` module). It holds the constants, the
bid slots, the keep mask and the output decoder. The TypeScript mirror is `sdk/src/layout.ts`. Tests
compare both with `sdk/test-vectors/layout.json` and `slots.json`.

Input 0 of each E3 is the configuration `"interfold-token-launch-config-v1" || uint8 role || uint8 levels
|| uint16 probeMask`. The metadata of a bid leaf is `bidder || uint40 index`. A sale with no counted bid
has no output: the E3 times out and `refundEscrow` and `refundSupply` return the funds.

The server (`server/`) schedules the compute of round 1 at the end of the input window, and the compute
of round 2 only after `ProbesPublished`. It reads the inputs from the chain logs and calls the runner.
A **keeper** inside the server sends `publishProbes`, `clear` and `payMarginal` (they are
permissionless and idempotent). It keeps no state: it reads the chain.

Routes: `GET /health`, `POST /callback/:e3Id/:token` (runner), `GET /availability/objects/:hash`
(mock data availability), `POST /relay { e3Id, data }` (a bid) and `POST /relay/claim { saleId, data }`
(a claim). The relay routes simulate first and answer `{ txHash }` or `{ error }`. On the local chain
the relayer is anvil account 9 (`RELAYER_PRIVATE_KEY` elsewhere). See `server/.env.example`.

## Local smoke run (not yet run end to end)

**Status: the full local run is not complete.** On the main agent's decision the end-to-end run was
stopped before the clearing step. The parts below were observed. The parts after them were **not**
observed. Do not treat them as proven.

What the partial runs (`pnpm vitest run ./tests/integration.spec.ts`, anvil, `pnpm dev:ciphernodes`,
`pnpm dev:server`, `pnpm dev:program`, mock compute proof) showed, on an M3 Pro:

| Observed                                                                                   | Result                                                               |
| ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| Two requests (round 1 = sale id, round 2) at `+40 s`                                       | Both E3s created                                                     |
| Both committee keys published (full DKG, `insecure-simd`, `minimum`)                       | about 940 s to 975 s                                                 |
| Four real bid proofs in Node (alice, bob, carol, dave): encryption trees plus pair proof   | about 70 s to 80 s per bid on a quiet machine                        |
| `publishInput` with the real Honk bid verifier: two direct bids and two relayed bids       | accepted; the escrow moved; the relayer paid the gas for relayed bids |
| A bid with the wrong tier, or sent by another address, in `eth_call`                       | reverted (`SumcheckFailed()` `0x9fc3a218`, or `SenderNotBidder`)      |

The run stopped on test-bookkeeping assertions about balances that earlier runs on the same chain had
changed. The assertions are now relative to the balances before the test. A bug that the run found
and that is fixed: an E3 id can be larger than the BN254 field, so the circuits and the contract use
`saleId mod r` (`saleField`).

**Not observed:** round-1 compute and decryption, `publishProbes`, round 2, `clear`, a claim to a
fresh address, a refund, the marginal registration and `payMarginal`, and the web app in a browser.
The smoke spec `tests/integration.spec.ts` covers all of these (4 bidders; expected payouts: alice
7.5e18 tokens, paid 30e6, refund 10e6; dave 0 tokens, refund 40e6; bob 10e18 tokens, paid 40e6;
carol 12.5e18 tokens, paid 50e6, refund 50e6; total sold 30e18, proceeds 120e6). The expected values
come from a hand calculation, and the contract tests check the same clearing. To run it:

```sh
pnpm dev:all                      # or the named services below
export $(interfold print-env --chain localhost)
E3_PROGRAM__DEV=true TEMPLATE_UNPROVED_TEST=1 pnpm vitest run ./tests/integration.spec.ts
```

A full run takes about 25 minutes: a DKG of about 16 minutes for the two E3s, and about 5 minutes
for four bid proofs. Run it on a fresh chain.

Unit-level evidence (run on this branch): `pnpm test` (Hardhat) 65 passing; `pnpm vitest run ./server
./sdk` 215 passing; `cargo test -p e3-user-program` 26 passing; `pnpm -C client build` succeeds.
The OpenVM guest is not built (`cargo-openvm` is not installed), so the runner runs the program
natively in dev mode.

## Test

```sh
pnpm test                # Hardhat: program, clearing properties, the real verifiers
pnpm test:server         # vitest: the server and the SDK
pnpm test:integration    # the full local stack, one sale (see "Local smoke run")
cargo test -p e3-user-program --lib      # the FHE program with real keys (from program/)
nargo test               # in circuits/bid and circuits/claim
```

The Hardhat tests (`test/`) cover the request and `validate` errors, the bid and its public inputs,
every branch of the probe search, an abort on a counted-set mismatch (and the forfeit), the clearing on
300 random sales, claims (nullifier reuse, a wrong tier, a wrong class, refunds), the marginal
registration, `payMarginal` in the order of the bids, a late marginal claim, the sweep and a failed E3.
`verifiers.test.ts` checks the generated verifiers against the real proofs of
`sdk/test-vectors/proofs.json` and rejects a changed public input. Regenerate the proofs with
`pnpm -C sdk proofs:regenerate`.

## Layout

| Path                                   | What it holds                                                                                |
| -------------------------------------- | -------------------------------------------------------------------------------------------- |
| `contracts/`                           | The program, the libraries, the interface, the generated verifiers and the mocks.            |
| `test/`                                | The Hardhat tests.                                                                           |
| `deploy/`, `scripts/deploy-*.ts`       | `deployTemplate`, the library deploy and linking, the local and network deploys.             |
| `circuits/`                            | The Noir circuits (bid, claim), the public inputs (`PUBLIC_INPUTS.md`) and the table tool.   |
| `sdk/`                                 | `@interfold/token-launch`: layout, sale encoders, commitments, provers, probe and clearing mirrors, claim tree and the shared test vectors. |
| `program/`, `runner/`, `guest/`, `da/` | The FHE program, its runner, the OpenVM guest and the Avail helper.                          |
| `server/`                              | The coordination server, the keeper and the relayer.                                         |
| `client/`                              | The web app.                                                                                 |
| `scripts/`, `tests/`                   | The local scripts, the leak estimate and the smoke test.                                     |

## Limits

- The parameters are insecure (`N = 128`, `t = 257`). They give no security.
- A sale has at most **85 bidders** (`85 * 3 = 255 <= t - 1`) and at most **16 levels**. A budget is
  `1..4095` units.
- One bid per address. The bid is final. There is no update and no cancel.
- A bid costs two ciphertexts and one proof of about 1.43 M gates. This is under the browser limit,
  and takes minutes to prove (6.4 minutes in Node on a busy 11-core machine).
- The committee decrypts the sums of the probe levels, so the public sees 6 or 7 budget sums. A
  bid at the clearing step in a capped sale **links its index** when it registers. A small tier or
  class gives a small anonymity set.
- The claim reveals the tier and (for a winner) the budget. A marginal fill needs the registration in
  the first 3 days. After that, the marginal bid gets a refund only. If nobody calls `payMarginal`
  within the claim window, `sweep` takes the unpaid fill.
- A bidder has 30 days after `clear` to claim. After that, the creator can sweep.
- The bid secret (salt, `B`, `b`, `X`, index) is the only way to claim. The client stores it in the
  browser and offers an export. A lost secret loses the refund and the tokens.
- The sale and payment tokens must be standard ERC-20 tokens. Do not use fee-on-transfer or rebasing
  tokens.
- The compute proof is a mock on the local chain (`TEMPLATE_UNPROVED_TEST`). The OpenVM guest was not
  built here (`cargo-openvm` is not installed). The program runs natively in the runner.
- The probe search is for `levels` 8 to 16. It needs two rounds and two E3 fees.

## Open decisions

- **Marginal unlinkability.** Marginal claims link their index. A design that proves a position in the
  order without revealing it needs a committed order and range proofs. This is more work. The first-bid
  order is public because the index order is the order of the deposits.
- **Tiers.** Fewer tiers make larger anonymity sets, but they cost more escrow for a small budget.
- **Window lengths.** `MARGINAL_WINDOW` is 3 days and `CLAIM_WINDOW` is 30 days. A sale parameter may
  replace them.
- **Fees.** A sale pays two E3 fees. A shared E3 for round 2 is not possible with one output.
- **Sepolia.** This checkout made no Sepolia deployment. `deploy-network.ts` exists. It is not run.
