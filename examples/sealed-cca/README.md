# Sealed CCA: a sealed-bid token sale

This example is a standalone token sale on Interfold. It is a sealed, one-batch, uniform-price sale
in the style of a Uniswap continuous clearing auction (CCA). A creator sells a supply of an ERC-20
token. Bidders send encrypted bids. No one sees a bid. After the sale closes, the committee decrypts
only the demand curve. The contract clears the sale at one price for everyone.

| Step           | What happens                                                                                                                                                |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Create         | The creator approves the supply of the sale token, pays the E3 fee and requests an E3. `SealedCcaProgram.validate` pulls the supply into the contract.      |
| Key generation | The ciphernodes run a distributed key generation. It makes the l-BFV public key.                                                                            |
| Deposit        | A bidder escrows the fixed amount `escrow` of the payment token once, and gets a bidder index `i` (0 to 111). A relayer can send the deposit with a permit. |
| Bid            | The bidder encrypts the highest price step that they accept, proves in the browser that the bid is valid, and sends it. A bidder can update a bid twice.    |
| Computation    | The FHE program adds the counted bid ciphertexts. It needs no key.                                                                                          |
| Decryption     | The committee decrypts one ciphertext: the demand curve and the counted version of each bidder.                                                             |
| Clearing       | Anyone calls `clear(e3Id)`. The contract reads the plaintext and finds the uniform price, with integer arithmetic only.                                     |
| Claim          | Each bidder claims with a small proof of how their private step compares with the clearing step. They get tokens and a refund.                              |
| Withdraw       | The creator takes the payments and the unsold tokens. After the claim window, the creator sweeps what is left.                                              |

This example runs on the **insecure SIMD parameters (parameter set 5: N = 128, t = 257)**. They are
for development and give no security. Do not use the app for real value.

## The sale

The creator chooses these values:

| Value                         | Meaning                                                                                                                     |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `levels` (L)                  | The number of price steps, from 2 to 16.                                                                                    |
| `prices[0..L-1]`              | The price of each step. The prices increase strictly. A price is in payment-token base units for one whole sale token.      |
| `saleToken`                   | The ERC-20 token that is for sale. The contract reads its `decimals`: `U = 10^decimals` is one whole token in base units.   |
| `supply` (S)                  | The sale-token base units to sell.                                                                                          |
| `paymentToken`                | The ERC-20 token that bidders pay with.                                                                                     |
| `escrow` (E)                  | The payment-token base units that every bidder escrows. It is the same for every bid.                                       |
| `revealMode`                  | `0` is the demand curve (this version). `1` (clearing only) is research: the contract reverts with `RevealModeUnsupported`. |
| `title`, `gate`, `gateConfig` | A title. An optional bidder gate (`IBidderGate`) and its configuration. Zero gate means that anyone may bid.                |

`customParams = abi.encode(uint8 revealMode, uint8 levels, uint256[16] prices, address saleToken, uint256 supply, address paymentToken, uint256 escrow, string title, address gate, bytes gateConfig)`.
`prices[L..15]` must be zero. Supply, escrow and the largest price must be at most `2^112`.

**The supply deposit.** `Interfold.request` calls `SealedCcaProgram.validate`. The requester is
already known at that point. `validate` calls `transferFrom(requester, program, supply)`. So the
creator approves `supply` of the sale token to the program before the request. A separate `fund`
step is not needed. If the approval is missing, the request reverts.

A bidder who accepts the price step `b` is _active_ at every price up to `prices[b]`. A bidder who
is active at the price `p` buys `E * U / p` sale-token base units with the escrow `E`.

## How a bid works

A bid is a whole number `b` from 0 to `L-1`: the index of the highest price that the bidder accepts.
The plaintext has 128 slots (SIMD):

| Slots            | Plaintext of a bid                                                   |
| ---------------- | -------------------------------------------------------------------- |
| `0..L-1`         | The thermometer: `m[l] = 1` if `l <= b`, else `0`.                   |
| `16 + i`         | The version of this bid (1 to 3), for the bidder with the index `i`. |
| Every other slot | `0`.                                                                 |

The program adds the ciphertexts of the counted bids. After the decryption:

| Output slots | Value                                                                                                           |
| ------------ | --------------------------------------------------------------------------------------------------------------- |
| `0..15`      | `c[l]`: the number of counted bidders with `b >= l`. `c[l] <= 112 < 257`.                                       |
| `16..127`    | `counted[i]` for the bidder with the index `i` (0 to 111): the counted version (1 to 3), or `0` if not counted. |

The decryption proof is verified on chain by Interfold. So the contract reads the counted set from
the plaintext without extra trust.

### The deposit

`deposit(e3Id, gateProof)` takes `escrow` from the sender once. It gives the sender the next bidder
index `i` and emits `Deposited(e3Id, bidder, index)`. The sale has at most 112 bidders
(`TooManyBidders`). A bidder must deposit before the first bid. The deposit checks the gate, so an
address that the gate refuses cannot take an index.

A relayer can send a deposit for a bidder. The bidder signs an EIP-2612 permit for the payment token
(value `escrow`, spender the program). The relayer calls
`depositFor(e3Id, bidder, gateProof, deadline, v, r, s)`. The call tolerates a permit that someone
else used first, if the allowance is enough. The payment token of the demo, `MockPaymentToken`,
supports permits.

Money that is not used is never lost. A depositor who is not counted gets the whole escrow back.

### Send a bid

`publishInput(e3Id, data)` with
`data = abi.encode(address bidder, bytes ciphertext, bytes32 ctCommitment, bytes32 bidCommitment, bytes proof, bytes gateProof, bytes signature)`.

The bid needs a deposit. The bidder has an index `i` from it. The bid version is `bidCount + 1`. One
proof (`sealed_cca_bid`, below 2^21 gates, proved in the browser) shows:

- The ciphertext is a valid encryption under the E3 committee key.
- Its plaintext is the thermometer of `b` in the slots 0 to 15, `b < levels`, and the version in the
  slot `16 + i`. All other slots are 0.
- `bidCommitment = poseidon2(DOMAIN_BID, b, salt, bidder, e3Id mod r)`. An E3 id has 256 bits and
  can be above the BN254 scalar field `r`, so the circuits take `e3_id = e3Id mod r`. The contract
  and the SDK (`e3Field`) reduce it the same way. Storage, events and the EIP-712 `Bid` keep the
  full `e3Id`.

The contract does not trust the bidder for the index and the version. It takes both from its storage
and puts them in the public inputs. So a bidder cannot count in the slot of another bidder. The
public inputs of the bid proof, in this order (see `circuits/PUBLIC_INPUTS.md`):

`ct_commitment, bid_commitment, bidder, e3_id, levels, bidder_index, version, pk_commitment, vk_anchor`

The bidder, the E3 and the commitment are in the proof. A copied `bidCommitment` is useless for
another bidder or another sale.

Each bid is one leaf of the input tree:
`sha256(keccak256(ciphertext) || ctCommitment || bidder || uint40 version) mod BN254`. Leaf 0 is the
configuration leaf, `keccak256("interfold-sealed-cca-config-v1" || uint8 revealMode) mod BN254`. The
contract emits
`BidSubmitted(e3Id, bidder, version, index, ciphertext, ctCommitment, bidCommitment)`. The leaves
follow the log order.

**Updates.** A bidder can bid up to 3 times (a bid and two updates). The escrow is taken once, at
the deposit. The contract stores the `bidCommitment` of every version.

**Relayed bids.** With a non-empty `signature`, anyone can send the bid. The signature is the
EIP-712 signature of the bidder. The domain is `SealedCcaProgram`, version `1`. The type is
`Bid(uint256 e3Id,address bidder,uint32 version,bytes32 inputsHash)`, with
`inputsHash = keccak256(abi.encode(ctCommitment, bidCommitment, keccak256(ciphertext)))`. A relayer
cannot swap a byte of a signed bid. An old signature is useless once the bidder has bid again.
Without a signature the sender must be the bidder.

**The bidder gate.** A sale can name a gate (`IBidderGate`). It is checked at the deposit and at
each bid. The example gate `MerkleAllowlistGate` is an allowlist:
`gateConfig = abi.encode(address[] members)` (1 to 256 strictly increasing addresses), and the
bidder proof is `abi.encode(bytes32[] path)`. The default gate is none: anyone may bid.

### The program: which bids count

The program is the homomorphic sum of the selected bid ciphertexts. It needs no key and no
relinearization. Per bidder, it counts the latest version whose bytes open `ctCommitment`. Earlier
versions are the fallback. A bidder with no such version is dropped. The contract cannot check this,
because it cannot open a ciphertext. The leaf binds the bytes and the commitment together, and the
program checks them. A bid that does not open is skipped. The output shows which version counted
(`counted[i]`), and the contract uses that version's `bidCommitment` for the claim.

## Clearing

The contract clears the sale in `clear(e3Id)`. Anyone can call it once after Interfold publishes the
plaintext. `claim` and `withdrawUnsold` call it when nobody did. It decodes `c[0..15]` and
`counted[0..111]` from the plaintext, and then runs the clearing below.

**Decoding the plaintext.** Interfold publishes the plaintext as 128 coefficients (the polynomial
basis), each a little-endian `uint64`. SIMD slot `j` is the value of the polynomial at a fixed point
`POINTS[j]` modulo 257. `contracts/libraries/SlotCodec.sol` holds the table. It is the slot order of
fhe.rs. The vectors in `sdk/test-vectors/slots.json` pin it against the fhe.rs decoder. The contract
rejects an output that is not valid: a coefficient of 257 or more, a curve that rises with the step,
a curve that is not zero above `levels`, a counted version above the bids of the bidder, or a number
of counted bidders that is not `c[0]`.

**Notation.** `c[L] = 0`. `U = 10^saleDecimals`. All values are integers. Division rounds down,
except where `ceil` is written. `p[l]` is `prices[l]`.

For `l` from `L-1` down to 1, the bidders with `b >= l` over-demand just above `p[l-1]` when
`c[l] * E * U > p[l-1] * S`. The first such `l` decides:

| Case                  | Condition                                      | Price `pStar`                             | Who gets what                                                                                                              |
| --------------------- | ---------------------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Capped** at `s = l` | `c[l]*E*U > p[l-1]*S` and `c[l]*E*U >= p[l]*S` | `p[s]`                                    | Bidders with `b > s` are filled in full. Bidders with `b == s` share the rest. Bidders with `b < s` get their escrow back. |
| **Uncapped** at `l`   | `c[l]*E*U > p[l-1]*S` and `c[l]*E*U < p[l]*S`  | `ceil(c[l]*E*U / S)`, in `(p[l-1], p[l]]` | Bidders with `b >= l` are filled in full. Bidders with `b < l` get their escrow back.                                      |
| **Capped** at `s = 0` | No `l` found, and `c[0]*E*U >= p[0]*S`         | `p[0]`                                    | Same as capped: bidders with `b > 0` full, bidders with `b == 0` share the rest.                                           |
| **Undersubscribed**   | No `l` found, and `c[0]*E*U < p[0]*S`          | `p[0]`                                    | Everybody is filled in full. The unsold tokens go back to the creator.                                                     |

**A full fill** is `full = floor(E * U / pStar)` sale-token base units. A bidder pays
`cost(t) = ceil(t * pStar / U)` for `t` tokens. The cost of a full fill is at most `E`. The rest of
the escrow is refunded.

**Capped at `s`.** The loop at `s+1` failed (or `s+1 == L`), so the `c[s+1]` bidders above `s`
demand at most `S` at `p[s]`. They are filled in full. The `m = c[s] - c[s+1]` bidders at `s` share
the rest `R = S - c[s+1] * full`. Each gets `min(floor(R / m), full)` tokens. The `min` matters when
the rounding of `full` leaves more than one full fill in `R`: nobody gets more than a full fill, so
nobody pays more than `E`. The creator gets the dust.

**Uncapped at `l`.** The price is rounded **up**. A rounded-down price could sell a few base units
more than `S`. With `ceil`, `c[l] * floor(E * U / pStar) <= S` holds, so the sale never sells more
than the supply. `pStar` is at most `p[l]`, so every winner (`b >= l`) accepts it.

**Guarantees** (checked by the Hardhat tests, with 300 random sales):

- The sale sells at most `S`.
- Nobody pays more than `E`, and nobody pays more per token than their own maximum price.
- There is one uniform price. A bidder below the clearing step gets nothing.
- A higher bid never gets a worse outcome: the tokens do not decrease with `b`.
- The Solidity result equals the independent TypeScript port in `test/helpers.ts` and the SDK
  mirror.

**Example.** The prices are 1.00, 2.00, 3.00 and 4.00 USDC per token. The supply is 100 tokens. The
escrow is 50 USDC. One bidder accepts step 3, four accept step 1 and one accepts step 0. So
`c = [6, 5, 1, 1]`. In USDC, the demand `c[l] * E` of each step is compared with `p[l-1] * S` and
`p[l] * S / U`:

- `l = 3`: `1 * 50 = 50`, which is not above `p[2] * 100 = 300`. Not found.
- `l = 2`: `1 * 50 = 50`, which is not above `p[1] * 100 = 200`. Not found.
- `l = 1`: `5 * 50 = 250`, which is above `p[0] * 100 = 100`, and at least `p[1] * 100 = 200`.

The sale is **capped** at `s = 1`, with `pStar = 2.00`. A full fill is 25 tokens for 50 USDC. The
bidder at step 3 gets 25 tokens. The rest is `R = 100 - 25 = 75` tokens, and `m = 5 - 1 = 4`. The
four bidders at step 1 get 18.75 tokens each. Each pays 37.50 USDC and gets 12.50 USDC back. The
bidder at step 0 gets the whole 50 USDC back. The sale sells 100 tokens.

## Claim

`claim(e3Id, bidder, data)`. Anyone can send it. The funds go to `bidder`. `data` is
`abi.encode(uint8 cmp, bytes proof)`.

**The claim window.** A bidder can claim for 30 days after `clear` (`CLAIM_WINDOW`). `clear` stores
the end of the window as `claimDeadline` and emits `ClaimWindowOpened(e3Id, deadline)`.
`clearing(e3Id)` returns `claimDeadline` as its last value. A claim that is mined at the time
`claimDeadline` still works. After it, every `claim` reverts with `ClaimWindowClosed(deadline)`.
This includes the refunds of dropped bidders and of depositors that never bid, which need no proof.

The claim circuit (`sealed_cca_claim`, about 3000 gates, proved in the browser in seconds) has the
private inputs `b` and `salt`. Its public inputs are `bid_commitment, bidder, e3_id, k` and its
output `cmp`: `0` if `b < k`, `1` if `b == k`, `2` if `b > k`. The contract sets the first four: the
stored `bidCommitment` of the counted version, the bidder, the E3 and `k`. `k` is `s` (capped) or
`l` (uncapped). The proof bytes do not hold `cmp`, so the claimant sends it. The contract rejects
`cmp > 2`.

| Bidder                                   | Proof | Tokens     | Paid             | Refund     |
| ---------------------------------------- | ----- | ---------- | ---------------- | ---------- |
| Not counted (dropped, or deposit only)   | none  | 0          | 0                | `E`        |
| Any counted bidder, undersubscribed sale | none  | `full`     | `cost(full)`     | `E - paid` |
| Uncapped: `cmp >= 1`                     | yes   | `full`     | `cost(full)`     | `E - paid` |
| Uncapped: `cmp == 0`                     | yes   | 0          | 0                | `E`        |
| Capped: `cmp == 2`                       | yes   | `full`     | `cost(full)`     | `E - paid` |
| Capped: `cmp == 1`                       | yes   | `marginal` | `cost(marginal)` | `E - paid` |
| Capped: `cmp == 0`                       | yes   | 0          | 0                | `E`        |

`previewClaim(e3Id, bidder, cmp)` returns the three amounts after `clear`.

**The creator.** `withdrawProceeds(e3Id)` sends the payments of the claims so far. The creator calls
it again after more claims. `withdrawUnsold(e3Id)` sends `supply - sold`, once. The unsold amount is
large only in the undersubscribed case; otherwise it is rounding dust. Both work before and after
the claim window.

**The sweep.** After `claimDeadline`, the creator calls `sweep(e3Id)`, once. Before the deadline it
reverts with `ClaimWindowOpen`. A second call reverts with `AlreadySwept`. The sweep sends to the
creator:

- The sale tokens that the sale still holds:
  `supply - tokens paid to claimants - unsold tokens that the creator already took`. These are the
  tokens of winners that did not claim, and the unsold tokens if the creator did not take them.
- The payment tokens that the sale still holds: one `escrow` for each depositor that did not claim,
  and the payments that the creator did not take yet.

The contract counts both amounts for each sale (`tokensClaimed`, `claimedCount`,
`proceedsAvailable`). So a sweep cannot move the tokens of another sale. After the sweep, `claim`,
`withdrawProceeds` and `withdrawUnsold` have nothing to give. The event is
`Swept(e3Id, creator, saleTokens, paymentTokens)`.

**A failed E3.** If the E3 fails (stage `Failed`, for example no one decrypts),
`refundEscrow(e3Id, bidder)` returns an escrow, and `refundSupply(e3Id)` returns the supply to the
creator.

## What stays hidden and what is public

| Item                                                    | Visibility                                                                                                   |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| The max price step `b` of a bidder                      | **Hidden.** It is only inside the ciphertext and the private proof inputs. It is never decrypted per bidder. |
| `salt`                                                  | Hidden (the bidder's browser only).                                                                          |
| The bid ciphertext                                      | Public, but encrypted under the committee key.                                                               |
| `bidCommitment`                                         | Public. It hides `b` behind `salt` and binds the bidder and the E3.                                          |
| The sale parameters, supply, escrow, prices             | Public.                                                                                                      |
| Who deposited, the index, the number of bids (versions) | Public (calldata and events).                                                                                |
| The demand curve `c[0..15]`                             | **Public after decryption.** It is the histogram of all counted bids by step, with no names.                 |
| Which bidders counted, and which version                | **Public after decryption** (`counted[i]`). A dropped bidder is visible.                                     |
| The clearing price and the clearing step `k`            | Public.                                                                                                      |
| The outcome of one bidder                               | Public only when that bidder claims: `cmp` and the amounts. A counted bidder who never claims stays hidden.  |
| Individual `b` of a claimant                            | Only its comparison with `k` (below, equal or above). The claim proof reveals nothing more about `b`.        |

The demand curve is a histogram. With few bidders it can reveal a lot: with a single counted bidder,
`c` shows that bidder's step. Use the sale with enough bidders. The committee sees only the sum,
never a single bid.

## What is proven

| Proof                        | Where it is checked                        | What it shows                                                                                 |
| ---------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------- |
| Bid proof (`sealed_cca_bid`) | `SealedCcaBidVerifier` in `publishInput`   | The ciphertext holds the thermometer of `b < levels` and the version in slot `16 + i`.        |
| Claim proof                  | `SealedCcaClaimVerifier` in `claim`        | The claimant knows `b, salt` for the stored `bidCommitment`, and `cmp` compares `b` with `k`. |
| Compute proof                | `SealedCcaProgram.verify` (OpenVM receipt) | The FHE program computed the output from the inputs of the input tree.                        |
| Decryption proof             | Interfold (`BfvDecryptionVerifier`)        | The plaintext is the decryption of the output ciphertext.                                     |

All verifiers are generated: the Solidity verifiers come from `circuits/compile.sh` (never edit them
by hand), and the two Honk verifiers link two external libraries each.

## Contracts

| Contract                       | Role                                                                               |
| ------------------------------ | ---------------------------------------------------------------------------------- |
| `SealedCcaProgram`             | The E3 program: request, deposit, bids, clearing, claims, withdrawals.             |
| `libraries/SaleClearing`       | The clearing math (external library, because of the contract size limit).          |
| `libraries/SaleConfig`         | Decodes and checks the sale parameters of the request (external library).          |
| `libraries/SaleOutput`         | Reads the decrypted output: the curve and the counted versions (external library). |
| `libraries/SlotCodec`          | Decodes the published coefficients into SIMD slots.                                |
| `gates/MerkleAllowlistGate`    | An example `IBidderGate`: an allowlist.                                            |
| `verifiers/SealedCca*Verifier` | The generated Honk verifiers of the bid and claim circuits.                        |
| `mocks/MockSaleToken`          | The demo sale token. 18 decimals. Anyone can `mint`.                               |
| `mocks/MockPaymentToken`       | The demo payment token ("Mock USDC"). 6 decimals, EIP-2612, anyone can `mint`.     |

Events: `SaleCreated`, `Deposited`, `BidSubmitted`, `SaleCleared(e3Id, pStar, kind, step, c[16])`
(`kind`: 0 undersubscribed, 1 capped, 2 uncapped), `Claimed(e3Id, bidder, tokens, paid, refund)`,
`ClaimWindowOpened(e3Id, deadline)`, `ProceedsWithdrawn`, `UnsoldWithdrawn`, `Swept`,
`EscrowRefunded`, `SupplyRefunded`. The parameter checks revert with the errors of `SaleConfig` (for
example `RevealModeUnsupported`, `InvalidPrices`, `InvalidAmount`). Load the ABI of `SaleConfig` to
decode them.

Views: `sale(e3Id)`, `salePrices(e3Id)`, `bidderCount`, `bidderAt`, `bidderIndex`, `deposited`,
`bidCount`, `bidCommitments`, `clearing(e3Id)`, `countedVersion`, `previewClaim`, `claimed`,
`proceedsAvailable`, `unsoldAmount`, `swept`.

## Prerequisites

- Rust, Node, pnpm, `nargo` 1.0.0-rc.3, `bb` 6.0.0 and Foundry (`anvil`).
- An `interfold` CLI built from this checkout. `pnpm dev:setup` installs it.

## Run it

Run these commands in this order. The steps are the same as for `examples/auction-e2e`.

1. Build the Noir circuits of the protocol for the insecure SIMD preset. Run it in the repository
   root:

   ```sh
   pnpm build:circuits --preset insecure-simd --committee minimum
   ```

2. Build the SDK of the repository (`pnpm sdk:build`). It bundles the user-data encryption circuits.

3. Set up the example. It compiles the two circuits (`circuits/compile.sh`) and writes the two
   verifiers and `circuits/target/vk_anchor.json`:

   ```sh
   pnpm install
   pnpm dev:setup
   ```

4. Start the stack: anvil, the ciphernodes, the program server, the program runner and the web app:

   ```sh
   pnpm dev:all
   ```

`pnpm dev:all` deploys the contracts with `scripts/deploy-local.ts` (`deploy/default.ts`). The
deploy records `SealedCcaProgram`, `MockSaleToken`, `MockPaymentToken`, `MerkleAllowlistGate`, the
two verifiers and the libraries in `deployed_contracts.json`.

The web app has these pages: the list of sales, **Create** (token, supply, a grid of prices with a
"linear from floor to cap" helper, escrow, window), the sale page (status, deposit, bid, update),
the results page (clearing price, demand curve, your outcome, **Claim** with an in-browser claim
proof) and the creator panel (withdraw). The **Mint test tokens** button mints the demo tokens.

## The FHE program, the server and the runner

The FHE program (`program/`, `runner/`, `guest/`) is the homomorphic sum of the selected bid
ciphertexts. Input 0 is the configuration `"interfold-sealed-cca-config-v1" || uint8 revealMode`;
`validate` inserts its leaf. The metadata of a bid leaf is `bidder || uint40 version` (25 bytes).
The slot layout lives in `program/src/lib.rs`, `sdk/src/layout.ts` and
`contracts/libraries/SlotCodec.sol`; tests check that they agree. A sale with no counted bid has no
output. The server skips it, the E3 times out, and `refundEscrow` and `refundSupply` return the
funds.

The server (`server/`) watches the committee key, schedules the compute at the end of the input
window, reads the inputs from the chain, calls the runner, and publishes the output on the callback.
It reads `SaleCreated` (the block of creation), `BidSubmitted` (bytes and commitments) and
`sale(e3Id)`. The leaf of a bid is its place in the log order (block, log index) after the
configuration leaf. It checks the number of leaves against `inputs(e3Id)` before it calls the
runner. It does not decode the plaintext: anyone calls `clear(e3Id)`.

The routes are `GET /health`, `POST /callback/:e3Id/:token` (runner),
`GET /availability/objects/:hash` (mock DA), `POST /relay { e3Id, data }` (`publishInput`) and
`POST /relay/deposit { e3Id, bidder, gateProof?, deadline, v, r, s }` (`depositFor` with a permit).
The relay routes simulate first, and answer `{ txHash }` or `{ error }` with the revert reason. On
the local chain the relayer is Anvil account 9 (`RELAYER_PRIVATE_KEY` elsewhere). See
`server/.env.example`.

## Test

```sh
pnpm test                # Hardhat: contracts, clearing properties, slot decoder, generated verifiers
pnpm test:server         # vitest: the server and the SDK
pnpm test:integration    # the full local stack: one sale with four bidders
```

The Hardhat tests (`test/`) cover:

- `clearing.test.ts`: the case analysis, the TypeScript reference, 300 random sales for the
  properties above, and the shared vectors `sdk/test-vectors/clearing.json`. Run
  `UPDATE_VECTORS=1 pnpm test` to rewrite the vector file after a change of the clearing.
- `SealedCcaProgram.test.ts`: the request (the supply pull, the bad parameters), the deposit
  (direct, permit, the 112-bidder limit), the claim window and the sweep (exact amounts, concurrent
  sales), the bids (public inputs, updates, relay, gate), the clearing and the claims (uncapped,
  capped, undersubscribed, dropped), the invalid outputs, and a failed E3.
- `verifiers.test.ts`: the generated verifiers accept the real proofs of
  `sdk/test-vectors/proofs.json` and reject a changed public input.
- The slot decoder test checks `sdk/test-vectors/slots.json`, which comes from the fhe.rs decoder.

The integration test (`tests/integration.spec.ts`) runs one sale with four bidders (a full winner, a
marginal bidder, a loser and a dropped bidder), a permit deposit and a relayed bid, real bid and
claim proofs, the clearing check against the TypeScript mirror, all claims and the creator
withdrawals. Expect about one hour: the key generation takes about 10 minutes, and the bid proofs
and the committee compute take the rest.

## Deploy to Sepolia

The app can run on Sepolia. This checkout has made no Sepolia deployment. The local flow does not
change: on chain 31337 the deploy uses the mock data-availability verifier, and the server uses
`mock_http`. Read "Limits" first. The parameters are insecure, and the compute proof is a mock.

The requirements are the same as for `examples/auction-e2e`: a protocol with a route for parameter
set 5 (own protocol, or the owner of the official one adds the route), ciphernodes that run the
insecure SIMD circuits (`BFV_PRESET=insecure-simd`), Sepolia ETH for the deploy account and the
server key, and the built circuits of this example (`circuits/target/vk_anchor.json` and the two
verifiers). Avail is the data-availability layer for the ciphertext output: see the section "Deploy
to Sepolia" of `examples/auction-e2e/README.md` for the Avail setup and its timing.

```sh
pnpm compile
export SEPOLIA_RPC_URL=https://...          # an HTTP RPC endpoint
export PRIVATE_KEY=0x...                    # the deploy key. Never commit it.
export INTERFOLD_ADDRESS=0x...              # the protocol; the script does not need a record of it
export TEMPLATE_UNPROVED_TEST=1             # the mock compute verifier
export ALLOW_SEPOLIA_UNPROVED_COMPUTE=true  # the explicit acknowledgment that Sepolia requires
pnpm deploy:sepolia
```

| Variable                                 | Effect                                                                                                                              |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `SEPOLIA_RPC_URL`                        | The RPC endpoint of the `sepolia` network. It falls back to `RPC_URL`.                                                              |
| `PRIVATE_KEY`                            | The deploy key. The `sepolia` network has no other account.                                                                         |
| `INTERFOLD_ADDRESS`                      | The Interfold address. Without it the script reads `deployed_contracts.json`.                                                       |
| `POSEIDON_T3_ADDRESS`                    | The `PoseidonT3` library. Without it the script uses the record, then the canonical address, then deploys it.                       |
| `TEMPLATE_UNPROVED_TEST=1`               | Deploy `MockOpenVmReceiptVerifier`. It accepts every compute receipt. Chain 31337 allows it. Sepolia also needs the next variable.  |
| `ALLOW_SEPOLIA_UNPROVED_COMPUTE`         | `true` acknowledges the mock compute verifier on Sepolia. Every other chain refuses it.                                             |
| `MOCK_DATA_AVAILABILITY=true`            | Deploy `MockDataAvailabilityVerifier` on a public testnet. Mainnet refuses it. The server needs `DATA_AVAILABILITY_MODE=mock_http`. |
| `DEFER_PROTOCOL_WIRING=true`             | Skip `setCiphertextVerifier` and `registerE3Program` even when the key is the owner.                                                |
| `ALLOW_REPLACE_CIPHERTEXT_VERIFIER=true` | Replace a ciphertext verifier that the protocol already has. Without it, the script prints the calls instead.                       |

The script deploys the two Honk verifiers with their libraries, the two clearing libraries, the
program, the allowlist gate and the two demo tokens (`MockSaleToken`, `MockPaymentToken`). It
records every address in `deployed_contracts.json` and writes `e3_program` and its `deploy_block` to
the `sepolia` entry of `interfold.config.yaml`. Write down the `deploy_block`: the server needs it
as `DEPLOY_BLOCK`. If the deploy key is the Interfold owner, the script also sends
`setCiphertextVerifier` and `registerE3Program`. Otherwise it prints both calls for the owner.

## Layout

| Path                                   | What it holds                                                                             |
| -------------------------------------- | ----------------------------------------------------------------------------------------- |
| `contracts/`                           | The program, the libraries, the gate, the generated verifiers and the mocks.              |
| `test/`                                | The Hardhat tests.                                                                        |
| `deploy/default.ts`                    | `deployTemplate`: the deploy of the program and what it needs.                            |
| `circuits/`                            | The Noir circuits (bid, claim), their public inputs (`PUBLIC_INPUTS.md`) and the tooling. |
| `sdk/`                                 | `@interfold/sealed-cca`: layout, provers, clearing mirror and the shared test vectors.    |
| `program/`, `runner/`, `guest/`, `da/` | The FHE program, its runner, the OpenVM guest and the Avail helper.                       |
| `server/`                              | The coordination server and the relayer.                                                  |
| `client/`                              | The web app.                                                                              |
| `scripts/`, `tests/`                   | The local scripts and the integration test.                                               |

## Limits

- The parameters are insecure (N = 128, t = 257). They give no security.
- A sale has at most 112 bidders (16 slots for the curve, 112 for the counted versions).
- A bidder bids at most 3 times. The escrow is the same for every bid.
- The demand curve is public. With few bidders it reveals the steps of the bidders.
- A bidder has 30 days after `clear` to claim. After that, the creator can sweep the unclaimed
  tokens and escrows, and the bidder loses the claim.
- `revealMode` 1 (clearing only, with no demand curve) is not built.
- The sale and payment tokens must be standard ERC-20 tokens. Do not use fee-on-transfer or rebasing
  tokens.
- The compute proof is a mock on the local chain and on Sepolia (`TEMPLATE_UNPROVED_TEST`).
