# @interfold/auction-first-price

First-price sealed-bid auction on Interfold (type 0).

The highest bid wins. The winner pays its own bid. Each bidder has its own region of 16 slots in the
result, one slot for each price step. The committee computes `out = own_ge + mask_sum * (G + E)` on
the encrypted bids. The multiplicative depth is 1. The result never fails to show the winner,
because the mask only touches slots where `G + E` is at least 1. If the top bids tie, the tied
bidder who bid first wins. The tie is not revealed.

## What the auction reveals

The result shows the winner and the price. The price is the bid of the winner. Nothing else is
revealed.

## Whom you trust

One honest bidder is enough. Each bidder adds a random mask to the result. The masks hide every slot
that the result does not need. If one bidder keeps its mask secret, the hidden slots are uniform. No
mask provider takes part.

## Install

The package is private. Use it from the pnpm workspace. Add it to the `package.json` of your
package:

```json
{ "dependencies": { "@interfold/auction-first-price": "workspace:*" } }
```

Run `pnpm install`. Then run `pnpm build` in `examples/auction-e2e/sdk/first-price`. The build
copies the compiled circuits from `examples/auction-e2e/circuits`. Run `pnpm compile:circuits` in
`examples/auction-e2e` first if they do not exist.

## Quickstart

```ts
import { evenPrices } from '@interfold/auction-core'
import { decodeResult, encodeParams } from '@interfold/auction-first-price'
import { createBidProver } from '@interfold/auction-first-price/prover'

// 1. Request an E3. Give `customParams` to `requestE3`.
const customParams = encodeParams(evenPrices(10n, 10n, 16), 'Lot 1')

// 2. Prove a bid at step 7. 3 ciphertexts and 1 proof go on chain.
const prover = await createBidProver()
const bid = await prover.prove(7, 16, committeeKey, bidderAddress, (step) => console.log(step.kind))
await prover.destroy()
// Send `encodeBidInput({ bidder, ciphertexts: bid.ciphertexts, commitments: bid.commitments,
//   proof: bid.proof, gateProof: '0x', signature: '0x' })` (from core) to `publishInput`.

// 3. Decode the published plaintext. `2` is the number of counted bids.
const result = await decodeResult(plaintextHex, 2)
console.log(result.winner, result.price)
```

## API

| Export                                            | Entry     | Purpose                                                                                                  |
| ------------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------- |
| `TYPE`                                            | root      | The type id, `AuctionType.FirstPrice` (0).                                                               |
| `design`                                          | root      | Name, label, description, roles, `ciphertextsPerBid` (3), `providers` (`'none'`), `reveals` and `trust`. |
| `encodeParams(prices, title, gate?, gateConfig?)` | root      | The `customParams` of `requestE3`.                                                                       |
| `decodeResult(plaintextHex, bidders)`             | root      | Winner, price and the non-zero pattern of the result. `null` when the pattern is invalid.                |
| `expectedResult(bids)`                            | root      | The winner and the price on plaintext bids. Use it as a reference.                                       |
| `createBidProver()`                               | `/prover` | A prover with `prove(bid, levels, committeeKey, bidder, onStep?)` and `destroy()`.                       |
| `BidProver`, `BidStep`, `PreparedBid`             | `/prover` | Types of the prover.                                                                                     |

The root entry has no proving backend. The `/prover` entry loads `@aztec-foundation/bb.js` and the
circuit `auction_bid3`. The shared parts (constants, `encodeBidInput`, `selectBids`, the allowlist
tree) are in `@interfold/auction-core`.

## Limits

- The package uses the demo preset: polynomial degree N = 128, plaintext modulus t = 257. The preset
  is not secure. Use it for demonstrations only.
- An auction has 2 to 8 bidders. Each bidder gets one region of 16 slots.
- An auction has 2 to 16 price steps (levels). A bid is a step in `[0, levels)`.
- A bidder can send a first bid and 2 updates (3 bids at most).
- The prover loads the SRS (2^21 points) once. Keep one prover open for all your bids.

## API documentation

Run `pnpm docs:api` in this directory. TypeDoc writes the API reference to `docs/api`. Open
`docs/api/index.html`.
