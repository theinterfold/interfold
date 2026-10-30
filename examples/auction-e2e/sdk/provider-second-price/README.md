# @interfold/auction-provider-second-price

Second-price sealed-bid auction with mask providers on Interfold (type 1).

The highest bid wins. The winner pays the second-highest bid. The creator names 1 to 4 mask
providers. Each provider sends one mask, and the mask proof shows that no slot of the mask is zero.
The committee multiplies the result by the masks. A non-zero slot is never read as zero, so the
result never fails to show the winner. If the top bids tie, the tied bidder who bid first wins. The
tie is not revealed.

## What the auction reveals

The result shows the winner and the price. The price is the second-highest bid. Nothing else is
revealed, if one provider is honest.

## Whom you trust

Privacy needs 1 honest provider out of the 1 to 4 that the auction names. Correctness needs nobody.
Liveness needs every provider: the auction cannot run until each provider sends its mask. Use
`checkMasks` to find the providers that did not send a valid mask.

## Install

The package is private. Use it from the pnpm workspace. Add it to the `package.json` of your
package:

```json
{ "dependencies": { "@interfold/auction-provider-second-price": "workspace:*" } }
```

Run `pnpm install`. Then run `pnpm build` in `examples/auction-e2e/sdk/provider-second-price`. The
build copies the compiled circuits from `examples/auction-e2e/circuits`. Run `pnpm compile:circuits`
in `examples/auction-e2e` first if they do not exist.

## Quickstart

```ts
import { evenPrices } from '@interfold/auction-core'
import { decodeResult, encodeParams } from '@interfold/auction-provider-second-price'
import { createBidProver } from '@interfold/auction-provider-second-price/prover'

// 1. Request an E3 with 1 to 4 mask providers. Give `customParams` to `requestE3`.
const customParams = encodeParams(evenPrices(10n, 10n, 16), 'Lot 1', [providerAddress])

// 2. A provider proves its mask. A bidder proves a bid at step 7.
const prover = await createBidProver()
const mask = await prover.proveMask(committeeKey, providerAddress)
const bid = await prover.prove(7, 16, committeeKey, bidderAddress, (step) => console.log(step.kind))
await prover.destroy()
// Send `encodeMaskInput({ provider: providerAddress, ...mask })` or `encodeBidInput(...)` to `publishInput`.

// 3. Decode the published plaintext. `2` is the number of counted bids.
const result = await decodeResult(plaintextHex, 2)
console.log(result.winner, result.price)
```

## API

| Export                                                                              | Entry     | Purpose                                                                                                      |
| ----------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------ |
| `TYPE`                                                                              | root      | The type id, `AuctionType.ProviderSecondPrice` (1).                                                          |
| `design`                                                                            | root      | Name, label, description, roles, `ciphertextsPerBid` (2), `providers` (`'required'`), `reveals` and `trust`. |
| `encodeParams(prices, title, providers, gate?, gateConfig?)`                        | root      | The `customParams` of `requestE3`.                                                                           |
| `decodeResult(plaintextHex, bidders)`                                               | root      | Winner, price and the non-zero pattern of the result. `null` when the pattern is invalid.                    |
| `expectedResult(bids)`                                                              | root      | The winner and the price on plaintext bids. Use it as a reference.                                           |
| `MAX_PROVIDERS`, `MASK_VERSION`, `providersError`                                   | root      | The provider limit (4), the leaf version of a mask, and the check of a provider list.                        |
| `encodeMaskInput(input)`                                                            | root      | The `publishInput` data of a mask.                                                                           |
| `checkMasks(masks, providers, opens)`, `SubmittedMask`, `MaskStatus`                | root      | Find the providers that sent no mask or an invalid mask.                                                     |
| `createBidProver()`                                                                 | `/prover` | A prover with `prove(...)`, `proveMask(committeeKey, provider, onStep?)` and `destroy()`.                    |
| `BidProver`, `BidStep`, `PreparedBid`, `ProviderProver`, `PreparedMask`, `MaskStep` | `/prover` | Types of the prover.                                                                                         |

The root entry has no proving backend. The `/prover` entry loads `@aztec-foundation/bb.js` and the
circuits `auction_bid2` and `auction_mask`. The shared parts (constants, `encodeBidInput`,
`selectBids`, the allowlist tree) are in `@interfold/auction-core`.

## Limits

- The package uses the demo preset: polynomial degree N = 128, plaintext modulus t = 257. The preset
  is not secure. Use it for demonstrations only.
- An auction has 2 to 8 bidders. Each bidder gets one region of 16 slots.
- An auction has 2 to 16 price steps (levels). A bid is a step in `[0, levels)`.
- A bidder can send a first bid and 2 updates (3 bids at most).
- The prover loads the SRS (2^21 points) once. Keep one prover open for all your bids.
- An auction has 1 to 4 mask providers.

## API documentation

Run `pnpm docs:api` in this directory. TypeDoc writes the API reference to `docs/api`. Open
`docs/api/index.html`.
