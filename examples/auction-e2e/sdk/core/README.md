# @interfold/auction-core

The shared part of the Interfold sealed-bid auction SDK.

Interfold runs a sealed-bid auction on encrypted bids. A bidder encrypts a bid to the committee key
and proves that the bid is valid. The committee adds the encrypted bids and publishes only the
result. This package holds everything that the three auction designs share: the slot encoding, the
on-chain encoding, the bid selection, the allowlist tree, the reader of the published result and the
proving engine. Each design has its own package and builds on this package.

## Designs

| Package                                    | Type | Auction                                                            |
| ------------------------------------------ | ---- | ------------------------------------------------------------------ |
| `@interfold/auction-first-price`           | 0    | The winner pays its own bid.                                       |
| `@interfold/auction-provider-second-price` | 1    | The winner pays the second-highest bid. Mask providers send masks. |
| `@interfold/auction-qnr-second-price`      | 2    | The winner pays the second-highest bid. No mask providers.         |

Import a design package to request an auction, prove a bid and decode the result. Import this
package for the shared types and helpers. The contract, the FHE program and the circuits are the
same for all designs. Only the type id changes.

## What each design reveals and whom you trust

| Design                | Reveals                                                                                                                             | Trust                                                                                                   |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| First price           | The winner and the price (the winning bid).                                                                                         | One honest bidder for the mask randomness.                                                              |
| Provider second price | The winner and the price (the second-highest bid).                                                                                  | Privacy needs 1 honest provider out of 1 to 4. Correctness needs nobody. Liveness needs every provider. |
| QNR second price      | The winner and the price (the second-highest bid), and a faint statistical hint (at most 0.36 bits per auction on the demo preset). | Only yourself.                                                                                          |

## Install

The package is private. Use it from the pnpm workspace. Add it to the `package.json` of your
package:

```json
{ "dependencies": { "@interfold/auction-core": "workspace:*" } }
```

Run `pnpm install`. Then run `pnpm build` in `examples/auction-e2e/sdk/core`. The build copies the
compiled circuits from `examples/auction-e2e/circuits`. Run `pnpm compile:circuits` in
`examples/auction-e2e` first if they do not exist.

## Quickstart

```ts
import {
  allowlistProof,
  bidTypedData,
  bidInputsHash,
  encodeAllowlistConfig,
  selectBids,
} from '@interfold/auction-core'
import { createBidProver } from '@interfold/auction-first-price/prover'

// Restrict bidding to a list of addresses. Pass `gateConfig` with the gate to `encodeParams`.
const gateConfig = encodeAllowlistConfig(members)
const gateProof = allowlistProof(members, bidderAddress)

// Prove a bid with the prover of a design. The engine in `@interfold/auction-core/prover` is the base of every prover.
const prover = await createBidProver()
const bid = await prover.prove(7, 16, committeeKey, bidderAddress)

// Let a relayer send the bid. The bidder signs this message.
const hash = bidInputsHash(bid.commitments, bid.ciphertexts)
const typedData = bidTypedData(chainId, programAddress, e3Id, bidderAddress, 1, hash)

// Find the bids that count, from the `BidSubmitted` events of the auction.
const counted = selectBids(events, (ciphertext, commitment) => opens(ciphertext, commitment))
```

## API

| Group             | Exports                                                                                                                                                                                                             |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Constants         | `DEGREE`, `PLAINTEXT_MODULUS`, `PRESET`, `PARAM_SET`, `LEVELS`, `MIN_LEVELS`, `GROUPS`, `MIN_BIDDERS`, `MAX_BIDDERS`, `MAX_BIDS_PER_BIDDER`, `OUTPUT_COEFFS`, `MAX_PROVIDERS`, `MASK_VERSION`                       |
| Types and roles   | `AuctionType`, `AUCTION_TYPES`, `isAuctionType`, `AuctionDesign`, `Role`, `ROLE_LABELS`, `rolesFor`                                                                                                                 |
| Slot encoding     | `slotIndex`, `assertBid`, `bidSlots`                                                                                                                                                                                |
| On-chain encoding | `auctionConfigInput`, `AUCTION_CONFIG_DOMAIN`, `encodeAuctionParams`, `providersError`, `PriceList`, `priceListError`, `evenPrices`, `readPriceList`, `BidInput`, `encodeBidInput`, `bidInputsHash`, `bidTypedData` |
| Selection         | `SubmittedBid`, `SelectedBid`, `selectBids`                                                                                                                                                                         |
| Allowlist         | `MAX_ALLOWLIST_MEMBERS`, `sortedAllowlist`, `encodeAllowlistConfig`, `allowlistRoot`, `allowlistProof`                                                                                                              |
| Result            | `RegionResult`, `RegionOutput`, `assertBidderCount`, `readRegionOutput`                                                                                                                                             |
| Hex               | `toHex`, `bytesToHex`                                                                                                                                                                                               |
| `/prover`         | `ProvingEngine`, `BidTreeSpec`, `BidTreeContext`, `BidProver`, `BidStep`, `PreparedBid`, `EncryptedCiphertext`, `ProvenCiphertext`, `InnerProof`, `InnerKey`, `proofToFields`, `keyOf`, `word`                      |

The root entry has no proving backend. The `/prover` entry loads `@aztec-foundation/bb.js` and the
circuit `auction_bid_pair`. The file `vk_anchor.json` is in `circuits/`.

## Demo deployment (Sepolia)

| Item                  | Value                                                         |
| --------------------- | ------------------------------------------------------------- |
| `AuctionProgram`      | `0xaca1cD626d5E788A1dA98AC0852c171944A6A773` (block 12020400) |
| `MerkleAllowlistGate` | `0x28f004b52243926C13fCC104FD737a7646eD506F`                  |
| Interfold             | `0x0CdF132Be58dc57e1f45b39A403467c674c10b4B`                  |
| Server                | https://auction-testnet-server.theinterfold.com               |
| Mask provider         | `0x761475d370e24C7f42a12d92913C805Ab929beE1`                  |
| Site                  | https://auction-testnet.theinterfold.com                      |

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
