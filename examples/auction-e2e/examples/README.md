# Auction SDK examples

Three scripts run one complete sealed-bid auction each on the live Sepolia deploy. Each script uses
one design SDK. Each script does these steps:

1. Request an auction of its type and pay the fee.
2. Wait for the committee key.
3. Encrypt and prove two bids.
4. Publish the two bids.
5. Wait for the committee to publish the result.
6. Decode the result and compare it with the plaintext reference.

| Command                              | Design SDK                                 | Mask providers                                                 | Price the winner pays  |
| ------------------------------------ | ------------------------------------------ | -------------------------------------------------------------- | ---------------------- |
| `pnpm example:first-price`           | `@interfold/auction-first-price`           | none                                                           | its own bid            |
| `pnpm example:provider-second-price` | `@interfold/auction-provider-second-price` | the demo server (`0x761475d370e24C7f42a12d92913C805Ab929beE1`) | the second-highest bid |
| `pnpm example:qnr-second-price`      | `@interfold/auction-qnr-second-price`      | none                                                           | the second-highest bid |

In each run, bidder 1 bids step 5 and bidder 2 bids step 9 of 16 steps (100, 200, ... 1600). Bidder
2 wins. The first-price auction charges step 9 (price 1000). The two second-price auctions charge
step 5 (price 600).

> **These scripts spend real Sepolia ETH.** Do not run them without a funded test account. Only use
> a key that holds testnet funds.

## Prerequisites

- Node.js 22 or later and pnpm.
- A Sepolia account with at least 0.02 ETH, and an HTTPS Sepolia RPC endpoint.
- A machine that can run the Barretenberg prover (the proofs use several GiB of RAM).
- A built workspace. `@interfold/sdk` must be built (`pnpm sdk:build` at the repository root). Then
  `pnpm dev:setup` in `examples/auction-e2e` compiles the circuits, builds the four SDK packages and
  compiles the contracts with their TypeChain types (`types/`):

  ```sh
  pnpm install
  pnpm sdk:build
  cd examples/auction-e2e
  pnpm dev:setup
  ```

  If the circuits are already compiled, `pnpm build:sdk && pnpm compile` in `examples/auction-e2e`
  is enough.

The scripts use the live deploy addresses in `examples/lib/config.ts`. They need no deploy.

## Environment variables

Put them in the shell or in a `.env` file in `examples/auction-e2e`.

| Variable              | Required | Meaning                                                                                                                                                             |
| --------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SEPOLIA_RPC_URL`     | yes      | HTTPS endpoint of a Sepolia node.                                                                                                                                   |
| `PRIVATE_KEY`         | yes      | Key of the creator and bidder 1 (64 hex characters, `0x` optional). It needs Sepolia ETH.                                                                           |
| `BIDDER2_PRIVATE_KEY` | no       | Key of bidder 2. It must differ from `PRIVATE_KEY`. If you do not set it, the script makes a new key, funds it for one bid, and sends the leftover back at the end. |
| `WINDOW_MINUTES`      | no       | Minutes from the request to the end of the bid window. Default 30. Minimum 15.                                                                                      |

If a required variable is missing, the script prints the missing names and stops before it sends a
transaction.

## Cost

| Item                                     | Amount                                                                                                        |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Gas for each bid                         | about 6 M gas                                                                                                 |
| ETH funding for a generated bidder 2     | 7 M gas at twice the current fee, at least 0.005 ETH (the script refunds what is left)                        |
| Gas for the request and the fee approval | small compared with the bids                                                                                  |
| Fee token (MockUSDC)                     | about 15.5 M units for each request. The script takes the units from the faucet if the creator holds too few. |

## Expected runtime

| Step                                             | Time                                                       |
| ------------------------------------------------ | ---------------------------------------------------------- |
| Key generation by the committee                  | 5 to 8 minutes                                             |
| Proof of each bid                                | 1 to 5 minutes                                             |
| Mask from the demo server (provider design only) | about 2 minutes after the key, in parallel with the proofs |
| Wait for the end of the bid window               | up to `WINDOW_MINUTES` after the request                   |
| Result after the window closes                   | about 1 minute                                             |

A whole run takes about 30 to 35 minutes with the default window. The script prints a line for each
step, so you can see the progress. If the script stops with an error, it sends the funds that are
left on the generated bidder 2 back to the creator. If you kill the process, these funds stay on
bidder 2.

## Sample output

A real run of `pnpm example:qnr-second-price` on Sepolia, shortened (hashes cut, proof steps left
out):

```text
Auction design: Second-price, no providers
Program: 0xaca1cD626d5E788A1dA98AC0852c171944A6A773 (Sepolia)
Bidder 1 (creator): 0x8837e47c4Bb520ADE83AAB761C3B60679443af1B
Bidder 2 (new key, funded by the creator): 0x6739836B6Acb0F1b4107Eeeb1332550505B42508

== 1. Request the auction ==
[  0m09s] Funded bidder 2 with 0.005 ETH, tx 0xb902...9839
[  0m34s] Approved a fee of at most 17117980 fee-token units (quote 15561800), tx 0xe771...f47b
[  0m47s] Requested E3 582189...327059, tx 0x9f56...f218, block 12026632
[  0m47s] Bid window: 2026-10-30T12:23:12.000Z to 2026-10-30T12:49:12.000Z

== 2. Wait for the committee key ==
[  5m23s] Committee key published and verified after 4m47s; stage KeyPublished

== 3. Prove the bids ==
[  7m54s] Bidder 1 proved a bid of step 5 in 2m31s
[ 10m53s] Bidder 2 proved a bid of step 9 in 2m59s

== 4. Publish the bids ==
[ 10m58s] Bidder 1 published its bid, tx 0xce75...38ea, gas 6309052
[ 11m11s] Bidder 2 published its bid, tx 0xe362...c5bc, gas 6342702

== 5. Wait for the result ==
[ 11m11s] The bid window closes at 2026-10-30T12:49:12.000Z. The server then starts the encrypted computation.
[ 30m47s] Plaintext output published 40s after the window closed

== 6. Decode the result ==
E3:       582189...327059
Design:   Second-price, no providers
Bids:     bidder 1 step 5, bidder 2 step 9 (price of a step: 100, 200, ..., 1600)
Decoded:  winner bidder 2 0x6739836B6Acb0F1b4107Eeeb1332550505B42508, step 5, price 600
Expected: winner bidder 2, step 5, price 600
Timings:  key generation 4m47s, proofs 2m31s and 2m59s, result 40s after the window closed, total 30m47s
Result matches the plaintext reference.
[ 31m00s] Refunded 0.004999999578609668 ETH from bidder 2 to the creator, tx 0xc07f...649b
```

The provider design prints one more step, "Wait for the mask providers", before it publishes the
bids.

If the decoded result and the reference differ, the script prints `MISMATCH` and exits with code 1.

## Files

- `first-price.ts`, `provider-second-price.ts`, `qnr-second-price.ts`: the design-specific part
  (prices, request parameters, bids). Read one of them to see how a design SDK is used.
- `lib/config.ts`: the live deploy addresses and the environment loader.
- `lib/auction.ts`: the flow that is the same for all designs (fee, request, wait for key, prove,
  publish, wait for result, decode).
- `lib/log.ts`: the transcript output and the polling helper.

To type-check the scripts without running them: `pnpm exec tsc --noEmit -p .` in
`examples/auction-e2e`.
