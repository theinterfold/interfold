# Sealed-bid auctions

This example is a standalone sealed-bid auction application on Interfold. Anyone connects a wallet
and creates an auction. Other users connect a wallet and bid. No one sees a bid. The committee
decrypts one result.

The creator selects the auction type:

| Type                      | Bidders | Winner                                                                   | Price                                                 | The result shows                          |
| ------------------------- | ------- | ------------------------------------------------------------------------ | ----------------------------------------------------- | ----------------------------------------- |
| First-price               | 2 to 4  | the highest bid                                                          | the highest bid                                       | the winner, the price                     |
| Second-price (Vickrey)    | 2 to 4  | the highest bid                                                          | the second-highest bid                                | the winner, the price                     |
| First-price, ratio lanes  | 2 to 8  | the highest bid; on a tie, one of the tied bidders by a random value     | the highest bid                                       | the price, the tie set, a random value    |
| Second-price, ratio lanes | 2 to 8  | the highest bid; on a top tie, one of the tied bidders by a random value | the second-highest bid (the highest bid on a top tie) | the price, the winner set, a random value |

For a second-price auction, the winning bid stays secret, except when the top bids tie: then the
price is the tied bid. The two region types (first-price and Vickrey) resolve a tie inside the
computation and do not show it. The two ratio-lane types show the tie set: the bidders whose bid
equals the price. They pick the winner from it with the random value of the result.

| Step           | What happens                                                                                                                                                             |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Create         | The creator pays the E3 fee and requests an E3. The request carries the type, the title and the price of each bid level.                                                 |
| Key generation | The ciphernodes run a distributed key generation. It makes the l-BFV public key and the threshold relinearization key.                                                   |
| Bid            | Each bidder encrypts a bid in the browser and proves the bid is valid.                                                                                                   |
| Computation    | The FHE program multiplies ciphertexts. It uses the threshold relinearization key.                                                                                       |
| Decryption     | The committee decrypts one ciphertext. It holds the winner and the price only.                                                                                           |
| Result         | The web app decodes the result and shows the winner and the price. Region types also show the tie priority. Ratio-lane types also show the tie set and the random value. |

This example runs on the **insecure SIMD parameters (parameter set 5: N = 128, t = 257)**. They are
for development and give no security.

The four types come from the design study in [`../auction`](../auction): the designs in Rust, a
plaintext simulation, a design visualizer (`../auction/viz`) and the report for review
(`../auction/REPORT.md`).

## How a bid works

A bid is a whole number `b` from 0 to 15. The 128 slots of the SIMD plaintext hold 8 groups of 16
slots. Slot `i` has level `i % 16`. Each bidder sends three ciphertexts, or four for the
second-price ratio-lane type:

| Role | Name       | Slot `i` holds                                                                                                                      | Types                   |
| ---- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| 0    | `ge`       | `1` if `b >= i % 16`, else `0`                                                                                                      | all                     |
| 1    | `gt`       | `1` if `b > i % 16`, else `0`                                                                                                       | all                     |
| 2    | `mask`     | a uniform random value in 0 to 256                                                                                                  | all                     |
| 3    | `pairMask` | a uniform random value. Slot `(2c) * 16 + l` and slot `(2c + 1) * 16 + l` hold the same value, for `c` in 0 to 3 and `l` in 0 to 15 | ratio-lane second-price |

These ciphertexts do not depend on the number of bidders or on the position of the bidder.

`AuctionProgram.validate` reads
`customParams = abi.encode(uint8 auctionType, uint256[16] prices, string title)`. It stores the
auction and emits `AuctionCreated`. It inserts leaf 0: the configuration leaf,
`keccak256("interfold-auction-config-v1" || auctionType)` in the BN254 field. `prices[b]` is the
price of bid level `b`. The prices must increase strictly; the steps can be uneven. Read them with
`auctionPrices(e3Id)`. The program and the circuits see only levels, so the prices do not change the
computation. The coordination server gives the program the configuration bytes as input 0. The
program reads the type from them, so the compute proof binds the type through the input root.

`AuctionProgram.publishInput` takes one ciphertext in each call. The bidder is the sender. Each role
is accepted once for each bidder. `roleCount(type)` gives the number of roles of a type (3 or 4).
The roles 2 and 3 have no bid commitment, and `bidCommitment` is 0 for them. When all roles of the
type are in, the contract inserts their commitments as consecutive leaves, from leaf 1: `roleCount`
leaves for each bidder. It emits `BidLinked`. `submittedRoles(e3Id, bidder)` is a bit mask of the
roles of a bidder: 7 (3 roles) or 15 (4 roles) when the bidder is linked. The FHE program reads the
leaves after the configuration in groups of `roleCount` ciphertexts, one group for each bidder.
`maxBidders(type)` gives the limit of a type: 4 for the region types and 8 for the ratio-lane types.

### The program: region types

With `n` bidders, the program makes `floor(8 / n)` copies of `n` regions. A region has 16 slots. The
program zeroes the unused groups. It multiplies a test vector by the sum of the bidder masks. A slot
is uniform where the test is non-zero, so the result shows only the zero slots.

The tie priority comes from the published ciphertexts. The seed is `keccak256` of the `ge`
ciphertexts of all bidders in leaf order. The program ranks the bidder positions by
`keccak256(seed || u32_be(position))`. The highest hash gets priority `n - 1`. The priority is fixed
only when the last `ge` ciphertext is in. A tie at the top goes to the bidder with the higher
priority.

**First-price.** One ciphertext product, depth 1. The result has one zero slot in each copy: the
region of the winner, at the highest bid `h`.

**Second-price.** Four ciphertext products, each relinearized with the threshold key, depth 3. With
`s` the second-highest bid:

- At a level below `s`, every region is non-zero.
- At level `s`, only the region of the winner is zero.
- At a level above `s`, every region is zero.

All other slots hold uniform random values. The result does not show the other bids or a tie. For a
second-price auction it also does not show the winning bid. `shared/layout.ts` decodes the result. A
set slot reads as zero by error with probability `1 / 257` for each copy.

### The ratio-lane types

The ratio-lane types have no regions and no tie priority. Bidder position `k` (leaf order) has the
weight `w_k = 2^k`. The weights of 8 bidders add up to `255`, which is below `t = 257`. A sum of
weights thus shows which bidders it contains. A bit of the sum is a bidder. The tie set is the set
of bidders whose bid equals the price.

In the formulas, `C` is the number of bids at least `p`, `A` is the number of bids above `p`, `m` is
the sum of the masks and `R` is the sum of the pair masks. `Z` is the sum of `w_k * ge_k`, `G` is
the sum of `w_k * gt_k` and `E = Z - G`.

**First-price, ratio lanes.** One ciphertext product, depth 1. Level `p` is slot `p` of group 0:
`out[p] = Z[p] + m[p] * A[p]`. With `h` the highest bid:

- At a level above `h`, the lane is 0.
- At level `h`, the lane is the sum of the weights of the tie set.
- At a level below `h`, the lane is uniform.

**Second-price, ratio lanes.** Six ciphertext products, depth 3. There are three copies. In copy
`c`, group `2c` holds the `y` lanes and group `2c + 1` holds the `z` lanes:

```text
c = C (C - 1)      u = A (A - 1)      L = G + (1 - A) E
y[p] = R[p] c[p]        + m[p] u[p]
z[p] = R[p] c[p] L[p]   + m'[p] u[p]
```

The pair mask gives the same `R` to the `y` lane and the `z` lane of a level. With `s` the
second-highest bid (the highest bid when the top bids tie):

- At a level above `s`, both lanes are 0.
- At level `s`, `u = 0`. Then `z / y = L`, which is the sum of the weights of the winner set: the
  one top bidder, or the tie set when the top bids tie.
- At a level below `s`, `(y, z)` is a uniform pair.

The decoder takes `s` as the highest level with `y != 0`, and the highest `s` of the three copies.
`y` at `s` is 0 only if `R` is 0 there. This has the probability `1 / 257` for one copy and
`1 / 257^3` for the three copies. The decoder reads the ratio `z / y` from a copy that shows
`y != 0`. All copies must show the same ratio.

**The random lane.** Both ratio-lane types have one more slot: slot 16 (first-price) or slot 96
(second-price). It holds the sum of the masks at that slot, and no result lane uses it. It is
uniform if one bidder is honest. The encrypted masks fix it, so no bidder can know it before the
window closes, and no bidder can grind it alone. The result shows it. The winner is
`tieSet[random mod |tieSet|]`, with the tie set sorted by bidder position. A bidder without a tie
wins with certainty. Every slot that is not a result lane or the random lane is 0.

The result is a function of the price, the tie set and the random value only. It does not show the
other bids, or any count. Compared with the region types, a ratio-lane type shows the tie set. It
does not need regions, so it supports 8 bidders. The lane count does not depend on the number of
bidders. The fourth ciphertext of the second-price type adds about 40 seconds of proof time for each
bid.

## What is proven

- **`circuits/record`** (`auction_bid`): for the roles 0 and 1, the plaintext is the thermometer of
  a private bid `b` below 16. The circuit also returns `bid_commitment = poseidon2(b, salt)`. For
  the mask, `k1` is free and `bid_commitment` is 0. For the pair mask (role 3), the plaintext is a
  mod-`t` combination of 64 unit rows, one for each `(c, l)`. Thus the slots `(2c) * 16 + l` and
  `(2c + 1) * 16 + l` are equal, and `bid_commitment` is 0. Without this proof, a bidder could give
  `R` two values (in the `y` lane and in the `z` lane) and change the winner that the decoder reads.
  The thermometers come from a table that `program/examples/bid_table.rs` generates from fhe.rs.
- **Interfold user-data encryption proof**: the ciphertext encrypts that plaintext under this E3
  committee key.
- **`circuits/fold`** (`auction_fold`): it verifies both proofs and checks that they use the same
  plaintext. Its public inputs are the role, the ciphertext commitment, the bid commitment, the
  bidder address, the committee key commitment and a VK anchor. Only this proof leaves the browser.

The contract gives `msg.sender` as the bidder address. Thus a proof that another address copies
fails. Without this, a copy of the thermometers of the highest bidder would make a tie at that bid,
and the price would show the bid.

The contract rejects a second thermometer that has a different bid commitment from the first. Thus
both thermometers come from one bid. The cap is `maxBidders(type)`: 4 for the region types, 8 for
the ratio-lane types.

## Prerequisites

- Rust, Node, pnpm, `nargo` 1.0.0-beta.26, `bb` 5.2.0 and Foundry (`anvil`).
- An `interfold` CLI built from this checkout. `pnpm dev:setup` installs it.

Proof aggregation stays on everywhere, tests included. The l-BFV key aggregator has no skip path.
The deploy uses the real DKG and decryption verifiers (`ENABLE_ZK_VERIFICATION=true` in
`scripts/lib/dev_config.sh`).

## Run it

Run these commands in this order.

1. Build the Noir circuits for the insecure SIMD preset. Run it in the repository root:

   ```sh
   pnpm build:circuits --preset insecure-simd --committee minimum
   ```

2. Build the SDK. It bundles the user-data encryption circuits. Run it after the last circuit build:
   a later circuit build cleans `circuits/bin/threshold/target`, and the SDK reads a circuit from
   that directory.

   ```sh
   pnpm sdk:build
   ```

   The SDK build selects `insecure/minimum` at its end. Step 3 selects `insecure-simd/minimum`
   again.

3. Set up the example. This step runs `scripts/compile_circuits.sh`, which compiles `auction_bid`
   and `auction_fold` and writes the fold verifier and the VK anchor. It builds
   `program/examples/vk_hash.rs` to hash the verification keys:

   ```sh
   pnpm install
   pnpm dev:setup
   ```

4. Start the stack: anvil, the ciphernodes, the program server, the coordination server and the web
   app:

   ```sh
   pnpm dev:all
   ```

If `interfold noir setup` (the last step of `dev:setup`) fails with
`checksum missing for circuits-<version>.tar.gz`, the CLI `versions.json` has no checksum for that
version. Pack the build of this repository instead:

```sh
STAGE=$(mktemp -d) && mkdir -p "$STAGE/circuits/insecure-simd"
cp -R ../../dist/circuits/insecure-simd/minimum "$STAGE/circuits/insecure-simd/"
jq '.files |= with_entries(select(.key | startswith("insecure-simd/minimum/")))' \
  ../../dist/circuits/checksums.json > "$STAGE/circuits/checksums.json"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$STAGE" -czf /tmp/auction-circuits.tar.gz circuits
interfold noir setup --circuits-archive /tmp/auction-circuits.tar.gz \
  --circuits-configuration insecure-simd/minimum --allow-unpinned-archive
```

`COPYFILE_DISABLE=1` stops macOS `tar` from adding `._*` entries. The installer refuses those
entries.

### Use the web app

Open <http://localhost:3000>. The app has three pages: **Auctions** (the list), **Create** and **How
it works**.

1. **Connect a wallet.** Add the anvil network to a browser wallet (chain ID 31337, RPC
   `http://localhost:8545`). Import some of the well-known anvil keys. Do not use accounts 1 to 5:
   they are the ciphernodes. Use these keys on a local chain only.
2. **Get test tokens.** A request pays a fee in the fee token. On anvil, select **Get test tokens**
   to mint some.
3. **Create an auction.** Enter a title (1 to 80 bytes), select the type, the price levels and the
   bidding duration. The page offers four types: first-price, second-price (Vickrey), first-price
   with ratio lanes and second-price with ratio lanes. It shows the bidder limit of the chosen type
   (2 to 4 bidders for the first two types, 2 to 8 for the ratio-lane types) and the number of
   ciphertexts of each bid. A ratio-lane auction resolves a top tie with a public random draw among
   the tied bidders. The tie set becomes public: the result names every bidder that tied. For the
   price levels, select **Even steps** (a start price and a step) or **Custom list** (16 prices that
   increase, for example a 1-2-5 scale). Key generation takes some minutes. Bidding opens when the
   committee publishes the key, and it closes at the end of the duration.
4. **Bid.** Open the auction page from another account. Select one of the 16 prices that the creator
   set. Select the bid button. A bid is 3 ciphertexts: the bid thermometer "at least", the bid
   thermometer "above" and a random mask. A ratio-lane second-price bid adds a fourth, the paired
   mask. The browser encrypts and proves each ciphertext, and the wallet publishes each one. Each
   proof takes some minutes. The bidder is linked, and takes one of the places, when all ciphertexts
   of the type are on chain (`submittedRoles` is 7, or 15 for ratio-lane second-price). The auction
   is full when `linkedBidders` reaches the limit of its type. The bid and its salt stay in the
   browser storage: a page reload resumes an incomplete bid and sends only the missing ciphertexts.
5. **Result.** When the window closes, the server computes the result, and the committee decrypts
   it. The page decodes the published plaintext in the browser. First-price and Vickrey show the
   winner, the price, your outcome and the region grid (one row for each bidder, one column for each
   level). The grid shows that the region of the winner is the only zero region at the price level.
   Ratio-lane types show the winner, the price and one lane of 16 slots: zero above the price, the
   set of tied bidders at the price, and random values below. If more than one bidder tied, the page
   also shows the tie set, the random value `r` and the draw `r mod |tie set|`. The page shows an
   error when a lane does not decode to a price and a tie set, when the copies of ratio-lane
   second-price disagree, or when the random lane is unreadable during a tie.

An auction needs 2 bidders at least, and 4 (region types) or 8 (ratio-lane types) at most. With
fewer than 2 complete bids, the server computes nothing, and the E3 fails at its compute deadline.

## Test

```sh
cargo test --release -p e3-user-program   # the FHE program, all four types, against a local l-BFV key
(cd circuits/record && nargo test)        # the bid validity rules
pnpm test:integration                     # DKG -> 29 proven ciphertexts -> FHE -> threshold decryption, all four types
```

The integration test runs four auctions at the same time:

| Type                      | Bids         | Result checked                                           |
| ------------------------- | ------------ | -------------------------------------------------------- |
| Second-price (Vickrey)    | `[5, 12, 9]` | bidder 1 wins at price 9                                 |
| First-price               | `[6, 11]`    | bidder 1 wins at price 11                                |
| First-price, ratio lanes  | `[4, 13]`    | price 13, tie set `[1]`, bidder 1 wins                   |
| Second-price, ratio lanes | `[7, 7]`     | price 7, tie set `[0, 1]`, winner `tieSet[random mod 2]` |

The test also checks that the contract rejects a second thermometer with a different bid commitment,
a proof sent from another address, and role 3 in an auction that has 3 roles. It checks `roleCount`,
`maxBidders`, `submittedRoles` and the leaves of each bidder. `cargo test` covers more ties, 8
bidders, the zero slots of the output and the plaintext formulas of the ratio-lane types.
`pnpm test:server` runs the unit tests of the server, including the input assembly for 3 and 4
roles.

## Deploy to Sepolia

The app can run on Sepolia. This checkout has made no Sepolia deployment. The steps below prepare
one. The local flow does not change: on chain 31337 the deploy uses the mock data-availability
verifier, and the server uses `mock_http`.

Read "Limits on Sepolia" at the end of this section first. The parameters are insecure, and the
compute proof is a mock.

### 1. Choose the Interfold protocol

| Target            | What you need                                                                                                                                                  |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Your own protocol | Deploy the protocol from this branch (`pnpm protocol:deploy` in `packages/interfold-contracts`). Your account owns it, so the deploy wires the program itself. |
| The official one  | The addresses are in `packages/interfold-contracts/deploy/protocol/sepolia-protocol.deployment.json`. The owner is a Safe.                                     |

The official Sepolia deployment cannot run this app yet:

- It has no route for parameter set 5 (insecure SIMD, l-BFV). Its routes cover the parameter sets 0
  and 2. The owner must add the route for set 5.
- Interfold keeps one ciphertext verifier for each encryption scheme (`fhe.rs:BFV`).
  `setCiphertextVerifier` replaces the verifier that other programs, such as CRISP, use for new E3s.
  With the mock compute verifier, this change also stops the proof check for those programs. Use
  your own protocol, or agree the change with the owner.
- The deploy script cannot call `setCiphertextVerifier` or `registerE3Program`. It prints the calls
  for the Safe (step 4).

Your protocol and the official one need these as well:

- Ciphernodes that run the insecure SIMD l-BFV circuits (`BFV_PRESET=insecure-simd`). Register and
  bond them in the registry. The `minimum` committee has 3 nodes. Enable the `sepolia` chain in
  `interfold.config.yaml` (`enabled: true`) and start each node with `interfold start`.
- The built circuits of this example: `pnpm dev:setup` writes `circuits/target/vk_anchor.json` and
  the fold verifier. The deploy reads both.
- Sepolia ETH for the deploy account and for the server key. The auction creators need the fee token
  of the protocol.

### 2. Set up Avail

The server publishes each ciphertext output to Avail. The `AvailVectorXDataAvailabilityVerifier`
checks the VectorX proof on Ethereum. Only the output uses Avail. The bids are calldata of
`publishInput`.

1. Create an Avail application ID on the Avail testnet (Turing). Sepolia uses the Turing VectorX
   bridge.
2. Create an Avail account and fund it with testnet tokens. Its secret URI is `AVAIL_SEED`.
3. Build the helper that the server runs:

   ```sh
   cargo build --release -p auction-da
   ```

`auction-da` has two commands. Each prints one JSON document.

```sh
# Environment: AVAIL_RPC_URL, AVAIL_APP_ID, AVAIL_SEED, AVAIL_BRIDGE_API_URL, DESTINATION_CHAIN_ID
auction-da submit --file ciphertext.bin     # waits for Avail finality; prints the publication
auction-da proof --pending '<publication>'  # prints {"status":"pending"} or {"status":"ready", ...}
```

The timing matters:

- Avail finalizes the data in minutes. `auction-da submit` waits for it, for up to 5 minutes.
- The VectorX proof can take up to about 3 hours. CRISP reserves 10 800 seconds for it.
- The compute window starts when the input window closes. The compute, the Avail finalization, the
  proof and the publication transaction must all fit in it. The official Sepolia value is 604 800
  seconds (7 days). For your own protocol, set `interfold.timeoutConfig.computeWindow` to at least
  14 400 seconds (4 hours).
- The input window needs no Avail time, because the bids do not use Avail.

### 3. Deploy the program

Compile first (`pnpm compile`). Then deploy:

```sh
export SEPOLIA_RPC_URL=https://...        # an HTTP RPC endpoint
export PRIVATE_KEY=0x...                  # the deploy key. Never commit it.
export INTERFOLD_ADDRESS=0x...            # the protocol; the script does not need a record of it
export TEMPLATE_UNPROVED_TEST=1           # the mock compute verifier
export ALLOW_SEPOLIA_UNPROVED_COMPUTE=true  # the explicit acknowledgment that Sepolia requires
pnpm deploy:sepolia
```

| Variable                                 | Effect                                                                                                                                                                                                                                                       |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SEPOLIA_RPC_URL`                        | The RPC endpoint of the `sepolia` network. It falls back to `RPC_URL`.                                                                                                                                                                                       |
| `PRIVATE_KEY`                            | The deploy key. The `sepolia` network has no other account.                                                                                                                                                                                                  |
| `INTERFOLD_ADDRESS`                      | The Interfold address. Without it the script reads `deployed_contracts.json`.                                                                                                                                                                                |
| `POSEIDON_T3_ADDRESS`                    | The `PoseidonT3` library. Without it the script uses the record, then the canonical address, then deploys it.                                                                                                                                                |
| `TEMPLATE_UNPROVED_TEST=1`               | Deploy `MockOpenVmReceiptVerifier`. It accepts every compute receipt. Chain 31337 allows it. Sepolia also needs the next variable.                                                                                                                           |
| `ALLOW_SEPOLIA_UNPROVED_COMPUTE`         | `true` acknowledges the mock compute verifier on Sepolia. Every other chain refuses it.                                                                                                                                                                      |
| `MOCK_DATA_AVAILABILITY=true`            | Deploy `MockDataAvailabilityVerifier` on a public testnet. Mainnet refuses it. The server needs `DATA_AVAILABILITY_MODE=mock_http`, and the `sepolia` chain of `interfold.config.yaml` needs `data_availability.mode: mock_http` with the URL of the server. |
| `DEFER_PROTOCOL_WIRING=true`             | Skip `setCiphertextVerifier` and `registerE3Program` even when the key is the owner.                                                                                                                                                                         |
| `ALLOW_REPLACE_CIPHERTEXT_VERIFIER=true` | Replace a ciphertext verifier that the protocol already has. Without it, the script prints the calls instead.                                                                                                                                                |

Without `TEMPLATE_UNPROVED_TEST`, the script deploys the real `OpenVmReceiptVerifier` with the
identity that `interfold program compile` wrote. Real proofs on Sepolia are not tested. Without
`MOCK_DATA_AVAILABILITY`, the data-availability verifier is `AvailVectorXDataAvailabilityVerifier`
with the Sepolia bridge and VectorX addresses of `@interfold/contracts`.

The script records every address in `deployed_contracts.json` and writes `e3_program` and its
`deploy_block` to the `sepolia` entry of `interfold.config.yaml`. Write down the `deploy_block`. The
server needs it as `DEPLOY_BLOCK`.

### 4. Wire the protocol

If the deploy key is the Interfold owner, the script sends `setCiphertextVerifier` and
`registerE3Program` and checks `e3Programs`. Otherwise it prints both calls as JSON with `to`,
`function`, `args` and `data`. Send them in that order from the owner (for example a Safe batch).
The program is not usable until both calls are executed.

### 5. Run the server

Copy `server/.env.example` and fill the Sepolia block. The server refuses a bad configuration at
start.

```sh
set -a && source server/.env && set +a
pnpm tsx ./server/index.ts
```

Or run the Docker image. Build it from the repository root, after the host builds that the
`Dockerfile` header lists:

```sh
docker build -f examples/auction-e2e/server/Dockerfile -t auction-server .
docker run -p 8080:8080 -v auction-data:/data --env-file examples/auction-e2e/server/.env auction-server
```

| Variable                                                                           | Use                                                                                                                                            |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `RPC_URL`, `WS_RPC_URL`, `CHAIN_ID`, `PRIVATE_KEY`                                 | The chain (31337 or 11155111), the HTTP endpoint, an optional WebSocket endpoint for the live listener, and the operator key.                  |
| `INTERFOLD_ADDRESS`, `REGISTRY_ADDRESS`, `FEE_TOKEN_ADDRESS`, `E3_PROGRAM_ADDRESS` | The contracts.                                                                                                                                 |
| `DEPLOY_BLOCK`, `LOG_CHUNK_SIZE`                                                   | The first block to scan, and the largest log range of one request (default 10 000). `DEPLOY_BLOCK` is required on Sepolia.                     |
| `PORT`, `PROGRAM_RUNNER_URL`, `CALLBACK_URL`                                       | The listen port, the program runner and the base URL of this server that the runner calls back. In Docker, use service names, not `127.0.0.1`. |
| `DATA_AVAILABILITY_MODE`                                                           | `mock_http` (default) or `avail`.                                                                                                              |
| `AVAIL_RPC_URL`, `AVAIL_APP_ID`, `AVAIL_SEED`, `AVAIL_BRIDGE_API_URL`              | The Avail settings of `avail` mode. `DESTINATION_CHAIN_ID` is `CHAIN_ID`.                                                                      |
| `AVAIL_PROOF_POLL_INTERVAL_SECONDS`, `AUCTION_DA_BIN`                              | The proof poll interval (default 60) and the path of `auction-da`.                                                                             |
| `DATA_DIRECTORY`                                                                   | The directory of the published objects and the Avail records. Keep it on a volume.                                                             |

The server does this:

- At start it lists the `AuctionCreated` events from `DEPLOY_BLOCK`. For each auction that has a
  committee key and no output, it rebuilds the key from the historical events, checks the key
  commitment and schedules the compute.
- In `avail` mode it stores each output in `DATA_DIRECTORY/e3-<id>/`, publishes it to Avail, polls
  the proof and then calls `publishCiphertextOutput` with the ABI proof as the availability proof.
  After a restart it resumes each unfinished output. It checks the E3 stage before it publishes, so
  it never publishes an output twice.
- It gives each run a random token and sends the runner `CALLBACK_URL/callback/<e3Id>/<token>`. The
  callback accepts only that token. A failed run is tried again with backoff until the E3 leaves
  `KeyPublished` or chain time passes the compute deadline.
- In `avail` mode it calls `verify` on the program before it spends Avail funds on an output.
- `GET /health` returns 200 when the process is up.

Run `pnpm test:server` for the unit tests of the configuration, the log chunks and the publication
steps.

### 6. Run the program runner

Run it where the ciphernodes can reach it, and put its URL in `PROGRAM_RUNNER_URL`. The server must
be reachable from the runner at `CALLBACK_URL`.

```sh
E3_PROGRAM__DEV=true interfold program start   # the unproved runner that matches the mock compute verifier
```

### 7. Deploy the web app

The web app is a static Vite build. Vercel cannot build it from git: the build needs the compiled
circuits, `types/` and the built SDK and wasm package, and none of them is committed. Build it on a
prepared host and upload the output.

1. Prepare the host. Run `pnpm dev:setup` and `pnpm compile` in this directory, and build the
   workspace packages the client imports (`@interfold/sdk` and `@interfold/contracts`).
2. Link the client to a Vercel project: `cd client && vercel link`.
3. Pull the project settings: `vercel pull --yes --environment=production`. Set the `VITE_*`
   variables of `client/.env.example` on the project first. Every value is public in the bundle: put
   no secret in them. For Sepolia: `VITE_CHAIN_ID=11155111`, `VITE_RPC_URL`, `VITE_DEPLOY_BLOCK`
   (the program `deploy_block`), `VITE_LOG_CHUNK_SIZE`, the four contract addresses and, if you want
   them, `VITE_FAUCET_ADDRESS` and `VITE_WALLETCONNECT_PROJECT_ID`.
4. Build locally: `vercel build --prod`. This runs `pnpm run build` and writes
   `client/.vercel/output`.
5. Upload the output: `vercel deploy --prebuilt --prod`.

`client/vercel.json` turns off git deployments and the install step, and keeps the cross-origin
isolation headers and the single-page rewrite. Prover threads need those headers.

### Limits on Sepolia

- The parameters are insecure (N = 128, t = 257). They give no security. Do not use the app for
  anything of value.
- The compute proof is a mock. The on-chain verifier accepts every compute receipt. Nothing proves
  that the output follows from the bids. Trust the operator of the server and of the program runner.
- Data availability is real: the VectorX proof is checked on Ethereum. The server key and the Avail
  account are single points of trust and of availability.
- The VectorX proof takes hours. A result appears after the compute, the Avail finalization, the
  proof and the decryption.
- The official Sepolia deployment needs the owner to add the route for parameter set 5, and a change
  of the shared ciphertext verifier (step 1).
- No Sepolia deployment of this app was run from this checkout. Test each step on your own before
  you rely on it.

## Timings

These figures come from one run of `pnpm test:integration` (Node, 11 prover threads) and one web app
run in headless Chromium, on an Apple Silicon laptop. They are estimates.

| Step                                                                 | Time                                                                                       |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Proofs for one ciphertext (Node)                                     | about 40 seconds                                                                           |
| Proofs for one bidder (Node, 3 ciphertexts)                          | about 2 minutes                                                                            |
| Proofs for one bidder (Node, 4 ciphertexts, ratio-lane second-price) | about 2.7 minutes (estimate: 4 times the time of one ciphertext)                           |
| Proofs for one bidder (browser, 3 ciphertexts)                       | about 5 minutes                                                                            |
| Proofs for one bidder (browser, 4 ciphertexts)                       | about 7 minutes (estimate)                                                                 |
| Key generation (request to published key, real DKG)                  | 6 to 13 minutes for one auction; about 26 minutes when the test runs four at the same time |
| Threshold decryption (ciphertext output to result)                   | about 20 seconds                                                                           |
| Integration test (4 auctions, 9 bidders, 29 ciphertexts)             | about 71 minutes                                                                           |

## Layout

| Path                            | What                                                                                           |
| ------------------------------- | ---------------------------------------------------------------------------------------------- |
| `shared/layout.ts`              | the slot encoding, the roles and limits of each type, the tie priority and the result decoders |
| `shared/prover.ts`              | encrypt, the three proofs and the `publishInput` calldata                                      |
| `circuits/`                     | `auction_bid`, `auction_fold`; `scripts/compile_circuits.sh`                                   |
| `contracts/AuctionProgram.sol`  | auction config, bidder roles, proof check, bidder linkage, DA check                            |
| `program/src/lib.rs`            | the FHE processor and the input policy (all four auction types)                                |
| `program/examples/bid_table.rs` | the generator of `circuits/record/src/constants.nr`                                            |
| `program/examples/vk_hash.rs`   | the hash of ordered VK hashes, for the VK anchor                                               |
| `runner/`                       | the program server (`program-runner`) that serves `program/`                                   |
| `guest/`                        | the OpenVM guest that proves the program                                                       |
| `server/`                       | the coordination server: events, compute, output publication, `/health`                        |
| `da/`                           | `auction-da`: the Avail helper of the server (Rust)                                            |
| `deploy/default.ts`             | the deployment of the program, for the local chain and Sepolia                                 |
| `client/`                       | the web app                                                                                    |
| `tests/`                        | the integration test and its input helper                                                      |

## Limits

- The parameters are insecure. They give no security.
- An auction has 2 to 4 bidders (region types) or 2 to 8 bidders (ratio-lane types).
  `maxBidders(type)` and `MAX_BIDDERS_BY_TYPE` in `shared/layout.ts` set the limit. The region types
  are limited by the slot layout: `floor(8 / n)` copies of `n` regions of 16 slots. The ratio-lane
  types are limited by the weights `2^k`, which must add up to less than `t = 257`, and by
  `n (n - 1) < t` (56 for 8 bidders).
- A bid has 16 levels (0 to 15).
- Anyone can bid. Only a complete bid (all ciphertexts of the type: 3, or 4 for ratio-lane
  second-price) takes a place. A bidder that does not finish blocks nobody. When the places are full
  (4 or 8), the contract rejects all other ciphertexts. One party with that many addresses can fill
  all places.
- The proof binds the ciphertext commitment, not the published bytes. A bidder that publishes bytes
  that do not open the commitment stalls the E3.
- The bid commitment is `poseidon2(b, salt)`. A bidder must keep `salt` secret. The web app keeps it
  in the browser storage.
- A region type resolves a tie at the top with the tie priority: the tied bidder with the higher
  priority wins. The result does not show that a tie happened. The last bidder sees all other `ge`
  ciphertexts. That bidder can encrypt again with new randomness until the priority is good for the
  bidder. This can change the winner only when the bids tie.
- A ratio-lane type resolves a tie with the random lane. The result shows the tie set (every bidder
  whose bid equals the price) and the random value. This is the one thing the result shows beyond
  the winner and the price. The random lane is the sum of all masks at one slot. It is uniform if at
  least one mask is chosen at random by a bidder who does not collude with the others. The encrypted
  masks fix the value, and a bidder cannot read the masks of other bidders, so one bidder alone
  cannot grind it. Bidders that all collude can choose it. A fair draw against such a group needs
  randomness that is set after the input window closes. The platform does not supply it.
- A ratio-lane second-price bid has a fourth ciphertext, so a bid takes about 33 percent more proof
  time than the other types.
- In a region type, a slot reads as zero by error with probability `1 / 257` for each copy. The
  decoder then cannot find a unique winner. Run the auction again.
- Ratio-lane first-price has no such error: the lane at the price has no mask. In ratio-lane
  second-price, the price reads too low if `R` is 0 at the price level in all three copies. This has
  the probability `1 / 257^3`.
- The committee publishes 128 coefficients (the whole ring) for this preset. Other presets
  publish 50.
