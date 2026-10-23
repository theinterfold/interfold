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
| Bid            | Each bidder encrypts a bid in the browser, proves with one proof that the bid is valid, and sends it. A bidder can update a bid, and a relayer can send it.              |
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

### Create an auction

`AuctionProgram.validate` reads
`customParams = abi.encode(uint8 auctionType, uint8 levels, uint256[16] prices, string title, address gate, bytes gateConfig)`.
`levels` is the number of price steps, from 2 to 16 (`InvalidLevels` otherwise). It stores the
auction and emits `AuctionCreated`, which carries `gate` and `gateConfig`. It inserts leaf 0: the
configuration leaf, `keccak256("interfold-auction-config-v1" || auctionType)` in the BN254 field. If
`gate` is not the zero address, it calls `IBidderGate(gate).configure(e3Id, gateConfig)` (see "The
bidder gate"). `prices[b]` is the price of step `b`. The first `levels` prices must increase
strictly, and the other prices must be zero (`InvalidPrices` otherwise); the steps can be uneven.
Read them with `auctionPrices(e3Id)`, and the number of steps with `auctions(e3Id)`, which returns
`(auctionType, levels, creator, title, gate)`. The program and the circuits see only steps, so the
prices do not change the computation. The coordination server gives the program the configuration
bytes as input 0. The program reads the type from them, so the compute proof binds the type through
the input root.

### Send a bid

One `publishInput(e3Id, data)` call sends one complete bid. The bidder does not send the ciphertexts
one by one.

```text
data = abi.encode(address bidder, bytes[] ciphertexts, bytes32[] commitments,
                  bytes proof, bytes gateProof, bytes signature)
```

`ciphertexts` and `commitments` have `roleCount(type)` entries (3 or 4), in role order.
`commitments[r]` is the ciphertext commitment of `ciphertexts[r]`. The contract does these steps:

1. It rejects the call after the input window (`InputDeadlineReached`).
2. It rejects a wrong number of ciphertexts or commitments, an empty ciphertext and a zero bidder
   (`InvalidBidShape`, `EmptyInputData`, `BidderIsZero`).
3. It gives the bid the version `bidCount(e3Id, bidder) + 1`. A fourth bid of one address fails
   (`TooManyBids`). The first bid of an address takes one of the places: `maxBidders(type)` is 4 for
   the region types and 8 for the ratio-lane types (`TooManyBidders`).
4. It checks the sender. A direct bid comes from `bidder` (`SenderNotBidder`). A relayed bid carries
   the signature of `bidder` (see "Relayed bids").
5. If the auction has a gate, it asks the gate if `bidder` can bid (`BidderNotEligible`).
6. It verifies the bid proof (`InvalidBidProof`) with `bidVerifier3` (3 roles) or `bidVerifier4` (4
   roles). The public inputs are the commitments, the bidder, `levels`, the committee key commitment
   of the E3 and the VK anchor.
7. It inserts one leaf for each ciphertext as consecutive leaves, in role order, and emits
   `BidSubmitted(e3Id, bidder, version, firstIndex, ciphertexts, commitments)`. `firstIndex` is the
   leaf index of the first ciphertext.

The leaf of a bid ciphertext is
`sha256(keccak256(ciphertext) || commitment || bidder || uint40 version)` in the BN254 field
(`inputLeaf`). It binds four things: the published bytes, the commitment, the bidder and the
version. The contract cannot check that the bytes open the commitment. It binds both in the leaf,
and the program checks them (see "The program: which bids count").

`bidCount(e3Id, bidder)` gives the number of bids of an address. `bidderCount(e3Id)` gives the
number of addresses that bid. The ciphertexts are in the calldata and in the `BidSubmitted` event.
The server and the web app read them from the event.

### Bid updates

A bidder is an address. It can send up to `MAX_BIDS_PER_BIDDER` = 3 bids: the first bid and two
updates. Each bid has its own ciphertexts, its own proof and the next version. An update does not
remove the earlier bid: all leaves stay in the tree and in the input root.

The program counts one bid for each bidder: the latest bid whose ciphertexts all open their
commitments. If the latest bid does not open, an earlier version counts. If no bid of a bidder
opens, the program drops the bidder whole. The program never counts part of a bid.

### Relayed bids

A bidder can sign a bid, and any account can send it. The relayer pays the gas. The bidder address
stays the bidder of the proof, the gate check and the leaves.

The signature is EIP-712 with the domain name `AuctionProgram` and the domain version `1`, and the
type `Bid(uint256 e3Id,address bidder,uint32 version,bytes32 inputsHash)`:

- `version` is the version the bid will get: `bidCount + 1`. An old signature is useless after the
  bidder bids again.
- `inputsHash` is `keccak256(abi.encode(commitments, ciphertextHashes))`, with
  `ciphertextHashes[r] = keccak256(ciphertexts[r])`. A relayer cannot swap the bytes of a signed
  bid.

`bidDigest(e3Id, bidder, version, inputsHash)` returns the digest to sign. The contract checks the
signature with OpenZeppelin `SignatureChecker`, so it accepts an EOA and an ERC-1271 wallet. With an
empty `signature`, the bid is direct.

The coordination server has a relayer: `POST /relay` sends `publishInput` from the account of
`RELAYER_PRIVATE_KEY`. On the local chain this key is Anvil account 9 by default. No bidder and no
ciphernode uses it. The web app signs with the wallet when you select **Send through relayer**. See
"Run the server" for the endpoint.

### The bidder gate

An auction can name a gate contract. The gate decides which addresses can bid. A gate implements
`IBidderGate`:

```solidity
function configure(uint256 e3Id, bytes calldata config) external;
function isEligible(
  uint256 e3Id,
  address bidder,
  bytes calldata proof
) external view returns (bool);
```

`validate` calls `configure` once for each auction, with `gateConfig`. Each bid calls `isEligible`
with `gateProof`. The gate keys its state by `(msg.sender, e3Id)`, and `msg.sender` is the program.
If `gate` is the zero address, anyone can bid and `gateConfig` must be empty
(`GateConfigWithoutGate`). A non-zero `gate` must be a contract (`InvalidGate`).

`contracts/gates/MerkleAllowlistGate.sol` is an example gate. Its `gateConfig` is
`abi.encode(address[] members)`: 1 to 256 addresses in strictly increasing order. The gate builds
the Merkle root on chain, stores it and emits `AllowlistSet(program, e3Id, root, members)`. The leaf
of a member is `keccak256(member)`. The inner nodes use the sorted-pair `keccak256`, and an odd node
moves up unchanged. The `gateProof` of a bidder is `abi.encode(bytes32[] path)`.
`shared/allowlist.ts` (`allowlistRoot`, `allowlistProof`) builds the same root and path. The web app
sorts and deduplicates the addresses that the creator enters. It builds the proof of a bidder from
the `AllowlistSet` event. The web app finds the gate through `VITE_ALLOWLIST_GATE_ADDRESS`.

### The program: which bids count

The server sends the runner every published input, not only the bids that count. For each input it
sends the commitment (`input_commitments`), the bidder (`input_slots`) and the bid version
(`input_parents`). The program reads the 5-byte field `input_parents` as the bid version, not as a
parent. Input 0 (the configuration) has a zero commitment, a zero slot and the parent 0. The input
policy of the program (`policy()` in `program/src/lib.rs`) has two parts:

- **Leaf.** The leaf of input 0 is the configuration leaf. For every other input, the program needs
  a commitment and 25 bytes of metadata (`bidder || uint40 version`). It computes the same leaf as
  `inputLeaf`. A ciphertext that does not open its commitment still gets a leaf, because every
  published input needs one.
- **Select.** The program always selects input 0. It groups the other inputs into bids: a bid is a
  maximal run of consecutive inputs with identical metadata, because the contract inserts one bid as
  one run. For each bidder it keeps the run with the highest version in which every input opens its
  commitment. A bidder with no such run is dropped whole. A run with malformed metadata is never
  selected. The bidder position in the computation is the order of the selected runs by leaf index.

`shared/selection.ts` (`selectBids`) is the same rule in TypeScript. The server, the web app and the
integration test use it. The server starts no computation with fewer than 2 selected bidders.

### The program: region types

With `n` bidders, the program makes `floor(8 / n)` copies of `n` regions. A region has 16 slots. The
program zeroes the unused groups. It multiplies a test vector by the sum of the bidder masks. A slot
is uniform where the test is non-zero, so the result shows only the zero slots.

The tie priority comes from the published ciphertexts. The seed is `keccak256` of the `ge`
ciphertexts of the selected bids, in bidder-position order. The program ranks the bidder positions
by `keccak256(seed || u32_be(position))`. The highest hash gets priority `n - 1`. The priority is
fixed only when the input window closes, because a bidder can update a bid until then. A tie at the
top goes to the bidder with the higher priority.

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
bidders. The fourth ciphertext of the second-price type adds one encryption, one encryption proof
and a larger bid circuit to each bid.

## What is proven

Each bidder publishes one bid proof. It is `auction_bid3` for the types with 3 roles and
`auction_bid4` for the second-price ratio-lane type. The proof runs in the browser, and a browser
can prove at most 2^21 gates (the WASM heap is 4 GiB; a 2^22 circuit runs out of memory after it
loads the SRS). One circuit that verifies all `K` encryption proofs has more gates than that, so the
bid is a tree of four circuits. Every one has fewer than 2^21 gates and pads to 2^21. The shared
rules are in the Noir library `circuits/bid` (`auction_bid`). The four circuits are thin packages
around it:

- `auction_bid_pair` (`circuits/pair`) verifies the encryption proofs of the roles 0 and 1. It holds
  the bid.
- `auction_bid_masks` (`circuits/masks`, type 3 only) verifies the encryption proofs of the roles 2
  and 3. It holds the pair-mask check.
- `auction_bid3` (`circuits/bid3`) verifies the pair proof and the encryption proof of role 2.
- `auction_bid4` (`circuits/bid4`) verifies the pair proof and the masks proof.

Only `auction_bid3` and `auction_bid4` have an EVM verifier. The two inner circuits make recursive
proofs. Together, the circuits check these facts:

- **The encryption.** Every ciphertext has an Interfold user-data encryption proof. It shows that
  the ciphertext encrypts a plaintext `k1` under this E3 committee key. All proofs use the same
  verification key, and they carry the same `ct0` and `ct1` verification-key chains. The inner
  proofs publish the key row commitment, the key hash and the chains, and the outer circuit checks
  that they are the same in every proof of the tree.
- **The bid.** `auction_bid_pair` has one private bid `b`. The public input `levels` is the number
  of price steps that the creator chose. The circuit proves that `levels` is in 2 to 16, that
  `b < levels` and that `b` has a one-hot vector. The contract gives the `levels` of the auction, so
  no valid proof exists for a bid at a step that the auction does not have.
- **The plaintexts.** The `k1` of role 0 is the row `b` of the table for `ge`. The `k1` of role 1 is
  the row `b` of the table for `gt`. Both roles use the same `b` inside `auction_bid_pair`, so
  nothing links them afterwards. A mask has a free `k1`. For the pair mask (role 3),
  `auction_bid_masks` checks that the plaintext is a mod-`t` combination of 64 unit rows, one for
  each `(c, l)`. Thus the slots `(2c) * 16 + l` and `(2c + 1) * 16 + l` are equal. Without this
  check, a bidder could give `R` two values (in the `y` lane and in the `z` lane) and change the
  winner that the decoder reads. The tables come from `program/examples/bid_table.rs` and fhe.rs.
- **The binding.** Each ciphertext commitment is the commitment of its encryption proof. The bidder
  is not zero.

The public inputs of the bid proof, in order, are: the `K` ciphertext commitments, `bidder`,
`levels`, the committee key commitment and the VK anchor. That is `K + 4` values. The contract
supplies `bidder`, `levels`, the committee key commitment of the E3 and the anchor of the
deployment. The VK anchor covers the user-data encryption circuits and the inner circuits of the
tree. It is `vkAnchor3` for `K = 3` (it contains `auction_bid_pair`) and `vkAnchor4` for `K = 4` (it
contains `auction_bid_pair` and `auction_bid_masks`). The contract chooses the verifier and the
anchor by the type.

| Circuit             | Proof                             | Types  | Gates (`bb gates`) | Padded size |
| ------------------- | --------------------------------- | ------ | ------------------ | ----------- |
| `auction_bid_pair`  | recursive, roles 0 and 1          | 0 to 3 | 1,427,574          | 2^21        |
| `auction_bid_masks` | recursive, roles 2 and 3          | 3      | 1,429,486          | 2^21        |
| `auction_bid3`      | EVM, the pair proof and role 2    | 0 to 2 | 1,426,850          | 2^21        |
| `auction_bid4`      | EVM, the pair proof and the masks | 3      | 1,426,857          | 2^21        |

Only the bid proof leaves the browser. The encryption proofs stay on the machine of the bidder.

The proof has `bidder` as a public input. For a direct bid, `bidder` is `msg.sender`. For a relayed
bid, it is the signer. A proof that another address copies fails, because the bidder is part of the
proof. Without this, a copy of the thermometers of the highest bidder would make a tie at that bid,
and the price would show the bid.

The `ge` and `gt` ciphertexts of one bid come from one `b`, because the circuit has only one `b`.
The limit of bidders is `maxBidders(type)`: 4 for the region types and 8 for the ratio-lane types.

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

3. Set up the example. This step runs `scripts/compile_circuits.sh`, which compiles the four bid
   circuits and writes the verifiers of `auction_bid3` and `auction_bid4`
   (`contracts/verifiers/AuctionVerifier3.sol` and `AuctionVerifier4.sol`) and the two VK anchors.
   It builds `program/examples/vk_hash.rs` to hash the verification keys:

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
   they are the ciphernodes. Do not use account 9: it is the relayer of the server. Use these keys
   on a local chain only.
2. **Get test tokens.** A request pays a fee in the fee token. On anvil, select **Get test tokens**
   to mint some.
3. **Create an auction.** Enter a title (1 to 80 bytes), select the type, the price steps and the
   bidding duration. The page offers four types: first-price, second-price (Vickrey), first-price
   with ratio lanes and second-price with ratio lanes. It shows the bidder limit of the chosen type
   (2 to 4 bidders for the first two types, 2 to 8 for the ratio-lane types) and the number of
   ciphertexts of each bid. A ratio-lane auction resolves a top tie with a public random draw among
   the tied bidders. The tie set becomes public: the result names every bidder that tied. For the
   price steps, first set **Number of steps** (2 to 16, 8 by default). Then select **Even steps** (a
   start price and a step) or **Custom list** (one price for each step, increasing, for example a
   1-2-5 scale). Under **Who can bid**, select **Anyone** or **Allowlist**. For an allowlist, enter
   the addresses. The page sorts them and removes duplicates. The **Allowlist** choice needs
   `VITE_ALLOWLIST_GATE_ADDRESS`. Key generation takes some minutes. Bidding opens when the
   committee publishes the key, and it closes at the end of the duration.
4. **Bid.** Open the auction page from another account. Select one of the prices that the creator
   set (the steps 0 to `levels - 1`). Select **Submit bid**. A bid is 3 ciphertexts: the bid
   thermometer "at least", the bid thermometer "above" and a random mask. A ratio-lane second-price
   bid adds a fourth, the paired mask. The browser encrypts each ciphertext and proves its
   encryption, then makes the bid proof. The page shows each step. Each proof takes some minutes.
   The wallet then sends one transaction. With **Send through relayer**, the wallet signs the bid
   and the server sends the transaction. The bid counts when the transaction is mined. On an
   allowlist auction, the page shows if the account is on the list. After a bid, the page shows the
   version of the bid and **Update bid (n left)**: an address can send 3 bids. An update has a new
   proof. The latest bid whose bytes open counts. The auction is full when `bidderCount` reaches the
   limit of its type. The page keeps the level and the transaction hash of each version in the
   browser storage.
5. **Result.** When the window closes, the server computes the result, and the committee decrypts
   it. The page decodes the published plaintext in the browser. It uses `selectBids` to find the
   bids that counted. It shows the bidders that it dropped because their bytes did not open, and the
   version of each bid that counted. First-price and Vickrey show the winner, the price, your
   outcome and the region grid (one row for each bidder, one column for each level). The grid shows
   that the region of the winner is the only zero region at the price level. Ratio-lane types show
   the winner, the price and one lane of 16 slots: zero above the price, the set of tied bidders at
   the price, and random values below. If more than one bidder tied, the page also shows the tie
   set, the random value `r` and the draw `r mod |tie set|`. The page shows an error when a lane
   does not decode to a price and a tie set, when the copies of ratio-lane second-price disagree, or
   when the random lane is unreadable during a tie.

An auction needs 2 bidders at least, and 4 (region types) or 8 (ratio-lane types) at most. A bidder
counts only if one of its bids opens its commitments. With fewer than 2 such bidders, the server
computes nothing, and the E3 fails at its compute deadline.

## Test

```sh
cargo test --release -p e3-user-program   # the FHE program and its input policy, all four types, against a local l-BFV key
(cd circuits/bid && nargo test)           # the bid validity rules (the shared library)
hardhat test                              # the contract and the allowlist gate (with a mock bid verifier)
pnpm test:server                          # the server and the shared code
pnpm test:integration                     # DKG -> 11 bid proofs -> FHE -> threshold decryption, all four types
```

`pnpm test` runs `hardhat test`. `pnpm test:integration` runs `pnpm test:server` first.

The integration test runs four auctions at the same time. They need 35 encryptions and 11 bid
proofs.

| Type                      | Bids (bidder: step)              | What else it covers                                                                                                                             | Result checked                                           |
| ------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| Second-price (Vickrey)    | `0: 14`, `1: 12`, `2: 9`, `0: 5` | The update counts: bidder 0 bids the highest step and then updates. The test sends the update again as version 3, and a fourth bid is rejected. | bidder 1 wins at price 9                                 |
| First-price               | `0: 6`, `1: 9`, `2: 11`          | An allowlist of bidders 0 to 2, and the creator account is rejected. The bytes of bidder 2 do not open, so the program drops bidder 2.          | bidder 1 wins at price 9                                 |
| First-price, ratio lanes  | `0: 2`, `1: 7`                   | Bidder 1 signs, and the relayer of the server sends the bid.                                                                                    | price 7, tie set `[1]`, bidder 1 wins                    |
| Second-price, ratio lanes | `0: 5`, `1: 5`                   | A top tie on step 5 of a 6-step auction.                                                                                                        | price 5, tie set `[0, 1]`, winner `tieSet[random mod 2]` |

The test also checks that the contract rejects these bids:

- a 4-ciphertext bid for an auction with 3 roles (`InvalidBidShape`);
- a proof whose commitments are swapped (the verifier fails);
- a proof that another bidder copies with its own address (the verifier fails);
- a direct bid from an account that is not the bidder (`SenderNotBidder`);
- a bid from an account that is not on the allowlist (`BidderNotEligible`);
- a signed bid with two ciphertexts swapped, a bid with the signature of another account, and the
  same signed bid after it was sent (`InvalidSignature`);
- a fourth bid of one address (`TooManyBids`).

It checks `bidCount`, `bidderCount`, the `firstIndex` and the `version` of each `BidSubmitted` event
and the number of leaves. It then selects the bids with `selectBids` and compares them with the
expected bids. `cargo test` covers more ties, 8 bidders, the zero slots of the output, the plaintext
formulas of the ratio-lane types, and the leaf and the selection of the input policy. The latest
valid version wins. An earlier version counts if the latest does not open. A bidder with no bid that
opens is dropped whole. A leaf vector is shared with the Solidity `inputLeaf`. `hardhat test` covers
the contract (bids, updates, relayed bids, the 4-role verifier, the allowlist and the gate
configuration) and the Merkle root of the allowlist gate on chain and in TypeScript.
`pnpm test:server` runs the unit tests of the server and of `shared/`, including the input assembly
for 3 and 4 roles, the relay and the bid selection.

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
- The built circuits of this example: `pnpm dev:setup` writes `circuits/target/vk_anchor.json`
  (`vkAnchor3` and `vkAnchor4`) and the two bid verifiers. The deploy reads them.
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

| Variable                                                                           | Use                                                                                                                                                                            |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `RPC_URL`, `WS_RPC_URL`, `CHAIN_ID`, `PRIVATE_KEY`                                 | The chain (31337 or 11155111), the HTTP endpoint, an optional WebSocket endpoint for the live listener, and the operator key.                                                  |
| `INTERFOLD_ADDRESS`, `REGISTRY_ADDRESS`, `FEE_TOKEN_ADDRESS`, `E3_PROGRAM_ADDRESS` | The contracts.                                                                                                                                                                 |
| `DEPLOY_BLOCK`, `LOG_CHUNK_SIZE`                                                   | The first block to scan, and the largest log range of one request (default 10 000). `DEPLOY_BLOCK` is required on Sepolia.                                                     |
| `PORT`, `PROGRAM_RUNNER_URL`, `CALLBACK_URL`                                       | The listen port, the program runner and the base URL of this server that the runner calls back. In Docker, use service names, not `127.0.0.1`.                                 |
| `DATA_AVAILABILITY_MODE`                                                           | `mock_http` (default) or `avail`.                                                                                                                                              |
| `AVAIL_RPC_URL`, `AVAIL_APP_ID`, `AVAIL_SEED`, `AVAIL_BRIDGE_API_URL`              | The Avail settings of `avail` mode. `DESTINATION_CHAIN_ID` is `CHAIN_ID`.                                                                                                      |
| `AVAIL_PROOF_POLL_INTERVAL_SECONDS`, `AUCTION_DA_BIN`                              | The proof poll interval (default 60) and the path of `auction-da`.                                                                                                             |
| `DATA_DIRECTORY`                                                                   | The directory of the published objects and the Avail records. Keep it on a volume.                                                                                             |
| `RELAYER_PRIVATE_KEY`                                                              | The account that pays the gas of `POST /relay`. On the local chain it defaults to Anvil account 9, which no bidder or ciphernode uses. On Sepolia the relay is off without it. |

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
- It reads every `BidSubmitted` event of the auction and sends the runner all the inputs: the
  configuration and each ciphertext of each bid, with its commitment, its bidder and its bid version
  (`input_commitments`, `input_slots`, `input_parents`). The input root covers all of them. The
  program then counts, for each bidder, its latest bid whose ciphertexts open their commitments. The
  server applies the same rule (`shared/selection.ts`) and does not start a run with fewer than two
  such bidders.
- `POST /relay` with `{ "e3Id": "<decimal>", "data": "0x..." }` sends `publishInput(e3Id, data)`
  from the relayer account, after a simulation, and answers `{ "txHash": "0x..." }` once it is
  mined, or `{ "error": "<revert reason>" }` with status 422. It makes no other check: the program
  verifies the EIP-712 signature, the gate and the proof, and a relayed bid cannot change after it
  is signed. Any page may call it (CORS is open). It spends the gas of `RELAYER_PRIVATE_KEY`, so a
  public server needs its own funded key and a rate limit in front.

Run `pnpm test:server` for the unit tests of the configuration, the log chunks, the publication
steps, the input metadata, the relay and the bid selection.

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

These figures come from one run of `pnpm test:integration` (Node, 11 prover threads) on an Apple
Silicon laptop. They are estimates.

| Step                                                | Time                                                                                       |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Key generation (request to published key, real DKG) | 6 to 13 minutes for one auction; about 26 minutes when the test runs four at the same time |
| Threshold decryption (ciphertext output to result)  | about 20 seconds                                                                           |

The time of a bidder (encryptions, encryption proofs and the bid proof, in Node and in the browser)
and the time of the integration test have not been measured again for the flow of one bid proof. The
older figures were for a proof of each ciphertext, and they do not apply.

## Layout

| Path                            | What                                                                                                             |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `shared/layout.ts`              | the slot encoding, the roles and limits of each type, the tie priority and the result decoders                   |
| `shared/prover.ts`              | `BidProver`: encrypt, the encryption proofs, the pair, masks and bid proofs                                      |
| `shared/selection.ts`           | `selectBids`: the TypeScript form of the input policy (which bids count)                                         |
| `shared/allowlist.ts`           | `allowlistRoot` and `allowlistProof`: the allowlist tree of `MerkleAllowlistGate`                                |
| `circuits/bid/`                 | `auction_bid`: the library with the bid rules shared by the four circuits, and the tables of the honest bids     |
| `circuits/pair/`, `masks/`      | `auction_bid_pair` (roles 0 and 1, the bid) and `auction_bid_masks` (roles 2 and 3, the pair mask): recursive    |
| `circuits/bid3/`, `bid4/`       | `auction_bid3` and `auction_bid4`: the proofs the contract verifies; `scripts/compile_circuits.sh` builds all    |
| `contracts/AuctionProgram.sol`  | auction config, bids and updates, relayed-bid signatures, gate check, bid proof check, leaves, DA check          |
| `contracts/interfaces/`         | `IBidderGate` and `IBidVerifier`                                                                                 |
| `contracts/gates/`              | `MerkleAllowlistGate`: the example gate                                                                          |
| `contracts/verifiers/`          | `AuctionVerifier3.sol` and `AuctionVerifier4.sol`: generated by `scripts/compile_circuits.sh`. Do not edit them. |
| `program/src/lib.rs`            | the FHE processor and the input policy (the leaf and the selection; all four auction types)                      |
| `program/examples/bid_table.rs` | the generator of `circuits/bid/src/constants.nr`                                                                 |
| `program/examples/vk_hash.rs`   | the hash of ordered VK hashes, for the VK anchor                                                                 |
| `runner/`                       | the program server (`program-runner`) that serves `program/`                                                     |
| `guest/`                        | the OpenVM guest that proves the program                                                                         |
| `server/`                       | the coordination server: events, compute, relay (`POST /relay`), output publication, `/health`                   |
| `da/`                           | `auction-da`: the Avail helper of the server (Rust)                                                              |
| `deploy/default.ts`             | the deployment of the program and of the allowlist gate, for the local chain and Sepolia                         |
| `client/`                       | the web app                                                                                                      |
| `test/`                         | the Hardhat tests of the contract and the gate                                                                   |
| `tests/`                        | the integration test and its input helper                                                                        |

## Limits

- The parameters are insecure. They give no security.
- An auction has 2 to 4 bidders (region types) or 2 to 8 bidders (ratio-lane types).
  `maxBidders(type)` and `MAX_BIDDERS_BY_TYPE` in `shared/layout.ts` set the limit. The region types
  are limited by the slot layout: `floor(8 / n)` copies of `n` regions of 16 slots. The ratio-lane
  types are limited by the weights `2^k`, which must add up to less than `t = 257`, and by
  `n (n - 1) < t` (56 for 8 bidders).
- An auction has 2 to 16 price steps, chosen by its creator. The slot layout always has 16 levels (0
  to 15). The steps `levels` to 15 stay empty, because every thermometer is 0 there. Thus the price
  never decodes to a step that the auction does not have.
- Anyone can bid, unless the auction has a gate. The first bid of an address takes one of the places
  (4 or 8), even if its bytes do not open. When the places are full, the contract rejects the first
  bid of every new address. One party with that many addresses can fill all places. A gate limits
  who can bid, but the example allowlist does not limit one party that holds several listed
  addresses.
- An address can send 3 bids at most: the first bid and 2 updates.
- The proof binds the ciphertext commitment, not the published bytes. A bidder that publishes bytes
  that do not open the commitment does not count: the program uses an earlier version, or drops the
  bidder whole. This does not stall the E3. The auction needs 2 bidders that count.
- A bidder can withdraw by publishing bytes that do not open the commitments. The bidder learns
  nothing from this.
- The ciphertexts are still on chain as calldata. This example has no data-availability input path
  yet. The leaf already binds the content hash of each ciphertext, so a later data-availability path
  can supply the bytes.
- A relayed bid shows the bidder address on chain, as a direct bid does. `POST /relay` has no
  authentication and no rate limit.
- A region type resolves a tie at the top with the tie priority: the tied bidder with the higher
  priority wins. The result does not show that a tie happened. The priority comes from the `ge`
  ciphertexts of the selected bids. A bidder can encrypt again with new randomness until the
  priority is good for the bidder. This can change the winner only when the bids tie. Updates make
  this cheaper: a bidder does not need to bid last. It can update after it has seen the ciphertexts
  of the other bidders, until the window closes. Randomness that is set after the window closes
  would fix this.
- A ratio-lane type resolves a tie with the random lane. The result shows the tie set (every bidder
  whose bid equals the price) and the random value. This is the one thing the result shows beyond
  the winner and the price. The random lane is the sum of all masks at one slot. It is uniform if at
  least one mask is chosen at random by a bidder who does not collude with the others. The encrypted
  masks fix the value, and a bidder cannot read the masks of other bidders, so one bidder alone
  cannot grind it. Bidders that all collude can choose it. A fair draw against such a group needs
  randomness that is set after the input window closes. The platform does not supply it.
- A ratio-lane second-price bid has a fourth ciphertext. It needs one more encryption and one more
  encryption proof, and it has one more proof in the tree: `auction_bid_masks`, so a bid makes three
  proofs after the encryptions, against two for the other types.
- In a region type, a slot reads as zero by error with probability `1 / 257` for each copy. The
  decoder then cannot find a unique winner. Run the auction again.
- Ratio-lane first-price has no such error: the lane at the price has no mask. In ratio-lane
  second-price, the price reads too low if `R` is 0 at the price level in all three copies. This has
  the probability `1 / 257^3`.
- The committee publishes 128 coefficients (the whole ring) for this preset. Other presets
  publish 50.
