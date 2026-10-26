# Negotiation: a sealed price negotiation

This example is a standalone two-party price negotiation on Interfold. A seller has a private
minimum price. A buyer has a private maximum price. Neither price is ever revealed.

- If the maximum of the buyer is at least the minimum of the seller, everyone learns **one final
  price**. It is drawn at random from the prices between the two, on a public price grid.
- If the maximum is below the minimum, everyone learns only **"no match"**.

The two prices stay inside an FHE computation of the committee. The ideal leak is the match bit and
the final price. The real leak is a little larger: the final price is **almost** uniform, not
exactly uniform (see "How uniform is the price"). `DESIGN.md` has the full design, the alternatives
that the study rejected, and the leak analysis.

The app is a small sibling of `examples/sealed-cca`. It uses the same program contract, server,
client and proof pipeline. It has no tokens and no deposits.

## How a negotiation works

1. **Create.** Anyone (the creator) names the seller and the buyer (two different addresses), a
   price grid `[min, max, step]` of 2 to 16 levels, a title and an input window. The creator pays
   the E3 fee. The creator shares the link `/n/<e3Id>`.
2. **Offers.** The seller seals its minimum, and the buyer seals its maximum. Each party picks a
   level of the grid and a random 4-bit share. The browser encrypts three ciphertexts under the
   committee key, proves in zero knowledge that they are well formed, and sends them with
   `publishInput`. A party sends one offer and cannot change it.
3. **Compute.** After the window, the program of the committee runs on the six ciphertexts. It uses
   one ciphertext multiplication layer (depth 1) and needs no other input.
4. **Settle.** The committee decrypts one ciphertext. Anyone calls `settle(e3Id)`. The contract
   reads the 128 slots and stores either the match bit and the price, or "no match".

### The encoding

The grid has `L <= 16` levels. Level `i` has the price `min + i * step`. The program picks the level
of the least `i xor u` in `[s, b]`, where `s` and `b` are the levels of the seller and the buyer,
and `u = a xor c` is a pointer from the two random 4-bit shares. `u` is uniform and secret if one
party draws its share honestly. Each party sends:

| Ciphertext | Contents (128 SIMD slots; slot `g * 16 + i` is group `g`, level `i`)     |
| ---------- | ------------------------------------------------------------------------ |
| 0          | the lanes 0 to 7 of a 0/1 tensor that depends on its level and its share |
| 1          | the lanes 8 to 15 of that tensor                                         |
| 2          | a random mask with sum 0 mod 257 over the 8 groups of each level         |

The program computes `X0*Y0 + X1*Y1 + M_seller + M_buyer` slot by slot. After the decryption, the
sum of the 8 groups of level `i` is 1 if `i` is the agreed level, and 0 for every other level. The 8
values of a group are otherwise uniform because of the masks. The sum is zero at every level if
`b < s`. `sdk/src/layout.ts` is the reference implementation and `sdk/test-vectors/layout.json` has
fixed vectors that the circuit, the program and the contract tests share.

## What is public, and what each party learns

| Item                                             | Seller | Buyer | The public / the committee |
| ------------------------------------------------ | ------ | ----- | -------------------------- |
| Own price and own share                          | yes    | -     | no                         |
| The other price                                  | no     | no    | no                         |
| That an offer was sent, by which address, when   | yes    | yes   | yes                        |
| The three ciphertexts of each offer              | yes    | yes   | yes (encrypted)            |
| The match bit                                    | yes    | yes   | yes                        |
| The final price `p`                              | yes    | yes   | yes                        |
| `b >= p` (from a match)                          | yes    | -     | yes                        |
| `s <= p` (from a match)                          | -      | yes   | yes                        |
| `b < s` (from no match)                          | yes    | yes   | yes                        |
| The pointer `u`, the lane tensor, the other mask | no     | no    | no                         |

The leak is the match bit and `p`. The reasons are in `DESIGN.md`: the pointer is secret and joint,
so neither party can steer `p`, and the masks make the 128 output slots uniform given the level
sums. The committee, the runner and the server see only ciphertexts and the final output.

Two things leak beyond the ideal one:

- A match shows `b >= p` to the seller and `s <= p` to the buyer. This is in the ideal mechanism
  too.
- The law of `p` is not uniform in `[s, b]`. A reader who knows the mechanism can weigh `p` as a
  likelihood: a high `p` makes some `(s, b)` pairs more likely than others. The next section gives
  the numbers.

### How uniform is the price

The law of `p` is exact: `pnpm -C sdk uniformity` prints it. Over all 136 intervals of 16 levels (a
uniform prior on `(s, b)`):

| Measure                                                      | Value                            |
| ------------------------------------------------------------ | -------------------------------- |
| Largest total variation distance from the uniform law        | 0.417, at `[3, 8]`               |
| Mean total variation distance over all intervals             | 0.144                            |
| A level that the output excludes (probability 0 in `[s, b]`) | none                             |
| Most over-weighted level (times the uniform weight)          | 4.5                              |
| Most under-weighted level                                    | 0.375                            |
| Extra mutual information with `(s, b)` over the ideal one    | 0.120 bits (1.837 against 1.717) |
| Intervals that are aligned power-of-2 blocks                 | exactly uniform                  |

For 8 levels the largest distance is 0.30 and the mean is 0.087. For 4 levels it is 0.167. For the
demo interval 50 to 60 (levels 2 to 12 of a grid that starts at 48) the exact law in sixteenths is
`2:2 3:2 4:1 5:1 6:1 7:1 8:1 9:1 10:1 11:1 12:4`: the buyer's maximum (60) wins 25% of the time and
the seller's minimum (50) 12.5% of the time, against 9.1% each for a uniform price.
`research/measurements.md` has the histograms of 300, 3000 and 30000 runs of the real FHE program,
which follow this law (chi-square against it: p = 0.53, 0.27, 0.96). Better families (affine, golden
ratio) reach a distance of 0.07 to 0.15, but their rank is in the hundreds, and the platform has no
rotation key, so they do not fit in 3 ciphertexts or in depth 1 (`DESIGN.md`, table with
`research/alternatives.py`).

## Contracts

`contracts/NegotiationProgram.sol` is the E3 program, the verifier of the offers and the settlement.
The interface that the client, the server, the circuit and the program share:

**Create** (`customParams` of the E3 request):
`abi.encode(address seller, address buyer, uint8 levels, uint256 minPrice, uint256 stepPrice, string title)`.
The seller and the buyer are non-zero and different, `levels` is 2 to 16 and `stepPrice > 0`.
`validate` stores them and emits
`NegotiationCreated(e3Id, creator, seller, buyer, levels, minPrice, stepPrice, title)`.

**Offer** (`publishInput`):
`data = abi.encode(address party, bytes[] ciphertexts, bytes32[] commitments, bytes proof, bytes signature)`
with 3 ciphertexts and 3 commitments. `party` is the seller or the buyer. The sender is `party`, or
`signature` is the EIP-712 signature of `party` over
`Offer(uint256 e3Id, address party, bytes32 inputsHash)` (the relayed path). One offer for each
role. The contract verifies one Honk proof. Its 8 public inputs are
`ct_commitments[3], party, role, levels, pk_commitment, vk_anchor`. It adds three leaves to the
input tree, with the metadata `party (20 bytes) || uint40(role * 256 + index)` and emits
`OfferSubmitted`.

**Settle** (`settle(e3Id)`, anyone): decodes the plaintext, sums the 8 groups of each level,
requires a valid outcome (all zero, or one level with 1) and emits
`Settled(e3Id, matched, step, price)`. Views: `negotiation(e3Id)`, `offerSubmitted(e3Id, role)`,
`outcome(e3Id)`.

## What is proven

| Proof                     | Checked by                 | What it shows                                                                                |
| ------------------------- | -------------------------- | -------------------------------------------------------------------------------------------- |
| Encryption (3x)           | `negotiation_offer`        | Each ciphertext is a valid encryption under the committee key (user data encryption)         |
| `negotiation_offer_lanes` | `negotiation_offer`        | Ciphertexts 0 and 1 hold the lane tensor of the private level and share, for the public role |
| `negotiation_offer`       | `NegotiationOfferVerifier` | The above, and that ciphertext 2 is a mask with zero sum at every level; `step < levels`     |
| Compute proof             | `Interfold`                | The program ran on the inputs of the input tree (mock verifier on the local chain)           |

| Circuit                   | Gates     |
| ------------------------- | --------- |
| `negotiation_offer_lanes` | 1,452,410 |
| `negotiation_offer`       | 1,431,863 |

Each circuit is below the browser limit of 2^21 = 2,097,152 gates. One offer needs three encryption
proofs, the lanes proof and the top proof: 281 s in Node on an M3 Pro (the three encryption proofs
take 82 s, 72 s and 81 s, the lanes proof 28 s, the top proof about 18 s). The browser is slower.

## The FHE program, the server and the runner

The FHE program (`program/`, `runner/`, `guest/`) is `out = X0*Y0 + X1*Y1 + M_a + M_b`. It adds the
two products and relinearizes once with the threshold relinearization key. It drops an offer that is
not a complete run of the indices 0, 1, 2 of one party and role, or whose ciphertexts do not open
their commitments. Input 0 is the constant `"interfold-negotiation-config-v1"`.

The noise of the output is 67 to 68 bits for a ciphertext with a budget of 159 bits (fresh inputs:
19 bits). The preset's smudging noise for depth 3 leaves a margin of 4.8 bits, the same as for any
program of depth 3 or less. `research/measurements.md` has the numbers and the commands.

The server (`server/`) is the sealed-cca server without the deposit relay. It reads
`NegotiationCreated` and `OfferSubmitted`, builds the input tree in log order, calls the runner at
the end of the window, publishes the output and relays offers (`POST /relay { e3Id, data }`). It
skips an E3 with a missing role. It also stores the picture of a negotiation (see below).

### The negotiation picture

A negotiation can have one picture. The creator adds it, and every visitor sees it in the list and
on the negotiation page. The picture is not on chain. The server stores it in
`DATA_DIRECTORY/images/`. This directory needs no new setting, and it is on the same volume as the
other server data. A reverse proxy such as Caddy must pass the `PUT` and `OPTIONS` methods, the
header `x-negotiation-image-signature` and a request body of 1 MiB. Caddy does this by default.

`PUT /negotiations/:e3Id/image` stores the picture. The body is the image bytes. The request header
`x-negotiation-image-signature` holds the signature of the creator (`personal_sign`, hex). The
creator is the `creator` field of `negotiation(e3Id)` on chain: the account that requested the E3.
It is not always the seller or the buyer. The signed text has five lines:

```text
Interfold negotiation image
chain: <chain id>
program: <NegotiationProgram address, checksum form>
e3Id: <decimal>
sha256: 0x<hex SHA-256 of the exact body bytes>
```

The server answers with these statuses:

| Status | Cause                                                                                 |
| ------ | ------------------------------------------------------------------------------------- |
| 400    | `e3Id` is not a decimal number, the body is empty, or the signature is missing or bad |
| 413    | The body is larger than 1 MiB (1 048 576 bytes)                                       |
| 415    | The first bytes are not PNG, JPEG or WebP. SVG is refused.                            |
| 404    | `negotiation(e3Id)` on chain has the zero address as creator                          |
| 403    | The signer is not the creator, or the signature covers other bytes                    |
| 204    | The server stored the picture. It replaced an earlier picture of this negotiation.    |

The server reads the type from the first bytes and ignores the content type of the request. It
writes the file to a temporary name and then renames it, so a reader never gets half a file. The
size limit of 1 MiB applies to this route only.

`GET /negotiations/:e3Id/image` returns the bytes. It sets `Content-Type` to the type that it found,
`X-Content-Type-Options: nosniff`, `Cache-Control: public, max-age=60`, a restrictive
`Content-Security-Policy` and `ETag` (the SHA-256 of the file). It answers 304 when `If-None-Match`
matches. It answers 404 when the negotiation has no picture. Any page can call both routes (CORS is
open, as for `POST /relay`). The response also sets `Cross-Origin-Resource-Policy: cross-origin`,
because the web app is cross-origin isolated.

The web app shrinks the picture before it uploads it. It scales the picture to 1280 pixels on the
long side, and encodes WebP (JPEG if the browser cannot encode WebP). This removes the metadata and
transparency. After the create transaction is mined, the wallet asks for the signature. If the
upload fails, the negotiation stays and the page shows the error. The creator can then select **Add
picture** (or **Replace picture**) on the negotiation page. The web app reads the server URL from
`VITE_SERVER_URL`, as for the relay.

## Prerequisites

- Rust, Node, pnpm, `nargo` 1.0.0-rc.3, `bb` 6.0.0 and Foundry (`anvil`).
- An `interfold` CLI built from this checkout with the feature `test-only-skip-proof-aggregation`
  (`pnpm dev:setup` installs it).

Proof aggregation of the committee (the recursive folds of the nodes and the `DkgAggregatorV2` proof
of the aggregator) dominates the key generation time. `pnpm dev:ciphernodes` skips it when the
installed CLI has the feature: it exports `E3_NODES__CN1..5__SKIP_PROOF_AGGREGATION=true`, deploys
the mock DKG and decryption verifiers and the aggregator publishes a placeholder proof that only the
mock verifiers accept. Set `NEGOTIATION_REAL_PROOFS_AGG=1` to aggregate the proofs and deploy the
real verifiers. A CLI without the feature takes this path too. The feature is for the local chain
only.

## Run it

> **Status: the local stack has not been run end to end.** The circuits compile, the contracts, the
> program, the SDK and the server pass their unit tests, and the client builds. A full local run
> (key generation of the committee, two real offer proofs, decryption, `settle`) was not made. The
> commands below are the intended flow, taken from `scripts/` and from `examples/sealed-cca`. Do not
> treat them as observed output.

Run these commands in this order, in this directory unless stated otherwise.

1. Build the Noir circuits of the protocol for the insecure SIMD preset. Run it in the repository
   root. `e3-zk-build` bakes in the repository root at compile time: build it in your own target
   directory.

   ```sh
   CARGO_TARGET_DIR=$PWD/target-zk pnpm build:circuits --preset insecure-simd --committee minimum
   ```

   This switches the generated configuration (`ActiveCryptoConfig.sol`, `scripts/utils.ts`,
   `circuits/lib/src/configs/default/`) to the insecure SIMD preset. Do not commit these files.

2. Build the SDK of the protocol (it bundles the user-data encryption circuits): `pnpm sdk:build` in
   the repository root.

3. Set up the example. It compiles the offer circuits (`circuits/compile.sh`: it writes the verifier
   `contracts/verifiers/NegotiationOfferVerifier.sol` and the VK anchor
   `circuits/target/vk_anchor.json`), builds the program, builds `@interfold/negotiation` and
   compiles the contracts:

   ```sh
   pnpm install
   pnpm dev:setup
   ```

   If `interfold noir setup` (the last step of `dev:setup`) fails with
   `checksum missing for circuits-...`, install the circuits of this checkout instead, as
   `examples/auction-e2e/README.md` describes (`--circuits-archive`,
   `--circuits-configuration insecure-simd/minimum`, `--allow-unpinned-archive`).

4. Start the stack: anvil, the ciphernodes, the program server, the coordination server and the web
   app (<http://localhost:3000>):

   ```sh
   pnpm dev:all
   ```

   Ports 13415 (swarm) and 13151 (program runner) are fixed: run one local stack at a time.

### Use the web app

1. Connect a wallet to anvil (chain ID 31337, RPC `http://localhost:8545`). Do not use the accounts
   1 to 5 (ciphernodes) or 9 (the relayer of the server). Use the well-known keys on a local chain
   only.
2. **Get test tokens** (fee token for the E3 request).
3. **Create** a negotiation: title, seller address, buyer address, range `[min, max, step]` of 2 to
   16 levels (for example 48 to 63 with step 1), window in minutes. Optionally choose a picture
   (PNG, JPEG or WebP): the page shrinks it, and the wallet signs the upload after the request is
   mined. Copy the link `/n/<e3Id>`. Key generation takes about 11 minutes with full proof
   aggregation and less with the skipped one (see Prerequisites).
4. Open the link as the seller and as the buyer. Enter a price on the grid (the seller 50, the
   buyer 60) and select **Seal my price**. The page shows the 3 encryptions, the 3 encryption
   proofs, the lanes proof and the offer proof. Each proof takes about 1 to 2 minutes in Node. Then
   the wallet sends one transaction (or the relayer does, with a signature). The page does not show
   the price again, except from the browser storage.
5. After the window the server computes, the committee decrypts, and anyone selects **Settle**. The
   page shows the agreed price (a level of the grid, for 50 and 60 one of 50 to 60) or **No match**.

### The integration test

`tests/integration.spec.ts` runs the whole flow against a local stack with real proofs. It opens all
negotiations first, then proves and sends each offer (the seller directly, the buyer through the
relay with an EIP-712 signature), waits for the decryption, calls `settle` and checks the outcome
against `expectedOutcome`. It prints one line
`NEGOTIATION <e3Id> seller=<price> buyer=<price> -> price=<p|no match>` for each negotiation. The
grid starts at the price 48 with step 1.

```sh
NEGOTIATION_CASES="2:12,2:12,2:12,11:3" pnpm test:integration   # seller step : buyer step
```

The variables are in the header of `scripts/test_integration.sh` (`NEGOTIATIONS`, `SELLER_STEP`,
`BUYER_STEP`, `PROOF_CONCURRENCY`). Run it once to see the distribution of the price for 50 against
60 (the first three negotiations) and a no-match (the last). No output of this run is recorded here.

## Test

```sh
pnpm test                            # Hardhat: program contract, output decoder, generated verifier
pnpm test:server                     # vitest: server and SDK (layout, encoders, uniformity, pictures)
pnpm -C sdk uniformity               # the exact law of the price and its distance to the uniform law
(cd circuits/lib && nargo test)      # circuit encoding rules against the shared vectors
cargo test -p e3-user-program        # the FHE program against the shared vectors
cargo run --release -p e3-user-program --example distribution -- --seller-step 2 --buyer-step 12 --runs 300
cargo run --release -p e3-user-program --example noise -- --negotiations 40 --parties 3
python3 research/alternatives.py     # the table of families in DESIGN.md
```

`NEG_PROVE=1 pnpm -C sdk test` also makes one real offer proof (about 5 minutes).

Gas with the mock verifier: `publishInput` 371,216; `settle` 453,805 on a match and 429,385 on no
match. `settle` sums the 8 groups of each level with a table of 16 x 128 weights, because the sum is
linear in the coefficients. The program contract is 20.6 KB.

## Layout

| Path                                   | What it holds                                                                          |
| -------------------------------------- | -------------------------------------------------------------------------------------- |
| `DESIGN.md`                            | The design, the rejected alternatives, the leak analysis                               |
| `contracts/NegotiationProgram.sol`     | The E3 program: create, offers, settle                                                 |
| `contracts/libraries/`                 | `SlotCodec` (coefficients to slots), `NegotiationOutput` (sum of the groups, validity) |
| `contracts/verifiers/`                 | The generated Honk verifier of `negotiation_offer`                                     |
| `circuits/{lib,lanes,offer}`           | The encoding rules and tests; the lanes proof; the top (EVM) proof                     |
| `program/`, `guest/`, `runner/`, `da/` | The FHE program, the OpenVM guest, the dev runner, the data-availability helper        |
| `server/`                              | Coordination server: inputs, scheduling, relay, pictures                               |
| `client/`                              | The web app (Vite, React)                                                              |
| `sdk/`                                 | `@interfold/negotiation`: layout, uniformity, encoders, `OfferProver`, test vectors    |
| `research/`                            | `alternatives.py` (families of priorities), `measurements.md` (noise, distribution)    |
| `test/`, `tests/`                      | Hardhat tests; the integration test                                                    |

## Limits

- The parameters are insecure (N = 128, t = 257). They give no security.
- The agreed price is **not** exactly uniform: the largest total variation distance from the uniform
  law is 0.42 and the mean is 0.14 over all intervals of 16 levels. A price from the top of the
  interval is more likely than an inner price. A family with a smaller distance needs a rank in the
  hundreds, which does not fit in the platform. A grid of 8 levels has a largest distance of 0.30
  and a mean of 0.087.
- The grid has at most 16 levels (the 16 slots of a group). A finer grid needs more coefficients in
  the output; this is not built.
- There is one offer for each party and no update. A party that does not send an offer stops the
  negotiation, with no leak and no refund (there is no deposit).
- The match bit and the price are public, as is who sent an offer and when. Privacy of the two
  prices rests on the committee key: a committee that decrypts an input ciphertext breaks it.
- A malicious party can pick its own price and share freely, but cannot learn the other price, steer
  `p`, or add a non-zero offset to the mask: the circuit checks the encoding and the zero sum.
- If both parties collude they learn nothing beyond the two prices they already know. If one party
  draws a non-uniform share, the pointer is still uniform if the other party draws uniformly.
- The compute proof is a mock on the local chain (`TEMPLATE_UNPROVED_TEST`). The OpenVM guest does
  not build without `cargo openvm build`, as in `examples/auction-e2e`.
- The browser proof of one offer takes minutes (3 encryption proofs, one lanes proof, one offer
  proof).
- With the skipped proof aggregation the committee key and the decryption are not proven on chain;
  the mock verifiers accept any well-formed placeholder. Use `NEGOTIATION_REAL_PROOFS_AGG=1` to
  check the real path.
- The server stores the picture of a negotiation without a rate limit. A creator can upload 1 MiB
  for each negotiation that the creator owns, and the file stays on the disk of the server. The
  picture is public. An EOA wallet must sign the upload: the server does not check ERC-1271
  signatures.
- This example was not run on Sepolia.
