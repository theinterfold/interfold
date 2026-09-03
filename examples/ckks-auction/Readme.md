# CKKS Sealed-Bid Auction — an E3 program on Interfold

A sealed-bid auction whose **winner is computed under threshold CKKS and revealed as a matrix of
±1 comparison signs and nothing else**. Bids are encrypted and proven **in the bidder's browser**,
submitted **from the bidder's own wallet**, and verified **on-chain by three UltraHonk proofs**
before they enter the computation. The coordination server never sees a bid; the committee never
decrypts one.

Shaped like [`examples/CRISP`](../CRISP): actix-web + sled coordination server with an Interfold
indexer, token-holder (balance) Merkle snapshot, a Vite/React client, a client SDK, a plain-Rust
program crate, deploy scripts and a one-command dev runner.

```
ckks-auction/
├── client/                      # Vite + React 18 + viem + react-query + react-router (port 5173)
├── server/                      # Rust: actix-web 4 + sled + Interfold indexer (port 8090); bins: server, cli
│   └── src/server/{indexer,rounds,evaluate,contract,repo,models,routes/,token_holders/}.rs
├── program/                     # plain-Rust policy wrapper: sign-extraction winner + result decode
├── packages/ckks-auction-sdk/   # TS: WASM encrypt → 3-leg proving, balance tree, envelope + wallet tx, API client
├── scripts/                     # dev.sh (one command), deploy.sh, dev_cipher.sh, dev_server.sh, dev_client.sh, e2e.mjs
├── Cargo.toml                   # workspace (server + program), path deps on ../../crates
└── Readme.md
```

Shared building blocks (read-only, consumed): `examples/ckks-common/packages/ckks-zk-inputs`
(browser WASM CKKS encryption + Greco witnesses), the circuits in `circuits/bin/threshold`
(`user_data_encryption_ckks_ct{0,1}_ps2`, `ckks_auction_validity_ps2`), the program contract
`packages/interfold-contracts/contracts/test/CkksAuctionE3Program.sol` and its Honk verifiers,
the hardhat tasks `program:set-balance-root` / `program:publish-app-input`, and the
`e3-trckks` sign-extraction policy.

## The protocol

1. **Snapshot → root.** The round opener (server key) builds a Poseidon Merkle tree over
   `poseidon([address, balance])` leaves (CRISP's token-holder model; zero-leaf padding, depth
   `max(1, ⌈log₂ n⌉)`, max 20) and publishes ONE root on the program contract with
   `setBalanceRoot(e3Id, root)`. The E3 is requested **through** `CkksAuctionE3Program` — the
   program address selects the CKKS scheme and ParamSet 2 (the 12-iteration sign-extraction
   ladder: N=512, one 45-bit + 37×40-bit limbs, Δ=2⁴⁰, plus three 60-bit special primes for
   HYBRID key switching).
2. **DKG + relin ceremony.** Five ciphernodes run the threshold-CKKS DKG (over the wide DKG
   transport) and ONE two-round multiparty HYBRID relin-key ceremony, writing the single joint
   key to `$CKKS_RELIN_KEY_DIR/<chain>:<e3Id>/rlk_hybrid.bin`. Why one ceremony: the sign map
   multiplies at 24 different levels of the modulus chain, and a classic RNS-decomposition
   relin key is bound to ONE level (24 keys ≈ 115 MiB/party upload, ~2 min of DHT transport on
   the dev stack). The hybrid gadget (special primes `P`, digit decomposition, Han–Ki 2020)
   makes one key at modulus `Q·P` serve every level — ~2.7 MiB, one round trip per ceremony
   round — and divides the relinearization noise by `P`, which is what keeps the 12-iteration
   chain precise at secure parameters.
3. **Bid (browser).** The client fetches the bidder's leaf + path (`GET
   /rounds/{id}/balance-proof/{address}`) and the committee key, then — all in the page —
   - CKKS-encrypts `bid` slot-replicated (`@interfold/ckks-zk-inputs`, ONE encryption producing
     the ciphertext AND both Greco witness input maps),
   - proves the **app leg** `ckks_auction_validity_ps2` (bid ≤ balance under the root, address
     public input, slot-replication tail bound, recomputed `m_commitment`),
   - proves the **Greco ct1** and **ct0** legs (`user_data_encryption_ckks_ct{1,0}_ps2`),
   - ABI-encodes the 7-tuple envelope and sends `publishInput(e3Id, data)` **from the bidder's
     wallet** (viem; injected wallet or an anvil dev key).
4. **Gate (chain).** `CkksAuctionE3Program` requires `u_commitment` equal across ct0/ct1,
   `m_commitment` equal across ct0/app, `cap == bidCap`, `address == msg.sender`, the round's
   root, no prior `(e3Id, u_commitment)`, and then verifies all three Honk proofs (~3 M gas).
   It emits `VerifiedInputPublished`; the ciphertext lives in calldata.
5. **Index.** The server indexes `VerifiedInputPublished` (raw log handler → keeps the tx hash),
   fetches the transaction, decodes the envelope and checks `keccak(ciphertext)` against the
   emitted commitment — CRISP's `InputPublished` model: no side upload, chain is canonical.
6. **Evaluate + publish.** When the input window closes (indexer deadline hook, with retries
   until the ceremony keys are on disk; or the admin "Evaluate now" button) the server runs
   `sign_extraction_policy`: all i<j differences normalised by `1/bound`, packed one per slot,
   12 iterations of `f(y) = (1.5 − 0.5y²)y` with the ONE hybrid ceremony key, and publishes the resulting
   ciphertext with `publishCiphertextOutput`.
7. **Open.** The committee threshold-decrypts; the aggregator publishes the canonical
   fixed-point plaintext. The server decodes the ±1 sign matrix, counts wins, names the winner
   (bid index → publisher address) and flags any unsaturated slot.

### What the proof proves (and what stays hidden)

| leg | circuit | proves |
| --- | --- | --- |
| ct0 | `user_data_encryption_ckks_ct0_ps2` | `ct0 = pk0·u + e0 + m` per limb with bounded `u`, `e0`, `m`; outputs `(pk0_c, ct0_c, m_commitment, u_commitment)` |
| ct1 | `user_data_encryption_ckks_ct1_ps2` | `ct1 = pk1·u + e1` per limb; outputs `(pk1_c, ct1_c, u_commitment)` |
| app | `ckks_auction_validity_ps2` | same `m` (re-commits `m_commitment`); `m₀ = round(Δ·bid/cap)` (±2·cap) and every tail coefficient ≤ 64 ⇒ **slot-replicated**; `0 ≤ bid ≤ balance`; `poseidon(address, balance)` opens to `merkle_root`; public `[cap, address, merkle_root]` |

Hidden: every bid value and every gap between bids (12 sign iterations binarise gaps ≥ ~2 % of
the bound to exactly ±1; smaller gaps shrink toward 0 rather than leaking magnitude). Public: who
bid, how many bids, the full comparison order. Sender binding is `msg.sender` on-chain, not an
in-circuit signature.

## Running it

Prerequisites: the interfold toolchain (Rust 1.91.1, `nargo` v1.0.0-beta.26, `bb`, Foundry,
pnpm), a **release** node binary (`cargo build --release --bin interfold` at the repo root —
the ladder DKG blocks a debug node for minutes), the compiled ps2 circuits
(`circuits/bin/threshold/target/*_ps2.json`), and the built WASM package
(`examples/ckks-common/packages/ckks-zk-inputs/dist`).

```bash
cd examples/ckks-auction
pnpm install                     # sdk + client (+ playwright for the e2e)
pnpm build:server                # server + cli (release)
pnpm dev:up                      # anvil → contracts → 5 ciphernodes → server :8090 → client :5173
```

`dev:up` runs `scripts/dev.sh`: `anvil` (chain 31337, 1 s blocks) ‖ `deploy.sh` (Interfold +
mocks + `CkksAuctionE3Program` + ParamSet 2, registers the program, syncs the node config,
writes `server/.env`) → `dev_cipher.sh` (wallets, `noir setup`, `nodes up`, registers the 5
nodes) ‖ `dev_server.sh` ‖ `dev_client.sh`. Ctrl-C tears it down.

Then in the client: **Rounds → Request round** (default snapshot: anvil accounts #6–#9 and #0
with balances 100/500/1000/1000/1000; accounts #1–#5 are the ciphernodes), wait ~2–3 min for
`committee key published` + `1/1 keys`, open the round, pick a dev wallet in the navbar, enter
a bid, **Encrypt, prove & submit**. The per-stage timings are shown live. When the window closes
(or on **Evaluate now**) the results panel shows the winner and the sign matrix.

CLI: `target/release/cli open|rounds|round <id>|evaluate <id>`.

### API (server, port 8090)

| route | |
| --- | --- |
| `GET /status` | chain/program addresses, bound, param set |
| `GET /rounds` · `GET /rounds/{id}` | summaries · detail (snapshot, bids, ceremony key count, results, timings) |
| `POST /rounds/request` `{snapshot:[{address,balance}], durationSecs?}` | open a round (admin key) |
| `GET /rounds/{id}/public-key` | committee CKKS pk (hex) |
| `GET /rounds/{id}/balance-proof/{address}` | leaf + path (CRISP `state/token-holders` analogue) |
| `POST /rounds/{id}/evaluate` | evaluate + publish now |

There is deliberately **no bid endpoint**.

## End-to-end test

```bash
pnpm dev:up                      # in one terminal (CKKS_AUCTION_NO_CLIENT=0)
pnpm test:e2e                    # in another: drives the REAL client in headless Chromium
```

`scripts/e2e.mjs` (playwright) opens a round through the Rounds page with the 5-address
snapshot, waits for the key + ceremony, then for each bidder selects the dev wallet in the
navbar, types the bid and clicks submit — the page does the WASM encryption, the three proofs and
the wallet transaction. It asserts: (1) a bid of 700 from the balance-500 wallet **fails
client-side before proving** with `bid 700 exceeds your attested balance 500` (the app-leg
predicate); (2) four bids 220/815/402/382 are accepted (tx hashes, gas); (3) re-sending bid #0's
exact calldata **reverts with `DuplicateSubmission`**; (4) after the window closes → evaluate →
publish → threshold decrypt, the winner is the 815 bidder and **every opened slot is a saturated
±1** — including the 402 vs 382 pair (a 2 % gap). The report lands in
`/tmp/ckks-auction-e2e-report.json`.

Unit tests: `cargo test --release` (server: calldata recovery, tree parity with the on-chain
fixture; program: outcome decoding), `pnpm test:sdk` (poseidon-lite tree parity with the same
fixture root — `0x2ae63b16…db47`).

## Measured timings

See the "Live run" section at the end for the numbers recorded by the e2e (browser proving per
leg, tx gas, DKG+ceremony wall, evaluation, decryption). Standalone browser probe (Apple Silicon,
headless Chrome, `crossOriginIsolated`, SRS 2²⁰): WASM encrypt+witness ~2.0 s, noir execute
~2.7 s per Greco leg, **prove ct1 ≈ 13.1 s, ct0 ≈ 13.6 s, app ≈ 1.0 s**, Barretenberg init
~4.7 s, total ≈ 40 s per bid. The ps2 Greco legs (circuit_size ≈ 836 k) prove in-browser; no
fallback to native proving was needed.

## Honest scope / deviations from CRISP

- **No RISC Zero program.** CRISP's `program/` is a zkVM guest with a compute-provider proof; the
  CKKS policy runs natively in the server (`program/` is the plain-Rust wrapper) and the
  ciphertext output is published with the dev stack's mock ciphertext verifier. Bid VALIDITY is
  fully proven and verified on-chain; the correctness of the homomorphic evaluation itself is
  not (same posture as `demo/ckks-auction`).
- Threshold decryption of the ladder runs proof-free on the nodes (the C6 circuit is compiled for
  ParamSet 0 only; see the skill notes), and the relin ceremony has no ZK proof wired anywhere in
  the stack (verify-by-determinism; a C8 circuit for the hybrid round-1 share,
  `relin_round1_hybrid_ckks`, exists and proves but is not emitted/verified).
- The balance snapshot is an admin-supplied list (CRISP's `get_mock_token_holders` analogue), not
  an Etherscan/on-chain census.
- Sender binding is `msg.sender` (CRISP-style), so bids cannot be relayed by the server — hence
  the wallet in the client and no relay endpoint.
- Circuits are served by a Vite middleware from `circuits/bin/threshold/target` (5 MB each), not
  copied into the SDK package.
- Poseidon: the server uses `e3_zk_helpers::…::BalanceTree` (light-poseidon 0.2, circom params);
  the client uses `poseidon-lite` like CRISP's sdk. Both are pinned to the same fixture root the
  on-chain gate accepted a real proof under.
