<!--
SPDX-License-Identifier: LGPL-3.0-only

This file is provided WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.
-->

# Public inputs of the token-launch proofs

This file is the contract between the circuits, the Solidity program, the SDK and the client. Each
value is one BN254 field element. In Solidity it is a `bytes32` (big-endian, below the field
modulus). The array has no pairing-point elements: the generated verifier appends them itself.

## Bid proof: `token_launch_bid`

One circuit, one proof for BOTH ciphertexts of a bid (one under the committee key of each E3 of
the sale). It has 1,432,756 gates, fewer than 2^21, so a browser can prove it. Solidity verifier:
`contracts/verifiers/TokenLaunchBidVerifier.sol`, contract `TokenLaunchBidVerifier`
(`verify(bytes proof, bytes32[] publicInputs) returns (bool)`). Eleven public inputs, in this order:

| #   | Name              | Value                                                                                   | Who sets it                     |
| --- | ----------------- | --------------------------------------------------------------------------------------- | ------------------------------- |
| 0   | `ct_commitment_1` | The commitment of the round-1 ciphertext (`ctCommitment1` of the `BidInput`).           | the bidder, checked by the leaf |
| 1   | `ct_commitment_2` | The commitment of the round-2 ciphertext (`ctCommitment2`).                             | the bidder, checked by the leaf |
| 2   | `bid_commitment`  | `Poseidon2([BID_DOMAIN, b, B, X, salt, bidder, sale_id], 7)` (`bidCommitment`).         | the bidder                      |
| 3   | `bidder`          | `uint160(bidder)`: the sender, or the signer of a relayed bid.                          | the contract                    |
| 4   | `sale_id`         | The id of the round-1 E3.                                                               | the contract                    |
| 5   | `levels`          | The number of price steps of the sale (8 to 16).                                        | the contract (from the sale)    |
| 6   | `bidder_index`    | The index `i` of the bid (0 to 84): `bidCount` before this bid.                         | the contract (from storage)     |
| 7   | `escrow_units`    | `X`: the escrow of the tier, in budget units (at most 4095).                            | the contract (from the tier)    |
| 8   | `pk_commitment_1` | The committee key commitment of E3-1 (`e3.committeePublicKey`).                         | the contract                    |
| 9   | `pk_commitment_2` | The committee key commitment of E3-2.                                                   | the contract                    |
| 10  | `vk_anchor`       | `vkAnchor` of the deployment (see below).                                               | the contract (immutable)        |

Inputs 0 to 7 are `pub` parameters of `main` (`ct_commitments: pub [Field; 2]` first). Inputs 8 to 10
are its return value.

- `BID_DOMAIN` is the ASCII bytes of `tlaunch-bid-v1` as one big-endian integer:
  `0x746c61756e63682d6269642d7631` (`BID_DOMAIN` in both circuits and in `sdk/src/commitments.ts`).
- `Poseidon2` is `poseidon::poseidon2::Poseidon2::hash` of the noir-lang/poseidon package over BN254
  with the 7 inputs above. `@aztec-foundation/bb.js` `poseidon2Hash` computes the same value
  (`sdk/src/prover.test.ts` and the circuit tests pin it).
- The circuit proves: each ciphertext (of `ct_commitment_r`) is a well-formed encryption under the
  committee key of `pk_commitment_r` (Interfold user-data encryption proof, both with the same
  wrapper circuit and the same two VK chains); the plaintext polynomial `k1` is the same in both and
  is the SIMD plaintext of the bid (`sdk/src/layout.ts`): cell `(l, j)` at slot `6 l + j` is the
  digit `d_j` of `B` (base 4, little endian) if `l <= b` and 0 otherwise, the flag cell at slot
  `96 + floor(i / 8)` is `2^(i % 8)`, every other slot is 0; the digits are below 4 and
  `B = sum d_j 4^j`; `1 <= B <= X <= 4095`; `b < levels`; `levels` is in 8 to 16; `bidder_index < 85`;
  `bidder != 0`; and `bid_commitment` opens to `(b, B, X, salt, bidder, sale_id)`.
- `vk_anchor = compute_vk_hash([ude_key_hash, ct0_chain, ct1_chain])`. It covers the user-data
  encryption circuits. The bid circuit has no inner circuit. `circuits/compile.sh` computes it and
  writes `circuits/target/vk_anchor.json` as `{ "vkAnchor": "0x..." }`. The SDK ships the file.

## Claim proof: `token_launch_claim`

Solidity verifier: `contracts/verifiers/TokenLaunchClaimVerifier.sol`, contract
`TokenLaunchClaimVerifier` (same `verify` signature). About 17,000 gates. Eleven public inputs, in
this order:

| #   | Name             | Value                                                                              | Who sets it                              |
| --- | ---------------- | ---------------------------------------------------------------------------------- | ---------------------------------------- |
| 0   | `root`           | The final root of the claim tree (depth 7, `InternalLazyIMT`).                     | the contract (stored at `clear`)         |
| 1   | `counted_mask`   | The counted bitmap, below `2^85`: bit `i` is 1 if the bid `i` counted.             | the contract (stored at `clear`)         |
| 2   | `sale_id`        | The id of the round-1 E3.                                                          | the contract                             |
| 3   | `k`              | The step of the clearing: `s` (capped), `l` (uncapped) or 0 (undersubscribed).     | the contract (from the clearing)         |
| 4   | `nullifier`      | `Poseidon2([NULLIFIER_DOMAIN, salt, sale_id], 3)`.                                 | the claimant                             |
| 5   | `recipient`      | `uint160(recipient)`: the fresh address that is paid. The proof binds it.          | the claimant (`ClaimData`)               |
| 6   | `escrow_units`   | `X`: the escrow of the bid (in the commitment).                                    | the claimant (`ClaimData`)               |
| 7   | `budget_units`   | `B` if `cmp != 0`, else 0.                                                         | the claimant (`ClaimData`)               |
| 8   | `reveal_index`   | 1 iff the sale is capped and `now <= marginalDeadline`, else 0 (a bit).            | the contract                             |
| 9   | `cmp`            | `0` if `b < k`, `1` if `b == k`, `2` if `b > k`.                                   | the claimant: the circuit return         |
| 10  | `index_plus_one` | `index + 1` if `cmp == 1` and `reveal_index == 1`, else 0.                         | the claimant: the circuit return         |

Inputs 0 to 8 are `pub` parameters of `main`. Inputs 9 and 10 are its return value `(cmp, index_plus_one)`.

- Private inputs: `b`, `B`, `salt`, `bidder`, `index` (the leaf index of the bid) and the 7 siblings
  of its Merkle path. `bidder` and `index` stay private, so a claim does not link to the
  `BidSubmitted` event of the bid, except for a marginal registration (`index_plus_one != 0`): a
  marginal bid is filled in bid order, so it shows its position.
- The circuit proves: the commitment `Poseidon2([BID_DOMAIN, b, B, X, salt, bidder, sale_id], 7)`
  (the commitment of the bid circuit, with `X = escrow_units`) is the leaf `index` under `root`;
  bit `index` of `counted_mask` is 1; `nullifier` is as above; `cmp` compares `b` and `k` (4-bit
  values); `budget_units` is `B` if `cmp != 0` and 0 otherwise; `reveal_index` is a bit;
  `index_plus_one` is as above; `recipient != 0`.
- The claim tree hash is circomlib `Poseidon(2)` (`poseidon::poseidon::bn254::hash_2`), which equals
  the `PoseidonT3` of zk-kit's `InternalLazyIMT`. The empty subtree values are `Z0 = 0`,
  `Z(k + 1) = hash(Z(k), Z(k))`. Bit `k` of the leaf index is 1 if the node is the right child at
  level `k`.
- `NULLIFIER_DOMAIN` is the ASCII bytes of `tlaunch-null-v1`: `0x746c61756e63682d6e756c6c2d7631`.
- The proof bytes do not contain the public inputs. The contract rebuilds inputs 0 to 3 and 8 from
  storage and the clock, takes 4 to 7 from `ClaimData`, and needs `cmp` and `index_plus_one` as inputs
  9 and 10 too, so the claimant sends them in `ClaimData`. The contract MUST reject a `cmp` above 2,
  a `cmp` that disagrees with `budget_units` (`(cmp == 0) == (budget_units == 0)`), and an
  `index_plus_one` that is not 0 when `cmp != 1` or `reveal_index == 0` and not in `1..=bidCount`
  otherwise, before it verifies.
