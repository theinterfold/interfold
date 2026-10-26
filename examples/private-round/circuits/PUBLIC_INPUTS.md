<!--
SPDX-License-Identifier: LGPL-3.0-only

This file is provided WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.
-->

# Public inputs of the private-round proofs

This file is the contract between the circuits, the Solidity program, the SDK and the client. Each
value is one BN254 field element. In Solidity it is a `bytes32` (big-endian, below the field
modulus). The array has no pairing-point elements: the generated verifier appends them itself.

## Bid proof: `private_round_bid`

One circuit, one proof. It verifies both user-data encryption proofs of a bid (the bid ciphertext
and the mask ciphertext). It has 1,427,418 gates, fewer than 2^21, so a browser can prove it.
Solidity verifier: `contracts/verifiers/PrivateRoundBidVerifier.sol`, contract
`PrivateRoundBidVerifier` (`verify(bytes proof, bytes32[] publicInputs) returns (bool)`). Eleven
public inputs, in this order:

| #   | Name                 | Value                                                                              | Who sets it                     |
| --- | -------------------- | ---------------------------------------------------------------------------------- | ------------------------------- |
| 0   | `ct_commitment_bid`  | The commitment of the bid ciphertext (role 0, the first leaf of the bid).          | the bidder, checked by the leaf |
| 1   | `ct_commitment_mask` | The commitment of the mask ciphertext (role 1, the second leaf of the bid).        | the bidder, checked by the leaf |
| 2   | `bid_commitment`     | `poseidon2([DOMAIN_BID, b, salt, bidder, e3_id], 5)` (`bidCommitment`).            | the bidder                      |
| 3   | `bidder`             | `uint160(bidder)`: the sender, or the signer of a relayed bid.                     | the contract                    |
| 4   | `e3_id`              | `e3Id`.                                                                            | the contract                    |
| 5   | `levels`             | The number of price steps of the round (2 to 16).                                  | the contract (from the round)   |
| 6   | `reserve_step`       | The reserve step of the round (0 to `levels - 1`).                                 | the contract (from the round)   |
| 7   | `bidder_index`       | The index `i` of the bidder (0 to 12), assigned by `deposit`.                      | the contract (from storage)     |
| 8   | `version`            | The version of this bid (1 to 3).                                                  | the contract (`bidCount + 1`)   |
| 9   | `pk_commitment`      | The committee key commitment of the E3 (`e3.committeePublicKey`).                  | the contract                    |
| 10  | `vk_anchor`          | `vkAnchor` of the deployment (see below).                                          | the contract (immutable)        |

Inputs 0 to 8 are `pub` parameters of `main`. Inputs 9 and 10 are its return value.

- `DOMAIN_BID` is the ASCII bytes of `prnd-bid-v1` as one big-endian integer:
  `0x70726e642d6269642d7631` (`BID_DOMAIN` in `circuits/bid/src/main.nr`). The claim circuit uses
  the same value.
- `Poseidon2` is the Barretenberg Poseidon2 sponge over BN254 with the 5 inputs above (the
  `poseidon` package of Noir). `@aztec-foundation/bb.js` `poseidon2Hash` computes the same value.
- The circuit proves: the ciphertexts of `ct_commitment_bid` and `ct_commitment_mask` are well-formed
  encryptions under the committee key of `pk_commitment` (two Interfold user-data encryption proofs
  with the same wrapper key, the same two VK chains and the same encryption key); the plaintext of
  the bid ciphertext is the bid below; `b < levels`; `levels` is in 2 to 16; `reserve_step < levels`;
  `bidder_index < 13`; `version` is in 1 to 3; `bidder != 0`; and `bid_commitment` opens to
  `(b, salt, bidder, e3_id)`. The mask ciphertext has no plaintext constraint: its 128 slots are
  free, and the bidder chooses them uniformly in `[0, 257)`.
- The bid plaintext, with `rho = reserve_step`:
  - slot `g * 16 + l` is 1 if `l <= b`, else 0, for `g` in 0 to 5 and `l` in 0 to 15 (slots 0 to 95);
  - slot `96 + k` is 1 if `b >= rho`, else 0, for `k` in 0 to 5 (slots 96 to 101);
  - slot `115 + bidder_index` is `version` (slots 115 to 127);
  - every other slot is 0.
- `vk_anchor = compute_vk_hash([ude_key_hash, ct0_chain, ct1_chain])`. It covers the user-data
  encryption circuits. The bid circuit has no other inner circuit. `circuits/compile.sh` computes
  it and writes `circuits/target/vk_anchor.json` as `{ "vkAnchor": "0x..." }`. The SDK ships the
  file.

## Claim proof: `private_round_claim`

Solidity verifier: `contracts/verifiers/PrivateRoundClaimVerifier.sol`, contract
`PrivateRoundClaimVerifier` (same `verify` signature). Five public inputs, in this order:

| #   | Name             | Value                                                              | Who sets it                          |
| --- | ---------------- | ------------------------------------------------------------------ | ------------------------------------ |
| 0   | `bid_commitment` | The `bidCommitment` the contract stored for the counted version.   | the contract                         |
| 1   | `bidder`         | `uint160(bidder)`.                                                 | the contract                         |
| 2   | `e3_id`          | `e3Id`.                                                            | the contract                         |
| 3   | `k`              | The step of the claim: `l*` (sold out) or `reserve_step - 1`. 0 to 15. | the contract (from the clearing) |
| 4   | `cmp`            | `0` if `b < k`, `1` if `b == k`, `2` if `b > k`.                   | the claimant: the circuit returns it |

Inputs 0 to 3 are `pub` parameters of `main`. Input 4 is its return value.

- Private inputs: `b` (0 to 15) and `salt`.
- The circuit proves `bid_commitment == poseidon2([DOMAIN_BID, b, salt, bidder, e3_id], 5)` and that
  `cmp` is the comparison of `b` and `k`.
- The proof bytes do not contain `cmp`. The contract needs it as public input 4, so the claimant
  must send it. `ClaimProver.prove` returns `{ proof, cmp, calldata }`, with
  `calldata = abi.encode(uint8 cmp, bytes proof)`. The contract decides how to take it in `claim`.
  The contract MUST reject a `cmp` above 2 before it verifies.
