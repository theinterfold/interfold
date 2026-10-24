<!--
SPDX-License-Identifier: LGPL-3.0-only

This file is provided WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.
-->

# Public inputs of the sealed-cca proofs

This file is the contract between the circuits, the Solidity program, the SDK and the client. Each
value is one BN254 field element. In Solidity it is a `bytes32` (big-endian, below the field
modulus). The array has no pairing-point elements: the generated verifier appends them itself.

## Bid proof: `sealed_cca_bid`

One circuit, one proof. It has fewer than 2^21 gates, so a browser can prove it. Solidity verifier:
`contracts/verifiers/SealedCcaBidVerifier.sol`, contract `SealedCcaBidVerifier`
(`verify(bytes proof, bytes32[] publicInputs) returns (bool)`). Nine public inputs, in this order:

| #   | Name             | Value                                                                             | Who sets it                     |
| --- | ---------------- | --------------------------------------------------------------------------------- | ------------------------------- |
| 0   | `ct_commitment`  | The commitment of the bid ciphertext (`ctCommitment` in the `publishInput` data). | the bidder, checked by the leaf |
| 1   | `bid_commitment` | `poseidon2([DOMAIN_BID, b, salt, bidder, e3_id], 5)` (`bidCommitment`).           | the bidder                      |
| 2   | `bidder`         | `uint160(bidder)`: the sender, or the signer of a relayed bid.                    | the contract                    |
| 3   | `e3_id`          | `e3Id`.                                                                           | the contract                    |
| 4   | `levels`         | The number of price steps of the sale (2 to 16).                                  | the contract (from the sale)    |
| 5   | `bidder_index`   | The index `i` of the bidder (0 to 111), assigned by `deposit`.                    | the contract (from storage)     |
| 6   | `version`        | The version of this bid (1 to 3).                                                 | the contract (`bidCount + 1`)   |
| 7   | `pk_commitment`  | The committee key commitment of the E3 (`e3.committeePublicKey`).                 | the contract                    |
| 8   | `vk_anchor`      | `vkAnchor` of the deployment (see below).                                         | the contract (immutable)        |

Inputs 0 to 6 are `pub` parameters of `main`. Inputs 7 and 8 are its return value.

- `DOMAIN_BID` is the ASCII bytes of `scca-bid-v1` as one big-endian integer:
  `0x736363612d6269642d7631` (`BID_DOMAIN` in `circuits/bid/src/main.nr`). The claim circuit uses
  the same value.
- `Poseidon2` is the Noir standard library sponge (`std::hash::poseidon2::Poseidon2::hash`) over
  BN254 with the 5 inputs above. `@aztec/bb.js` `poseidon2Hash` computes the same value.
- The circuit proves: the ciphertext of `ct_commitment` is a well-formed encryption under the
  committee key of `pk_commitment` (Interfold user-data encryption proof); its plaintext is the
  thermometer `m[l] = 1 if l <= b else 0` in slots 0 to 15, `m[16 + bidder_index] = version`, and 0
  in every other slot; `b < levels`; `levels` is in 2 to 16; `bidder_index < 112`; `version` is in 1
  to 3; `bidder != 0`; and `bid_commitment` opens to `(b, salt, bidder, e3_id)`.
- `vk_anchor = compute_vk_hash([ude_key_hash, ct0_chain, ct1_chain])`. It covers the user-data
  encryption circuits. The bid circuit has no inner circuit. `scripts/compile_circuits.sh` computes
  it and writes `circuits/target/vk_anchor.json` as `{ "vkAnchor": "0x..." }`. The SDK ships the
  file.

## Claim proof: `sealed_cca_claim`

Solidity verifier: `contracts/verifiers/SealedCcaClaimVerifier.sol`, contract
`SealedCcaClaimVerifier` (same `verify` signature). Five public inputs, in this order:

| #   | Name             | Value                                                              | Who sets it                          |
| --- | ---------------- | ------------------------------------------------------------------ | ------------------------------------ |
| 0   | `bid_commitment` | The `bidCommitment` the contract stored for the counted version.   | the contract                         |
| 1   | `bidder`         | `uint160(bidder)`.                                                 | the contract                         |
| 2   | `e3_id`          | `e3Id`.                                                            | the contract                         |
| 3   | `k`              | The step of the clearing: `s` (capped) or `l` (uncapped). 0 to 15. | the contract (from the clearing)     |
| 4   | `cmp`            | `0` if `b < k`, `1` if `b == k`, `2` if `b > k`.                   | the claimant: the circuit returns it |

Inputs 0 to 3 are `pub` parameters of `main`. Input 4 is its return value.

- Private inputs: `b` (0 to 15) and `salt`.
- The circuit proves `bid_commitment == poseidon2([DOMAIN_BID, b, salt, bidder, e3_id], 5)` and that
  `cmp` is the comparison of `b` and `k`.
- The proof bytes do not contain `cmp`. The contract needs it as public input 4, so the claimant
  must send it. `ClaimProver.prove` returns `{ proof, cmp, calldata }`, with
  `calldata = abi.encode(uint8 cmp, bytes proof)`. The contract decides how to take it in `claim`.
  The contract MUST reject a `cmp` above 2 before it verifies.

## Slot layout of the program output (revealMode 0)

One ciphertext, `N = 128` slots (insecure-simd, `t = 257`):

| Slots     | Value                                                                                   |
| --------- | --------------------------------------------------------------------------------------- |
| `0..15`   | `c_l`: the number of counted bidders with `b >= l` (`c_l <= 112`)                       |
| `16..127` | `counted[i]` for bidder index `i = slot - 16`, `0..111`: the counted version 1..3, or 0 |

The bid ciphertext holds the thermometer in slots `0..L-1`, its version in slot `16 + i` (`i` is the
bidder index) and 0 in every other slot. The program only adds the selected ciphertexts, so after
threshold decryption slot `16 + i` is the counted version of bidder `i` (0 if dropped). The maximum
number of bidders is 112.

The committee publishes the plaintext as 128 polynomial coefficients. The SIMD decode
(`simd_decode`) maps them to the slots above.
