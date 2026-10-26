// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The hashes of the bid proof and the claim proof (`circuits/bid`, `circuits/claim`): the bid
 * commitment, the nullifier and the salt. Poseidon2 is the Barretenberg implementation, which equals
 * the `poseidon::poseidon2::Poseidon2` of the circuits; `test-vectors/proofs.json` and the circuit
 * tests pin the values. The claim tree hash (Poseidon1, circomlib) is in `merkle.ts`.
 */
import { Barretenberg } from '@aztec-foundation/bb.js'
import { type Address, type Hex, toHex } from 'viem'

/** The BN254 scalar field modulus: every public input is below it. */
export const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/** The domain of the bid commitment: the ASCII bytes of `tlaunch-bid-v1`. */
export const BID_DOMAIN = 0x746c61756e63682d6269642d7631n
/** The domain of the nullifier: the ASCII bytes of `tlaunch-null-v1`. */
export const NULLIFIER_DOMAIN = 0x746c61756e63682d6e756c6c2d7631n

/**
 * The sale id as a circuit input. An E3 id is `(Interfold address << 96) + counter`, which can exceed
 * the field modulus, so the circuits, the commitments and the contract all use `saleId mod r`.
 */
export function saleField(saleId: bigint): bigint {
  return saleId % BN254_R
}

/** A value that is not a field element. */
function assertField(name: string, value: bigint): void {
  if (value < 0n || value >= BN254_R) throw new Error(`${name} is not a BN254 field element`)
}

/** A field element as 32 big-endian bytes. */
export function fieldBytes(value: bigint): Uint8Array {
  assertField('A value', value)
  const bytes = new Uint8Array(32)
  let rest = value
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(rest & 0xffn)
    rest >>= 8n
  }
  return bytes
}

/** A field element as a 32-byte hex word (`bytes32`), the form the contract and the proofs use. */
export function fieldHex(value: bigint | Hex | string): Hex {
  return toHex(fieldBytes(BigInt(value)))
}

/** A fresh salt: 31 random bytes as a `bytes32` (below the field, so it is one field element). */
export function randomSalt(): Hex {
  const bytes = new Uint8Array(32)
  globalThis.crypto.getRandomValues(bytes.subarray(1))
  return toHex(bytes)
}

/** Poseidon2 of the field elements `inputs` (a sponge of the length of `inputs`). */
export async function poseidon2(inputs: readonly bigint[], api?: Barretenberg): Promise<Hex> {
  const own = api ?? (await Barretenberg.new({ threads: 1 }))
  try {
    const { hash } = await own.poseidon2Hash({ inputs: inputs.map(fieldBytes) })
    return toHex(hash)
  } finally {
    if (api === undefined) await own.destroy()
  }
}

/** What opens a bid commitment. */
export interface BidOpening {
  /** The max price step `b`. */
  step: number
  /** The budget `B` in budget units. */
  budget: number
  /** The escrow `X` in budget units. */
  escrowUnits: number
  /** The salt: 31 random bytes (`randomSalt`). */
  salt: Hex | bigint
  bidder: Address
  /** The sale id: the id of the round-1 E3. */
  saleId: bigint
}

/** `Poseidon2([BID_DOMAIN, b, B, X, salt, bidder, sale_id])`: `compute_bid_commitment` of both circuits. */
export function bidCommitment(opening: BidOpening, api?: Barretenberg): Promise<Hex> {
  const { step, budget, escrowUnits, salt, bidder, saleId } = opening
  return poseidon2([BID_DOMAIN, BigInt(step), BigInt(budget), BigInt(escrowUnits), BigInt(salt), BigInt(bidder), saleField(saleId)], api)
}

/** `Poseidon2([NULLIFIER_DOMAIN, salt, sale_id])`: `compute_nullifier` of the claim circuit. */
export function nullifier({ salt, saleId }: { salt: Hex | bigint; saleId: bigint }, api?: Barretenberg): Promise<Hex> {
  return poseidon2([NULLIFIER_DOMAIN, BigInt(salt), saleField(saleId)], api)
}
