// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Barretenberg, Crs, GrumpkinCrs, UltraHonkBackend } from '@aztec/bb.js'
import { type InputMap, Noir, type CompiledCircuit } from '@noir-lang/noir_js'
import { computeCiphertextCommitment, computePublicKeyCommitment, encryptVectorAndGenInputs, openLbfvKeyEnvelope } from '@interfold/sdk'
import { insecureSimdProofBundle } from '@interfold/sdk/internal/presets/insecure-simd'
import { proveUserDataEncryptionTree } from '@interfold/user-data-encryption-prover'
import type { Address, Hex } from 'viem'
import bid3CircuitJson from '../circuits/bid3/target/auction_bid3.json'
import bid4CircuitJson from '../circuits/bid4/target/auction_bid4.json'
import masksCircuitJson from '../circuits/masks/target/auction_bid_masks.json'
import pairCircuitJson from '../circuits/pair/target/auction_bid_pair.json'
import { assertBid, bidSlots, type AuctionType, GROUPS, LEVELS, MIN_LEVELS, PRESET, Role, rolesFor } from './layout'

/** The insecure SIMD parameters on the l-BFV path: param set 5. */
export { PRESET }
export const PARAM_SET = 5

/** The circuit that proves a whole bid, for each number of roles: `auction_bid3` or `auction_bid4`. */
const BID_CIRCUITS: Record<number, CompiledCircuit> = {
  3: bid3CircuitJson as CompiledCircuit,
  4: bid4CircuitJson as CompiledCircuit,
}
/** The inner proofs of the bid: the roles 0 and 1 with the bid itself, and the roles 2 and 3 (type 3). */
const pairCircuit = pairCircuitJson as CompiledCircuit
const masksCircuit = masksCircuitJson as CompiledCircuit

/**
 * The SRS size. Every circuit of the bid tree has fewer than 2^21 gates (`bb gates`: 1.43M each).
 * More than that does not fit the 4 GiB of the browser's WASM heap. On the WASM backend the size
 * must be given at creation.
 */
const SRS_POINTS = 2 ** 21

/** The number of free values of a pair mask: one for each level of each pair of groups. */
const PAIR_VALUES = (GROUPS / 2) * LEVELS

/** The free values of a pair mask: `values[c * LEVELS + l]` is the slot `l` of the group `2c`. */
function pairValues(slots: BigUint64Array): string[] {
  return Array.from({ length: PAIR_VALUES }, (_, unit) => {
    const [pair, level] = [Math.floor(unit / LEVELS), unit % LEVELS]
    return slots[2 * pair * LEVELS + level].toString()
  })
}

/** One bid, encrypted and proven, ready for `AuctionProgram.publishInput`. */
export interface PreparedBid {
  /** One ciphertext for each role of the auction type, in role order. */
  ciphertexts: Hex[]
  /** The ciphertext commitment of each ciphertext (bytes32), in role order. */
  commitments: Hex[]
  /** The bid proof, the only proof that goes on chain. */
  proof: Hex
  /** The proof's public outputs, for display: committee key commitment and VK anchor. */
  pkCommitment: Hex
  vkAnchor: Hex
}

export type BidStep =
  | { kind: 'encrypt' | 'encryption-proof'; role: Role }
  | { kind: 'pair-proof' }
  | { kind: 'masks-proof' }
  | { kind: 'bid-proof' }

export function toHex(bytes: Uint8Array): Hex {
  let hex = '0x'
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0')
  return hex as Hex
}

function proofToFields(proof: Uint8Array): string[] {
  const fields: string[] = []
  for (let i = 0; i < proof.length; i += 32) fields.push(toHex(proof.subarray(i, i + 32)))
  return fields
}

/** Normalize a field element to a 32-byte hex word, the form the contract and bb.js use. */
function word(value: string): Hex {
  return `0x${BigInt(value).toString(16).padStart(64, '0')}`
}

/** A proof that another circuit verifies: the proof, its public inputs, and the backend that made it. */
interface InnerProof {
  proof: Uint8Array
  publicInputs: string[]
  backend: UltraHonkBackend
}

/** What the verifying circuit needs of an inner circuit: its key and the hash of it. */
interface InnerKey {
  vkAsFields: string[]
  vkHash: string
}

/** One ciphertext of the bid with the proof of its encryption. */
interface Encrypted {
  role: Role
  slots: BigUint64Array
  ciphertext: Hex
  commitment: Hex
  /** The plaintext `k1` as the circuits take it. */
  k1: { coefficients: unknown }
  wrapper: InnerProof
}

/**
 * Proves auction bids with one Barretenberg instance. Loading the SRS dominates a small proof, so
 * a bidder should keep one prover open for all of its bids.
 */
export class BidProver {
  private constructor(private readonly api: Barretenberg) {}

  static async create(): Promise<BidProver> {
    if (!('window' in globalThis)) return new BidProver(await Barretenberg.new({ srsSize: SRS_POINTS }))
    // In a browser `Barretenberg.new` caches the decompressed SRS (2^21 × 64 bytes) as one
    // IndexedDB value, which Chromium rejects above 127 MiB. Load it the same way, minus that cache;
    // each page load downloads the compressed points again.
    const api = await Barretenberg.new({ srsSize: SRS_POINTS, skipSrsInit: true })
    const [crs, grumpkinCrs] = await Promise.all([Crs.new(SRS_POINTS), GrumpkinCrs.new(2 ** 16)])
    await api.srsInitSrs({ pointsBuf: crs.getG1Data(), numPoints: crs.numPoints, g2Point: crs.getG2Data() })
    await api.srsInitGrumpkinSrs({ pointsBuf: grumpkinCrs.getG1Data(), numPoints: grumpkinCrs.numPoints })
    return new BidProver(api)
  }

  async destroy(): Promise<void> {
    await this.api.destroy()
  }

  /**
   * Encrypt a bid to the committee key and prove it valid, with one proof for the whole bid.
   *
   * The bid is 3 or 4 ciphertexts, one for each role of `type`. The plaintext of each is
   * SIMD-encoded: the thermometer slots of the bid for the roles 0 and 1, uniform random slots for
   * the mask (role 2), and uniform random slots that repeat in each pair of groups for the pair
   * mask (role 3). All proofs run on this machine, so the bid never leaves it. The proofs form a
   * tree, and no circuit has more than 2^21 gates, so a browser can prove each one:
   *
   * - for every role, Interfold's user-data encryption proof (the ciphertext encrypts `k1` under
   *   the committee key);
   * - `auction_bid_pair`: the proofs of the roles 0 and 1, and `k1` of both is the thermometer of
   *   the one bid, which is below `levels`;
   * - `auction_bid_masks` (type 3 only): the proofs of the roles 2 and 3, and the pair mask is
   *   pair-equal;
   * - `auction_bid3` or `auction_bid4`: verifies the proofs above. This is the only proof
   *   published. It binds `bidder`, the address that will be the bidder of `publishInput` (the
   *   sender or the signer of a relayed bid), and `levels`, the number of price steps of the auction.
   */
  async prove(
    type: AuctionType,
    bid: number,
    levels: number,
    committeeKey: Uint8Array,
    bidder: Address,
    onStep?: (step: BidStep) => void,
  ): Promise<PreparedBid> {
    assertBid(bid)
    // The circuit enforces it as well; failing here saves the proofs that would be wasted.
    if (!Number.isInteger(levels) || levels < MIN_LEVELS || levels > LEVELS) {
      throw new Error(`An auction has ${MIN_LEVELS} to ${LEVELS} price steps, got ${levels}`)
    }
    if (bid >= levels) throw new Error(`The bid is step ${bid}, but this auction has the steps 0 to ${levels - 1}`)
    const roles = rolesFor(type)
    const bidCircuit = BID_CIRCUITS[roles.length]

    const encryptions: Encrypted[] = []
    for (const role of roles) {
      onStep?.({ kind: 'encrypt', role })
      const slots = bidSlots(role, bid)
      const { encryptedData, circuitInputs } = await encryptVectorAndGenInputs(slots, committeeKey, PRESET, {
        encoding: 'simd',
      })
      // An l-BFV committee key yields the chunked witness; a trBFV key would mean the wrong preset.
      if (!('r1is' in circuitInputs)) {
        throw new Error(`The committee key is not an l-BFV key; this program needs param set ${PARAM_SET}`)
      }
      const commitment = toHex(await computeCiphertextCommitment(encryptedData, PRESET))

      onStep?.({ kind: 'encryption-proof', role })
      const wrapper = await this.proveEncryption(circuitInputs)
      // Fail here rather than on chain: the leaf the contract inserts must be the commitment the
      // FHE program recomputes from the published bytes.
      if (word(wrapper.publicInputs[3]) !== commitment) {
        throw new Error('The encryption proof commits to a different ciphertext than the one being published')
      }
      encryptions.push({ role, slots, ciphertext: toHex(encryptedData), commitment, k1: circuitInputs.k1, wrapper })
    }

    // Every wrapper proof has the same circuit, so one key serves all of them. All of them also
    // carry the same encryption key row and VK chains (the circuits assert it).
    const [ude] = encryptions
    const udeKey = await keyOf(ude.wrapper)
    const shared = { pk_row0: ude.wrapper.publicInputs[2], ct0_chain: ude.wrapper.publicInputs[0], ct1_chain: ude.wrapper.publicInputs[1] }
    const wrapperInputs = (list: Encrypted[]) => ({
      user_data_encryption_verification_key: udeKey.vkAsFields,
      user_data_encryption_proofs: list.map(({ wrapper }) => proofToFields(wrapper.proof)),
      user_data_encryption_public_inputs: list.map(({ wrapper }) => wrapper.publicInputs),
    })
    const k1Of = ({ k1 }: Encrypted) => ({ coefficients: k1.coefficients })

    onStep?.({ kind: 'pair-proof' })
    const [ge, gt] = encryptions
    const pair = await this.proveInner(pairCircuit, {
      ...wrapperInputs([ge, gt]),
      ct_commitments: [ge.commitment, gt.commitment],
      levels,
      ...shared,
      user_data_encryption_key_hash: udeKey.vkHash,
      k1s: [k1Of(ge), k1Of(gt)],
      b: bid.toString(),
    } as InputMap)
    const pairKey = await keyOf(pair)

    const opening = await openLbfvKeyEnvelope(committeeKey, PRESET)
    const commonInputs = {
      user_data_encryption_key_hash: udeKey.vkHash,
      pair_verification_key: pairKey.vkAsFields,
      pair_proof: proofToFields(pair.proof),
      pair_key_hash: pairKey.vkHash,
      ct_commitments: encryptions.map(({ commitment }) => commitment),
      bidder: BigInt(bidder).toString(),
      levels,
      public_key_row_commitments: opening.publicKeyRows.map(toHex),
      relinearization_key_commitment: toHex(opening.relinearizationKey),
    }
    let finalInputs: InputMap
    if (roles.length === 4) {
      onStep?.({ kind: 'masks-proof' })
      const [, , mask, pairMask] = encryptions
      const masks = await this.proveInner(masksCircuit, {
        ...wrapperInputs([mask, pairMask]),
        ct_commitments: [mask.commitment, pairMask.commitment],
        ...shared,
        user_data_encryption_key_hash: udeKey.vkHash,
        pair_mask_k1: k1Of(pairMask),
        pair_values: pairValues(pairMask.slots),
      } as InputMap)
      const masksKey = await keyOf(masks)
      onStep?.({ kind: 'bid-proof' })
      finalInputs = {
        ...commonInputs,
        ct0_chain: shared.ct0_chain,
        ct1_chain: shared.ct1_chain,
        masks_verification_key: masksKey.vkAsFields,
        masks_proof: proofToFields(masks.proof),
        masks_key_hash: masksKey.vkHash,
      } as InputMap
    } else {
      onStep?.({ kind: 'bid-proof' })
      const mask = encryptions[2]
      finalInputs = {
        ...commonInputs,
        user_data_encryption_verification_key: udeKey.vkAsFields,
        mask_proof: proofToFields(mask.wrapper.proof),
        mask_public_inputs: mask.wrapper.publicInputs,
      } as InputMap
    }
    const { witness, returnValue } = await new Noir(bidCircuit).execute(finalInputs)
    // The contract checks this output against the E3's committee key commitment.
    const committeeCommitment = toHex(await computePublicKeyCommitment(committeeKey, PRESET))
    if (!Array.isArray(returnValue) || typeof returnValue[0] !== 'string' || word(returnValue[0]) !== committeeCommitment) {
      throw new Error('The bid circuit does not reproduce the committee key commitment')
    }
    const backend = new UltraHonkBackend(bidCircuit.bytecode, this.api)
    const proof = await backend.generateProof(witness, { verifierTarget: 'evm' })

    // The public inputs: the ciphertext commitments, bidder, levels, pk_commitment, vk_anchor.
    const outputs = proof.publicInputs.length - 2
    return {
      ciphertexts: encryptions.map(({ ciphertext }) => ciphertext),
      commitments: encryptions.map(({ commitment }) => commitment),
      proof: toHex(proof.proof),
      pkCommitment: word(proof.publicInputs[outputs]),
      vkAnchor: word(proof.publicInputs[outputs + 1]),
    }
  }

  /** A proof that the bid circuit verifies: a recursive proof, without zero knowledge. */
  private async proveInner(circuit: CompiledCircuit, inputs: InputMap): Promise<InnerProof> {
    const { witness } = await new Noir(circuit).execute(inputs)
    const backend = new UltraHonkBackend(circuit.bytecode, this.api)
    const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget: 'noir-recursive-no-zk' })
    return { proof, publicInputs, backend }
  }

  /**
   * The user-data encryption proof of one ciphertext: the proof tree, then the wrapper proof that
   * the bid circuits verify.
   */
  private async proveEncryption(circuitInputs: Parameters<typeof proveUserDataEncryptionTree>[2]): Promise<InnerProof> {
    const { userDataEncryption, ...proofTree } = insecureSimdProofBundle
    const { ct0, ct1 } = await proveUserDataEncryptionTree(this.api, proofTree, circuitInputs)
    return this.proveInner(userDataEncryption, {
      ct0_verification_key: ct0.vkAsFields,
      ct0_proof: proofToFields(ct0.proof),
      ct0_public_inputs: ct0.publicInputs,
      ct0_key_hash: ct0.vkHash,
      ct1_verification_key: ct1.vkAsFields,
      ct1_proof: proofToFields(ct1.proof),
      ct1_public_inputs: ct1.publicInputs,
      ct1_key_hash: ct1.vkHash,
    })
  }
}

/** The key of the circuit that made `inner`, as the verifying circuit takes it. */
async function keyOf({ backend, proof, publicInputs }: InnerProof): Promise<InnerKey> {
  const { vkAsFields, vkHash } = await backend.generateRecursiveProofArtifacts(proof, publicInputs.length, {
    verifierTarget: 'noir-recursive-no-zk',
  })
  return { vkAsFields, vkHash }
}
