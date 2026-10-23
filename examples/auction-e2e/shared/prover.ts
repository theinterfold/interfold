// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Barretenberg, Crs, GrumpkinCrs, UltraHonkBackend } from '@aztec/bb.js'
import { Noir, type CompiledCircuit } from '@noir-lang/noir_js'
import { computeCiphertextCommitment, computePublicKeyCommitment, encryptVectorAndGenInputs, openLbfvKeyEnvelope } from '@interfold/sdk'
import { insecureSimdProofBundle } from '@interfold/sdk/internal/presets/insecure-simd'
import { proveUserDataEncryptionTree } from '@interfold/user-data-encryption-prover'
import { encodeAbiParameters, parseAbiParameters } from 'viem'
import recordCircuitJson from '../circuits/record/target/auction_bid.json'
import foldCircuitJson from '../circuits/fold/target/auction_fold.json'
import { assertBid, bidSlots, GROUPS, LEVELS, PRESET, Role } from './layout'

/** The insecure SIMD parameters on the l-BFV path: param set 5. */
export { PRESET }
export const PARAM_SET = 5

const recordCircuit = recordCircuitJson as CompiledCircuit
const foldCircuit = foldCircuitJson as CompiledCircuit

/**
 * What a bidder keeps private for one bid: the bid and the salt of its commitment. The roles 0 and 1
 * of one bid must use the same secret, so the contract can link them by the commitment.
 */
export interface BidSecret {
  bid: number
  /** A random field element: it hides the bid in the bid commitment. */
  salt: bigint
}

/** The number of free values of a pair mask: one for each level of each pair of groups. */
const PAIR_VALUES = (GROUPS / 2) * LEVELS

/** The free values of a pair mask: `values[c * LEVELS + l]` is the slot `l` of the group `2c`. */
function pairValues(slots: BigUint64Array): string[] {
  return Array.from({ length: PAIR_VALUES }, (_, unit) => {
    const [pair, level] = [Math.floor(unit / LEVELS), unit % LEVELS]
    return slots[2 * pair * LEVELS + level].toString()
  })
}

/** One ciphertext, encrypted and proven, ready for `AuctionProgram.publishInput`. */
export interface PreparedInput {
  role: Role
  ciphertext: `0x${string}`
  ciphertextCommitment: `0x${string}`
  /** `poseidon2(bid, salt)` for the roles 0 and 1, and zero for the masks (roles 2 and 3). */
  bidCommitment: `0x${string}`
  proof: `0x${string}`
  /** The fold's public outputs, for display: committee key commitment and VK anchor. */
  pkCommitment: `0x${string}`
  vkAnchor: `0x${string}`
}

/** A secret for `bid`, with a fresh random salt (248 bits, below the field modulus). */
export function newBidSecret(bid: number): BidSecret {
  assertBid(bid)
  const bytes = crypto.getRandomValues(new Uint8Array(31))
  return { bid, salt: BigInt(toHex(bytes)) }
}

export type ProveStep = 'encrypt' | 'encryption-proof' | 'bid-proof' | 'fold-proof'

export function toHex(bytes: Uint8Array): `0x${string}` {
  let hex = '0x'
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0')
  return hex as `0x${string}`
}

function proofToFields(proof: Uint8Array): string[] {
  const fields: string[] = []
  for (let i = 0; i < proof.length; i += 32) fields.push(toHex(proof.subarray(i, i + 32)))
  return fields
}

/** Normalize a field element to a 32-byte hex word, the form the contract and bb.js use. */
function word(value: string): `0x${string}` {
  return `0x${BigInt(value).toString(16).padStart(64, '0')}`
}

/**
 * Proves auction ciphertexts with one Barretenberg instance. Loading the SRS dominates a small
 * proof, so a bidder submitting three ciphertexts should keep one prover open.
 */
export class InputProver {
  private constructor(private readonly api: Barretenberg) {}

  static async create(): Promise<InputProver> {
    // The fold circuit has 2^21 gates. On the WASM backend the SRS size must be given here.
    const srsPoints = 2 ** 21
    if (!('window' in globalThis)) return new InputProver(await Barretenberg.new({ srsSize: srsPoints }))
    // In a browser `Barretenberg.new` caches the decompressed SRS (2^21 × 64 bytes) as one
    // IndexedDB value, which Chromium rejects above 127 MiB. Load it the same way, minus that cache;
    // each page load downloads the compressed points again.
    const api = await Barretenberg.new({ srsSize: srsPoints, skipSrsInit: true })
    const [crs, grumpkinCrs] = await Promise.all([Crs.new(srsPoints), GrumpkinCrs.new(2 ** 16)])
    await api.srsInitSrs({ pointsBuf: crs.getG1Data(), numPoints: crs.numPoints, g2Point: crs.getG2Data() })
    await api.srsInitGrumpkinSrs({ pointsBuf: grumpkinCrs.getG1Data(), numPoints: grumpkinCrs.numPoints })
    return new InputProver(api)
  }

  async destroy(): Promise<void> {
    await this.api.destroy()
  }

  /**
   * Encrypt one ciphertext of a bid to the committee key and prove it valid.
   *
   * The plaintext is SIMD-encoded: the thermometer slots of the bid for the roles 0 and 1, uniform
   * random slots for the mask (role 2), and uniform random slots that repeat in each pair of
   * groups for the pair mask (role 3). Three proofs, all on this machine, so the bid never leaves
   * it: Interfold's user-data encryption proof (the ciphertext encrypts `k1` under the committee
   * key), the `auction_bid` proof (`k1` is the thermometer of the bid committed in
   * `bidCommitment`, anything for the mask, or a pair-equal mask for the pair mask), and the `auction_fold` proof that verifies both and
   * is the only one published. The fold proof binds `bidder`, the address that will send
   * `publishInput`: the contract rejects the proof from any other sender.
   */
  async prove(
    role: Role,
    secret: BidSecret,
    committeeKey: Uint8Array,
    bidder: `0x${string}`,
    onStep?: (step: ProveStep) => void,
  ): Promise<PreparedInput> {
    onStep?.('encrypt')
    const slots = bidSlots(role, secret.bid)
    const { encryptedData, circuitInputs } = await encryptVectorAndGenInputs(slots, committeeKey, PRESET, {
      encoding: 'simd',
    })
    const ciphertextCommitment = toHex(await computeCiphertextCommitment(encryptedData, PRESET))

    onStep?.('encryption-proof')
    const { userDataEncryption, ...proofTree } = insecureSimdProofBundle
    // An l-BFV committee key yields the chunked witness; a trBFV key would mean the wrong preset.
    if (!('r1is' in circuitInputs)) {
      throw new Error(`The committee key is not an l-BFV key; this program needs param set ${PARAM_SET}`)
    }
    const { ct0, ct1 } = await proveUserDataEncryptionTree(this.api, proofTree, circuitInputs)
    const { witness: wrapperWitness } = await new Noir(userDataEncryption).execute({
      ct0_verification_key: ct0.vkAsFields,
      ct0_proof: proofToFields(ct0.proof),
      ct0_public_inputs: ct0.publicInputs,
      ct0_key_hash: ct0.vkHash,
      ct1_verification_key: ct1.vkAsFields,
      ct1_proof: proofToFields(ct1.proof),
      ct1_public_inputs: ct1.publicInputs,
      ct1_key_hash: ct1.vkHash,
    })
    const wrapperBackend = new UltraHonkBackend(userDataEncryption.bytecode, this.api)
    const wrapper = await wrapperBackend.generateProof(wrapperWitness, { verifierTarget: 'noir-recursive-no-zk' })
    const wrapperArtifacts = await wrapperBackend.generateRecursiveProofArtifacts(wrapper.proof, wrapper.publicInputs.length, {
      verifierTarget: 'noir-recursive-no-zk',
    })
    // Fail here rather than on chain: the leaf the contract inserts must be the commitment the
    // FHE program recomputes from the published bytes.
    if (word(wrapper.publicInputs[3]) !== ciphertextCommitment) {
      throw new Error('The encryption proof commits to a different ciphertext than the one being published')
    }

    onStep?.('bid-proof')
    const commitsToBid = role === Role.Ge || role === Role.Gt
    const { witness: recordWitness, returnValue } = await new Noir(recordCircuit).execute({
      k1: { coefficients: circuitInputs.k1.coefficients },
      // The masks commit to nothing: their bid and salt are not constrained.
      b: commitsToBid ? secret.bid.toString() : '0',
      salt: commitsToBid ? `0x${secret.salt.toString(16)}` : '0',
      // The witness of the pair mask. Zero for the other roles.
      pair_values: role === Role.PairMask ? pairValues(slots) : Array<string>(PAIR_VALUES).fill('0'),
      role,
    })
    const recordBackend = new UltraHonkBackend(recordCircuit.bytecode, this.api)
    const recordProof = await recordBackend.generateProof(recordWitness, { verifierTarget: 'noir-recursive-no-zk' })
    const recordArtifacts = await recordBackend.generateRecursiveProofArtifacts(recordProof.proof, recordProof.publicInputs.length, {
      verifierTarget: 'noir-recursive-no-zk',
    })
    if (!Array.isArray(returnValue) || typeof returnValue[0] !== 'string' || typeof returnValue[1] !== 'string') {
      throw new Error('auction_bid must return the k1 commitment and the bid commitment')
    }
    const [k1Commitment, bidCommitment] = returnValue as [string, string]

    onStep?.('fold-proof')
    const opening = await openLbfvKeyEnvelope(committeeKey, PRESET)
    const { witness: foldWitness, returnValue: foldOutput } = await new Noir(foldCircuit).execute({
      user_data_encryption_verification_key: wrapperArtifacts.vkAsFields,
      user_data_encryption_proof: proofToFields(wrapper.proof),
      user_data_encryption_public_inputs: wrapper.publicInputs,
      user_data_encryption_key_hash: wrapperArtifacts.vkHash,
      record_verification_key: recordArtifacts.vkAsFields,
      record_proof: proofToFields(recordProof.proof),
      record_key_hash: recordArtifacts.vkHash,
      role,
      ct_commitment: ciphertextCommitment,
      bid_commitment: bidCommitment,
      bidder: BigInt(bidder).toString(),
      k1_commitment: k1Commitment,
      public_key_row_commitments: opening.publicKeyRows.map(toHex),
      relinearization_key_commitment: toHex(opening.relinearizationKey),
    })
    // The contract checks this output against the E3's committee key commitment.
    const committeeCommitment = toHex(await computePublicKeyCommitment(committeeKey, PRESET))
    if (!Array.isArray(foldOutput) || typeof foldOutput[0] !== 'string' || word(foldOutput[0]) !== committeeCommitment) {
      throw new Error('The fold circuit does not reproduce the committee key commitment')
    }
    const foldBackend = new UltraHonkBackend(foldCircuit.bytecode, this.api)
    const fold = await foldBackend.generateProof(foldWitness, { verifierTarget: 'evm' })

    return {
      role,
      ciphertext: toHex(encryptedData),
      ciphertextCommitment,
      bidCommitment: word(bidCommitment),
      proof: toHex(fold.proof),
      // The fold's public inputs: role, ct_commitment, bid_commitment, bidder, pk_commitment, vk_anchor.
      pkCommitment: word(fold.publicInputs[4]),
      vkAnchor: word(fold.publicInputs[5]),
    }
  }
}

/** The `data` argument of `AuctionProgram.publishInput`. */
export function encodeBidInput(input: PreparedInput): `0x${string}` {
  return encodeAbiParameters(parseAbiParameters('uint8, bytes, bytes32, bytes32, bytes'), [
    input.role,
    input.ciphertext,
    input.ciphertextCommitment,
    input.bidCommitment,
    input.proof,
  ])
}
