// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Barretenberg, Crs, GrumpkinCrs, UltraHonkBackend } from '@aztec-foundation/bb.js'
import { type InputMap, Noir, type CompiledCircuit } from '@noir-lang/noir_js'
import { computeCiphertextCommitment, computePublicKeyCommitment, encryptVectorAndGenInputs, openLbfvKeyEnvelope } from '@interfold/sdk'
import { insecureSimdProofBundle } from '@interfold/sdk/internal/presets/insecure-simd'
import { proveUserDataEncryptionTree } from '@interfold/user-data-encryption-prover'
import type { Address, Hex } from 'viem'
import lanesCircuitJson from '../circuits/negotiation_offer_lanes.json'
import offerCircuitJson from '../circuits/negotiation_offer.json'
import { assertShare, assertStep, LEVELS, MIN_LEVELS, OFFER_CIPHERTEXTS, offerSlots, PRESET, randomShare, type Role } from './layout'

/** The insecure SIMD parameters on the l-BFV path: param set 5. */
export { PRESET }
export const PARAM_SET = 5

/** The proof of the lane ciphertexts 0 and 1 (a recursive proof) and the offer proof (the EVM proof). */
const lanesCircuit = lanesCircuitJson as CompiledCircuit
const offerCircuit = offerCircuitJson as CompiledCircuit

/**
 * The SRS size. Every circuit of the offer tree has fewer than 2^21 gates (`bb gates` in
 * `circuits/compile.sh`). More than that does not fit the 4 GiB of the browser's WASM heap. On the WASM
 * backend the size must be given at creation.
 */
const SRS_POINTS = 2 ** 21

/** One offer, encrypted and proven, ready for `NegotiationProgram.publishInput`. */
export interface PreparedOffer {
  /** The three ciphertexts: lanes 0..7, lanes 8..15, mask. */
  ciphertexts: Hex[]
  /** The ciphertext commitment of each ciphertext (bytes32), in the same order. */
  commitments: Hex[]
  /** The offer proof, the only proof that goes on chain. */
  proof: Hex
  /** The proof's public outputs, for display: committee key commitment and VK anchor. */
  pkCommitment: Hex
  vkAnchor: Hex
}

/** The steps of `OfferProver.prove`, in order: `encrypt` and `encryption-proof` for each ciphertext index, then the two offer proofs. */
export type OfferStep = { kind: 'encrypt' | 'encryption-proof'; index: number } | { kind: 'lanes-proof' } | { kind: 'offer-proof' }

export interface OfferInput {
  /** `Role.Seller` (0) or `Role.Buyer` (1). */
  role: Role
  /** The private price step of the party: the seller's minimum or the buyer's maximum, `0 <= step < levels`. */
  step: number
  /** The private share of the party (4 bits). A uniform random share if omitted. */
  share?: number
  /** The mask slots (128 values mod `t`, zero sum over the groups of each level). A uniform random mask if omitted. */
  mask?: BigUint64Array
  /** The address that will be the party of `publishInput` (the sender or the signer of a relayed offer). */
  party: Address
  /** The number of price levels of the negotiation (2 to 16). */
  levels: number
  /** The committee key of the E3, as the key envelope the SDK takes. */
  committeeKey: Uint8Array
  onStep?: (step: OfferStep) => void
}

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

/** One ciphertext of the offer with the proof of its encryption. */
interface Encrypted {
  ciphertext: Hex
  commitment: Hex
  /** The plaintext `k1` as the circuits take it. */
  k1: { coefficients: unknown }
  wrapper: InnerProof
}

/**
 * Proves negotiation offers with one Barretenberg instance. Loading the SRS dominates a small proof, so
 * a party should keep one prover open for all of its offers.
 */
export class OfferProver {
  private constructor(private readonly api: Barretenberg) {}

  static async create(): Promise<OfferProver> {
    if (!('window' in globalThis)) return new OfferProver(await Barretenberg.new({ srsSize: SRS_POINTS }))
    // In a browser `Barretenberg.new` caches the decompressed SRS (2^21 × 64 bytes) as one
    // IndexedDB value, which Chromium rejects above 127 MiB. Load it the same way, minus that cache;
    // each page load downloads the compressed points again.
    const api = await Barretenberg.new({ srsSize: SRS_POINTS, skipSrsInit: true })
    const [crs, grumpkinCrs] = await Promise.all([Crs.new(SRS_POINTS), GrumpkinCrs.new(2 ** 16)])
    await api.srsInitSrs({ pointsBuf: crs.getG1Data(), numPoints: crs.numPoints, g2Point: crs.getG2Data() })
    await api.srsInitGrumpkinSrs({ pointsBuf: grumpkinCrs.getG1Data(), numPoints: grumpkinCrs.numPoints })
    return new OfferProver(api)
  }

  async destroy(): Promise<void> {
    await this.api.destroy()
  }

  /**
   * Encrypt an offer to the committee key and prove it valid, with one proof for the whole offer.
   *
   * The offer is 3 ciphertexts. The plaintext of each is SIMD-encoded: the lane tensor of the party for
   * the ciphertexts 0 and 1 (lanes 0..7 and 8..15) and a uniform random mask with zero sum over the 8
   * groups of each level for the ciphertext 2. All proofs run on this machine, so the step and the share
   * never leave it. The proofs form a tree, and no circuit has more than 2^21 gates, so a browser can
   * prove each one:
   *
   * - for every ciphertext, Interfold's user-data encryption proof (the ciphertext encrypts `k1` under
   *   the committee key);
   * - `negotiation_offer_lanes`: the proofs of the ciphertexts 0 and 1, and `k1` of both is the lane
   *   tensor of the one private `(step, share)` of `role`, with `step` below `levels`;
   * - `negotiation_offer`: verifies the proofs above and the mask proof, and the mask has zero sum. This
   *   is the only proof published. It binds `party`, the address that will be the party of
   *   `publishInput`, `role` and `levels`.
   */
  async prove({ role, step, share = randomShare(), mask, party, levels, committeeKey, onStep }: OfferInput): Promise<PreparedOffer> {
    // The circuit enforces all of it as well; failing here saves the proofs that would be wasted.
    if (!Number.isInteger(levels) || levels < MIN_LEVELS || levels > LEVELS) {
      throw new Error(`A negotiation has ${MIN_LEVELS} to ${LEVELS} price levels, got ${levels}`)
    }
    assertStep(step, levels)
    assertShare(share)
    const plaintexts = offerSlots(role, step, share, mask)

    const encryptions: Encrypted[] = []
    for (let index = 0; index < OFFER_CIPHERTEXTS; index++) {
      onStep?.({ kind: 'encrypt', index })
      const { encryptedData, circuitInputs } = await encryptVectorAndGenInputs(plaintexts[index], committeeKey, PRESET, {
        encoding: 'simd',
      })
      // An l-BFV committee key yields the chunked witness; a trBFV key would mean the wrong preset.
      if (!('r1is' in circuitInputs)) {
        throw new Error(`The committee key is not an l-BFV key; this program needs param set ${PARAM_SET}`)
      }
      const commitment = toHex(await computeCiphertextCommitment(encryptedData, PRESET))

      onStep?.({ kind: 'encryption-proof', index })
      const wrapper = await this.proveEncryption(circuitInputs)
      // Fail here rather than on chain: the leaf the contract inserts must be the commitment the
      // FHE program recomputes from the published bytes.
      if (word(wrapper.publicInputs[3]) !== commitment) {
        throw new Error('The encryption proof commits to a different ciphertext than the one being published')
      }
      encryptions.push({ ciphertext: toHex(encryptedData), commitment, k1: circuitInputs.k1, wrapper })
    }

    // Every wrapper proof has the same circuit, so one key serves all of them. All of them also
    // carry the same encryption key row and VK chains (the circuits assert it).
    const [lane0, lane1, maskEncryption] = encryptions
    const udeKey = await keyOf(lane0.wrapper)
    const shared = {
      pk_row0: lane0.wrapper.publicInputs[2],
      ct0_chain: lane0.wrapper.publicInputs[0],
      ct1_chain: lane0.wrapper.publicInputs[1],
    }
    const k1Of = ({ k1 }: Encrypted) => ({ coefficients: k1.coefficients })

    onStep?.({ kind: 'lanes-proof' })
    const lanes = await this.proveInner(lanesCircuit, {
      user_data_encryption_verification_key: udeKey.vkAsFields,
      user_data_encryption_proofs: [lane0, lane1].map(({ wrapper }) => proofToFields(wrapper.proof)),
      user_data_encryption_public_inputs: [lane0, lane1].map(({ wrapper }) => wrapper.publicInputs),
      ct_commitments: [lane0.commitment, lane1.commitment],
      role,
      levels,
      ...shared,
      user_data_encryption_key_hash: udeKey.vkHash,
      k1s: [k1Of(lane0), k1Of(lane1)],
      step: step.toString(),
      share: share.toString(),
    } as InputMap)
    const lanesKey = await keyOf(lanes)

    onStep?.({ kind: 'offer-proof' })
    const opening = await openLbfvKeyEnvelope(committeeKey, PRESET)
    const { witness, returnValue } = await new Noir(offerCircuit).execute({
      user_data_encryption_verification_key: udeKey.vkAsFields,
      mask_proof: proofToFields(maskEncryption.wrapper.proof),
      mask_public_inputs: maskEncryption.wrapper.publicInputs,
      user_data_encryption_key_hash: udeKey.vkHash,
      lanes_verification_key: lanesKey.vkAsFields,
      lanes_proof: proofToFields(lanes.proof),
      lanes_key_hash: lanesKey.vkHash,
      ct_commitments: encryptions.map(({ commitment }) => commitment),
      party: BigInt(party).toString(),
      role,
      levels,
      public_key_row_commitments: opening.publicKeyRows.map(toHex),
      relinearization_key_commitment: toHex(opening.relinearizationKey),
      mask_k1: k1Of(maskEncryption),
      mask: Array.from(plaintexts[2], (value) => value.toString()),
    } as InputMap)
    // The contract checks this output against the E3's committee key commitment.
    const committeeCommitment = toHex(await computePublicKeyCommitment(committeeKey, PRESET))
    if (!Array.isArray(returnValue) || typeof returnValue[0] !== 'string' || word(returnValue[0]) !== committeeCommitment) {
      throw new Error('The offer circuit does not reproduce the committee key commitment')
    }
    const backend = new UltraHonkBackend(offerCircuit.bytecode, this.api)
    const proof = await backend.generateProof(witness, { verifierTarget: 'evm' })

    // The public inputs: the ciphertext commitments, party, role, levels, pk_commitment, vk_anchor.
    const outputs = proof.publicInputs.length - 2
    return {
      ciphertexts: encryptions.map(({ ciphertext }) => ciphertext),
      commitments: encryptions.map(({ commitment }) => commitment),
      proof: toHex(proof.proof),
      pkCommitment: word(proof.publicInputs[outputs]),
      vkAnchor: word(proof.publicInputs[outputs + 1]),
    }
  }

  /** A proof that the offer circuit verifies: a recursive proof, without zero knowledge. */
  private async proveInner(circuit: CompiledCircuit, inputs: InputMap): Promise<InnerProof> {
    const { witness } = await new Noir(circuit).execute(inputs)
    const backend = new UltraHonkBackend(circuit.bytecode, this.api)
    const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget: 'noir-recursive-no-zk' })
    return { proof, publicInputs, backend }
  }

  /**
   * The user-data encryption proof of one ciphertext: the proof tree, then the wrapper proof that
   * the offer circuits verify.
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
