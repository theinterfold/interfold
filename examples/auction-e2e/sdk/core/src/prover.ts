// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The proving engine that the design packages share: one Barretenberg instance with its SRS, the
 * encryption of a ciphertext with the user-data encryption proof, the pair proof of the roles 0 and
 * 1, and the proof of the final circuit. A design package adds its own final circuit and
 * the inputs of that circuit. It ships only its own circuits.
 *
 * This entry loads `@aztec-foundation/bb.js` and the circuit `auction_bid_pair`. Import it only
 * where proofs are made. The root of the package has no proving backend.
 *
 * @packageDocumentation
 */
import { Barretenberg, Crs, GrumpkinCrs, UltraHonkBackend } from '@aztec-foundation/bb.js'
import { type InputMap, Noir, type CompiledCircuit } from '@noir-lang/noir_js'
import { computeCiphertextCommitment, computePublicKeyCommitment, encryptVectorAndGenInputs, openLbfvKeyEnvelope } from '@interfold/sdk'
import { insecureSimdProofBundle } from '@interfold/sdk/internal/presets/insecure-simd'
import { proveUserDataEncryptionTree } from '@interfold/user-data-encryption-prover'
import type { Address, Hex } from 'viem'
import pairCircuitJson from '../circuits/auction_bid_pair.json'
import { toHex } from './hex'
import { assertBid, bidSlots, LEVELS, MIN_LEVELS, PARAM_SET, PRESET, rolesFor, type AuctionType, type Role } from './layout'

/** The circuit that proves the roles 0 and 1 of a bid: the same thermometer, below `levels`. */
const pairCircuit = pairCircuitJson as CompiledCircuit

/**
 * The SRS size. Every circuit of the bid tree has fewer than 2^21 gates (`bb gates`: 1.43M each).
 * More than that does not fit the 4 GiB of the browser's WASM heap. On the WASM backend the size
 * must be given at creation.
 */
const SRS_POINTS = 2 ** 21

/** One bid, encrypted and proven, ready for `AuctionProgram.publishInput`. */
export interface PreparedBid {
  /** One ciphertext for each role of the auction type, in role order. */
  ciphertexts: Hex[]
  /** The ciphertext commitment of each ciphertext (bytes32), in role order. */
  commitments: Hex[]
  /** The bid proof, the only proof that goes on chain. */
  proof: Hex
  /** The proof's public output: the committee key commitment. For display. */
  pkCommitment: Hex
  /** The proof's public output: the VK anchor. For display. */
  vkAnchor: Hex
}

/** A step of the proof of a bid, for a progress display. The steps run in the order of this list. */
export type BidStep =
  | { kind: 'encrypt' | 'encryption-proof'; role: Role }
  | { kind: 'pair-proof' }
  | { kind: 'shares-proof' }
  | { kind: 'bid-proof' }

/** The prover that a design package returns from `createBidProver`. */
export interface BidProver {
  /**
   * Encrypt a bid to the committee key and prove it valid, with one proof for the whole bid. All
   * proofs run on this machine, so the bid never leaves it.
   *
   * @param bid The bid step, in `[0, levels)`.
   * @param levels The number of price steps of the auction.
   * @param committeeKey The public key of the committee of the E3.
   * @param bidder The address that will be the bidder of `publishInput`: the sender, or the signer of a relayed bid.
   * @param onStep Called before each step of the proof.
   * @throws When `bid` or `levels` is out of range, the committee key is not an l-BFV key, or a proof fails.
   */
  prove(bid: number, levels: number, committeeKey: Uint8Array, bidder: Address, onStep?: (step: BidStep) => void): Promise<PreparedBid>
  /** Release the Barretenberg instance. Call it when the prover is no longer in use. */
  destroy(): Promise<void>
}

/** A proof that another circuit verifies: the proof, its public inputs, and the backend that made it. */
export interface InnerProof {
  /** The proof bytes. */
  proof: Uint8Array
  /** The public inputs of the proof, as field elements. */
  publicInputs: string[]
  /** The backend that made the proof. */
  backend: UltraHonkBackend
}

/** What a verifying circuit needs of an inner circuit: its key and the hash of it. */
export interface InnerKey {
  /** The verification key as field elements. */
  vkAsFields: string[]
  /** The hash of the verification key. */
  vkHash: string
}

/** The witness of one user-data encryption proof. */
type EncryptionInputs = Parameters<typeof proveUserDataEncryptionTree>[2]

/** One ciphertext, with the witness of its encryption. */
export interface EncryptedCiphertext {
  /** The ciphertext bytes. */
  ciphertext: Hex
  /** The ciphertext commitment (bytes32). */
  commitment: Hex
  /** The plaintext `k1`, as the circuits take it. */
  k1: { coefficients: unknown }
  /** The witness of the user-data encryption proof. */
  circuitInputs: EncryptionInputs
}

/** One ciphertext with the proof of its encryption. */
export interface ProvenCiphertext extends Omit<EncryptedCiphertext, 'circuitInputs'> {
  /** The wrapper proof of the user-data encryption, which the bid circuits verify. */
  wrapper: InnerProof
}

/** What a design package sees while it builds the inputs of its final circuit. */
export interface BidTreeContext {
  /** The proving engine, for further inner proofs. */
  engine: ProvingEngine
  /** One proven ciphertext for each role, in role order. */
  encryptions: readonly ProvenCiphertext[]
  /** The key of the wrapper circuit. Every wrapper proof has the same circuit. */
  udeKey: InnerKey
  /** The values that every wrapper proof carries: the first public key row and the two ciphertext chains. */
  shared: { pk_row0: string; ct0_chain: string; ct1_chain: string }
  /** The inputs that every final circuit takes: the pair proof, the commitments, `bidder`, `levels` and the key commitments. */
  commonInputs: InputMap
  /** The inputs that a circuit takes to verify the wrapper proofs of `list`. */
  wrapperInputs(list: readonly ProvenCiphertext[]): InputMap
  /** Report a step of the proof. */
  step(step: BidStep): void
}

/** The final circuit of a design and the inputs of that circuit. */
export interface BidTreeSpec {
  /** The auction type. It sets the roles and so the number of ciphertexts. */
  type: AuctionType
  /** The compiled final circuit: the only proof that goes on chain. */
  bidCircuit: CompiledCircuit
  /**
   * Build the inputs of `bidCircuit`. The context already holds the encryptions and the pair proof.
   * Run any extra inner proof here.
   */
  finalInputs(context: BidTreeContext): Promise<InputMap>
}

/** Encode proof bytes as 32-byte field elements. */
export function proofToFields(proof: Uint8Array): string[] {
  const fields: string[] = []
  for (let i = 0; i < proof.length; i += 32) fields.push(toHex(proof.subarray(i, i + 32)))
  return fields
}

/** Normalize a field element to a 32-byte hex word, the form the contract and bb.js use. */
export function word(value: string): Hex {
  return `0x${BigInt(value).toString(16).padStart(64, '0')}`
}

/** Get the key of the circuit that made `inner`, as a verifying circuit takes it. */
export async function keyOf({ backend, proof, publicInputs }: InnerProof): Promise<InnerKey> {
  const { vkAsFields, vkHash } = await backend.generateRecursiveProofArtifacts(proof, publicInputs.length, {
    verifierTarget: 'noir-recursive-no-zk',
  })
  return { vkAsFields, vkHash }
}

/**
 * Proves with one Barretenberg instance. Loading the SRS dominates a small proof, so a bidder should
 * keep one engine open for all of its bids. A design package wraps the engine in its `createBidProver`.
 */
export class ProvingEngine {
  private constructor(private readonly api: Barretenberg) {}

  /**
   * Start Barretenberg and load the SRS.
   *
   * @returns A new engine. Call {@link ProvingEngine.destroy} when done.
   */
  static async create(): Promise<ProvingEngine> {
    if (!('window' in globalThis)) return new ProvingEngine(await Barretenberg.new({ srsSize: SRS_POINTS }))
    // In a browser `Barretenberg.new` caches the decompressed SRS (2^21 × 64 bytes) as one
    // IndexedDB value, which Chromium rejects above 127 MiB. Load it the same way, minus that cache;
    // each page load downloads the compressed points again.
    const api = await Barretenberg.new({ srsSize: SRS_POINTS, skipSrsInit: true })
    const [crs, grumpkinCrs] = await Promise.all([Crs.new(SRS_POINTS), GrumpkinCrs.new(2 ** 16)])
    await api.srsInitSrs({ pointsBuf: crs.getG1Data(), numPoints: crs.numPoints, g2Point: crs.getG2Data() })
    await api.srsInitGrumpkinSrs({ pointsBuf: grumpkinCrs.getG1Data(), numPoints: grumpkinCrs.numPoints })
    return new ProvingEngine(api)
  }

  /** Release the Barretenberg instance. */
  async destroy(): Promise<void> {
    await this.api.destroy()
  }

  /**
   * Encrypt a bid to the committee key and prove it valid, with one proof for the whole bid.
   *
   * The bid is 2 to 4 ciphertexts, one for each role of `spec.type`. The plaintext of each is
   * SIMD-encoded: the thermometer slots of the bid for the roles 0 and 1, and uniform random slots
   * for the other roles. The proofs form a tree, and no circuit has more than 2^21 gates, so a
   * browser can prove each one:
   *
   * - for every role, Interfold's user-data encryption proof (the ciphertext encrypts `k1` under
   *   the committee key);
   * - `auction_bid_pair`: the proofs of the roles 0 and 1, and `k1` of both is the thermometer of
   *   the one bid, which is below `levels`;
   * - the inner proofs that `spec.finalInputs` adds (for example the shares proof);
   * - the final circuit of the design. This is the only proof published. It binds `bidder` and
   *   `levels`.
   *
   * @param spec The final circuit of the design.
   * @param bid The bid step, in `[0, levels)`.
   * @param levels The number of price steps of the auction.
   * @param committeeKey The public key of the committee of the E3.
   * @param bidder The address that will be the bidder of `publishInput`.
   * @param onStep Called before each step.
   * @throws When `bid` or `levels` is out of range, the committee key is not an l-BFV key, or a proof fails.
   */
  async proveBid(
    spec: BidTreeSpec,
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

    const encryptions: ProvenCiphertext[] = []
    for (const role of rolesFor(spec.type)) {
      onStep?.({ kind: 'encrypt', role })
      const encrypted = await this.encrypt(bidSlots(role, bid), committeeKey)
      onStep?.({ kind: 'encryption-proof', role })
      encryptions.push(await this.proveEncrypted(encrypted))
    }

    // Every wrapper proof has the same circuit, so one key serves all of them. All of them also
    // carry the same encryption key row and VK chains (the circuits assert it).
    const [ude] = encryptions
    const udeKey = await keyOf(ude.wrapper)
    const shared = { pk_row0: ude.wrapper.publicInputs[2], ct0_chain: ude.wrapper.publicInputs[0], ct1_chain: ude.wrapper.publicInputs[1] }
    const wrapperInputs = (list: readonly ProvenCiphertext[]): InputMap => ({
      user_data_encryption_verification_key: udeKey.vkAsFields,
      user_data_encryption_proofs: list.map(({ wrapper }) => proofToFields(wrapper.proof)),
      user_data_encryption_public_inputs: list.map(({ wrapper }) => wrapper.publicInputs),
    })
    const k1Of = ({ k1 }: ProvenCiphertext) => ({ coefficients: k1.coefficients })

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
    } as InputMap

    const finalInputs = await spec.finalInputs({
      engine: this,
      encryptions,
      udeKey,
      shared,
      commonInputs,
      wrapperInputs,
      step: (step) => onStep?.(step),
    })
    onStep?.({ kind: 'bid-proof' })
    // The public inputs: the ciphertext commitments, bidder, levels, pk_commitment, vk_anchor.
    const { proof, pkCommitment, vkAnchor } = await this.proveFinal(spec.bidCircuit, finalInputs, committeeKey)
    return {
      ciphertexts: encryptions.map(({ ciphertext }) => ciphertext),
      commitments: encryptions.map(({ commitment }) => commitment),
      proof,
      pkCommitment,
      vkAnchor,
    }
  }

  /**
   * Encrypt `slots` to the committee key, and keep the commitment and the witness of the encryption.
   *
   * @param slots The `DEGREE` SIMD slot values.
   * @param committeeKey The public key of the committee of the E3.
   * @throws When the committee key is not an l-BFV key of the preset.
   */
  async encrypt(slots: BigUint64Array, committeeKey: Uint8Array): Promise<EncryptedCiphertext> {
    const { encryptedData, circuitInputs } = await encryptVectorAndGenInputs(slots, committeeKey, PRESET, {
      encoding: 'simd',
    })
    // An l-BFV committee key yields the chunked witness; a trBFV key would mean the wrong preset.
    if (!('r1is' in circuitInputs)) {
      throw new Error(`The committee key is not an l-BFV key; this program needs param set ${PARAM_SET}`)
    }
    const commitment = toHex(await computeCiphertextCommitment(encryptedData, PRESET))
    return { ciphertext: toHex(encryptedData), commitment, k1: circuitInputs.k1, circuitInputs }
  }

  /**
   * Prove the user-data encryption of a ciphertext, and check the proof against its commitment.
   *
   * @param encrypted The result of {@link ProvingEngine.encrypt}.
   * @throws When the proof commits to another ciphertext than the one that is published.
   */
  async proveEncrypted({ circuitInputs, ...encrypted }: EncryptedCiphertext): Promise<ProvenCiphertext> {
    const wrapper = await this.proveEncryption(circuitInputs)
    // Fail here rather than on chain: the leaf the contract inserts must be the commitment the
    // FHE program recomputes from the published bytes.
    if (word(wrapper.publicInputs[3]) !== encrypted.commitment) {
      throw new Error('The encryption proof commits to a different ciphertext than the one being published')
    }
    return { ...encrypted, wrapper }
  }

  /**
   * The proof that goes on chain: execute the outer circuit, check that it reproduces the committee
   * key commitment, and prove it for the EVM verifier. The outputs are the last two public inputs.
   *
   * @param circuit The compiled final circuit.
   * @param inputs The inputs of the circuit.
   * @param committeeKey The public key of the committee of the E3.
   * @throws When the circuit does not reproduce the committee key commitment.
   */
  async proveFinal(
    circuit: CompiledCircuit,
    inputs: InputMap,
    committeeKey: Uint8Array,
  ): Promise<{ proof: Hex; pkCommitment: Hex; vkAnchor: Hex }> {
    const { witness, returnValue } = await new Noir(circuit).execute(inputs)
    // The contract checks this output against the E3's committee key commitment.
    const committeeCommitment = toHex(await computePublicKeyCommitment(committeeKey, PRESET))
    if (!Array.isArray(returnValue) || typeof returnValue[0] !== 'string' || word(returnValue[0]) !== committeeCommitment) {
      throw new Error('The circuit does not reproduce the committee key commitment')
    }
    const backend = new UltraHonkBackend(circuit.bytecode, this.api)
    const proof = await backend.generateProof(witness, { verifierTarget: 'evm' })
    const outputs = proof.publicInputs.length - 2
    return {
      proof: toHex(proof.proof),
      pkCommitment: word(proof.publicInputs[outputs]),
      vkAnchor: word(proof.publicInputs[outputs + 1]),
    }
  }

  /**
   * A proof that a bid circuit verifies: a recursive proof, without zero knowledge.
   *
   * @param circuit The compiled inner circuit.
   * @param inputs The inputs of the circuit.
   */
  async proveInner(circuit: CompiledCircuit, inputs: InputMap): Promise<InnerProof> {
    const { witness } = await new Noir(circuit).execute(inputs)
    const backend = new UltraHonkBackend(circuit.bytecode, this.api)
    const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget: 'noir-recursive-no-zk' })
    return { proof, publicInputs, backend }
  }

  /**
   * The user-data encryption proof of one ciphertext: the proof tree, then the wrapper proof that
   * the bid circuits verify.
   */
  private async proveEncryption(circuitInputs: EncryptionInputs): Promise<InnerProof> {
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
