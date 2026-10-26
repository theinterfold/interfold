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
import { type Address, type Hex, toHex } from 'viem'
import bidCircuitJson from '../circuits/token_launch_bid.json'
import claimCircuitJson from '../circuits/token_launch_claim.json'
import { bidCommitment, fieldHex, nullifier, randomSalt, saleField } from './commitments'
import { budgetDigits, CLAIM_TREE_DEPTH, LEVELS_MAX, MAX_BIDDERS, MAX_BUDGET_UNITS, MIN_LEVELS, PRESET, bidSlots } from './layout'

export { PRESET }
/** The insecure SIMD parameters on the l-BFV path: param set 5. */
export const PARAM_SET = 5

const bidCircuit = bidCircuitJson as CompiledCircuit
const claimCircuit = claimCircuitJson as CompiledCircuit

/**
 * The SRS size of the bid prover. The bid circuit has 1,432,756 gates (below 2^21), and each user-data
 * encryption wrapper proof it verifies has 1.47M gates, so 2^21 points are needed. More than that does
 * not fit the 4 GiB of the browser's WASM heap. On the WASM backend the size must be given at creation.
 */
const SRS_POINTS = 2 ** 21
/** The claim circuit has about 17,000 gates; 2^15 points are enough for the zero-knowledge proof. */
const CLAIM_SRS_POINTS = 2 ** 15

/** The public inputs of the bid proof, in order (`circuits/PUBLIC_INPUTS.md`). */
export const BID_PUBLIC_INPUTS = 11
/** The public inputs of the claim proof, in order (`circuits/PUBLIC_INPUTS.md`). */
export const CLAIM_PUBLIC_INPUTS = 11

function proofToFields(proof: Uint8Array): string[] {
  const fields: string[] = []
  for (let i = 0; i < proof.length; i += 32) fields.push(toHex(proof.subarray(i, i + 32)))
  return fields
}

/** Normalize a field element to a 32-byte hex word, the form the contract and bb.js use. */
function word(value: string): Hex {
  return fieldHex(BigInt(value))
}

/** Where a bid is, for a progress display. The encryption proof of each round is the long part. */
export type BidStep = { kind: 'encrypt' } | { kind: 'encryption-proof'; round: 1 | 2 } | { kind: 'bid-proof' }

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

/** The inputs of one bid. */
export interface BidInput {
  /** The l-BFV committee key envelope of E3-1 (round 1; its id is the sale id) and of E3-2 (round 2). */
  committeeKey1: Uint8Array
  committeeKey2: Uint8Array
  /** The max price step `b`, below `levels`. */
  step: number
  /** The budget `B` in budget units, `1..=escrowUnits`. */
  budget: number
  /** The escrow `X` in budget units: the tier the bidder pays. */
  escrowUnits: number
  bidder: Address
  /** The sale id: the id of the round-1 E3. */
  saleId: bigint
  /** The bid index: the number of bids the sale has before this one (`bidCount`). */
  index: number
  /** The price steps of the sale (`MIN_LEVELS..=LEVELS_MAX`). */
  levels: number
  /** Fresh unless given. The caller must store it: the claim needs it. */
  salt?: Hex
  onProgress?: (step: BidStep) => void
}

/** One bid, encrypted twice and proven, ready for `TokenLaunchProgram.publishInput`. */
export interface PreparedBid {
  /** The ciphertext under the key of E3-1 and under the key of E3-2 (the l-BFV ciphertext bytes). */
  ciphertext1: Hex
  ciphertext2: Hex
  /** The SAFE commitments of the ciphertexts (bytes32). */
  ctCommitment1: Hex
  ctCommitment2: Hex
  /** The commitment of the bid (bytes32). Keep `salt` for the claim. */
  bidCommitment: Hex
  /** The salt of `bidCommitment` (32 bytes). The claim proof needs it: store it. */
  salt: Hex
  /** The bid proof, the only proof that goes on chain. */
  proof: Hex
  /** The proof's public outputs, for display: the committee key commitments and the VK anchor. */
  pkCommitment1: Hex
  pkCommitment2: Hex
  vkAnchor: Hex
  /** All `BID_PUBLIC_INPUTS` public inputs of the proof in the order of `circuits/PUBLIC_INPUTS.md`, as 32-byte words. */
  publicInputs: Hex[]
}

/**
 * Proves token-launch bids with one Barretenberg instance. Loading the SRS dominates a small proof,
 * so a bidder should keep one prover open for all of its proofs.
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
   * Encrypt a bid to the committee keys of both E3s and prove it valid, with one proof.
   *
   * The bid is ONE SIMD plaintext (`bidSlots` in `layout.ts`) encrypted once under each key. The
   * proofs run on this machine, so the bid never leaves it:
   *
   * - Interfold's user-data encryption proof of each ciphertext (two proof trees, one after the
   *   other: Barretenberg already uses every thread for one proof, so running them side by side would
   *   only add memory): the ciphertext encrypts `k1` under that committee key;
   * - `token_launch_bid`: verifies both proofs, both `k1` are the plaintext of `(step, budget, index)`,
   *   `step < levels`, `budget <= escrowUnits`, and the bid commitment opens to
   *   `(step, budget, escrowUnits, salt, bidder, saleId)`. It is the only proof published. It binds
   *   `bidder` (the sender or the signer of a relayed bid), `saleId`, `levels`, `index` and
   *   `escrowUnits`, which the contract supplies from its storage.
   */
  async prove(input: BidInput): Promise<PreparedBid> {
    const { committeeKey1, committeeKey2, step, budget, escrowUnits, bidder, saleId, index, levels, onProgress } = input
    // The circuit enforces all of this; failing here saves the proofs that would be wasted.
    if (!Number.isInteger(levels) || levels < MIN_LEVELS || levels > LEVELS_MAX) {
      throw new Error(`A sale has ${MIN_LEVELS} to ${LEVELS_MAX} price steps, got ${levels}`)
    }
    if (!Number.isInteger(step) || step < 0 || step >= levels) {
      throw new Error(`The bid is step ${step}, but this sale has the steps 0 to ${levels - 1}`)
    }
    if (!Number.isInteger(escrowUnits) || escrowUnits < 1 || escrowUnits > MAX_BUDGET_UNITS) {
      throw new Error(`The escrow is 1 to ${MAX_BUDGET_UNITS} budget units, got ${escrowUnits}`)
    }
    if (!Number.isInteger(budget) || budget < 1 || budget > escrowUnits) {
      throw new Error(`The budget is 1 to ${escrowUnits} budget units (the escrow), got ${budget}`)
    }
    if (!Number.isInteger(index) || index < 0 || index >= MAX_BIDDERS)
      throw new Error(`The bid index is 0 to ${MAX_BIDDERS - 1}, got ${index}`)
    const salt = input.salt ?? randomSalt()

    onProgress?.({ kind: 'encrypt' })
    const slots = bidSlots({ step, budget, index })
    const encrypted = await Promise.all([committeeKey1, committeeKey2].map((key) => encryptLbfv(slots, key)))
    const ctCommitments = await Promise.all(
      encrypted.map(async ({ encryptedData }) => toHex(await computeCiphertextCommitment(encryptedData, PRESET))),
    )
    const k1 = encrypted[0].circuitInputs.k1.coefficients
    // The same plaintext, so the same `k1`: the circuit commits one `k1` in both wrappers.
    if (JSON.stringify(encrypted[1].circuitInputs.k1.coefficients) !== JSON.stringify(k1)) {
      throw new Error('The two encryptions have different plaintext polynomials')
    }

    const wrappers: InnerProof[] = []
    for (const [i, { circuitInputs }] of encrypted.entries()) {
      const round = (i + 1) as 1 | 2
      onProgress?.({ kind: 'encryption-proof', round })
      const wrapper = await this.proveEncryption(circuitInputs)
      // Fail here rather than on chain: the leaf the contract inserts must be the commitment the
      // FHE program recomputes from the published bytes.
      if (word(wrapper.publicInputs[3]) !== ctCommitments[i]) {
        throw new Error(`The encryption proof of round ${round} commits to a different ciphertext than the one being published`)
      }
      wrappers.push(wrapper)
    }
    const udeKey = await keyOf(wrappers[0])
    if ((await keyOf(wrappers[1])).vkHash !== udeKey.vkHash) throw new Error('The two encryption proofs come from different circuits')

    const commitment = await bidCommitment({ step, budget, escrowUnits, salt, bidder, saleId }, this.api)
    const openings = await Promise.all([committeeKey1, committeeKey2].map((key) => openLbfvKeyEnvelope(key, PRESET)))
    onProgress?.({ kind: 'bid-proof' })
    const inputs = {
      user_data_encryption_verification_key: udeKey.vkAsFields,
      user_data_encryption_proofs: wrappers.map(({ proof }) => proofToFields(proof)),
      user_data_encryption_public_inputs: wrappers.map(({ publicInputs }) => publicInputs),
      user_data_encryption_key_hash: udeKey.vkHash,
      ct_commitments: ctCommitments,
      bid_commitment: commitment,
      bidder: BigInt(bidder).toString(),
      sale_id: saleField(saleId).toString(),
      levels,
      bidder_index: index,
      escrow_units: escrowUnits,
      k1: { coefficients: k1 },
      digits: budgetDigits(budget),
      b: step.toString(),
      salt: BigInt(salt).toString(),
      public_key_row_commitments: openings.map(({ publicKeyRows }) => publicKeyRows.map((row) => toHex(row))),
      relinearization_key_commitments: openings.map(({ relinearizationKey }) => toHex(relinearizationKey)),
    } as InputMap
    const { witness, returnValue } = await new Noir(bidCircuit).execute(inputs)
    // The contract checks these outputs against the committee key commitment of each E3.
    const committeeCommitments = await Promise.all(
      [committeeKey1, committeeKey2].map(async (key) => toHex(await computePublicKeyCommitment(key, PRESET))),
    )
    if (!Array.isArray(returnValue) || committeeCommitments.some((expected, i) => word(returnValue[i] as string) !== expected)) {
      throw new Error('The bid circuit does not reproduce the committee key commitments')
    }
    const backend = new UltraHonkBackend(bidCircuit.bytecode, this.api)
    const proof = await backend.generateProof(witness, { verifierTarget: 'evm' })
    if (proof.publicInputs.length !== BID_PUBLIC_INPUTS) {
      throw new Error(`The bid proof has ${proof.publicInputs.length} public inputs, expected ${BID_PUBLIC_INPUTS}`)
    }

    const publicInputs = proof.publicInputs.map(word)
    return {
      ciphertext1: toHex(encrypted[0].encryptedData),
      ciphertext2: toHex(encrypted[1].encryptedData),
      ctCommitment1: ctCommitments[0],
      ctCommitment2: ctCommitments[1],
      bidCommitment: commitment,
      salt,
      proof: toHex(proof.proof),
      pkCommitment1: publicInputs[8],
      pkCommitment2: publicInputs[9],
      vkAnchor: publicInputs[10],
      publicInputs,
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
   * the bid circuit verifies.
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

/** `slots` encrypted to an l-BFV committee key, with the witness of the encryption proof. */
async function encryptLbfv(slots: BigUint64Array, committeeKey: Uint8Array) {
  const { encryptedData, circuitInputs } = await encryptVectorAndGenInputs(slots, committeeKey, PRESET, { encoding: 'simd' })
  // An l-BFV committee key yields the chunked witness; a trBFV key would mean the wrong preset.
  if (!('r1is' in circuitInputs)) throw new Error(`A committee key is not an l-BFV key; this program needs param set ${PARAM_SET}`)
  return { encryptedData, circuitInputs }
}

/** The key of the circuit that made `inner`, as the verifying circuit takes it. */
async function keyOf({ backend, proof, publicInputs }: InnerProof): Promise<InnerKey> {
  const { vkAsFields, vkHash } = await backend.generateRecursiveProofArtifacts(proof, publicInputs.length, {
    verifierTarget: 'noir-recursive-no-zk',
  })
  return { vkAsFields, vkHash }
}

/** Prove one bid with a prover of its own. Keep a `BidProver` for several. */
export async function proveBid(input: BidInput): Promise<PreparedBid> {
  const prover = await BidProver.create()
  try {
    return await prover.prove(input)
  } finally {
    await prover.destroy()
  }
}

/** What a claim proves. */
export interface ClaimInput {
  /** The private opening of the bid: its step, budget, escrow, salt, bidder and index. */
  step: number
  budget: number
  escrowUnits: number
  salt: Hex
  bidder: Address
  /** The leaf index of the bid in the claim tree: its bid index. */
  index: number
  saleId: bigint
  /** The step of the clearing: `s` (capped), `l` (uncapped) or 0 (undersubscribed). */
  k: number
  /** The FRESH address that receives the tokens and the refund. The proof binds it. */
  recipient: Address
  /**
   * Whether the contract registers marginal claims now (a capped sale before its marginal deadline). A
   * marginal bid (`step == k`) then reveals its index; any other claim ignores it.
   */
  revealIndex: boolean
  /** The final claim tree root (`claimRoot` after the clearing) and the counted bitmap (`SaleCleared`). */
  root: Hex | bigint
  countedMask: bigint
  /** The `CLAIM_TREE_DEPTH` siblings of the leaf, bottom up. */
  path: readonly (Hex | bigint)[]
}

export interface PreparedClaim {
  /** The claim proof. */
  proof: Hex
  /** `Poseidon2([NULLIFIER_DOMAIN, salt, saleId])`: the public nullifier that stops a second claim. */
  nullifier: Hex
  /** 0 if `step < k`, 1 if `step == k`, 2 if `step > k`: the public output the contract needs. */
  cmp: 0 | 1 | 2
  /** `budget` if `cmp != 0`, else 0: the public budget the contract pays out of. */
  budgetUnits: number
  /** `index + 1` of a marginal registration (`cmp == 1` and `revealIndex`), else 0. */
  indexPlusOne: number
  /** All `CLAIM_PUBLIC_INPUTS` public inputs of the proof in the order of `circuits/PUBLIC_INPUTS.md`, as 32-byte words. */
  publicInputs: Hex[]
}

/**
 * Proves claims. The claim circuit is small (about 17,000 gates), so a proof takes a few seconds in a
 * browser. The proof is zero knowledge: it shows the Merkle membership of the bid, that it was counted
 * and how its step compares with `k`, and nothing else about it.
 */
export class ClaimProver {
  private constructor(private readonly api: Barretenberg) {}

  static async create(): Promise<ClaimProver> {
    return new ClaimProver(await Barretenberg.new({ srsSize: CLAIM_SRS_POINTS }))
  }

  async destroy(): Promise<void> {
    await this.api.destroy()
  }

  async prove(input: ClaimInput): Promise<PreparedClaim> {
    const { step, budget, escrowUnits, salt, bidder, index, saleId, k, recipient, revealIndex, root, countedMask, path } = input
    if (!Number.isInteger(step) || step < 0 || step >= LEVELS_MAX) throw new Error(`The step is 0 to ${LEVELS_MAX - 1}, got ${step}`)
    if (!Number.isInteger(k) || k < 0 || k >= LEVELS_MAX) throw new Error(`The clearing step is 0 to ${LEVELS_MAX - 1}, got ${k}`)
    if (path.length !== CLAIM_TREE_DEPTH) throw new Error(`The Merkle path has ${CLAIM_TREE_DEPTH} siblings, got ${path.length}`)
    const cmp = step < k ? 0 : step === k ? 1 : 2
    const budgetUnits = cmp === 0 ? 0 : budget
    const indexPlusOne = cmp === 1 && revealIndex ? index + 1 : 0
    const nullifierHex = await nullifier({ salt, saleId }, this.api)
    const inputs = {
      root: fieldHex(BigInt(root)),
      counted_mask: countedMask.toString(),
      sale_id: saleField(saleId).toString(),
      k,
      nullifier: nullifierHex,
      recipient: BigInt(recipient).toString(),
      escrow_units: escrowUnits,
      budget_units: budgetUnits,
      reveal_index: revealIndex ? 1 : 0,
      b: step.toString(),
      budget: budget.toString(),
      salt: BigInt(salt).toString(),
      bidder: BigInt(bidder).toString(),
      index,
      path: path.map((sibling) => fieldHex(BigInt(sibling))),
    } as InputMap
    const { witness, returnValue } = await new Noir(claimCircuit).execute(inputs)
    const returned = (returnValue as string[]).map((value) => Number(BigInt(value)))
    if (returned[0] !== cmp || returned[1] !== indexPlusOne) {
      throw new Error(`The claim circuit returned ${returned.join(', ')}, expected ${cmp}, ${indexPlusOne}`)
    }
    const backend = new UltraHonkBackend(claimCircuit.bytecode, this.api)
    const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget: 'evm' })
    if (publicInputs.length !== CLAIM_PUBLIC_INPUTS) {
      throw new Error(`The claim proof has ${publicInputs.length} public inputs, expected ${CLAIM_PUBLIC_INPUTS}`)
    }
    return { proof: toHex(proof), nullifier: nullifierHex, cmp, budgetUnits, indexPlusOne, publicInputs: publicInputs.map(word) }
  }
}

/** Prove one claim with a prover of its own. Keep a `ClaimProver` for several. */
export async function proveClaim(input: ClaimInput): Promise<PreparedClaim> {
  const prover = await ClaimProver.create()
  try {
    return await prover.prove(input)
  } finally {
    await prover.destroy()
  }
}
