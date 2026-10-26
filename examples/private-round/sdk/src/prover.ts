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
import { type Address, type Hex, toHex as viemToHex } from 'viem'
import bidCircuitJson from '../circuits/private_round_bid.json'
import claimCircuitJson from '../circuits/private_round_claim.json'
import {
  assertBid,
  assertBidderIndex,
  assertVersion,
  bidSalt,
  bidSlots,
  encodeClaimData,
  LEVELS,
  MIN_LEVELS,
  maskSlots,
  PRESET,
} from './layout'

export { PRESET, bidSalt }
/** The insecure SIMD parameters on the l-BFV path: param set 5. */
export const PARAM_SET = 5

const bidCircuit = bidCircuitJson as CompiledCircuit
const claimCircuit = claimCircuitJson as CompiledCircuit

/**
 * The SRS size of the bid prover. The bid circuit has 1,427,418 gates, and the user-data encryption
 * proofs inside the wrapper have 1.47M gates, so 2^21 points are needed for both. More than that
 * does not fit the 4 GiB of the browser's WASM heap. On the WASM backend the size must be given at
 * creation.
 */
const SRS_POINTS = 2 ** 21
/** The claim circuit has about 3,000 gates; 2^14 points are far more than it needs. */
const CLAIM_SRS_POINTS = 2 ** 14

/** The domain of the bid commitment: the ASCII bytes of `prnd-bid-v1`, as in both circuits. */
const BID_DOMAIN = 0x70726e642d6269642d7631n

/** A field element as 32 big-endian bytes. */
function fieldBytes(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32)
  let rest = value
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(rest & 0xffn)
    rest >>= 8n
  }
  if (rest !== 0n) throw new Error('A field element is below 2^256')
  return bytes
}

function toHex(bytes: Uint8Array): Hex {
  return viemToHex(bytes)
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

function toBigint(value: Hex | bigint): bigint {
  return typeof value === 'bigint' ? value : BigInt(value)
}

/** The inputs that open a bid commitment. */
export interface BidOpening {
  /** The price step of the bid. */
  b: number
  salt: Hex | bigint
  bidder: Address
  e3Id: bigint
}

/**
 * `poseidon2([BID_DOMAIN, b, salt, bidder, e3Id])`, as the bid and claim circuits compute it
 * (`compute_bid_commitment`): the commitment the contract stores for each bid version.
 */
export async function computeBidCommitment(opening: BidOpening, api?: Barretenberg): Promise<Hex> {
  const own = api ?? (await Barretenberg.new({ threads: 1 }))
  try {
    const inputs = [BID_DOMAIN, BigInt(opening.b), toBigint(opening.salt), BigInt(opening.bidder), opening.e3Id].map(fieldBytes)
    const { hash } = await own.poseidon2Hash({ inputs })
    return toHex(hash)
  } finally {
    if (api === undefined) await own.destroy()
  }
}

/** One bid, encrypted and proven, ready for `PrivateRoundProgram.publishInput`. */
export interface PreparedBid {
  /** The two ciphertexts (the l-BFV ciphertext bytes): the bid (role 0), then the mask (role 1). */
  ciphertexts: [Hex, Hex]
  /** The SAFE commitments of the two ciphertexts (bytes32), in the same order. */
  ctCommitments: [Hex, Hex]
  /** The commitment of the bid (bytes32). Keep `salt` for the claim. */
  bidCommitment: Hex
  /** The salt of `bidCommitment` (32 bytes). The claim proof needs it: store it. */
  salt: Hex
  /** The bid proof, the only proof that goes on chain. */
  proof: Hex
  /** The proof's public outputs, for display: committee key commitment and VK anchor. */
  pkCommitment: Hex
  vkAnchor: Hex
  /** All public inputs of the proof in the order of `circuits/PUBLIC_INPUTS.md`, as 32-byte words. */
  publicInputs: Hex[]
}

/** The steps of `BidProver.prove`, in order. The encryption proof of each ciphertext is one step. */
export type BidStep = { kind: 'encrypt' } | { kind: 'bid-encryption-proof' } | { kind: 'mask-encryption-proof' } | { kind: 'bid-proof' }

/** What `BidProver.prove` needs. */
export interface BidRequest {
  /** The price step of the bid, in `[0, levels)`. */
  level: number
  /** The number of price steps of the round. */
  levels: number
  /** The reserve step of the round, in `[0, levels)`. */
  reserveStep: number
  committeeKey: Uint8Array
  bidder: Address
  e3Id: bigint
  /** The index of the bidder, assigned by the deposit. */
  bidderIndex: number
  /** The version of this bid (1 to 3). */
  version: number
  onStep?: (step: BidStep) => void
  /** The salt of the bid commitment. Fresh unless given. */
  salt?: Hex
  /** The 128 slots of the mask ciphertext. Fresh and uniform unless given. */
  mask?: BigUint64Array
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

/**
 * Proves private-round bids with one Barretenberg instance. Loading the SRS dominates a small proof, so
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
   * Encrypt a bid to the committee key and prove it valid, with one proof.
   *
   * A bid is two ciphertexts (see `layout.ts`). The bid ciphertext holds `COPIES` thermometers of
   * `level`, the gate bit `level >= reserveStep` and `version` in the slot of `bidderIndex`. The mask
   * ciphertext holds 128 uniform values the bidder chooses. The proofs run on this machine, so the
   * bid never leaves it:
   *
   * - Interfold's user-data encryption proof of each ciphertext (two proof trees, one after the
   *   other): the ciphertext encrypts `k1` under the committee key;
   * - `private_round_bid`: verifies both wrapper proofs, `k1` of the bid is the plaintext above,
   *   `level < levels`, `reserveStep < levels` and the bid commitment opens to
   *   `(level, salt, bidder, e3Id)`. It is the only proof published. It binds `bidder` (the sender
   *   or the signer of a relayed bid), `e3Id`, `levels`, `reserveStep`, `bidderIndex` and `version`,
   *   which the contract supplies from its storage.
   *
   * `salt` is fresh unless given. The caller must store it: the claim needs it.
   */
  async prove({
    level,
    levels,
    reserveStep,
    committeeKey,
    bidder,
    e3Id,
    bidderIndex,
    version,
    onStep,
    salt = bidSalt(),
    mask = maskSlots(),
  }: BidRequest): Promise<PreparedBid> {
    assertBid(level)
    assertBid(reserveStep)
    assertBidderIndex(bidderIndex)
    assertVersion(version)
    // The circuit enforces it as well; failing here saves the proofs that would be wasted.
    if (!Number.isInteger(levels) || levels < MIN_LEVELS || levels > LEVELS) {
      throw new Error(`A round has ${MIN_LEVELS} to ${LEVELS} price steps, got ${levels}`)
    }
    if (level >= levels) throw new Error(`The bid is step ${level}, but this round has the steps 0 to ${levels - 1}`)
    if (reserveStep >= levels) throw new Error(`The reserve step is ${reserveStep}, but this round has the steps 0 to ${levels - 1}`)

    onStep?.({ kind: 'encrypt' })
    const bidEncryption = await encryptVectorAndGenInputs(bidSlots(level, reserveStep, bidderIndex, version), committeeKey, PRESET, {
      encoding: 'simd',
    })
    const maskEncryption = await encryptVectorAndGenInputs(mask, committeeKey, PRESET, { encoding: 'simd' })
    // An l-BFV committee key yields the chunked witness; a trBFV key would mean the wrong preset.
    if (!('r1is' in bidEncryption.circuitInputs) || !('r1is' in maskEncryption.circuitInputs)) {
      throw new Error(`The committee key is not an l-BFV key; this program needs param set ${PARAM_SET}`)
    }
    const ctCommitments: [Hex, Hex] = [
      toHex(await computeCiphertextCommitment(bidEncryption.encryptedData, PRESET)),
      toHex(await computeCiphertextCommitment(maskEncryption.encryptedData, PRESET)),
    ]

    onStep?.({ kind: 'bid-encryption-proof' })
    const bidWrapper = await this.proveEncryption(bidEncryption.circuitInputs)
    onStep?.({ kind: 'mask-encryption-proof' })
    const maskWrapper = await this.proveEncryption(maskEncryption.circuitInputs)
    // Fail here rather than on chain: the leaf the contract inserts must be the commitment the
    // FHE program recomputes from the published bytes.
    for (const [role, wrapper] of [bidWrapper, maskWrapper].entries()) {
      if (word(wrapper.publicInputs[3]) !== ctCommitments[role]) {
        throw new Error('The encryption proof commits to a different ciphertext than the one being published')
      }
    }
    const udeKey = await keyOf(bidWrapper)
    const bidCommitment = await computeBidCommitment({ b: level, salt, bidder, e3Id }, this.api)

    const opening = await openLbfvKeyEnvelope(committeeKey, PRESET)
    onStep?.({ kind: 'bid-proof' })
    const inputs = {
      user_data_encryption_verification_key: udeKey.vkAsFields,
      user_data_encryption_proofs: [proofToFields(bidWrapper.proof), proofToFields(maskWrapper.proof)],
      user_data_encryption_public_inputs: [bidWrapper.publicInputs, maskWrapper.publicInputs],
      user_data_encryption_key_hash: udeKey.vkHash,
      ct_commitments: ctCommitments,
      bid_commitment: bidCommitment,
      bidder: BigInt(bidder).toString(),
      e3_id: e3Id.toString(),
      levels,
      reserve_step: reserveStep,
      bidder_index: bidderIndex,
      version,
      k1: { coefficients: bidEncryption.circuitInputs.k1.coefficients },
      b: level.toString(),
      salt: toBigint(salt).toString(),
      public_key_row_commitments: opening.publicKeyRows.map(toHex),
      relinearization_key_commitment: toHex(opening.relinearizationKey),
    } as InputMap
    const { witness, returnValue } = await new Noir(bidCircuit).execute(inputs)
    // The contract checks this output against the E3's committee key commitment.
    const committeeCommitment = toHex(await computePublicKeyCommitment(committeeKey, PRESET))
    if (!Array.isArray(returnValue) || typeof returnValue[0] !== 'string' || word(returnValue[0]) !== committeeCommitment) {
      throw new Error('The bid circuit does not reproduce the committee key commitment')
    }
    const backend = new UltraHonkBackend(bidCircuit.bytecode, this.api)
    const proof = await backend.generateProof(witness, { verifierTarget: 'evm' })

    // The public inputs: ct_commitment_bid, ct_commitment_mask, bid_commitment, bidder, e3_id,
    // levels, reserve_step, bidder_index, version, pk_commitment, vk_anchor.
    const outputs = proof.publicInputs.length - 2
    return {
      ciphertexts: [toHex(bidEncryption.encryptedData), toHex(maskEncryption.encryptedData)],
      ctCommitments,
      bidCommitment,
      salt,
      proof: toHex(proof.proof),
      pkCommitment: word(proof.publicInputs[outputs]),
      vkAnchor: word(proof.publicInputs[outputs + 1]),
      publicInputs: proof.publicInputs.map(word),
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
   * The user-data encryption proof of the ciphertext: the proof tree, then the wrapper proof that
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

/** The key of the circuit that made `inner`, as the verifying circuit takes it. */
async function keyOf({ backend, proof, publicInputs }: InnerProof): Promise<InnerKey> {
  const { vkAsFields, vkHash } = await backend.generateRecursiveProofArtifacts(proof, publicInputs.length, {
    verifierTarget: 'noir-recursive-no-zk',
  })
  return { vkAsFields, vkHash }
}

/** What a claim proves. */
export interface ClaimInput extends BidOpening {
  /** The `bidCommitment` the contract stored for the counted version of the bidder. */
  bidCommitment: Hex
  /** The step of the claim: `l*` (sold out) or `reserveStep - 1` (undersubscribed). */
  k: number
}

export interface PreparedClaim {
  /** The claim proof. */
  proof: Hex
  /** 0 if `b < k`, 1 if `b == k`, 2 if `b > k`: the public output the contract needs. */
  cmp: 0 | 1 | 2
  /** `abi.encode(uint8 cmp, bytes proof)`: the `data` of `PrivateRoundProgram.claim`. */
  calldata: Hex
  /** All public inputs of the proof in the order of `circuits/PUBLIC_INPUTS.md`, as 32-byte words. */
  publicInputs: Hex[]
}

/**
 * Proves claims. The claim circuit is small (about 3,000 gates), so a proof takes a few seconds in a
 * browser. The proof is zero knowledge: it shows how `b` compares with `k`, and nothing else about `b`.
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
    assertBid(input.b)
    assertBid(input.k)
    const inputs = {
      bid_commitment: input.bidCommitment,
      bidder: BigInt(input.bidder).toString(),
      e3_id: input.e3Id.toString(),
      k: input.k,
      b: input.b.toString(),
      salt: toBigint(input.salt).toString(),
    } as InputMap
    const { witness, returnValue } = await new Noir(claimCircuit).execute(inputs)
    const cmp = Number(BigInt(returnValue as string))
    if (cmp !== 0 && cmp !== 1 && cmp !== 2) throw new Error(`The claim circuit returned ${cmp}`)
    const backend = new UltraHonkBackend(claimCircuit.bytecode, this.api)
    const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget: 'evm' })
    return { proof: toHex(proof), cmp, calldata: encodeClaimData(cmp, toHex(proof)), publicInputs: publicInputs.map(word) }
  }
}
