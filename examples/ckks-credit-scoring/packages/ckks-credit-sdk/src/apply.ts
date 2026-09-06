// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The applicant's local pipeline (credit v2): TWO CKKS encryptions (WASM,
// `@interfold/ckks-zk-inputs` `encryptCreditAndWitness` — slot encoding at the applicant's slot)
// feeding FIVE Honk proofs bound by commitments —
//
//   ct0/ct1 legs (logit ct)  user_data_encryption_ckks_ct{0,1}_ps4 → (…, m_commitment_z, u_z)
//   ct0/ct1 legs (mask ct)   user_data_encryption_ckks_ct{0,1}_ps4 → (…, m_commitment_m, u_m)
//   app leg                  ckks_credit_validity_ps4 →
//       [cap, address, merkle_root, index, w_0..w_7, bias] ⇒ (m_commitment_z, m_commitment_m)
//
// The app leg takes BOTH message polynomials the ct0 legs witnessed, recomputes their commitments,
// and proves the logit one is the slot-`index` encoding of `⟨w, x⟩/cap + b` under the round's
// registered model for the issuer-attested features `x` under the round's root, and the mask one
// is the slot-`index` encoding of an applicant-chosen `mask / 2^10 ∈ [0, 1024)` — every other slot
// 0 in both. The contract equates each m across ct0/app, each u across ct0/ct1, requires
// `address == msg.sender`, `index` == the sender's registered position, and the model words ==
// the registered model. Features, logit and mask never leave this process; the mask is what
// unmasks the probability the network computes (`σ_cubic(z) + m` in slot `index`).

import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js'
import type { ProofData } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { InputMap } from '@noir-lang/noir_js'
import { getAddress } from 'viem'
import type { Address, Hex } from 'viem'

import { requireCircuits } from './circuits'
import { rootFromProof } from './featureTree'
import { FEATURES, MASK_BITS, MASK_SCALE, MAX_APPLICANTS, MERKLE_MAX_DEPTH, WEIGHT_BOUND, WEIGHT_SCALE } from './types'
import type { ApplicationSubmission, FeatureProof, FixedPointModel, LegName, Model, ProgressCallback, ProvenLeg, ProvingTimings, RecoveredScore } from './types'

type WasmModule = typeof import('@interfold/ckks-zk-inputs')

interface WitnessBundle {
  ciphertext_hex: string
  ct0_inputs: InputMap
  ct1_inputs: InputMap
  u_commitment_hex: string
  m_commitment_hex: string
  encoded_values: number[]
}

interface CreditBundle {
  logit: WitnessBundle
  mask: WitnessBundle
  credit_inputs: InputMap
}

// Cached Barretenberg API (CRISP getBBApi pattern). The ps4 Greco legs are 5-limb circuits
// (circuit_size ≈ 2^17), so the 2^18 SRS the salary survey uses fits.
export const SRS_SIZE = 2 ** 18
let _api: Barretenberg | null = null
let _apiInit: Promise<Barretenberg> | null = null

export const getBBApi = async (): Promise<Barretenberg> => {
  if (_api) return _api
  if (!_apiInit) {
    _apiInit = (async () => {
      const backend = typeof window === 'undefined' ? { backend: BackendType.Wasm } : {}
      const api = await Barretenberg.new({ srsSize: SRS_SIZE, ...backend })
      _api = api
      return api
    })()
  }
  return _apiInit
}

export const destroyBBApi = async (): Promise<void> => {
  if (_api) await _api.destroy()
  _api = null
  _apiInit = null
}

let _wasm: WasmModule | null = null
const loadWasm = async (): Promise<WasmModule> => {
  if (_wasm) return _wasm
  const init = (await import('@interfold/ckks-zk-inputs/init')).default
  await init()
  _wasm = await import('@interfold/ckks-zk-inputs')
  return _wasm
}

export const word = (value: bigint): Hex => `0x${value.toString(16).padStart(64, '0')}`
const bytesToHex = (bytes: Uint8Array): Hex => `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`
const normalizeWords = (inputs: string[]): Hex[] => inputs.map((h) => word(BigInt(h)))

/** Fresh output-mask numerator: uniform in `[0, 2^20)` (mask value in `[0, 1024)`). */
export const sampleMask = (): number => {
  const out = new Uint32Array(1)
  crypto.getRandomValues(out)
  return out[0] % (1 << MASK_BITS)
}

/** The fixed-point model (`× 2^16`, rounded) the circuit and the contract take. */
export const toFixedPoint = (model: Model): FixedPointModel => ({
  weights: model.weights.map((w) => Math.round(w * WEIGHT_SCALE)),
  bias: Math.round(model.bias * WEIGHT_SCALE),
})

/** The BN254 word of a signed fixed-point coefficient (`p − |w|` when negative). */
export const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
export const signedWord = (v: number): Hex => word(v >= 0 ? BigInt(v) : BN254_R + BigInt(v))

/** The nine model words `[w_0..w_7, bias]` in the validity leg's public-input order. */
export const modelWords = (fixed: FixedPointModel): Hex[] => [...fixed.weights.map(signedWord), signedWord(fixed.bias)]

/**
 * The logit the applicant encrypts, EXACTLY as the circuit pins it: the fixed-point numerator
 * `Σ W_j x_j + B·cap` over `2^16 · cap` (exact in f64).
 */
export const creditLogit = (fixed: FixedPointModel, features: number[], cap: number): number => {
  let acc = 0n
  for (let j = 0; j < FEATURES; j++) acc += BigInt(fixed.weights[j]) * BigInt(features[j])
  acc += BigInt(fixed.bias) * BigInt(cap)
  return Number(acc) / (WEIGHT_SCALE * cap)
}

/** `σ_cubic(z) = 0.5 + 0.197 z − 0.004 z³` — what the network evaluates on the encrypted logit. */
export const sigmoidCubic = (z: number): number => 0.5 + 0.197 * z - 0.004 * z * z * z

/** Local pre-check of exactly what the app leg and the contract will refuse, so a doomed application fails in ms. */
export const checkApplication = (proof: FeatureProof, model: Model, mask: number, sender: Address): void => {
  if (proof.features.length !== FEATURES) throw new Error(`expected ${FEATURES} features`)
  if (!Number.isInteger(proof.cap) || proof.cap <= 0) throw new Error('cap must be a positive integer')
  for (const [j, x] of proof.features.entries()) {
    if (!Number.isInteger(x) || x < 0) throw new Error(`feature ${j} must be a non-negative integer`)
    if (x > proof.cap) throw new Error(`feature ${j} = ${x} exceeds the cap ${proof.cap} (the circuit rejects it)`)
  }
  if (model.weights.length !== FEATURES) throw new Error(`expected ${FEATURES} weights`)
  for (const [j, w] of model.weights.entries()) {
    if (!Number.isFinite(w) || Math.abs(w) > WEIGHT_BOUND) throw new Error(`weight ${j} = ${w} outside ±${WEIGHT_BOUND}`)
  }
  if (!Number.isFinite(model.bias) || Math.abs(model.bias) > WEIGHT_BOUND) throw new Error(`bias ${model.bias} outside ±${WEIGHT_BOUND}`)
  if (!Number.isInteger(mask) || mask < 0 || mask >= 1 << MASK_BITS) throw new Error(`mask ${mask} is not in [0, 2^${MASK_BITS})`)
  if (!Number.isInteger(proof.index) || proof.index < 0 || proof.index >= MAX_APPLICANTS) throw new Error(`slot index ${proof.index} outside [0, ${MAX_APPLICANTS})`)
  if (getAddress(proof.address) !== getAddress(sender)) throw new Error('feature proof is for a different address than the sender')
  if (proof.depth > MERKLE_MAX_DEPTH) throw new Error(`feature proof depth ${proof.depth} exceeds ${MERKLE_MAX_DEPTH}`)
  if (proof.indices.length !== proof.depth || proof.siblings.length !== proof.depth) throw new Error('feature proof path length mismatch')
  if (rootFromProof(proof).toLowerCase() !== proof.merkleRoot.toLowerCase()) throw new Error('feature proof does not open to its root')
}

/** The WASM `FeatureProof` JSON shape (big integers as decimal strings). */
const wasmFeatureProof = (proof: FeatureProof) => ({
  address: BigInt(getAddress(proof.address)).toString(),
  features: proof.features,
  merkle_root: BigInt(proof.merkleRoot).toString(),
  depth: proof.depth,
  indices: proof.indices,
  siblings: proof.siblings,
})

/**
 * Encrypt the model's logit over the attested features and an output mask at the applicant's slot
 * under the committee's CKKS public key and prove all five legs. `mask` defaults to a fresh random
 * one — KEEP the returned `submission.mask`; it is the only way to read the probability.
 */
export const encryptAndProveApplication = async (
  publicKey: Uint8Array,
  featureProof: FeatureProof,
  model: Model,
  sender: Address,
  mask: number = sampleMask(),
  onProgress: ProgressCallback = () => {},
): Promise<ApplicationSubmission> => {
  checkApplication(featureProof, model, mask, sender)
  const circuits = requireCircuits()
  const t0 = performance.now()
  const elapsed = () => performance.now() - t0
  const zero = { ct0Z: 0, ct1Z: 0, ct0M: 0, ct1M: 0, app: 0 }
  const timings: ProvingTimings = {
    encryptMs: 0,
    executeMs: { ...zero },
    proveMs: { ...zero },
    backendInitMs: 0,
    totalMs: 0,
  }
  const fixed = toFixedPoint(model)

  onProgress({ stage: 'encrypt' }, elapsed())
  const wasm = await loadWasm()
  let t = performance.now()
  const credit = wasm.encryptCreditAndWitness(
    publicKey,
    wasmFeatureProof(featureProof),
    featureProof.cap,
    fixed,
    featureProof.index,
    mask,
    undefined,
  ) as CreditBundle
  timings.encryptMs = performance.now() - t

  onProgress({ stage: 'backend' }, elapsed())
  t = performance.now()
  const api = await getBBApi()
  timings.backendInitMs = performance.now() - t

  const legs: { name: LegName; circuit: 'ct0' | 'ct1' | 'app'; inputs: InputMap; expectPublic: number }[] = [
    { name: 'app', circuit: 'app', inputs: credit.credit_inputs, expectPublic: 15 },
    { name: 'ct1Z', circuit: 'ct1', inputs: credit.logit.ct1_inputs, expectPublic: 3 },
    { name: 'ct0Z', circuit: 'ct0', inputs: credit.logit.ct0_inputs, expectPublic: 4 },
    { name: 'ct1M', circuit: 'ct1', inputs: credit.mask.ct1_inputs, expectPublic: 3 },
    { name: 'ct0M', circuit: 'ct0', inputs: credit.mask.ct0_inputs, expectPublic: 4 },
  ]
  const proven = {} as Record<LegName, ProvenLeg>
  for (const leg of legs) {
    const circuit = circuits[leg.circuit]
    onProgress({ stage: 'execute', leg: leg.name }, elapsed())
    t = performance.now()
    const { witness } = await new Noir(circuit).execute(leg.inputs)
    timings.executeMs[leg.name] = performance.now() - t

    onProgress({ stage: 'prove', leg: leg.name }, elapsed())
    t = performance.now()
    const backend = new UltraHonkBackend(circuit.bytecode, api)
    // 'evm' = keccak ZK transcript: the deployed verifiers are `bb write_vk -t evm` ZK verifiers.
    const proof: ProofData = await backend.generateProof(witness, { verifierTarget: 'evm' })
    timings.proveMs[leg.name] = performance.now() - t
    if (proof.publicInputs.length !== leg.expectPublic) {
      throw new Error(`${leg.name}: expected ${leg.expectPublic} public inputs, got ${proof.publicInputs.length}`)
    }
    proven[leg.name] = { proof: bytesToHex(proof.proof), publicInputs: normalizeWords(proof.publicInputs) }
  }

  const uZ = word(BigInt(credit.logit.u_commitment_hex))
  const uM = word(BigInt(credit.mask.u_commitment_hex))
  const mZ = word(BigInt(credit.logit.m_commitment_hex))
  const mM = word(BigInt(credit.mask.m_commitment_hex))
  if (proven.ct0Z.publicInputs[3] !== uZ || proven.ct1Z.publicInputs[2] !== uZ) throw new Error('u_commitment mismatch on the logit legs')
  if (proven.ct0M.publicInputs[3] !== uM || proven.ct1M.publicInputs[2] !== uM) throw new Error('u_commitment mismatch on the mask legs')
  if (proven.ct0Z.publicInputs[2] !== mZ || proven.app.publicInputs[13] !== mZ) throw new Error('m_commitment_z mismatch between the ct0 and app legs')
  if (proven.ct0M.publicInputs[2] !== mM || proven.app.publicInputs[14] !== mM) throw new Error('m_commitment_m mismatch between the ct0 and app legs')
  const expectedModel = modelWords(fixed)
  for (let j = 0; j < 9; j++) {
    if (proven.app.publicInputs[4 + j] !== expectedModel[j]) throw new Error(`model word ${j} differs from the circuit's public input`)
  }
  if (proven.app.publicInputs[3] !== word(BigInt(featureProof.index))) throw new Error('slot index differs from the circuit public input')

  timings.totalMs = elapsed()
  onProgress({ stage: 'done' }, timings.totalMs)
  return {
    ciphertextZ: `0x${credit.logit.ciphertext_hex}`,
    ciphertextM: `0x${credit.mask.ciphertext_hex}`,
    ct0Z: proven.ct0Z,
    ct1Z: proven.ct1Z,
    ct0M: proven.ct0M,
    ct1M: proven.ct1M,
    app: proven.app,
    mCommitmentZ: mZ,
    mCommitmentM: mM,
    uCommitmentZ: uZ,
    uCommitmentM: uM,
    index: featureProof.index,
    mask,
    logit: credit.logit.encoded_values[0],
    timings,
  }
}

export const logistic = (z: number): number => 1 / (1 + Math.exp(-z))

/**
 * The applicant's own recovery from the opened output: `σ(z) = opened[index] − m`. Only the holder
 * of the mask can do this; to everyone else `opened[index]` is a uniform-looking number in [0, 1025).
 */
export const recoverScore = (opened: number[], index: number, mask: number): RecoveredScore => {
  if (index < 0 || index >= opened.length) throw new Error(`no opened slot for application #${index}`)
  const m = mask / MASK_SCALE
  return { index, opened: opened[index], mask: m, probability: opened[index] - m }
}

/** The oracle: the true logit of cap-normalised features (test/e2e use — needs the plaintext features). */
export const linearScore = (model: Model, features: number[], cap: number): number => creditLogit(toFixedPoint(model), features, cap)
