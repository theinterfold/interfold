// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The DAO's local pipeline (private treasury risk, ParamSet 5): THREE COEFFICIENT-encoded CKKS
// encryptions (WASM `@interfold/ckks-zk-inputs` `encryptCoefficientsAndWitness`) feeding SEVEN
// Honk proofs bound by commitments —
//
//   ct0/ct1 legs (forward ct)   user_data_encryption_ckks_ct{0,1}_ps5 → (…, m_commitment_fwd, u_fwd)
//   ct0/ct1 legs (reversed ct)  user_data_encryption_ckks_ct{0,1}_ps5 → (…, m_commitment_rev, u_rev)
//   ct0/ct1 legs (mask ct)      user_data_encryption_ckks_ct{0,1}_ps5 → (…, m_commitment_mask, u_mask)
//   app leg                     ckks_treasury_validity_ps5 →
//       [w_0..w_3, address, index] ⇒ (m_commitment_fwd, m_commitment_rev, m_commitment_mask)
//
// The app leg takes the THREE message polynomials the ct0 legs witnessed (`ct0_inputs.m`),
// recomputes their commitments, and proves: the forward one is EXACTLY `forward(x)` (`x_a` on
// coefficient `a + 1`, `0 ≤ x_a ≤ 1` in `× 2^16` fixed point); the reversed one is EXACTLY
// `reversed(w ∘ x)` (`w_a · x_a` on coefficient `N − a − 1`) under the PUBLIC round weights `w`
// (`|w_a| ≤ 1`, negatives as `p − |W|` field words); the mask one is the `mask` layout
// (`m_j ∈ [0, 1024)` on coefficient `j + 1`, `j < 128`) — every other coefficient 0 in all three.
// The contract equates each m across ct0/app, each u across ct0/ct1, the weight words to the
// round's registered weights, `address == msg.sender` and `index` to the sender's registered slot.
// The exposures and the mask never leave this process.

import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js'
import type { ProofData } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { InputMap } from '@noir-lang/noir_js'
import { getAddress } from 'viem'
import type { Address, Hex } from 'viem'

import { requireCircuits } from './circuits'
import {
  APP_PUBLIC_INPUTS,
  ASSETS,
  EXPOSURE_BOUND,
  FRAC_SCALE,
  MASK_BITS,
  MASK_WIDTH,
  N,
  TREASURY_PARAM_SET,
  WEIGHT_BOUND,
  WORD_ADDRESS,
  WORD_INDEX,
  WORD_M_FWD,
  WORD_M_MASK,
  WORD_M_REV,
  WORD_WEIGHTS,
} from './types'
import type { LegName, ProgressCallback, ProvenLeg, ProvingTimings, TreasurySubmission } from './types'

type WasmModule = typeof import('@interfold/ckks-zk-inputs')

interface WitnessBundle {
  ciphertext_hex: string
  ct0_inputs: InputMap & { m: { coefficients: string[] } }
  ct1_inputs: InputMap
  u_commitment_hex: string
  m_commitment_hex: string
  encoded_values: number[]
}

// Cached Barretenberg API (CRISP getBBApi pattern). The ps5 Greco legs are 3-limb circuits; the
// validity leg is ~2^16 gates: the 2^18 SRS fits every leg.
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

/** BN254 scalar field modulus. */
export const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
/** A signed integer as its BN254 field representative (`p − |v|` when negative). */
export const signedFieldBigint = (v: number): bigint => (v >= 0 ? BigInt(v) : BN254_R + BigInt(v))
/** [`signedFieldBigint`] in decimal — the circuit's `weights[a]` InputMap entry. */
export const signedFieldDecimal = (v: number): string => signedFieldBigint(v).toString()
/** The on-chain `bytes32` word of a signed fixed-point weight (what `registerRound` stores). */
export const signedFieldWord = (v: number): Hex => word(signedFieldBigint(v))

/** Fresh cross-term mask: `MASK_WIDTH` integers uniform in `[0, 2^MASK_BITS)`. */
export const sampleMask = (): number[] => {
  const out = new Uint32Array(MASK_WIDTH)
  crypto.getRandomValues(out)
  return Array.from(out, (x) => x % (1 << MASK_BITS))
}

/** Fixed point (`× 2^16`, rounded) — the SAME rounding the Rust builder applies to exposures AND weights. */
export const toFixedPoint = (values: number[]): number[] => values.map((v) => Math.round(v * FRAC_SCALE))

/** The on-chain `bytes32[4]` of a round's real-valued weights (`registerRound`'s argument). */
export const weightWords = (weights: number[]): [Hex, Hex, Hex, Hex] => {
  const fixed = toFixedPoint(weights)
  if (fixed.length !== ASSETS) throw new Error(`expected ${ASSETS} weights, got ${fixed.length}`)
  return fixed.map(signedFieldWord) as [Hex, Hex, Hex, Hex]
}

/** Cap-normalise raw exposures: `x / cap` (must land in `[0, 1]`). */
export const normalise = (raw: number[], cap: number): number[] => raw.map((x) => x / cap)

/**
 * The length-N coefficient vectors of one submission in the policy's layout
 * (`e3_trckks::policy::coefficient_layout::{forward, reversed, mask}`; the same indices
 * `crates/zk-helpers/.../ckks_treasury_validity.rs::layout_vectors` pins). `fixedX` / `fixedW`
 * are the `× 2^16` integers; the reversed entries are the f64 products `w_a · x_a` exactly as the
 * Rust builder computes them (`Weights::weighted`).
 */
export const layoutVectors = (fixedX: number[], fixedW: number[], mask: number[]): { fwd: number[]; rev: number[]; msk: number[] } => {
  const fwd = new Array<number>(N).fill(0)
  const rev = new Array<number>(N).fill(0)
  const msk = new Array<number>(N).fill(0)
  for (let a = 0; a < ASSETS; a++) {
    const x = fixedX[a] / FRAC_SCALE
    const w = fixedW[a] / FRAC_SCALE
    fwd[a + 1] = x
    rev[N - a - 1] = w * x
  }
  for (let j = 0; j < MASK_WIDTH; j++) msk[j + 1] = mask[j]
  return { fwd, rev, msk }
}

/** Local pre-check of exactly what the app leg and the contract will refuse, so a doomed submission fails in ms. */
export const checkSubmission = (exposures: number[], weights: number[], mask: number[], index: number, slotAddress: Address, sender: Address): void => {
  if (exposures.length !== ASSETS) throw new Error(`expected ${ASSETS} exposures, got ${exposures.length}`)
  for (const [a, x] of exposures.entries()) {
    if (!Number.isFinite(x)) throw new Error(`exposure ${a} is not finite`)
    if (x < 0 || x > EXPOSURE_BOUND) throw new Error(`exposure ${a} = ${x} is outside [0, ${EXPOSURE_BOUND}] (cap-normalise first; the circuit rejects it)`)
  }
  if (weights.length !== ASSETS) throw new Error(`expected ${ASSETS} weights, got ${weights.length}`)
  for (const [a, w] of weights.entries()) {
    if (!Number.isFinite(w)) throw new Error(`weight ${a} is not finite`)
    if (Math.abs(w) > WEIGHT_BOUND) throw new Error(`weight ${a} = ${w} is outside [-${WEIGHT_BOUND}, ${WEIGHT_BOUND}]`)
  }
  if (mask.length !== MASK_WIDTH) throw new Error(`expected ${MASK_WIDTH} mask entries, got ${mask.length}`)
  for (const [j, m] of mask.entries()) {
    if (!Number.isInteger(m) || m < 0 || m >= 1 << MASK_BITS) throw new Error(`mask ${j} = ${m} is not in [0, 2^${MASK_BITS})`)
  }
  if (!Number.isInteger(index) || index < 0) throw new Error(`slot ${index} is not a valid registered index`)
  if (getAddress(slotAddress) !== getAddress(sender)) throw new Error('the registered slot is for a different address than the sender')
}

/**
 * Encrypt the DAO's cap-normalised exposure vector (`forward(x)`), the same vector weighted by
 * the round's PUBLIC weights (`reversed(w ∘ x)`) and a fresh cross-term mask under the committee's
 * CKKS public key, and prove all seven legs. `exposures` are real numbers in `[0, 1]` and
 * `weights` real numbers in `[-1, 1]`; both are rounded to `× 2^16` fixed point exactly as the
 * circuit pins them.
 */
export const encryptAndProveSubmission = async (
  publicKey: Uint8Array,
  exposures: number[],
  weights: number[],
  index: number,
  slotAddress: Address,
  sender: Address,
  mask: number[] = sampleMask(),
  onProgress: ProgressCallback = () => {},
): Promise<TreasurySubmission> => {
  checkSubmission(exposures, weights, mask, index, slotAddress, sender)
  const circuits = requireCircuits()
  const t0 = performance.now()
  const elapsed = () => performance.now() - t0
  const zero: Record<LegName, number> = { ct0F: 0, ct1F: 0, ct0R: 0, ct1R: 0, ct0M: 0, ct1M: 0, app: 0 }
  const timings: ProvingTimings = {
    encryptMs: 0,
    executeMs: { ...zero },
    proveMs: { ...zero },
    backendInitMs: 0,
    totalMs: 0,
  }
  const fixedX = toFixedPoint(exposures)
  const fixedW = toFixedPoint(weights)
  const { fwd, rev, msk } = layoutVectors(fixedX, fixedW, mask)

  onProgress({ stage: 'encrypt' }, elapsed())
  const wasm = await loadWasm()
  let t = performance.now()
  // Forward draws first, then reversed, then the mask (the order the Rust builder mirrors).
  const fwdBundle = wasm.encryptCoefficientsAndWitness(TREASURY_PARAM_SET, publicKey, new Float64Array(fwd), undefined) as WitnessBundle
  const revBundle = wasm.encryptCoefficientsAndWitness(TREASURY_PARAM_SET, publicKey, new Float64Array(rev), undefined) as WitnessBundle
  const maskBundle = wasm.encryptCoefficientsAndWitness(TREASURY_PARAM_SET, publicKey, new Float64Array(msk), undefined) as WitnessBundle
  timings.encryptMs = performance.now() - t

  // The validity leg's InputMap — exactly `main(m_fwd, m_rev, m_mask, x, mask, weights, address, index)`
  // of circuits/bin/threshold/ckks_treasury_validity_ps5/src/main.nr: the THREE message
  // polynomials as the ct0 legs witnessed them (canonical-field decimal strings, circuit layout),
  // the fixed-point exposures, the mask integers, and the public weights / address / index.
  const appInputs: InputMap = {
    m_fwd: fwdBundle.ct0_inputs.m,
    m_rev: revBundle.ct0_inputs.m,
    m_mask: maskBundle.ct0_inputs.m,
    x: fixedX.map((v) => v.toString()),
    mask: mask.map((m) => m.toString()),
    weights: fixedW.map(signedFieldDecimal),
    address: BigInt(getAddress(sender)).toString(),
    index: index.toString(),
  }

  onProgress({ stage: 'backend' }, elapsed())
  t = performance.now()
  const api = await getBBApi()
  timings.backendInitMs = performance.now() - t

  const legs: { name: LegName; circuit: 'ct0' | 'ct1' | 'app'; inputs: InputMap; expectPublic: number }[] = [
    { name: 'app', circuit: 'app', inputs: appInputs, expectPublic: APP_PUBLIC_INPUTS },
    { name: 'ct1F', circuit: 'ct1', inputs: fwdBundle.ct1_inputs, expectPublic: 3 },
    { name: 'ct0F', circuit: 'ct0', inputs: fwdBundle.ct0_inputs, expectPublic: 4 },
    { name: 'ct1R', circuit: 'ct1', inputs: revBundle.ct1_inputs, expectPublic: 3 },
    { name: 'ct0R', circuit: 'ct0', inputs: revBundle.ct0_inputs, expectPublic: 4 },
    { name: 'ct1M', circuit: 'ct1', inputs: maskBundle.ct1_inputs, expectPublic: 3 },
    { name: 'ct0M', circuit: 'ct0', inputs: maskBundle.ct0_inputs, expectPublic: 4 },
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

  const uF = word(BigInt(fwdBundle.u_commitment_hex))
  const uR = word(BigInt(revBundle.u_commitment_hex))
  const uM = word(BigInt(maskBundle.u_commitment_hex))
  const mF = word(BigInt(fwdBundle.m_commitment_hex))
  const mR = word(BigInt(revBundle.m_commitment_hex))
  const mM = word(BigInt(maskBundle.m_commitment_hex))
  if (proven.ct0F.publicInputs[3] !== uF || proven.ct1F.publicInputs[2] !== uF) throw new Error('u_commitment mismatch on the forward legs')
  if (proven.ct0R.publicInputs[3] !== uR || proven.ct1R.publicInputs[2] !== uR) throw new Error('u_commitment mismatch on the reversed legs')
  if (proven.ct0M.publicInputs[3] !== uM || proven.ct1M.publicInputs[2] !== uM) throw new Error('u_commitment mismatch on the mask legs')
  if (proven.ct0F.publicInputs[2] !== mF || proven.app.publicInputs[WORD_M_FWD] !== mF) throw new Error('m_commitment_fwd mismatch between the ct0 and app legs')
  if (proven.ct0R.publicInputs[2] !== mR || proven.app.publicInputs[WORD_M_REV] !== mR) throw new Error('m_commitment_rev mismatch between the ct0 and app legs')
  if (proven.ct0M.publicInputs[2] !== mM || proven.app.publicInputs[WORD_M_MASK] !== mM) throw new Error('m_commitment_mask mismatch between the ct0 and app legs')
  for (let a = 0; a < ASSETS; a++) {
    if (proven.app.publicInputs[WORD_WEIGHTS + a] !== signedFieldWord(fixedW[a])) throw new Error(`weight ${a} differs from the circuit public input`)
  }
  if (proven.app.publicInputs[WORD_ADDRESS] !== word(BigInt(getAddress(sender)))) throw new Error('address differs from the circuit public input')
  if (proven.app.publicInputs[WORD_INDEX] !== word(BigInt(index))) throw new Error('slot index differs from the circuit public input')

  timings.totalMs = elapsed()
  onProgress({ stage: 'done' }, timings.totalMs)
  return {
    ciphertextFwd: `0x${fwdBundle.ciphertext_hex}`,
    ciphertextRev: `0x${revBundle.ciphertext_hex}`,
    ciphertextMask: `0x${maskBundle.ciphertext_hex}`,
    ct0F: proven.ct0F,
    ct1F: proven.ct1F,
    ct0R: proven.ct0R,
    ct1R: proven.ct1R,
    ct0M: proven.ct0M,
    ct1M: proven.ct1M,
    app: proven.app,
    mCommitmentFwd: mF,
    mCommitmentRev: mR,
    mCommitmentMask: mM,
    uCommitmentFwd: uF,
    uCommitmentRev: uR,
    uCommitmentMask: uM,
    index,
    fixedPoint: fixedX,
    weightsFixed: fixedW,
    timings,
  }
}

/** The weighted concentration risk from the opened output: `Σ_a w_a (Σ_i x_{i,a})² = −opened[0]` (the `t^N ≡ −1` wrap). */
export const riskFromOpened = (opened: number[]): number => {
  if (opened.length === 0) throw new Error('opened output has no coefficient 0')
  return -opened[0]
}

/** The oracle: the fixed-point risk the network computes (test/e2e use — needs EVERY plaintext book). */
export const expectedRisk = (books: number[][], weights: number[]): number => {
  const w = toFixedPoint(weights).map((v) => v / FRAC_SCALE)
  const agg = new Array<number>(ASSETS).fill(0)
  for (const book of books) {
    const x = toFixedPoint(book).map((v) => v / FRAC_SCALE)
    for (let a = 0; a < ASSETS; a++) agg[a] += x[a]
  }
  let acc = 0
  for (let a = 0; a < ASSETS; a++) acc += w[a] * agg[a] * agg[a]
  return acc
}
