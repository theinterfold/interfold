// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The party's local pipeline (private matching, ParamSet 5): TWO COEFFICIENT-encoded CKKS
// encryptions (WASM `@interfold/ckks-zk-inputs` `encryptCoefficientsAndWitness`) feeding FIVE
// Honk proofs bound by commitments —
//
//   ct0/ct1 legs (vector ct)  user_data_encryption_ckks_ct{0,1}_ps5 → (…, m_commitment_vec, u_vec)
//   ct0/ct1 legs (mask ct)    user_data_encryption_ckks_ct{0,1}_ps5 → (…, m_commitment_mask, u_mask)
//   app leg                   ckks_matching_validity_ps5 →
//       [role, address, index] ⇒ (m_commitment_vec, m_commitment_mask)
//
// The app leg takes BOTH message polynomials the ct0 legs witnessed (`ct0_inputs.m`), recomputes
// their commitments, and proves the vector one is EXACTLY the `forward` (role 0 = A: `a_j` on
// coefficient `j + 1`) or `reversed` (role 1 = B: `b_j` on coefficient `N − j − 1`) coefficient
// encoding of 16 fixed-point entries `V_j / 2^16` with `|V_j| ≤ 2^16`, and the mask one is the
// `mask` layout (`m_j ∈ [0, 1024)` on coefficient `j + 1`, `j < 128`) — every other coefficient 0
// in both. The contract equates each m across ct0/app, each u across ct0/ct1, requires
// `address == msg.sender`, `index` == the sender's registered slot and `role == index`.
// The vector and the mask never leave this process.

import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js'
import type { ProofData } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { InputMap } from '@noir-lang/noir_js'
import { getAddress } from 'viem'
import type { Address, Hex } from 'viem'

import { requireCircuits } from './circuits'
import { ENTRY_BOUND, FRAC_SCALE, K, MASK_BITS, MASK_WIDTH, MATCHING_PARAM_SET, N, roleBit } from './types'
import type { LegName, MatchingSubmission, ProgressCallback, ProvenLeg, ProvingTimings, Role } from './types'

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
/** A signed integer as its BN254 field representative in decimal (`p − |v|` when negative) — the circuit's `values[j]`. */
export const signedFieldDecimal = (v: number): string => (v >= 0 ? BigInt(v) : BN254_R + BigInt(v)).toString()

/** Fresh cross-term mask: `MASK_WIDTH` integers uniform in `[0, 2^MASK_BITS)`. */
export const sampleMask = (): number[] => {
  const out = new Uint32Array(MASK_WIDTH)
  crypto.getRandomValues(out)
  return Array.from(out, (x) => x % (1 << MASK_BITS))
}

/** The fixed-point entries (`× 2^16`, rounded) the circuit proves against — the SAME rounding the Rust builder applies. */
export const toFixedPoint = (values: number[]): number[] => values.map((v) => Math.round(v * FRAC_SCALE))

/** Cap-normalise raw profile values: `x / cap` (must land in `[-1, 1]`). */
export const normalise = (raw: number[], cap: number): number[] => raw.map((x) => x / cap)

/**
 * The length-N coefficient vectors of one submission in the policy's layout
 * (`e3_trckks::policy::coefficient_layout::{forward, reversed, mask}`; the same indices
 * `crates/zk-helpers/.../ckks_matching_validity.rs::layout_vectors` pins).
 */
export const layoutVectors = (role: Role, fixed: number[], mask: number[]): { vec: number[]; msk: number[] } => {
  const vec = new Array<number>(N).fill(0)
  const msk = new Array<number>(N).fill(0)
  for (let j = 0; j < K; j++) {
    const v = fixed[j] / FRAC_SCALE
    if (role === 'a') vec[j + 1] = v
    else vec[N - j - 1] = v
  }
  for (let j = 0; j < MASK_WIDTH; j++) msk[j + 1] = mask[j]
  return { vec, msk }
}

/** Local pre-check of exactly what the app leg and the contract will refuse, so a doomed submission fails in ms. */
export const checkSubmission = (values: number[], mask: number[], role: Role, index: number, slotAddress: Address, sender: Address): void => {
  if (values.length !== K) throw new Error(`expected ${K} entries, got ${values.length}`)
  for (const [j, v] of values.entries()) {
    if (!Number.isFinite(v)) throw new Error(`entry ${j} is not finite`)
    if (Math.abs(v) > ENTRY_BOUND) throw new Error(`entry ${j} = ${v} is outside [-${ENTRY_BOUND}, ${ENTRY_BOUND}] (cap-normalise first; the circuit rejects it)`)
  }
  if (mask.length !== MASK_WIDTH) throw new Error(`expected ${MASK_WIDTH} mask entries, got ${mask.length}`)
  for (const [j, m] of mask.entries()) {
    if (!Number.isInteger(m) || m < 0 || m >= 1 << MASK_BITS) throw new Error(`mask ${j} = ${m} is not in [0, 2^${MASK_BITS})`)
  }
  if (index !== roleBit(role)) throw new Error(`slot ${index} does not match role ${role} (A = 0, B = 1)`)
  if (getAddress(slotAddress) !== getAddress(sender)) throw new Error('the registered slot is for a different address than the sender')
}

/**
 * Encrypt the party's cap-normalised profile vector (`forward` for A, `reversed` for B) and a
 * fresh cross-term mask under the committee's CKKS public key and prove all five legs.
 * `values` are real numbers in `[-1, 1]`; they are rounded to `× 2^16` fixed point exactly as
 * the circuit pins them.
 */
export const encryptAndProveSubmission = async (
  publicKey: Uint8Array,
  values: number[],
  role: Role,
  index: number,
  slotAddress: Address,
  sender: Address,
  mask: number[] = sampleMask(),
  onProgress: ProgressCallback = () => {},
): Promise<MatchingSubmission> => {
  checkSubmission(values, mask, role, index, slotAddress, sender)
  const circuits = requireCircuits()
  const t0 = performance.now()
  const elapsed = () => performance.now() - t0
  const zero = { ct0V: 0, ct1V: 0, ct0M: 0, ct1M: 0, app: 0 }
  const timings: ProvingTimings = {
    encryptMs: 0,
    executeMs: { ...zero },
    proveMs: { ...zero },
    backendInitMs: 0,
    totalMs: 0,
  }
  const fixed = toFixedPoint(values)
  const { vec, msk } = layoutVectors(role, fixed, mask)

  onProgress({ stage: 'encrypt' }, elapsed())
  const wasm = await loadWasm()
  let t = performance.now()
  // The vector encryption draws first, then the mask (the order the Rust builder mirrors).
  const vecBundle = wasm.encryptCoefficientsAndWitness(MATCHING_PARAM_SET, publicKey, new Float64Array(vec), undefined) as WitnessBundle
  const maskBundle = wasm.encryptCoefficientsAndWitness(MATCHING_PARAM_SET, publicKey, new Float64Array(msk), undefined) as WitnessBundle
  timings.encryptMs = performance.now() - t

  // The validity leg's InputMap: BOTH message polynomials exactly as the ct0 legs witnessed
  // them (canonical-field decimal strings, circuit layout), the fixed-point entries as field
  // words, the mask integers, and the three public words.
  const appInputs: InputMap = {
    m_vec: vecBundle.ct0_inputs.m,
    m_mask: maskBundle.ct0_inputs.m,
    values: fixed.map(signedFieldDecimal),
    mask: mask.map((m) => m.toString()),
    role: roleBit(role).toString(),
    address: BigInt(getAddress(sender)).toString(),
    index: index.toString(),
  }

  onProgress({ stage: 'backend' }, elapsed())
  t = performance.now()
  const api = await getBBApi()
  timings.backendInitMs = performance.now() - t

  const legs: { name: LegName; circuit: 'ct0' | 'ct1' | 'app'; inputs: InputMap; expectPublic: number }[] = [
    { name: 'app', circuit: 'app', inputs: appInputs, expectPublic: 5 },
    { name: 'ct1V', circuit: 'ct1', inputs: vecBundle.ct1_inputs, expectPublic: 3 },
    { name: 'ct0V', circuit: 'ct0', inputs: vecBundle.ct0_inputs, expectPublic: 4 },
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

  const uV = word(BigInt(vecBundle.u_commitment_hex))
  const uM = word(BigInt(maskBundle.u_commitment_hex))
  const mV = word(BigInt(vecBundle.m_commitment_hex))
  const mM = word(BigInt(maskBundle.m_commitment_hex))
  if (proven.ct0V.publicInputs[3] !== uV || proven.ct1V.publicInputs[2] !== uV) throw new Error('u_commitment mismatch on the vector legs')
  if (proven.ct0M.publicInputs[3] !== uM || proven.ct1M.publicInputs[2] !== uM) throw new Error('u_commitment mismatch on the mask legs')
  if (proven.ct0V.publicInputs[2] !== mV || proven.app.publicInputs[3] !== mV) throw new Error('m_commitment_vec mismatch between the ct0 and app legs')
  if (proven.ct0M.publicInputs[2] !== mM || proven.app.publicInputs[4] !== mM) throw new Error('m_commitment_mask mismatch between the ct0 and app legs')
  if (proven.app.publicInputs[0] !== word(BigInt(roleBit(role)))) throw new Error('role differs from the circuit public input')
  if (proven.app.publicInputs[1] !== word(BigInt(getAddress(sender)))) throw new Error('address differs from the circuit public input')
  if (proven.app.publicInputs[2] !== word(BigInt(index))) throw new Error('slot index differs from the circuit public input')

  timings.totalMs = elapsed()
  onProgress({ stage: 'done' }, timings.totalMs)
  return {
    ciphertextVec: `0x${vecBundle.ciphertext_hex}`,
    ciphertextMask: `0x${maskBundle.ciphertext_hex}`,
    ct0V: proven.ct0V,
    ct1V: proven.ct1V,
    ct0M: proven.ct0M,
    ct1M: proven.ct1M,
    app: proven.app,
    mCommitmentVec: mV,
    mCommitmentMask: mM,
    uCommitmentVec: uV,
    uCommitmentMask: uM,
    index,
    role,
    fixedPoint: fixed,
    timings,
  }
}

/** The compatibility score from the opened output: `⟨a, b⟩ = −opened[0]` (the `t^N ≡ −1` wrap). */
export const scoreFromOpened = (opened: number[]): number => {
  if (opened.length === 0) throw new Error('opened output has no coefficient 0')
  return -opened[0]
}

/** The oracle: the fixed-point dot product the network computes (test/e2e use — needs BOTH plaintext vectors). */
export const expectedScore = (a: number[], b: number[]): number => {
  const fa = toFixedPoint(a)
  const fb = toFixedPoint(b)
  let acc = 0
  for (let j = 0; j < K; j++) acc += (fa[j] / FRAC_SCALE) * (fb[j] / FRAC_SCALE)
  return acc
}
