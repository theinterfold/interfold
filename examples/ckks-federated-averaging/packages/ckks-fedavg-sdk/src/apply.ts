// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The client's local pipeline: TWO coefficient-encoded CKKS encryptions (WASM,
// `@interfold/ckks-zk-inputs` `encryptCoefficientsAndWitness`, called twice) feeding FIVE Honk
// proofs bound by commitments —
//
//   ct0/ct1 legs (gradient ct)  user_data_encryption_ckks_ct{0,1}_ps5 → (…, m_commitment_grad, u_g)
//   ct0/ct1 legs (count ct)     user_data_encryption_ckks_ct{0,1}_ps5 → (…, m_commitment_count, u_c)
//   app leg                     ckks_fedavg_validity_ps5 →
//       [norm_bound, address, index] ⇒ (m_commitment_grad, m_commitment_count)
//
// The app leg takes BOTH message polynomials the ct0 legs witnessed, recomputes their commitments,
// and proves the gradient one is `gradient_block(g)` with `|g_j| ≤ 1` and `Σ g_j² ≤ norm_bound`
// and the count one is `constant(n)` with `1 ≤ n < 1024` — every other coefficient 0 in both.
// The contract equates each m across ct0/app, each u across ct0/ct1, requires
// `address == msg.sender`, `index` == the sender's registered position and `norm_bound` == the
// round's. The update and the count never leave this process.
//
// Layouts mirror `e3_trckks::policy::coefficient_layout` EXACTLY (index for index):
//   gradient_block(g): g_j at coefficient j+1 for j < d, 1.0 at coefficient d+1, 0 elsewhere
//   constant(n):       n at coefficient 0, 0 elsewhere

import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js'
import type { ProofData } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { InputMap } from '@noir-lang/noir_js'
import { getAddress } from 'viem'
import type { Address, Hex } from 'viem'

import { requireCircuits } from './circuits'
import { COUNT_BOUND, D, ENTRY_BOUND, FEDAVG_PARAM_SET, N, NORM_SCALE, WEIGHT_SCALE } from './types'
import type { LegName, ProgressCallback, ProvenLeg, ProvingTimings, SlotInfo, UpdateSubmission } from './types'

type WasmModule = typeof import('@interfold/ckks-zk-inputs')

interface WitnessBundle {
  ciphertext_hex: string
  /** ct0 leg inputs; `m` is the message polynomial as `{ coefficients: [...] }` (canonical field decimals, circuit layout). */
  ct0_inputs: InputMap & { m: { coefficients: string[] } }
  ct1_inputs: InputMap
  u_commitment_hex: string
  m_commitment_hex: string
  encoded_values: number[]
}

// Cached Barretenberg API (CRISP getBBApi pattern). The ps5 Greco legs are 3-limb circuits, the
// validity leg is tiny (2^13); the 2^18 SRS fits everything.
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
/** A signed integer as its BN254 field representative (`p − |v|` when negative) — the ONE helper for words AND noir inputs. */
export const signedField = (v: number | bigint): bigint => {
  const b = BigInt(v)
  return b >= 0n ? b : BN254_R + b
}
export const signedWord = (v: number | bigint): Hex => word(signedField(v))

/** The update in the circuit's fixed point (`× 2^16`, rounded). */
export const toFixedPointUpdate = (g: number[]): number[] => g.map((v) => Math.round(v * WEIGHT_SCALE))

/** The exact f64 values the encoder takes back from the fixed point (`G / 2^16`). */
export const fromFixedPointUpdate = (fixed: number[]): number[] => fixed.map((v) => v / WEIGHT_SCALE)

/** `Σ G_j²` in `2^32` fixed point (exact integer arithmetic, as the circuit does it). */
export const squaredNormFixedPoint = (fixed: number[]): bigint => fixed.reduce((acc, g) => acc + BigInt(g) * BigInt(g), 0n)

/** `Σ g_j²` in real units of the fixed-point update. */
export const squaredNorm = (fixed: number[]): number => Number(squaredNormFixedPoint(fixed)) / NORM_SCALE

/** The round's bound in the circuit's `2^32` fixed point (rounded down, as the server registers it). */
export const normBoundFixedPoint = (bound: number): number => Math.floor(bound * NORM_SCALE)

/** `gradient_block(g)`: `g_j` at coefficient `j + 1`, `1.0` at `d + 1`, zero elsewhere (length N). */
export const gradientBlockLayout = (g: number[], n: number = N): number[] => {
  if (g.length + 2 > 64) throw new Error('gradient block does not fit the 64-coefficient output window')
  const c = new Array<number>(n).fill(0)
  g.forEach((v, j) => {
    c[j + 1] = v
  })
  c[g.length + 1] = 1.0
  return c
}

/** `constant(n)`: `n` at coefficient 0, zero elsewhere (length N). */
export const constantLayout = (v: number, n: number = N): number[] => {
  const c = new Array<number>(n).fill(0)
  c[0] = v
  return c
}

/** Local pre-check of exactly what the app leg and the contract will refuse, so a doomed update fails in ms. */
export const checkUpdate = (slot: SlotInfo, update: number[], count: number, sender: Address): number[] => {
  if (slot.d !== D) throw new Error(`round d = ${slot.d} but the circuit is compiled for d = ${D}`)
  if (update.length !== D) throw new Error(`expected ${D} update entries, got ${update.length}`)
  for (const [j, g] of update.entries()) {
    if (!Number.isFinite(g) || Math.abs(g) > ENTRY_BOUND) throw new Error(`entry ${j} = ${g} outside ±${ENTRY_BOUND} (the circuit rejects it)`)
  }
  const fixed = toFixedPointUpdate(update)
  const boundFp = BigInt(normBoundFixedPoint(slot.normBound))
  if (BigInt(slot.normBoundFixedPoint) !== boundFp) throw new Error(`server bound ${slot.normBoundFixedPoint} ≠ floor(${slot.normBound} · 2^32)`)
  const norm = squaredNormFixedPoint(fixed)
  if (norm > boundFp) throw new Error(`squared norm ${Number(norm) / NORM_SCALE} exceeds the round bound ${slot.normBound} (the circuit rejects it)`)
  if (!Number.isInteger(count) || count < 1 || count >= COUNT_BOUND) throw new Error(`sample count ${count} is not in [1, ${COUNT_BOUND})`)
  if (!Number.isInteger(slot.index) || slot.index < 0 || slot.index >= 1 << 16) throw new Error(`slot index ${slot.index} out of range`)
  if (getAddress(slot.address) !== getAddress(sender)) throw new Error('slot is for a different address than the sender')
  return fixed
}

/**
 * Encrypt the update (as `gradient_block`) and the private sample count (as `constant`) under
 * the committee's CKKS public key and prove all five legs.
 */
export const encryptAndProveUpdate = async (
  publicKey: Uint8Array,
  slot: SlotInfo,
  update: number[],
  count: number,
  sender: Address,
  onProgress: ProgressCallback = () => {},
): Promise<UpdateSubmission> => {
  const fixed = checkUpdate(slot, update, count, sender)
  const circuits = requireCircuits()
  const t0 = performance.now()
  const elapsed = () => performance.now() - t0
  const zero = { ct0G: 0, ct1G: 0, ct0C: 0, ct1C: 0, app: 0 }
  const timings: ProvingTimings = { encryptMs: 0, executeMs: { ...zero }, proveMs: { ...zero }, backendInitMs: 0, totalMs: 0 }

  onProgress({ stage: 'encrypt' }, elapsed())
  const wasm = await loadWasm()
  let t = performance.now()
  // The gradient encryption draws first, then the count (the order the native builder uses).
  const grad = wasm.encryptCoefficientsAndWitness(FEDAVG_PARAM_SET, publicKey, Float64Array.from(gradientBlockLayout(fromFixedPointUpdate(fixed))), undefined) as WitnessBundle
  const cnt = wasm.encryptCoefficientsAndWitness(FEDAVG_PARAM_SET, publicKey, Float64Array.from(constantLayout(count)), undefined) as WitnessBundle
  timings.encryptMs = performance.now() - t

  // The validity leg's inputs: the SAME `m`s the ct0 legs carry (canonical field decimals, circuit layout).
  const appInputs: InputMap = {
    m_grad: grad.ct0_inputs.m,
    m_count: cnt.ct0_inputs.m,
    g: fixed.map((v) => signedField(v).toString()),
    count: count.toString(),
    norm_bound: slot.normBoundFixedPoint.toString(),
    address: BigInt(getAddress(sender)).toString(),
    index: slot.index.toString(),
  }

  onProgress({ stage: 'backend' }, elapsed())
  t = performance.now()
  const api = await getBBApi()
  timings.backendInitMs = performance.now() - t

  const legs: { name: LegName; circuit: 'ct0' | 'ct1' | 'app'; inputs: InputMap; expectPublic: number }[] = [
    { name: 'app', circuit: 'app', inputs: appInputs, expectPublic: 5 },
    { name: 'ct1G', circuit: 'ct1', inputs: grad.ct1_inputs, expectPublic: 3 },
    { name: 'ct0G', circuit: 'ct0', inputs: grad.ct0_inputs, expectPublic: 4 },
    { name: 'ct1C', circuit: 'ct1', inputs: cnt.ct1_inputs, expectPublic: 3 },
    { name: 'ct0C', circuit: 'ct0', inputs: cnt.ct0_inputs, expectPublic: 4 },
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

  const uG = word(BigInt(grad.u_commitment_hex))
  const uC = word(BigInt(cnt.u_commitment_hex))
  const mG = word(BigInt(grad.m_commitment_hex))
  const mC = word(BigInt(cnt.m_commitment_hex))
  if (proven.ct0G.publicInputs[3] !== uG || proven.ct1G.publicInputs[2] !== uG) throw new Error('u_commitment mismatch on the gradient legs')
  if (proven.ct0C.publicInputs[3] !== uC || proven.ct1C.publicInputs[2] !== uC) throw new Error('u_commitment mismatch on the count legs')
  if (proven.ct0G.publicInputs[2] !== mG || proven.app.publicInputs[3] !== mG) throw new Error('m_commitment_grad mismatch between the ct0 and app legs')
  if (proven.ct0C.publicInputs[2] !== mC || proven.app.publicInputs[4] !== mC) throw new Error('m_commitment_count mismatch between the ct0 and app legs')
  if (proven.app.publicInputs[0] !== word(BigInt(slot.normBoundFixedPoint))) throw new Error('norm bound differs from the circuit public input')
  if (proven.app.publicInputs[2] !== word(BigInt(slot.index))) throw new Error('slot index differs from the circuit public input')

  timings.totalMs = elapsed()
  onProgress({ stage: 'done' }, timings.totalMs)
  return {
    ciphertextG: `0x${grad.ciphertext_hex}`,
    ciphertextC: `0x${cnt.ciphertext_hex}`,
    ct0G: proven.ct0G,
    ct1G: proven.ct1G,
    ct0C: proven.ct0C,
    ct1C: proven.ct1C,
    app: proven.app,
    mCommitmentG: mG,
    mCommitmentC: mC,
    uCommitmentG: uG,
    uCommitmentC: uC,
    index: slot.index,
    fixedPointUpdate: fixed,
    squaredNorm: squaredNorm(fixed),
    count,
    timings,
  }
}

/** The weighted mean from the opened coefficients: `opened[j+1] / opened[d+1]` (what the server also computes). */
export const weightedMean = (opened: number[], d: number): { mean: number[]; totalCount: number } => {
  if (opened.length < d + 2) throw new Error(`opened output has ${opened.length} coefficients, need ${d + 2}`)
  const totalCount = opened[d + 1]
  if (!(totalCount > 0.5)) throw new Error(`total sample count ${totalCount} is not positive`)
  return { mean: opened.slice(1, d + 1).map((v) => v / totalCount), totalCount }
}

/** The oracle: the exact weighted mean of plaintext updates (test/e2e use — needs every client's plaintext). */
export const expectedWeightedMean = (updates: { update: number[]; count: number }[]): { mean: number[]; totalCount: number } => {
  const d = updates[0]?.update.length ?? 0
  const totalCount = updates.reduce((a, u) => a + u.count, 0)
  const mean = new Array<number>(d).fill(0)
  for (const { update, count } of updates) update.forEach((g, j) => (mean[j] += count * g))
  return { mean: mean.map((m) => m / totalCount), totalCount }
}
