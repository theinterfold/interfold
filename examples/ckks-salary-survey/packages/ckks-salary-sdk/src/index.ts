// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * `@interfold/ckks-salary-sdk` — the participant-side pipeline of the CKKS
 * salary survey, usable from the browser (Vite) and from Node (e2e):
 *
 *   1. `encryptAndWitness` (WASM, `@interfold/ckks-zk-inputs`): ONE CKKS
 *      encryption of `salary / cap` replicated across all N/2 slots, plus the
 *      Greco witness maps for the ct0 / ct1 circuits and the message
 *      polynomial `m`.
 *   2. noir_js `execute` × 3 legs → witnesses.
 *   3. bb.js UltraHonk `generateProof` × 3 legs (keccak oracle, `evm`
 *      target — what the on-chain Solidity verifiers expect).
 *   4. `submission.json` — the exact shape `CkksSalaryE3Program.publishInput`
 *      is fed (`program:publish-app-input` and the server relay agree).
 *
 * The three legs are bound by commitments the contract checks:
 *   ct0 outputs `[pk0_c, ct0_c, m_commitment, u_commitment]`,
 *   ct1 outputs `[pk1_c, ct1_c, u_commitment]`,
 *   app outputs `[cap, m_commitment]`.
 * The app leg's witness is `{ m, value_raw, cap }` where `m` is the SAME
 * polynomial the ct0 leg carries (`ct0_inputs.m`, circuit layout) — so the
 * app-validity InputMap is assembled here in TS from the WASM bundle; no
 * separate WASM builder is needed (see `appLegInputs`).
 */

import type { CompiledCircuit, InputMap } from '@noir-lang/noir_js'

export const PARAM_SET = 3
/** ps3 Greco circuits have circuit_size ≈ 65k; 2^18 CRS fits the browser's IndexedDB cap. */
export const SRS_SIZE = 2 ** 18

export type Leg = 'ct0' | 'ct1' | 'app'

export const CIRCUIT_NAMES: Record<Leg, string> = {
  ct0: 'user_data_encryption_ckks_ct0_ps3',
  ct1: 'user_data_encryption_ckks_ct1_ps3',
  app: 'ckks_salary_validity_ps3',
}

export type CircuitBundle = Record<Leg, CompiledCircuit>

export interface ProofLeg {
  proofHex: string
  publicInputs: string[]
}

/** `submission.json` — what the relay / hardhat task publish on-chain. */
export interface Submission {
  app: 'salary'
  paramSet: number
  ciphertextHex: string
  ct0: ProofLeg
  ct1: ProofLeg
  appLeg: ProofLeg
}

export interface WitnessBundle {
  param_set: number
  ciphertext_hex: string
  ct0_inputs: InputMap
  ct1_inputs: InputMap
  u_commitment_hex: string
  m_commitment_hex: string
  message_poly: string[]
  message_poly_limbs: string[][]
  encoded_values: number[]
}

export interface StageTiming {
  stage: string
  millis: number
}

export type ProgressFn = (stage: string, detail?: string) => void

export interface ProveResult {
  submission: Submission
  uCommitment: string
  mCommitment: string
  timings: StageTiming[]
  totalMillis: number
}

/** Minimal surface of `@interfold/ckks-zk-inputs` we use. */
export interface CkksWasm {
  encryptAndWitness: (
    set: number,
    pk: Uint8Array,
    value: number,
    cap: number,
    replicate: boolean,
    seed?: Uint8Array | null,
  ) => WitnessBundle
  ckksParamSetInfo: (set: number) => { degree: number; num_limbs: number; scale_bits: number; input_bound: number }
}

/** bb.js surface we use (typed loosely so Node and browser bundles both fit). */
export interface HonkBackend {
  generateProof: (
    witness: Uint8Array,
    opts?: { verifierTarget?: string },
  ) => Promise<{ proof: Uint8Array; publicInputs: string[] }>
  verifyProof?: (proof: { proof: Uint8Array; publicInputs: string[] }, opts?: { verifierTarget?: string }) => Promise<boolean>
  destroy?: () => Promise<void>
}

export interface ProverDeps {
  wasm: CkksWasm
  /** `new Noir(circuit)` constructor from `@noir-lang/noir_js`. */
  Noir: new (circuit: CompiledCircuit) => { execute: (inputs: InputMap) => Promise<{ witness: Uint8Array; returnValue: unknown }> }
  /** Build an UltraHonk backend for a circuit (shares one Barretenberg api). */
  backendFor: (circuit: CompiledCircuit) => Promise<HonkBackend>
  circuits: CircuitBundle
}

const hex32 = (h: string): string => `0x${BigInt(h).toString(16).padStart(64, '0')}`
const bytesToHex = (b: Uint8Array): string =>
  `0x${Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')}`

/**
 * The app-validity leg's InputMap, assembled from the WASM bundle:
 * `m` is exactly `ct0_inputs.m` (the message polynomial in circuit layout,
 * field-canonical coefficients), `value_raw` the integer salary and `cap`
 * the public normalization cap.
 */
export const appLegInputs = (bundle: WitnessBundle, salary: number, cap: number): InputMap => {
  const m = bundle.ct0_inputs['m']
  if (!m) throw new Error('bundle.ct0_inputs.m missing')
  return { m, value_raw: String(salary), cap: String(cap) }
}

export const validateSalary = (salary: number, cap: number): void => {
  if (!Number.isInteger(salary) || salary < 0) throw new Error('salary must be a non-negative integer')
  if (salary > cap) throw new Error(`salary must be ≤ the survey cap ${cap}`)
}

const normalizeOutputs = (returnValue: unknown): string[] => {
  // noir_js returns a single Field as a string, a tuple as an array.
  const arr = Array.isArray(returnValue)
    ? returnValue
    : typeof returnValue === 'object' && returnValue !== null
      ? Object.values(returnValue)
      : [returnValue]
  return arr.map((v) => hex32(String(v)))
}

/**
 * Full participant pipeline: encrypt + witness, execute × 3, prove × 3,
 * assemble `submission.json`. Throws if the solved public outputs disagree
 * with the bundle's commitments (a witness/encoding bug, never a
 * malformed proof reaching the chain).
 */
export const proveSalarySubmission = async (
  deps: ProverDeps,
  publicKey: Uint8Array,
  salary: number,
  cap: number,
  onProgress: ProgressFn = () => {},
): Promise<ProveResult> => {
  validateSalary(salary, cap)
  const timings: StageTiming[] = []
  const t0 = performance.now()
  const timed = async <T>(stage: string, fn: () => Promise<T> | T): Promise<T> => {
    onProgress(stage)
    const s = performance.now()
    const r = await fn()
    timings.push({ stage, millis: Math.round(performance.now() - s) })
    return r
  }

  const bundle = await timed('encrypt + witness (WASM)', () =>
    deps.wasm.encryptAndWitness(PARAM_SET, publicKey, salary, cap, true, undefined),
  )
  const expectU = bundle.u_commitment_hex.toLowerCase()
  const expectM = bundle.m_commitment_hex.toLowerCase()

  // `expect` = public inputs+outputs the proof carries (what goes
  // on-chain); `returns` = the circuit's return values (noir_js
  // `returnValue`), which for the app leg excludes its public input `cap`.
  const legs: { leg: Leg; inputs: InputMap; expect: number; returns: number; check: (o: string[]) => void }[] = [
    {
      leg: 'ct0',
      inputs: bundle.ct0_inputs,
      expect: 4,
      returns: 4,
      check: (o) => {
        if (o[3].toLowerCase() !== expectU) throw new Error(`ct0 u_commitment ${o[3]} != ${expectU}`)
        if (o[2].toLowerCase() !== expectM) throw new Error(`ct0 m_commitment ${o[2]} != ${expectM}`)
      },
    },
    {
      leg: 'ct1',
      inputs: bundle.ct1_inputs,
      expect: 3,
      returns: 3,
      check: (o) => {
        if (o[2].toLowerCase() !== expectU) throw new Error(`ct1 u_commitment ${o[2]} != ${expectU}`)
      },
    },
    {
      leg: 'app',
      inputs: appLegInputs(bundle, salary, cap),
      expect: 2,
      returns: 1,
      check: (o) => {
        if (o[0].toLowerCase() !== expectM) throw new Error(`app m_commitment ${o[0]} != ${expectM}`)
      },
    },
  ]

  const proofs = {} as Record<Leg, ProofLeg>
  for (const { leg, inputs, expect, returns, check } of legs) {
    const circuit = deps.circuits[leg]
    const { witness, returnValue } = await timed(`noir_js execute (${leg})`, () =>
      new deps.Noir(circuit).execute(inputs),
    )
    const outputs = normalizeOutputs(returnValue)
    if (outputs.length !== returns) throw new Error(`${leg}: expected ${returns} outputs, got ${outputs.length}`)
    check(outputs)
    const backend = await deps.backendFor(circuit)
    const { proof, publicInputs } = await timed(`bb.js prove (${leg})`, () =>
      backend.generateProof(witness, { verifierTarget: 'evm' }),
    )
    // Only the circuit's public inputs/outputs go on-chain (the verifier
    // reads the pairing-point limbs from the proof tail).
    const pub = publicInputs.map(hex32)
    if (pub.length !== expect) throw new Error(`${leg}: proof carries ${pub.length} public inputs, want ${expect}`)
    if (leg === 'app' && BigInt(pub[0]) !== BigInt(cap)) throw new Error(`app cap ${pub[0]} != ${cap}`)
    if (leg === 'app' && pub[1].toLowerCase() !== expectM) throw new Error(`app proof m_commitment ${pub[1]} != ${expectM}`)
    proofs[leg] = { proofHex: bytesToHex(proof), publicInputs: pub }
    onProgress(`proved ${leg}`, `${proof.length} bytes`)
  }

  const submission: Submission = {
    app: 'salary',
    paramSet: PARAM_SET,
    ciphertextHex: `0x${bundle.ciphertext_hex}`,
    ct0: proofs.ct0,
    ct1: proofs.ct1,
    appLeg: proofs.app,
  }
  return {
    submission,
    uCommitment: expectU,
    mCommitment: expectM,
    timings,
    totalMillis: Math.round(performance.now() - t0),
  }
}

// ── Server API client ──────────────────────────────────────────────────

export type RoundStatus = 'requested' | 'open' | 'closed' | 'evaluating' | 'complete' | 'failed'

export interface SubmissionRecord {
  index: number
  publisher: string
  tx_hash: string
  block_number: number
  ciphertext_hash: string
  m_commitment: string
  u_commitment: string
  ciphertext_bytes: number
  verified: boolean
  gas_used: number | null
  submitted_at: number
}

export interface Results {
  count: number
  sum: number
  sum_of_squares: number
  mean: number
  variance: number
  stddev: number
  opened_slots: number[]
  plaintext_hex: string
  decrypted_at: number
}

export interface Round {
  e3_id: string
  chain_id: number
  status: RoundStatus
  program_address: string
  requester: string
  param_set: number
  salary_cap: number
  input_window: [number, number]
  requested_at: number
  request_tx_hash: string | null
  committee: string[]
  public_key_hex: string | null
  key_published_at: number | null
  submissions: SubmissionRecord[]
  evaluation: {
    input_count: number
    ciphertext_bytes: number
    commitment: string
    publish_tx_hash: string | null
    evaluated_at: number
    eval_millis: number
  } | null
  results: Results | null
  failure_reason: string | null
}

export interface RoundSummary {
  e3_id: string
  status: RoundStatus
  salary_cap: number
  input_window: [number, number]
  requested_at: number
  submission_count: number
  has_public_key: boolean
  has_results: boolean
}

export interface SubmitResponse {
  accepted: boolean
  e3_id: string
  index: number
  tx_hash: string
  block_number: number
  gas_used: number
  u_commitment: string
  m_commitment: string
  relay_millis: number
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public duplicate = false,
  ) {
    super(message)
  }
}

export const hexToBytes = (h: string): Uint8Array => {
  const s = h.startsWith('0x') ? h.slice(2) : h
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16)
  return out
}

export class SurveyApi {
  constructor(
    public baseUrl: string,
    private adminKey = '',
  ) {}

  private async req<T>(method: string, path: string, body?: unknown, admin = false): Promise<T> {
    const headers: Record<string, string> = { 'content-type': 'application/json' }
    if (admin && this.adminKey) headers['x-admin-key'] = this.adminKey
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    const json = (await res.json().catch(() => ({}))) as { error?: string; duplicate?: boolean }
    if (!res.ok) throw new ApiError(res.status, json.error ?? `${method} ${path} failed (${res.status})`, !!json.duplicate)
    return json as T
  }

  health = () => this.req<Record<string, unknown>>('GET', '/health')
  rounds = () => this.req<RoundSummary[]>('GET', '/rounds')
  round = (id: string) => this.req<Round>('GET', `/rounds/${id}`)
  pubkey = (id: string) =>
    this.req<{ e3_id: string; public_key_hex: string; param_set: number; salary_cap: number }>('GET', `/rounds/${id}/pubkey`)
  submit = (id: string, submission: Submission) => this.req<SubmitResponse>('POST', `/rounds/${id}/submit`, { submission })
  createRound = (durationSecs?: number) =>
    this.req<{ e3_id: string; tx_hash: string; input_window: [number, number] }>('POST', '/rounds', { duration_secs: durationSecs }, true)
  evaluate = (id: string) => this.req<Round['evaluation']>('POST', `/rounds/${id}/evaluate`, undefined, true)
}

/** Population statistics of cleartext salaries (for tests / demos). */
export const expectedStatistics = (salaries: number[]) => {
  const n = salaries.length
  const sum = salaries.reduce((a, b) => a + b, 0)
  const sumsq = salaries.reduce((a, b) => a + b * b, 0)
  const mean = sum / n
  const variance = Math.max(0, sumsq / n - mean * mean)
  return { count: n, sum, sum_of_squares: sumsq, mean, variance, stddev: Math.sqrt(variance) }
}
