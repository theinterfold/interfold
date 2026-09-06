// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Address, Hex } from 'viem'

/** On-chain ParamSet the federated-averaging app runs on (N=512, 3 × 36-bit limbs, Δ=2^40). */
export const FEDAVG_PARAM_SET = 5

/** Ring degree: every coefficient vector handed to the WASM encoder has exactly N entries. */
export const N = 512

/** Model-update dimension compiled into `ckks_fedavg_validity_ps5` (Noir `CKKS_FEDAVG_D`). */
export const D = 8

/** Fixed-point bits of an update entry (`g × 2^16`), `|g| ≤ 1`. */
export const WEIGHT_FRAC_BITS = 16
export const WEIGHT_SCALE = 2 ** WEIGHT_FRAC_BITS
export const ENTRY_BOUND = 1

/** Fixed-point bits of the squared-norm bound (`B × 2^32`). */
export const NORM_FRAC_BITS = 32
export const NORM_SCALE = 2 ** NORM_FRAC_BITS

/** Sample count range: `1 ≤ n < COUNT_BOUND`. */
export const COUNT_BOUND = 1024

/** Coefficients the opened output publishes (`int128[64]` at 4 decimals). */
export const OUTPUT_COUNT = 64
export const OUTPUT_DECIMALS = 4

/** Nargo package names of the circuits (the Greco pair is proven TWICE: gradient ct, count ct). */
export const CIRCUIT_NAMES = {
  ct0: 'user_data_encryption_ckks_ct0_ps5',
  ct1: 'user_data_encryption_ckks_ct1_ps5',
  app: 'ckks_fedavg_validity_ps5',
} as const

export type CircuitName = keyof typeof CIRCUIT_NAMES

/** The five proven legs of one update. */
export type LegName = 'ct0G' | 'ct1G' | 'ct0C' | 'ct1C' | 'app'

/** A round's public parameters. */
export interface RoundParams {
  d: number
  normBound: number
  minClients: number
}

/** The slot the server serves for a registered client (`GET /rounds/{id}/slot/{address}`). */
export interface SlotInfo {
  address: Address
  /** The client's SLOT index: its position in the round's registered client list. */
  index: number
  d: number
  normBound: number
  /** The bound as the circuit takes it (`B × 2^32`). */
  normBoundFixedPoint: number
}

/** A proven leg ready for the envelope. */
export interface ProvenLeg {
  proof: Hex
  /** Exactly the circuit's public inputs/outputs, 32-byte words. */
  publicInputs: Hex[]
}

/** Everything a client produces locally. The update and the count NEVER leave the browser. */
export interface UpdateSubmission {
  /** The gradient ciphertext (`gradient_block(g)`). */
  ciphertextG: Hex
  /** The count ciphertext (`constant(n)`). */
  ciphertextC: Hex
  ct0G: ProvenLeg
  ct1G: ProvenLeg
  ct0C: ProvenLeg
  ct1C: ProvenLeg
  app: ProvenLeg
  mCommitmentG: Hex
  mCommitmentC: Hex
  uCommitmentG: Hex
  uCommitmentC: Hex
  /** The client's slot. */
  index: number
  /** The update in fixed point (`× 2^16`), what was actually encrypted. */
  fixedPointUpdate: number[]
  /** `Σ g_j²` of the fixed-point update (real units). */
  squaredNorm: number
  /** The private sample count that was encrypted. */
  count: number
  timings: ProvingTimings
}

export interface ProvingTimings {
  encryptMs: number
  executeMs: Record<LegName, number>
  proveMs: Record<LegName, number>
  backendInitMs: number
  totalMs: number
}

export type ProvingStage =
  | { stage: 'encrypt' }
  | { stage: 'backend' }
  | { stage: 'execute'; leg: LegName }
  | { stage: 'prove'; leg: LegName }
  | { stage: 'done' }

export type ProgressCallback = (stage: ProvingStage, elapsedMs: number) => void

/** Round summary as served by the coordination server. */
export interface RoundSummary {
  e3Id: string
  status: RoundStatus
  d: number
  normBound: number
  minClients: number
  inputWindow: [number, number]
  updateCount: number
  createdAt: number
}

export type RoundStatus = 'requested' | 'active' | 'evaluating' | 'published' | 'finished' | 'failed'

export interface IndexedUpdate {
  /** The client's slot (position in the registered list). */
  index: number
  publisher: Address
  transactionHash: Hex
  block: number
  gradientCiphertextHash: Hex
  countCiphertextHash: Hex
  mCommitmentGrad: Hex
  mCommitmentCount: Hex
  /** Whether the server fetched and hash-checked both ciphertexts from the transaction calldata. */
  ciphertextAvailable: boolean
}

export interface RoundResults {
  /** The first 64 opened coefficients (`opened[j+1] = Σ n_i g_{i,j}`, `opened[d+1] = Σ n_i`). */
  opened: number[]
  /** `opened[j+1] / opened[d+1]` for `j < d` — the sample-weighted mean update. */
  mean: number[]
  /** `opened[d+1]` — total samples across all clients. */
  totalCount: number
  /** Raw on-chain plaintext bytes (canonical fixed point, 4 decimals). */
  plaintextHex: Hex
}

export interface RoundDetail extends RoundSummary {
  programAddress: Address
  paramSet: number
  normBoundFixedPoint: number
  /** Registered client addresses in SLOT order. */
  clients: Address[]
  updates: IndexedUpdate[]
  publicKeyAvailable: boolean
  results: RoundResults | null
  error: string | null
  timings: Record<string, number>
}
