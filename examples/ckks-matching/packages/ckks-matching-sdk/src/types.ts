// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Address, Hex } from 'viem'

/** On-chain ParamSet the matching app runs on (N=512, 3 × 36-bit limbs, Δ=2^40, coefficient encoding). */
export const MATCHING_PARAM_SET = 5

/** Ring degree of ParamSet 5 (the full coefficient vector the WASM encodes). */
export const N = 512

/** Length of each party's profile vector (Noir `K` of `ckks_matching_validity_ps5`). */
export const K = 16

/** Exactly two parties per round: slot 0 = A (forward layout), slot 1 = B (reversed layout). */
export const PARTIES = 2

/** Cross-term mask: `MASK_WIDTH` integers uniform in `[0, 2^MASK_BITS)` on coefficients `1..=MASK_WIDTH`. */
export const MASK_WIDTH = 128
export const MASK_BITS = 10
export const MASK_BOUND = 2 ** MASK_BITS

/** Fixed-point bits of vector entries the circuit takes (`v × 2^16`), `|v| ≤ 1`. */
export const FRAC_BITS = 16
export const FRAC_SCALE = 2 ** FRAC_BITS
export const ENTRY_BOUND = 1

/** The published output: the first 64 coefficients at 4 decimals (`int128[]` big-endian). */
export const OUTPUT_COUNT = 64
export const OUTPUT_DECIMALS = 4

/** Nargo package names of the circuits (the Greco pair is proven TWICE: vector ct, mask ct). */
export const CIRCUIT_NAMES = {
  ct0: 'user_data_encryption_ckks_ct0_ps5',
  ct1: 'user_data_encryption_ckks_ct1_ps5',
  app: 'ckks_matching_validity_ps5',
} as const

export type CircuitName = keyof typeof CIRCUIT_NAMES

/** The five proven legs of one submission. */
export type LegName = 'ct0V' | 'ct1V' | 'ct0M' | 'ct1M' | 'app'

/** `a` = slot 0 (forward), `b` = slot 1 (reversed). */
export type Role = 'a' | 'b'

export const roleBit = (role: Role): number => (role === 'a' ? 0 : 1)
export const roleFromIndex = (index: number): Role => {
  if (index === 0) return 'a'
  if (index === 1) return 'b'
  throw new Error(`matching has exactly two slots (0 = A, 1 = B); got ${index}`)
}
export const roleLayout = (role: Role): 'forward' | 'reversed' => (role === 'a' ? 'forward' : 'reversed')

/** The slot response the server serves for a registered party (`GET /rounds/{id}/slot/{address}`). */
export interface SlotResponse {
  address: Address
  /** 0 = A, 1 = B. */
  index: number
  role: Role
  layout: 'forward' | 'reversed'
}

/** A proven leg ready for the envelope. */
export interface ProvenLeg {
  proof: Hex
  /** Exactly the circuit's public inputs/outputs, 32-byte words. */
  publicInputs: Hex[]
}

/** Everything a party produces locally. The vector and the mask NEVER leave the browser. */
export interface MatchingSubmission {
  /** The vector ciphertext (`forward(a)` for A, `reversed(b)` for B). */
  ciphertextVec: Hex
  /** The mask ciphertext (`mask(m)`). */
  ciphertextMask: Hex
  ct0V: ProvenLeg
  ct1V: ProvenLeg
  ct0M: ProvenLeg
  ct1M: ProvenLeg
  app: ProvenLeg
  mCommitmentVec: Hex
  mCommitmentMask: Hex
  uCommitmentVec: Hex
  uCommitmentMask: Hex
  /** The party's slot (= role bit). */
  index: number
  role: Role
  /** The fixed-point entries (`× 2^16`) that were encoded (local record only). */
  fixedPoint: number[]
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
  inputWindow: [number, number]
  partyA: Address
  partyB: Address
  submissionCount: number
  createdAt: number
}

export type RoundStatus = 'requested' | 'active' | 'evaluating' | 'published' | 'finished' | 'failed'

export interface IndexedSubmission {
  /** The party's slot (0 = A, 1 = B) — also its role. */
  index: number
  role: Role
  publisher: Address
  transactionHash: Hex
  block: number
  vectorCiphertextHash: Hex
  maskCiphertextHash: Hex
  mCommitmentVec: Hex
  mCommitmentMask: Hex
  /** Whether the server fetched and hash-checked both ciphertexts from the transaction calldata. */
  ciphertextAvailable: boolean
}

export interface RoundResults {
  /** The compatibility score `⟨a, b⟩` (already negated from `opened[0]`). */
  score: number
  /** The raw opened coefficients: `opened[0] = −score`, `1..` are mask-hidden cross terms. */
  opened: number[]
  /** Raw on-chain plaintext bytes (canonical fixed point, 4 decimals). */
  plaintextHex: Hex
}

export interface RoundDetail extends RoundSummary {
  programAddress: Address
  paramSet: number
  k: number
  /** `[A, B]` in slot order. */
  parties: Address[]
  submissions: IndexedSubmission[]
  publicKeyAvailable: boolean
  results: RoundResults | null
  error: string | null
  timings: Record<string, number>
}
