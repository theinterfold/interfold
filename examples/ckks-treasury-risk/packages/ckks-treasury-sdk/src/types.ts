// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Address, Hex } from 'viem'

/** On-chain ParamSet the treasury app runs on (N=512, 3 × 36-bit limbs, Δ=2^40, coefficient encoding). */
export const TREASURY_PARAM_SET = 5

/** Ring degree of ParamSet 5 (the full coefficient vector the WASM encodes). */
export const N = 512

/** Number of public assets per exposure vector (Noir `ASSETS` of `ckks_treasury_validity_ps5`). */
export const ASSETS = 4

/** Minimum number of DAOs before the server evaluates (one DAO's "aggregate" is its own book). */
export const MIN_DAOS = 2

/** Cross-term mask: `MASK_WIDTH` integers uniform in `[0, 2^MASK_BITS)` on coefficients `1..=MASK_WIDTH`. */
export const MASK_WIDTH = 128
export const MASK_BITS = 10
export const MASK_BOUND = 2 ** MASK_BITS

/** Fixed-point bits of exposures and weights the circuit takes (`v × 2^16`). */
export const FRAC_BITS = 16
export const FRAC_SCALE = 2 ** FRAC_BITS
/** `0 ≤ x_a ≤ EXPOSURE_BOUND` (cap-normalised by the DAO: `exposure / cap`). */
export const EXPOSURE_BOUND = 1
/** `|w_a| ≤ WEIGHT_BOUND`. */
export const WEIGHT_BOUND = 1

/** The published output: the first 64 coefficients at 4 decimals (`int128[]` big-endian). */
export const OUTPUT_COUNT = 64
export const OUTPUT_DECIMALS = 4

/** Validity-leg public words, in on-chain order: `[w_0..w_3, address, index, m_c_fwd, m_c_rev, m_c_mask]`. */
export const APP_PUBLIC_INPUTS = 9
export const WORD_WEIGHTS = 0
export const WORD_ADDRESS = 4
export const WORD_INDEX = 5
export const WORD_M_FWD = 6
export const WORD_M_REV = 7
export const WORD_M_MASK = 8

/** Nargo package names of the circuits (the Greco pair is proven THREE times: forward, reversed, mask). */
export const CIRCUIT_NAMES = {
  ct0: 'user_data_encryption_ckks_ct0_ps5',
  ct1: 'user_data_encryption_ckks_ct1_ps5',
  app: 'ckks_treasury_validity_ps5',
} as const

export type CircuitName = keyof typeof CIRCUIT_NAMES

/** The seven proven legs of one submission. */
export type LegName = 'ct0F' | 'ct1F' | 'ct0R' | 'ct1R' | 'ct0M' | 'ct1M' | 'app'

/** The slot response the server serves for a registered DAO (`GET /rounds/{id}/slot/{address}`). */
export interface SlotResponse {
  address: Address
  /** The DAO's position in the round's registered list. */
  index: number
}

/** A proven leg ready for the envelope. */
export interface ProvenLeg {
  proof: Hex
  /** Exactly the circuit's public inputs/outputs, 32-byte words. */
  publicInputs: Hex[]
}

/** Everything a DAO produces locally. The exposures and the mask NEVER leave the browser. */
export interface TreasurySubmission {
  /** `forward(x)` ciphertext. */
  ciphertextFwd: Hex
  /** `reversed(w ∘ x)` ciphertext. */
  ciphertextRev: Hex
  /** `mask(m)` ciphertext. */
  ciphertextMask: Hex
  ct0F: ProvenLeg
  ct1F: ProvenLeg
  ct0R: ProvenLeg
  ct1R: ProvenLeg
  ct0M: ProvenLeg
  ct1M: ProvenLeg
  app: ProvenLeg
  mCommitmentFwd: Hex
  mCommitmentRev: Hex
  mCommitmentMask: Hex
  uCommitmentFwd: Hex
  uCommitmentRev: Hex
  uCommitmentMask: Hex
  /** The DAO's registered slot. */
  index: number
  /** The fixed-point exposures (`× 2^16`) that were encoded (local record only). */
  fixedPoint: number[]
  /** The round's weights in fixed point (`× 2^16`, signed) — the public words the leg was proven under. */
  weightsFixed: number[]
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
  /** The round's public risk weights (real values, `|w| ≤ 1`). */
  weights: number[]
  daoCount: number
  submissionCount: number
  createdAt: number
}

export type RoundStatus = 'requested' | 'active' | 'evaluating' | 'published' | 'finished' | 'failed'

export interface IndexedSubmission {
  /** The DAO's slot (position in the registered list). */
  index: number
  publisher: Address
  transactionHash: Hex
  block: number
  forwardCiphertextHash: Hex
  reversedCiphertextHash: Hex
  maskCiphertextHash: Hex
  mCommitmentFwd: Hex
  mCommitmentRev: Hex
  mCommitmentMask: Hex
  /** Whether the server fetched and hash-checked all three ciphertexts from the transaction calldata. */
  ciphertextAvailable: boolean
}

export interface RoundResults {
  /** The weighted concentration risk of the combined book (already negated from `opened[0]`). */
  risk: number
  /** The raw opened coefficients: `opened[0] = −risk`, `1..` are mask-hidden cross terms. */
  opened: number[]
  /** Raw on-chain plaintext bytes (canonical fixed point, 4 decimals). */
  plaintextHex: Hex
}

export interface RoundDetail extends RoundSummary {
  programAddress: Address
  paramSet: number
  assets: number
  minDaos: number
  /** The weights in fixed point (`× 2^16`, signed) exactly as registered on-chain. */
  weightsFixed: number[]
  /** Registered DAOs in slot order. */
  daos: Address[]
  submissions: IndexedSubmission[]
  publicKeyAvailable: boolean
  results: RoundResults | null
  error: string | null
  timings: Record<string, number>
}
