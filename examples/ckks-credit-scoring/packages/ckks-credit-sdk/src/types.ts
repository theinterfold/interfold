// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Address, Hex } from 'viem'

/** On-chain ParamSet the credit-scoring app runs on (N=512, 5 × 36-bit limbs, Δ=2^40). */
export const CREDIT_PARAM_SET = 4

/** Number of issuer-attested features per applicant (Noir `FEATURES`). */
export const FEATURES = 8

/** Output-mask numerator width: `mask < 2^MASK_BITS`, mask value `mask / 2^MASK_FRAC_BITS ∈ [0, 1024)`. */
export const MASK_BITS = 20
export const MASK_FRAC_BITS = 10
export const MASK_SCALE = 2 ** MASK_FRAC_BITS

/** Fixed-point bits of the model the circuit takes (`w × 2^16`), `|w| ≤ 8`. */
export const WEIGHT_FRAC_BITS = 16
export const WEIGHT_SCALE = 2 ** WEIGHT_FRAC_BITS
export const WEIGHT_BOUND = 8

/** Slots per output ciphertext (one applicant each): `N / 2`. */
export const MAX_APPLICANTS = 256

/** `CREDIT_MERKLE_MAX_DEPTH` compiled into `ckks_credit_validity_ps4`. */
export const MERKLE_MAX_DEPTH = 20

/** Nargo package names of the circuits (the Greco pair is proven TWICE: logit ct, mask ct). */
export const CIRCUIT_NAMES = {
  ct0: 'user_data_encryption_ckks_ct0_ps4',
  ct1: 'user_data_encryption_ckks_ct1_ps4',
  app: 'ckks_credit_validity_ps4',
} as const

export type CircuitName = keyof typeof CIRCUIT_NAMES

/** The five proven legs of one application. */
export type LegName = 'ct0Z' | 'ct1Z' | 'ct0M' | 'ct1M' | 'app'

/** The public model a round is scored with (`|w_j| ≤ 8`, `|b| ≤ 8`). */
export interface Model {
  weights: number[]
  bias: number
}

/** The model in the circuit's fixed point (`× 2^16`, rounded) — what is registered on-chain. */
export interface FixedPointModel {
  weights: number[]
  bias: number
}

/** One entry of a round's issuer snapshot (address + attested feature numerators over `cap`). */
export interface ApplicantEntry {
  address: Address
  features: number[]
}

/** The opening the server serves for one snapshot address (`GET /rounds/{id}/feature-proof/{address}`). */
export interface FeatureProof {
  address: Address
  /** The applicant's SLOT index: its position in the round's registered applicant list. */
  index: number
  features: number[]
  cap: number
  /** 32-byte hex root the leaf opens to. */
  merkleRoot: Hex
  depth: number
  /** Path direction bits, leaf to root (`false` = node is the left child). */
  indices: boolean[]
  /** Sibling hashes, leaf to root, as decimal field-element strings. */
  siblings: string[]
}

/** A proven leg ready for the envelope. */
export interface ProvenLeg {
  proof: Hex
  /** Exactly the circuit's public inputs/outputs, 32-byte words. */
  publicInputs: Hex[]
}

/** Everything an applicant produces locally. The mask is SECRET and stays in the browser. */
export interface ApplicationSubmission {
  /** The logit ciphertext (slot `index` = `⟨w, x⟩/cap + b`). */
  ciphertextZ: Hex
  /** The mask ciphertext (slot `index` = `mask / 2^10`). */
  ciphertextM: Hex
  ct0Z: ProvenLeg
  ct1Z: ProvenLeg
  ct0M: ProvenLeg
  ct1M: ProvenLeg
  app: ProvenLeg
  mCommitmentZ: Hex
  mCommitmentM: Hex
  uCommitmentZ: Hex
  uCommitmentM: Hex
  /** The applicant's slot. */
  index: number
  /** Output-mask numerator (`m = mask / 2^10`) — keep it; it unmasks the score. */
  mask: number
  /** The logit that was encrypted (local oracle for the applicant's own check). */
  logit: number
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
  cap: number
  inputWindow: [number, number]
  applicationCount: number
  createdAt: number
}

export type RoundStatus = 'requested' | 'active' | 'evaluating' | 'published' | 'finished' | 'failed'

export interface IndexedApplication {
  /** The applicant's slot (position in the registered list). */
  index: number
  publisher: Address
  transactionHash: Hex
  block: number
  logitCiphertextHash: Hex
  maskCiphertextHash: Hex
  mCommitmentZ: Hex
  mCommitmentM: Hex
  /** Whether the server fetched and hash-checked both ciphertexts from the transaction calldata. */
  ciphertextAvailable: boolean
}

export interface RoundResults {
  /** `opened[i] = σ_cubic(z_i) + m_i` for slot `i` (0.5 for an empty slot). */
  opened: number[]
  /** Raw on-chain plaintext bytes (canonical fixed point, 4 decimals). */
  plaintextHex: Hex
}

export interface RoundDetail extends RoundSummary {
  programAddress: Address
  paramSet: number
  model: Model
  fixedPointModel: FixedPointModel | null
  issuerRoot: Hex | null
  /** Snapshot addresses in SLOT order. */
  applicantAddresses: Address[]
  applications: IndexedApplication[]
  publicKeyAvailable: boolean
  results: RoundResults | null
  error: string | null
  timings: Record<string, number>
}

/** What the applicant recovers from the opened output with their own mask. */
export interface RecoveredScore {
  /** The applicant's slot. */
  index: number
  /** The opened slot value as published (`σ(z) + m`, masked). */
  opened: number
  /** `m` — the mask subtracted. */
  mask: number
  /** `σ_cubic(z)` — the credit probability the network computed. */
  probability: number
}
