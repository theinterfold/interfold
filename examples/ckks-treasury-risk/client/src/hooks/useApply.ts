// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The DAO pipeline as a hook: slot lookup (position in the registered list) → cap-normalise the
// exposure vector locally → sample a cross-term mask → WASM coefficient-encode (forward /
// reversed(w∘x) / mask) + encrypt THREE times → 7 proofs (with per-stage timings) → wallet tx.
// The exposures and the mask NEVER go to the server; a local record (exposures + fixed point) is
// kept in localStorage keyed by (e3Id, address) so the DAO can compare the opened risk with its
// own book.

import { useCallback, useState } from 'react'
import type { Address, Hex } from 'viem'
import { encryptAndProveSubmission, normalise, publishSubmission, sampleMask } from '@ckks-treasury/sdk'
import type { ProvingStage, TreasurySubmission } from '@ckks-treasury/sdk'

import { api, ensureCircuits } from '../api'
import { useWallet } from '../wallet'

export interface StepLog {
  label: string
  ms?: number
  status: 'running' | 'done' | 'failed'
}

export interface ApplyState {
  steps: StepLog[]
  running: boolean
  error: string | null
  submission: TreasurySubmission | null
  txHash: Hex | null
  gasUsed: bigint | null
}

/** localStorage record of a DAO's own submission for one round (never leaves the browser). */
export interface StoredSubmission {
  index: number
  /** The cap-normalised exposures that were encrypted. */
  exposures: number[]
  fixedPoint: number[]
  weights: number[]
  uCommitmentFwd: Hex
  txHash: Hex
}

export const submissionKey = (e3Id: string, address: Address) => `ckks-treasury:submission:${e3Id}:${address.toLowerCase()}`

export const loadSubmission = (e3Id: string, address: Address): StoredSubmission | null => {
  const raw = localStorage.getItem(submissionKey(e3Id, address))
  return raw ? (JSON.parse(raw) as StoredSubmission) : null
}

const stageLabel = (s: ProvingStage): string => {
  switch (s.stage) {
    case 'encrypt':
      return 'CKKS coefficient-encode + encrypt forward / reversed(w∘x) / mask + witnesses (WASM)'
    case 'backend':
      return 'Barretenberg init (SRS 2^18)'
    case 'execute':
      return `witness ${s.leg}`
    case 'prove':
      return `prove ${s.leg} (UltraHonk)`
    case 'done':
      return 'proving done'
  }
}

export const useApply = (e3Id: string, program: Address, weights: number[]) => {
  const { walletClient, publicClient, address } = useWallet()
  const [state, setState] = useState<ApplyState>({ steps: [], running: false, error: null, submission: null, txHash: null, gasUsed: null })

  const pushStep = (label: string) =>
    setState((s) => ({
      ...s,
      steps: [...s.steps.map((st) => (st.status === 'running' ? { ...st, status: 'done' as const } : st)), { label, status: 'running' }],
    }))
  const finishStep = (ms: number) =>
    setState((s) => {
      const steps = [...s.steps]
      const last = steps[steps.length - 1]
      if (last && last.status === 'running') steps[steps.length - 1] = { ...last, status: 'done', ms }
      return { ...s, steps }
    })

  /**
   * `raw` is the DAO's exposure vector (4 non-negative values); `cap` normalises it to `[0, 1]`.
   * `weightsOverride` lets the UI (and the e2e) deliberately prove under the WRONG weights — the
   * contract rejects it (`WrongWeights`), which is the point.
   */
  const submit = useCallback(
    async (raw: number[], cap: number, weightsOverride?: number[]) => {
      if (!walletClient || !address) throw new Error('connect a wallet first')
      setState({ steps: [], running: true, error: null, submission: null, txHash: null, gasUsed: null })
      let lastAt = performance.now()
      try {
        pushStep('load circuits + registered slot + committee key')
        const [, slot, pk] = await Promise.all([ensureCircuits(), api.slot(e3Id, address), api.publicKey(e3Id)])
        finishStep(performance.now() - lastAt)
        const exposures = normalise(raw, cap)
        const w = weightsOverride ?? weights

        const mask = sampleMask()
        const submission = await encryptAndProveSubmission(pk, exposures, w, slot.index, slot.address, address, mask, (stage) => {
          const now = performance.now()
          finishStep(now - lastAt)
          lastAt = now
          if (stage.stage !== 'done') pushStep(stageLabel(stage))
        })
        setState((s) => ({ ...s, submission }))

        pushStep('wallet: publishInput (7 on-chain Honk verifies)')
        const t = performance.now()
        const res = await publishSubmission(walletClient, publicClient, program, BigInt(e3Id), submission)
        finishStep(performance.now() - t)
        const stored: StoredSubmission = { index: submission.index, exposures, fixedPoint: submission.fixedPoint, weights: w, uCommitmentFwd: submission.uCommitmentFwd, txHash: res.hash }
        localStorage.setItem(submissionKey(e3Id, address), JSON.stringify(stored))
        setState((s) => ({ ...s, running: false, txHash: res.hash, gasUsed: res.gasUsed }))
      } catch (e) {
        const message = (e as Error).message ?? String(e)
        setState((s) => ({
          ...s,
          running: false,
          error: message,
          steps: s.steps.map((st) => (st.status === 'running' ? { ...st, status: 'failed' } : st)),
        }))
        throw e
      }
    },
    [walletClient, publicClient, address, e3Id, program, weights],
  )

  return { state, submit }
}
