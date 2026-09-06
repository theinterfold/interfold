// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The party pipeline as a hook: slot lookup (role A/B from the registered position) → cap-normalise
// the profile vector locally → sample a cross-term mask → WASM coefficient-encode (forward /
// reversed + mask) + encrypt TWICE → 5 proofs (with per-stage timings) → wallet tx. The vector and
// the mask NEVER go to the server; a local record (vector + fixed point) is kept in localStorage
// keyed by (e3Id, address) so the party can compare the opened score with its own expectation.

import { useCallback, useState } from 'react'
import type { Address, Hex } from 'viem'
import { encryptAndProveSubmission, normalise, publishSubmission, sampleMask } from '@ckks-matching/sdk'
import type { MatchingSubmission, ProvingStage, Role } from '@ckks-matching/sdk'

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
  submission: MatchingSubmission | null
  txHash: Hex | null
  gasUsed: bigint | null
}

/** localStorage record of a party's own submission for one round (never leaves the browser). */
export interface StoredSubmission {
  role: Role
  index: number
  /** The cap-normalised entries that were encrypted. */
  values: number[]
  fixedPoint: number[]
  uCommitmentVec: Hex
  txHash: Hex
}

export const submissionKey = (e3Id: string, address: Address) => `ckks-matching:submission:${e3Id}:${address.toLowerCase()}`

export const loadSubmission = (e3Id: string, address: Address): StoredSubmission | null => {
  const raw = localStorage.getItem(submissionKey(e3Id, address))
  return raw ? (JSON.parse(raw) as StoredSubmission) : null
}

const stageLabel = (s: ProvingStage): string => {
  switch (s.stage) {
    case 'encrypt':
      return 'CKKS coefficient-encode + encrypt vector & mask + witnesses (WASM)'
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

export const useApply = (e3Id: string, program: Address) => {
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
   * `raw` is the party's profile vector (16 real values); `cap` normalises it to `[-1, 1]`.
   * `roleOverride` lets the UI (and the e2e) deliberately prove the WRONG layout — the contract
   * rejects it (`WrongRole`), which is the point.
   */
  const submit = useCallback(
    async (raw: number[], cap: number, roleOverride?: Role) => {
      if (!walletClient || !address) throw new Error('connect a wallet first')
      setState({ steps: [], running: true, error: null, submission: null, txHash: null, gasUsed: null })
      let lastAt = performance.now()
      try {
        pushStep('load circuits + registered slot (role) + committee key')
        const [, slot, pk] = await Promise.all([ensureCircuits(), api.slot(e3Id, address), api.publicKey(e3Id)])
        finishStep(performance.now() - lastAt)
        const role = roleOverride ?? slot.role
        const values = normalise(raw, cap)

        const mask = sampleMask()
        const submission = await encryptAndProveSubmission(pk, values, role, slot.index, slot.address, address, mask, (stage) => {
          const now = performance.now()
          finishStep(now - lastAt)
          lastAt = now
          if (stage.stage !== 'done') pushStep(stageLabel(stage))
        })
        setState((s) => ({ ...s, submission }))

        pushStep('wallet: publishInput (5 on-chain Honk verifies)')
        const t = performance.now()
        const res = await publishSubmission(walletClient, publicClient, program, BigInt(e3Id), submission)
        finishStep(performance.now() - t)
        const stored: StoredSubmission = { role, index: submission.index, values, fixedPoint: submission.fixedPoint, uCommitmentVec: submission.uCommitmentVec, txHash: res.hash }
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
    [walletClient, publicClient, address, e3Id, program],
  )

  return { state, submit }
}
