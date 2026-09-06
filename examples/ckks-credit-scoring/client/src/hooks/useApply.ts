// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The applicant pipeline as a hook (credit v2): feature proof (with the applicant's slot) → compute
// the registered model's logit locally → sample an OUTPUT mask → WASM slot-encode + encrypt TWICE →
// 5 proofs (with per-stage timings) → wallet tx → mask persisted in localStorage keyed by
// (e3Id, address) so the probability can be recovered once the round is opened. The mask NEVER
// goes to the server.

import { useCallback, useState } from 'react'
import type { Address, Hex } from 'viem'
import { encryptAndProveApplication, publishApplication, sampleMask } from '@ckks-credit/sdk'
import type { ApplicationSubmission, Model, ProvingStage } from '@ckks-credit/sdk'

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
  submission: ApplicationSubmission | null
  txHash: Hex | null
  gasUsed: bigint | null
}

/** localStorage record of an applicant's output mask for one round. */
export interface StoredMask {
  mask: number
  index: number
  logit: number
  uCommitmentZ: Hex
  txHash: Hex
}

export const maskKey = (e3Id: string, address: Address) => `ckks-credit:mask:${e3Id}:${address.toLowerCase()}`

export const loadMask = (e3Id: string, address: Address): StoredMask | null => {
  const raw = localStorage.getItem(maskKey(e3Id, address))
  return raw ? (JSON.parse(raw) as StoredMask) : null
}

const stageLabel = (s: ProvingStage): string => {
  switch (s.stage) {
    case 'encrypt':
      return 'CKKS slot-encode + encrypt logit & mask + witnesses (WASM)'
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

export const useApply = (e3Id: string, program: Address, model: Model) => {
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
   * `featureOverride` lets the UI (and the e2e) deliberately submit a feature vector different from
   * the attested one — the circuit rejects it (wrong leaf / over cap), which is the point.
   * `modelOverride` submits under a DIFFERENT model than the registered one — the contract rejects
   * it (`WrongModel`).
   */
  const submit = useCallback(
    async (featureOverride?: number[], modelOverride?: Model) => {
      if (!walletClient || !address) throw new Error('connect a wallet first')
      setState({ steps: [], running: true, error: null, submission: null, txHash: null, gasUsed: null })
      let lastAt = performance.now()
      try {
        pushStep('load circuits + feature proof (slot) + committee key')
        const [, proof, pk] = await Promise.all([ensureCircuits(), api.featureProof(e3Id, address), api.publicKey(e3Id)])
        finishStep(performance.now() - lastAt)
        const effectiveProof = featureOverride ? { ...proof, features: featureOverride } : proof

        const mask = sampleMask()
        const submission = await encryptAndProveApplication(pk, effectiveProof, modelOverride ?? model, address, mask, (stage) => {
          const now = performance.now()
          finishStep(now - lastAt)
          lastAt = now
          if (stage.stage !== 'done') pushStep(stageLabel(stage))
        })
        setState((s) => ({ ...s, submission }))

        pushStep('wallet: publishInput (5 on-chain Honk verifies)')
        const t = performance.now()
        const res = await publishApplication(walletClient, publicClient, program, BigInt(e3Id), submission)
        finishStep(performance.now() - t)
        const stored: StoredMask = { mask: submission.mask, index: submission.index, logit: submission.logit, uCommitmentZ: submission.uCommitmentZ, txHash: res.hash }
        localStorage.setItem(maskKey(e3Id, address), JSON.stringify(stored))
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
    [walletClient, publicClient, address, e3Id, program, model],
  )

  return { state, submit }
}
