// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The client pipeline as a hook: slot lookup (the client's registered position + the round's
// bound) → WASM coefficient-encode + encrypt TWICE (gradient block, private count) → 5 proofs
// (with per-stage timings) → wallet tx. The update and the count NEVER go to the server.

import { useCallback, useState } from 'react'
import type { Address, Hex } from 'viem'
import { encryptAndProveUpdate, publishUpdate } from '@ckks-fedavg/sdk'
import type { ProvingStage, UpdateSubmission } from '@ckks-fedavg/sdk'

import { api, ensureCircuits } from '../api'
import { useWallet } from '../wallet'

export interface StepLog {
  label: string
  ms?: number
  status: 'running' | 'done' | 'failed'
}

export interface SubmitState {
  steps: StepLog[]
  running: boolean
  error: string | null
  submission: UpdateSubmission | null
  txHash: Hex | null
  gasUsed: bigint | null
}

/** localStorage record of what this browser submitted for one round (for the local check against the opened mean). */
export interface StoredUpdate {
  update: number[]
  count: number
  index: number
  uCommitmentG: Hex
  txHash: Hex
}

export const updateKey = (e3Id: string, address: Address) => `ckks-fedavg:update:${e3Id}:${address.toLowerCase()}`

export const loadStoredUpdate = (e3Id: string, address: Address): StoredUpdate | null => {
  const raw = localStorage.getItem(updateKey(e3Id, address))
  return raw ? (JSON.parse(raw) as StoredUpdate) : null
}

const stageLabel = (s: ProvingStage): string => {
  switch (s.stage) {
    case 'encrypt':
      return 'CKKS coefficient-encode + encrypt update & count + witnesses (WASM)'
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

export const useSubmitUpdate = (e3Id: string, program: Address) => {
  const { walletClient, publicClient, address } = useWallet()
  const [state, setState] = useState<SubmitState>({ steps: [], running: false, error: null, submission: null, txHash: null, gasUsed: null })

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
   * `normBoundOverride` lets the UI (and the e2e) deliberately prove against a DIFFERENT bound than
   * the round's — the contract rejects it (`WrongNormBound`). An update over the round's bound, an
   * entry outside ±1 or a count outside [1, 1024) fails locally before any proof (the circuit
   * would refuse it anyway).
   */
  const submit = useCallback(
    async (update: number[], count: number, normBoundOverride?: number) => {
      if (!walletClient || !address) throw new Error('connect a wallet first')
      setState({ steps: [], running: true, error: null, submission: null, txHash: null, gasUsed: null })
      let lastAt = performance.now()
      try {
        pushStep('load circuits + slot (registered index, round bound) + committee key')
        const [, slot, pk] = await Promise.all([ensureCircuits(), api.slot(e3Id, address), api.publicKey(e3Id)])
        finishStep(performance.now() - lastAt)
        const effectiveSlot =
          normBoundOverride !== undefined ? { ...slot, normBound: normBoundOverride, normBoundFixedPoint: Math.floor(normBoundOverride * 2 ** 32) } : slot

        const submission = await encryptAndProveUpdate(pk, effectiveSlot, update, count, address, (stage) => {
          const now = performance.now()
          finishStep(now - lastAt)
          lastAt = now
          if (stage.stage !== 'done') pushStep(stageLabel(stage))
        })
        setState((s) => ({ ...s, submission }))

        pushStep('wallet: publishInput (5 on-chain Honk verifies)')
        const t = performance.now()
        const res = await publishUpdate(walletClient, publicClient, program, BigInt(e3Id), submission)
        finishStep(performance.now() - t)
        const stored: StoredUpdate = { update, count, index: submission.index, uCommitmentG: submission.uCommitmentG, txHash: res.hash }
        localStorage.setItem(updateKey(e3Id, address), JSON.stringify(stored))
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
