// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The bidder pipeline as a hook: balance proof → WASM encrypt → 3 proofs (with per-stage timings)
// → wallet tx. Every stage's wall time is kept so the page can show it (and the e2e can read it).

import { useCallback, useState } from 'react'
import type { Address, Hex } from 'viem'
import { encryptAndProveBid, publishBid } from '@ckks-auction/sdk'
import type { BidSubmission, ProvingStage } from '@ckks-auction/sdk'

import { api, ensureCircuits } from '../api'
import { useWallet } from '../wallet'

export interface StepLog {
  label: string
  ms?: number
  status: 'running' | 'done' | 'failed'
}

export interface BidState {
  steps: StepLog[]
  running: boolean
  error: string | null
  submission: BidSubmission | null
  txHash: Hex | null
  gasUsed: bigint | null
}

const stageLabel = (s: ProvingStage): string => {
  switch (s.stage) {
    case 'encrypt':
      return 'CKKS encrypt + witness (WASM)'
    case 'backend':
      return 'Barretenberg init (SRS 2^20)'
    case 'execute':
      return `witness ${s.leg}`
    case 'prove':
      return `prove ${s.leg} (UltraHonk)`
    case 'done':
      return 'proving done'
  }
}

export const useBid = (e3Id: string, program: Address) => {
  const { walletClient, publicClient, address } = useWallet()
  const [state, setState] = useState<BidState>({ steps: [], running: false, error: null, submission: null, txHash: null, gasUsed: null })

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

  const submit = useCallback(
    async (bid: number) => {
      if (!walletClient || !address) throw new Error('connect a wallet first')
      setState({ steps: [], running: true, error: null, submission: null, txHash: null, gasUsed: null })
      let lastAt = performance.now()
      try {
        pushStep('load circuits + balance proof')
        const [, proof, pk] = await Promise.all([ensureCircuits(), api.balanceProof(e3Id, address), api.publicKey(e3Id)])
        finishStep(performance.now() - lastAt)

        const submission = await encryptAndProveBid(pk, bid, proof, address, (stage) => {
          const now = performance.now()
          finishStep(now - lastAt)
          lastAt = now
          if (stage.stage !== 'done') pushStep(stageLabel(stage))
        })
        setState((s) => ({ ...s, submission }))

        pushStep('wallet: publishInput (3 on-chain Honk verifies)')
        const t = performance.now()
        const res = await publishBid(walletClient, publicClient, program, BigInt(e3Id), submission)
        finishStep(performance.now() - t)
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
