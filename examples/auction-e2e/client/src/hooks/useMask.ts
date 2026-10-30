// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import type { Address } from 'viem'
import { DEGREE } from '@interfold/auction-core'
import { encodeMaskInput } from '@interfold/auction-provider-second-price'
import { createBidProver, type MaskStep, type ProviderProver } from '@interfold/auction-provider-second-price/prover'
import { AuctionProgram__factory } from '@contract-types/factories/contracts/AuctionProgram__factory'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { type StepRow, type StepStatus } from './useBid'

/** The steps of one mask, in the order they run. A mask is always sent by the provider's own wallet. */
const MASK_STEPS: { id: string; label: string }[] = [
  { id: 'encrypt', label: `Draw a random mask of ${DEGREE} nonzero values and encrypt it to the committee key` },
  { id: 'encryption-proof', label: 'Prove the encryption of the mask' },
  { id: 'mask-proof', label: `Prove that every one of the ${DEGREE} values is nonzero` },
  { id: 'send', label: 'Send the mask (confirm in your wallet)' },
  { id: 'confirm', label: 'Wait for the transaction to be mined' },
]

export interface UseMask {
  /** The steps of the last submission; empty before the first one. */
  steps: StepRow[]
  submitting: boolean
  /** Wall-clock ms at which the last submission started, and how long it took once it is over. */
  run: { startedAt: number; elapsedMs: number | null } | null
  error: string | null
  /** Prove and send the mask of the connected account. */
  submit: () => Promise<void>
}

interface Params {
  e3Id: bigint
  account: Address | undefined
  committeeKey: Uint8Array | null
  /** Re-read the chain after a submission. */
  onSubmitted: () => void
}

/**
 * Drives the mask of the connected mask provider: one ciphertext of 128 random nonzero values,
 * encrypted and proven in the browser, then one transaction that the provider's wallet sends. The
 * contract takes one mask from each provider and no relayed mask, because the sender must be the provider.
 */
export function useMask({ e3Id, account, committeeKey, onSubmitted }: Params): UseMask {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()

  const [statuses, setStatuses] = useState<Record<string, StepStatus>>({})
  const [started, setStarted] = useState(false)
  const [run, setRun] = useState<UseMask['run']>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // The wallet may switch accounts while a proof is running; the proof binds the account it was made for.
  const accountRef = useRef(account)
  useEffect(() => {
    accountRef.current = account
  }, [account])
  const abandoned = useRef(false)
  useEffect(() => {
    abandoned.current = false
    return () => {
      abandoned.current = true
    }
  }, [])

  useEffect(() => {
    setStatuses({})
    setStarted(false)
    setRun(null)
    setError(null)
  }, [account, e3Id])

  /** `id` starts; the step that was running is over. */
  const advance = useCallback((id: string) => {
    setStatuses((prev) => ({
      ...Object.fromEntries(Object.entries(prev).map(([key, status]) => [key, status === 'active' ? 'done' : status])),
      [id]: 'active',
    }))
  }, [])

  const submit = useCallback(async () => {
    if (!account || !walletClient || !committeeKey || submitting) return
    const startedAt = Date.now()
    setSubmitting(true)
    setStarted(true)
    setError(null)
    setStatuses({})
    setRun({ startedAt, elapsedMs: null })
    let prover: ProviderProver | undefined
    try {
      prover = await createBidProver()
      const prepared = await prover.proveMask(committeeKey, account, (step: MaskStep) => advance(step.kind))
      if (abandoned.current) return
      if (accountRef.current?.toLowerCase() !== account.toLowerCase()) {
        throw new Error('The connected account changed while the proof was running. Reconnect the provider account and submit again.')
      }
      advance('send')
      const { request } = await publicClient.simulateContract({
        address: e3Program,
        abi: AuctionProgram__factory.abi,
        functionName: 'publishInput',
        args: [
          e3Id,
          encodeMaskInput({ provider: account, ciphertext: prepared.ciphertext, commitment: prepared.commitment, proof: prepared.proof }),
        ],
        account,
      })
      const hash = await walletClient.writeContract(request)
      advance('confirm')
      const receipt = await publicClient.waitForTransactionReceipt({ hash })
      if (receipt.status !== 'success') throw new Error('The publishInput transaction reverted')
      setStatuses((prev) => Object.fromEntries(Object.entries(prev).map(([key, status]) => [key, status === 'active' ? 'done' : status])))
      setRun({ startedAt, elapsedMs: Date.now() - startedAt })
    } catch (err) {
      setStatuses((prev) => {
        const active = Object.keys(prev).find((key) => prev[key] === 'active')
        return active === undefined ? prev : { ...prev, [active]: 'error' }
      })
      setError(formatError(err))
    } finally {
      await prover?.destroy()
      if (!abandoned.current) setSubmitting(false)
      onSubmitted()
    }
  }, [account, walletClient, committeeKey, submitting, e3Program, e3Id, advance, onSubmitted])

  const steps = started ? MASK_STEPS.map(({ id, label }): StepRow => ({ id, label, status: statuses[id] ?? 'pending' })) : []

  return { steps, submitting, run, error, submit }
}
