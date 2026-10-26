// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type Address } from 'viem'
import { type Role, encodeOfferInput, negotiationProgramAbi, offerInputsHash, offerTypedData } from '@interfold/negotiation'
import { type OfferStep, OfferProver } from '@interfold/negotiation/prover'
import { type StoredOffer, loadOffer, saveOffer } from '@/utils/offer-storage'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { relayOffer } from '@/utils/relayer'

export type StepStatus = 'pending' | 'active' | 'done' | 'error'

export interface StepRow {
  id: string
  label: string
  status: StepStatus
}

const CIPHERTEXT_LABELS = ['the price lanes 0 to 7', 'the price lanes 8 to 15', 'the random mask'] as const

const stepId = (step: OfferStep): string => ('index' in step ? `${step.kind}-${step.index}` : step.kind)

/** The steps of one submission, in the order they run. A relayed offer is signed and posted, a direct one is sent by the wallet. */
function planSteps(relayed: boolean): { id: string; label: string }[] {
  return [
    ...CIPHERTEXT_LABELS.flatMap((what, index) => [
      { id: `encrypt-${index}`, label: `Encrypt ${what}` },
      { id: `encryption-proof-${index}`, label: `Prove encryption ${index + 1} of ${CIPHERTEXT_LABELS.length}` },
    ]),
    { id: 'lanes-proof', label: 'Prove the two lane ciphertexts hold a price on the grid' },
    { id: 'offer-proof', label: 'Prove the whole offer is valid (final proof)' },
    ...(relayed
      ? [
          { id: 'sign', label: 'Sign the offer (confirm in your wallet)' },
          { id: 'send', label: 'Send the signed offer to the relayer' },
        ]
      : [{ id: 'send', label: 'Send the offer (confirm in your wallet)' }]),
    { id: 'confirm', label: 'Wait for the transaction to be mined' },
  ]
}

export interface UseOffer {
  /** The offer of this account that this browser remembers. */
  stored: StoredOffer | null
  /** The steps of the last submission; empty before the first one. */
  steps: StepRow[]
  submitting: boolean
  /** Wall-clock ms at which the last submission started, and how long it took once it is over. */
  run: { startedAt: number; elapsedMs: number | null } | null
  /** An error that is not tied to one step (wallet missing, rejected request). */
  error: string | null
  /** Prove and send an offer of the price step `step`; `relayed` signs it and lets the server send it. */
  submit: (step: number, relayed: boolean) => Promise<void>
}

interface Params {
  e3Id: bigint
  /** The levels of the price grid: a price step is below it. */
  levels: number
  /** The role of the connected account, or `null` if it is not a party. */
  role: Role | null
  account: Address | undefined
  committeeKey: Uint8Array | null
  /** Re-read the chain after a submission. */
  onSubmitted: () => void
}

/**
 * Drives the offer of the connected account: three ciphertexts encrypted and proven in the browser,
 * then one transaction that the wallet sends or, with `relayed`, the server.
 */
export function useOffer({ e3Id, levels, role, account, committeeKey, onSubmitted }: Params): UseOffer {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()

  const [stored, setStored] = useState<StoredOffer | null>(null)
  const [plan, setPlan] = useState<{ id: string; label: string }[]>([])
  const [statuses, setStatuses] = useState<Record<string, StepStatus>>({})
  const [run, setRun] = useState<UseOffer['run']>(null)
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

  const keyFor = useCallback((party: Address) => ({ chainId: chain.id, program: e3Program, e3Id, account: party }), [e3Id, e3Program])

  useEffect(() => {
    setPlan([])
    setStatuses({})
    setRun(null)
    setError(null)
    setStored(account ? loadOffer(keyFor(account)) : null)
  }, [account, keyFor])

  /** `id` starts; the step that was running is over. */
  const advance = useCallback((id: string) => {
    setStatuses((prev) => ({
      ...Object.fromEntries(Object.entries(prev).map(([key, status]) => [key, status === 'active' ? 'done' : status])),
      [id]: 'active',
    }))
  }, [])

  const submit = useCallback(
    async (step: number, relayed: boolean) => {
      if (!account || !walletClient || !committeeKey || role === null || submitting) return
      const startedAt = Date.now()
      setSubmitting(true)
      setError(null)
      setStatuses({})
      setPlan([])
      setRun({ startedAt, elapsedMs: null })
      let prover: OfferProver | undefined
      try {
        setPlan(planSteps(relayed))

        prover = await OfferProver.create()
        const prepared = await prover.prove({
          role,
          step,
          party: account,
          levels,
          committeeKey,
          onStep: (progress) => advance(stepId(progress)),
        })
        if (abandoned.current) return
        if (accountRef.current?.toLowerCase() !== account.toLowerCase()) {
          throw new Error('The connected account changed while the proof was running. Reconnect the account that offers and submit again.')
        }
        // The price is only readable here later: keep it before anything is sent.
        saveOffer(keyFor(account), { step, txHash: '0x' })
        const offer = { party: account, ciphertexts: prepared.ciphertexts, commitments: prepared.commitments, proof: prepared.proof }

        let hash: `0x${string}`
        if (relayed) {
          advance('sign')
          const typedData = offerTypedData(chain.id, e3Program, e3Id, account, offerInputsHash(offer.commitments, offer.ciphertexts))
          const signature = await walletClient.signTypedData({ account, ...typedData })
          advance('send')
          hash = await relayOffer(e3Id, encodeOfferInput({ ...offer, signature }))
        } else {
          advance('send')
          const { request } = await publicClient.simulateContract({
            address: e3Program,
            abi: negotiationProgramAbi,
            functionName: 'publishInput',
            args: [e3Id, encodeOfferInput({ ...offer, signature: '0x' })],
            account,
          })
          hash = await walletClient.writeContract(request)
        }

        advance('confirm')
        const receipt = await publicClient.waitForTransactionReceipt({ hash })
        if (receipt.status !== 'success') throw new Error('The publishInput transaction reverted')
        saveOffer(keyFor(account), { step, txHash: hash })
        setStored(loadOffer(keyFor(account)))
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
    },
    [account, walletClient, committeeKey, role, submitting, e3Program, e3Id, levels, keyFor, advance, onSubmitted],
  )

  const steps = plan.map(({ id, label }): StepRow => ({ id, label, status: statuses[id] ?? 'pending' }))

  return { stored, steps, submitting, run, error, submit }
}
