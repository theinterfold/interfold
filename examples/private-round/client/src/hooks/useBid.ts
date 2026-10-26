// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type Address } from 'viem'
import { MAX_BIDS_PER_BIDDER, bidInputsHash, bidTypedData, encodeBidInput } from '@interfold/private-round'
import { type BidStep, BidProver } from '@interfold/private-round/prover'
import { PrivateRoundProgram__factory } from '@contract-types/factories/contracts/PrivateRoundProgram__factory'
import { type StoredVersion, loadVersions, saveVersion } from '@/utils/bid-storage'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { relayBid } from '@/utils/relayer'

export type StepStatus = 'pending' | 'active' | 'done' | 'error'

export interface StepRow {
  id: string
  label: string
  status: StepStatus
}

const stepId = (step: BidStep): string => step.kind

/** The steps of one submission, in the order they run. A relayed bid is signed and posted, a direct one is sent by the wallet. */
function planSteps(relayed: boolean): { id: string; label: string }[] {
  return [
    { id: 'encrypt', label: 'Encrypt your bid and your random mask' },
    { id: 'bid-encryption-proof', label: 'Prove the encryption of the bid' },
    { id: 'mask-encryption-proof', label: 'Prove the encryption of the mask' },
    { id: 'bid-proof', label: 'Prove the bid is valid' },
    ...(relayed
      ? [
          { id: 'sign', label: 'Sign the bid (confirm in your wallet)' },
          { id: 'send', label: 'Send the signed bid to the relayer' },
        ]
      : [{ id: 'send', label: 'Send the bid (confirm in your wallet)' }]),
    { id: 'confirm', label: 'Wait for the transaction to be mined' },
  ]
}

export interface UseBid {
  /** The bids of this account that this browser remembers, ascending by version. */
  versions: StoredVersion[]
  /** The steps of the last submission; empty before the first one. */
  steps: StepRow[]
  submitting: boolean
  /** Wall-clock ms at which the last submission started, and how long it took once it is over. */
  run: { startedAt: number; elapsedMs: number | null } | null
  /** An error that is not tied to one step (wallet missing, balance). */
  error: string | null
  /** Prove and send a bid of `level`; `relayed` signs it and lets the server send it. */
  submit: (level: number, relayed: boolean) => Promise<void>
}

interface Params {
  e3Id: bigint
  /** The number of price steps of the round: a bid is below it. */
  levels: number
  /** The reserve step of the round: the proof binds it. */
  reserveStep: number
  /** The index the deposit gave the account, or `null` before it deposited: the proof binds it. */
  bidderIndex: number | null
  account: Address | undefined
  committeeKey: Uint8Array | null
  /** Re-read the chain after a submission. */
  onSubmitted: () => void
}

/**
 * Drives one bid of the connected account, after its deposit: two ciphertexts (the bid and a random
 * mask) encrypted and proven in the browser, then one transaction that the wallet sends or, with `relayed`, the server. A later
 * call updates the bid: the contract keeps every version and the program counts the newest one that
 * is valid.
 */
export function useBid({ e3Id, levels, reserveStep, bidderIndex, account, committeeKey, onSubmitted }: Params): UseBid {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()

  const [versions, setVersions] = useState<StoredVersion[]>([])
  const [plan, setPlan] = useState<{ id: string; label: string }[]>([])
  const [statuses, setStatuses] = useState<Record<string, StepStatus>>({})
  const [run, setRun] = useState<UseBid['run']>(null)
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

  const keyFor = useCallback((bidder: Address) => ({ chainId: chain.id, program: e3Program, e3Id, account: bidder }), [e3Id, e3Program])

  useEffect(() => {
    setPlan([])
    setStatuses({})
    setRun(null)
    setError(null)
    setVersions(account ? loadVersions(keyFor(account)) : [])
  }, [account, keyFor])

  /** `id` starts; the step that was running is over. */
  const advance = useCallback((id: string) => {
    setStatuses((prev) => ({
      ...Object.fromEntries(Object.entries(prev).map(([key, status]) => [key, status === 'active' ? 'done' : status])),
      [id]: 'active',
    }))
  }, [])

  const submit = useCallback(
    async (level: number, relayed: boolean) => {
      if (!account || !walletClient || !committeeKey || bidderIndex === null || submitting) return
      const startedAt = Date.now()
      setSubmitting(true)
      setError(null)
      setStatuses({})
      setPlan([])
      setRun({ startedAt, elapsedMs: null })
      let prover: BidProver | undefined
      try {
        const read = { address: e3Program, abi: PrivateRoundProgram__factory.abi } as const
        const count = Number(
          await publicClient.readContract({ ...read, functionName: 'bidCount', args: [e3Id, account], blockTag: 'pending' }),
        )
        if (count >= MAX_BIDS_PER_BIDDER) throw new Error(`A bidder can bid at most ${MAX_BIDS_PER_BIDDER} times in a round.`)
        const next = count + 1

        setPlan(planSteps(relayed))

        prover = await BidProver.create()
        const prepared = await prover.prove({
          level,
          levels,
          reserveStep,
          committeeKey,
          bidder: account,
          e3Id,
          bidderIndex,
          version: next,
          onStep: (step) => advance(stepId(step)),
        })
        if (abandoned.current) return
        if (accountRef.current?.toLowerCase() !== account.toLowerCase()) {
          throw new Error('The connected account changed while the proof was running. Reconnect the account that bids and submit again.')
        }
        // The step and the salt are the only way to claim later: keep them before anything is sent.
        saveVersion(keyFor(account), { version: next, level, salt: prepared.salt, bidCommitment: prepared.bidCommitment, txHash: '0x' })
        const bid = {
          bidder: account,
          ciphertexts: prepared.ciphertexts,
          ctCommitments: prepared.ctCommitments,
          bidCommitment: prepared.bidCommitment,
          proof: prepared.proof,
          gateProof: '0x' as const,
        }

        let hash: `0x${string}`
        if (relayed) {
          advance('sign')
          // The signature names the version the bid will get. Read it again: a long proof may have been overtaken.
          const signedVersion =
            Number(await publicClient.readContract({ ...read, functionName: 'bidCount', args: [e3Id, account], blockTag: 'pending' })) + 1
          if (signedVersion !== next) throw new Error('Your bid count changed while the proof was running. Submit again.')
          const typedData = bidTypedData(
            chain.id,
            e3Program,
            e3Id,
            account,
            next,
            bidInputsHash(bid.ctCommitments, bid.bidCommitment, bid.ciphertexts),
          )
          const signature = await walletClient.signTypedData({ account, ...typedData })
          advance('send')
          hash = await relayBid(e3Id, encodeBidInput({ ...bid, signature }))
        } else {
          advance('send')
          const { request } = await publicClient.simulateContract({
            ...read,
            functionName: 'publishInput',
            args: [e3Id, encodeBidInput({ ...bid, signature: '0x' })],
            account,
          })
          hash = await walletClient.writeContract(request)
        }

        advance('confirm')
        const receipt = await publicClient.waitForTransactionReceipt({ hash })
        if (receipt.status !== 'success') throw new Error('The publishInput transaction reverted')
        // The version this bid got is the bid count in the block that mined it.
        const version = Number(
          await publicClient.readContract({ ...read, functionName: 'bidCount', args: [e3Id, account], blockNumber: receipt.blockNumber }),
        )
        saveVersion(keyFor(account), { version, level, salt: prepared.salt, bidCommitment: prepared.bidCommitment, txHash: hash })
        setVersions(loadVersions(keyFor(account)))
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
    [account, walletClient, committeeKey, bidderIndex, submitting, e3Program, e3Id, levels, reserveStep, keyFor, advance, onSubmitted],
  )

  const steps = plan.map(({ id, label }): StepRow => ({ id, label, status: statuses[id] ?? 'pending' }))

  return { versions, steps, submitting, run, error, submit }
}
