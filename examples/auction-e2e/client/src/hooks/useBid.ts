// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type Address } from 'viem'
import {
  type AuctionType,
  MAX_BIDS_PER_BIDDER,
  ROLE_LABELS,
  allowlistProof,
  bidInputsHash,
  bidTypedData,
  encodeBidInput,
  rolesFor,
} from '@interfold/auction'
import { type BidStep, BidProver } from '@interfold/auction/prover'
import { AuctionProgram__factory } from '@contract-types/factories/contracts/AuctionProgram__factory'
import { type StoredVersion, loadVersions, saveVersion } from '@/utils/bid-storage'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { relayBid } from '@/utils/relayer'
import { type GateKind } from './useAllowlist'

export type StepStatus = 'pending' | 'active' | 'done' | 'error'

export interface StepRow {
  id: string
  label: string
  status: StepStatus
}

const stepId = (step: BidStep): string => ('role' in step ? `${step.kind}:${step.role}` : step.kind)

/** The steps of one submission, in the order they run. A relayed bid is signed and posted, a direct one is sent by the wallet. */
function planSteps(type: AuctionType, relayed: boolean): { id: string; label: string }[] {
  const roles = rolesFor(type)
  return [
    ...roles.flatMap((role, index) => [
      { id: stepId({ kind: 'encrypt', role }), label: `Encrypt ciphertext ${index + 1} of ${roles.length}: ${ROLE_LABELS[role]}` },
      { id: stepId({ kind: 'encryption-proof', role }), label: `Prove the encryption of ciphertext ${index + 1}` },
    ]),
    { id: 'pair-proof', label: 'Prove the bid in the first two ciphertexts' },
    ...(roles.length === 4 ? [{ id: 'masks-proof', label: 'Prove the masks in the last two ciphertexts' }] : []),
    { id: 'bid-proof', label: 'Combine the proofs into the bid proof' },
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
  /** An error that is not tied to one step (wallet missing, gate proof). */
  error: string | null
  /** Prove and send a bid of `level`; `relayed` signs it and lets the server send it. */
  submit: (level: number, relayed: boolean) => Promise<void>
}

interface Params {
  e3Id: bigint
  auctionType: AuctionType
  /** The number of price steps of the auction: a bid is below it. */
  levels: number
  gateKind: GateKind
  /** The allowlist members, once read. Only used when `gateKind` is `allowlist`. */
  members: Address[] | null
  account: Address | undefined
  committeeKey: Uint8Array | null
  /** Re-read the chain after a submission. */
  onSubmitted: () => void
}

/**
 * Drives one bid of the connected account: one ciphertext for each role of the auction type, each
 * encrypted and proven in the browser, one proof for the whole bid, then one transaction that the
 * wallet sends or, with `relayed`, the server. A later call updates the bid: the contract keeps
 * every version and the auction program computes over the newest one that is valid.
 */
export function useBid({ e3Id, auctionType, levels, gateKind, members, account, committeeKey, onSubmitted }: Params): UseBid {
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
      if (!account || !walletClient || !committeeKey || submitting) return
      const startedAt = Date.now()
      setSubmitting(true)
      setError(null)
      setStatuses({})
      setPlan(planSteps(auctionType, relayed))
      setRun({ startedAt, elapsedMs: null })
      let prover: BidProver | undefined
      try {
        let gateProof: `0x${string}` = '0x'
        if (gateKind === 'allowlist') {
          if (members === null) throw new Error('The allowlist of this auction is not loaded yet.')
          gateProof = allowlistProof(members, account)
        }

        prover = await BidProver.create()
        const prepared = await prover.prove(auctionType, level, levels, committeeKey, account, (step) => advance(stepId(step)))
        if (abandoned.current) return
        if (accountRef.current?.toLowerCase() !== account.toLowerCase()) {
          throw new Error('The connected account changed while the proof was running. Reconnect the account that bids and submit again.')
        }
        const bid = {
          bidder: account,
          ciphertexts: prepared.ciphertexts,
          commitments: prepared.commitments,
          proof: prepared.proof,
          gateProof,
        }
        const read = { address: e3Program, abi: AuctionProgram__factory.abi } as const

        let hash: `0x${string}`
        if (relayed) {
          advance('sign')
          // The signature names the version the bid will get. Read it now: a long proof may have been overtaken.
          const next =
            Number(await publicClient.readContract({ ...read, functionName: 'bidCount', args: [e3Id, account], blockTag: 'pending' })) + 1
          if (next > MAX_BIDS_PER_BIDDER) throw new Error(`A bidder can bid at most ${MAX_BIDS_PER_BIDDER} times in an auction.`)
          const typedData = bidTypedData(chain.id, e3Program, e3Id, account, next, bidInputsHash(bid.commitments, bid.ciphertexts))
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
        saveVersion(keyFor(account), { version, level, txHash: hash })
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
    [
      account,
      walletClient,
      committeeKey,
      submitting,
      e3Program,
      e3Id,
      auctionType,
      levels,
      gateKind,
      members,
      keyFor,
      advance,
      onSubmitted,
    ],
  )

  const steps = plan.map(({ id, label }): StepRow => ({ id, label, status: statuses[id] ?? 'pending' }))

  return { versions, steps, submitting, run, error, submit }
}
