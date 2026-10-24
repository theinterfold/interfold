// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type Address, parseEventLogs } from 'viem'
import { ClaimProver } from '@interfold/sealed-cca/prover'
import { SealedCcaProgram__factory } from '@contract-types/factories/contracts/SealedCcaProgram__factory'
import { type StoredVersion, loadVersions } from '@/utils/bid-storage'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { scanLogs } from '@/utils/logs'
import type { SaleState } from '@/utils/sale'
import type { Clearing } from './useClearing'

const POLL_MS = 5_000

/** What the claim pays or paid: sale-token base units, payment-token base units spent, payment-token base units refunded. */
export interface Amounts {
  tokens: bigint
  paid: bigint
  refund: bigint
}

/**
 * How the account fares in the cleared sale:
 * - `none`: it never deposited.
 * - `dropped`: it deposited but no bid counted; the claim refunds the whole escrow with no proof.
 * - `full` / `marginal` / `loser`: from the clearing and the step of the counted bid.
 * - `unknown`: a bid counted, but this browser does not hold its step and salt, so it cannot prove the outcome.
 */
export type Role = 'none' | 'dropped' | 'full' | 'marginal' | 'loser' | 'unknown'

export interface MyOutcome {
  role: Role
  /** The counted version, 1 to 3; 0 when no bid counted. */
  counted: number
  /** The record of the counted bid in this browser, if it has one. */
  version: StoredVersion | null
  /** `0` if the step of the bid is below `k`, `1` if equal, `2` if above. `null` when no proof is needed or the step is unknown. */
  cmp: 0 | 1 | 2 | null
  /** What a claim pays, as the contract previews it. */
  preview: Amounts | null
  claimed: boolean
  /** What the claim paid, once claimed. */
  result: Amounts | null
}

export type ClaimStep = 'proving' | 'sending' | 'confirming'

export interface UseClaim {
  /** `null` until the first read. */
  outcome: MyOutcome | null
  step: ClaimStep | null
  error: string | null
  claim: () => Promise<void>
}

/** The role of a bidder from the clearing and the comparison of its step with `k`. */
function roleOf(clearing: Clearing, counted: number, cmp: 0 | 1 | 2 | null): Role {
  if (counted === 0) return 'dropped'
  if (clearing.kind === 'undersubscribed') return 'full'
  if (cmp === null) return 'unknown'
  if (clearing.kind === 'uncapped') return cmp >= 1 ? 'full' : 'loser'
  return cmp === 2 ? 'full' : cmp === 1 ? 'marginal' : 'loser'
}

async function readClaimed(e3Id: bigint, bidder: Address): Promise<Amounts | null> {
  const { e3Program } = getContractAddresses()
  const { logs } = await scanLogs((range) =>
    publicClient.getContractEvents({
      address: e3Program,
      abi: SealedCcaProgram__factory.abi,
      eventName: 'Claimed',
      args: { e3Id, bidder },
      strict: true,
      ...range,
    }),
  )
  const last = logs.at(-1)
  return last ? { tokens: last.args.tokens, paid: last.args.paid, refund: last.args.refund } : null
}

/** The outcome of the connected account in a cleared sale, and the claim that pays it. */
export function useClaim(sale: SaleState, clearing: Clearing | null, account: Address | undefined): UseClaim {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()
  const [outcome, setOutcome] = useState<MyOutcome | null>(null)
  const [step, setStep] = useState<ClaimStep | null>(null)
  const [error, setError] = useState<string | null>(null)
  const e3Id = sale.e3Id
  const target = useRef({ e3Id, account, clearing })
  const wonResult = useRef<Amounts | null>(null)

  const refresh = useCallback(async () => {
    const { e3Id: id, account: bidder, clearing: cleared } = target.current
    if (!bidder || !cleared) return
    const read = { address: e3Program, abi: SealedCcaProgram__factory.abi } as const
    const [deposited, counted, claimed] = await Promise.all([
      publicClient.readContract({ ...read, functionName: 'deposited', args: [id, bidder] }),
      publicClient.readContract({ ...read, functionName: 'countedVersion', args: [id, bidder] }),
      publicClient.readContract({ ...read, functionName: 'claimed', args: [id, bidder] }),
    ])
    const version =
      loadVersions({ chainId: chain.id, program: e3Program, e3Id: id, account: bidder }).find((entry) => entry.version === counted) ?? null
    const cmp: MyOutcome['cmp'] =
      counted === 0 || cleared.kind === 'undersubscribed' || version === null
        ? null
        : version.level < cleared.step
          ? 0
          : version.level === cleared.step
            ? 1
            : 2
    const role: Role = !deposited ? 'none' : roleOf(cleared, Number(counted), cmp)
    const preview =
      role === 'none' || role === 'unknown'
        ? null
        : await publicClient
            .readContract({ ...read, functionName: 'previewClaim', args: [id, bidder, cmp ?? 0] })
            .then(([tokens, paid, refund]) => ({ tokens, paid, refund }))
            .catch(() => null)
    const result = claimed ? (wonResult.current ?? (await readClaimed(id, bidder).catch(() => null))) : null
    if (target.current.e3Id !== id || target.current.account !== bidder) return
    setOutcome({ role, counted: Number(counted), version, cmp, preview, claimed, result })
  }, [e3Program])

  useEffect(() => {
    target.current = { e3Id, account, clearing }
    wonResult.current = null
    setOutcome(null)
    setError(null)
    if (!account || !clearing) return
    const run = () => void refresh().catch((err) => console.warn('Could not read the outcome:', err))
    run()
    const timer = setInterval(run, POLL_MS)
    return () => clearInterval(timer)
  }, [e3Id, account, clearing, refresh])

  const claim = useCallback(async () => {
    if (!account || !walletClient || !clearing || !outcome || step !== null) return
    setError(null)
    let prover: ClaimProver | undefined
    try {
      const read = { address: e3Program, abi: SealedCcaProgram__factory.abi } as const
      // The proof opens the commitment of the counted version; no proof is needed when the contract refunds in full anyway.
      let data: `0x${string}` = '0x'
      if (outcome.role !== 'dropped' && clearing.kind !== 'undersubscribed') {
        if (!outcome.version)
          throw new Error('This browser does not hold the step and the salt of your counted bid, so it cannot prove the outcome.')
        setStep('proving')
        const bidCommitment = await publicClient.readContract({
          ...read,
          functionName: 'bidCommitments',
          args: [e3Id, account, outcome.counted],
        })
        prover = await ClaimProver.create()
        const proved = await prover.prove({
          b: outcome.version.level,
          salt: outcome.version.salt,
          bidder: account,
          e3Id,
          bidCommitment,
          k: clearing.step,
        })
        data = proved.calldata
      }
      setStep('sending')
      const { request } = await publicClient.simulateContract({ ...read, functionName: 'claim', args: [e3Id, account, data], account })
      const hash = await walletClient.writeContract(request)
      setStep('confirming')
      const receipt = await publicClient.waitForTransactionReceipt({ hash })
      if (receipt.status !== 'success') throw new Error('The claim transaction reverted')
      const paid = parseEventLogs({ abi: SealedCcaProgram__factory.abi, eventName: 'Claimed', logs: receipt.logs }).find(
        (log) => log.address.toLowerCase() === e3Program.toLowerCase() && log.args.bidder.toLowerCase() === account.toLowerCase(),
      )
      if (paid) wonResult.current = { tokens: paid.args.tokens, paid: paid.args.paid, refund: paid.args.refund }
    } catch (err) {
      setError(formatError(err))
    } finally {
      await prover?.destroy()
      setStep(null)
      void refresh().catch((err) => console.warn('Could not read the outcome:', err))
    }
  }, [account, walletClient, clearing, outcome, step, e3Program, e3Id, refresh])

  return { outcome, step, error, claim }
}
