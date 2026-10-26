// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type Address, parseEventLogs } from 'viem'
import { Outcome, compareBid } from '@interfold/private-round'
import { ClaimProver } from '@interfold/private-round/prover'
import { PrivateRoundProgram__factory } from '@contract-types/factories/contracts/PrivateRoundProgram__factory'
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
 * What the contract does with a claim of this account:
 * - `full`: one lot at the clearing price.
 * - `marginal`: the account bid exactly at the clearing step of a sold-out round. It registers in phase 2 and the contract settles it
 *   after phase 2 with a share of the lots that are left.
 * - `refund`: the whole escrow back, no lot.
 */
export type ClaimClass = 'full' | 'marginal' | 'refund'

/**
 * Why the account fares as it does:
 * - `not-deposited`: it never deposited.
 * - `not-counted`: it deposited, but no bid of it counted. The refund needs no proof.
 * - `failed`: the round was not met or aborted. Everybody is refunded, with no proof.
 * - `bid`: a bid counted, and this browser holds its step and salt, so it can prove how the step compares with the clearing step.
 * - `unknown-bid`: a bid counted, but this browser does not hold its step and salt, so it cannot prove the outcome.
 * - `no-proof`: a bid counted and the contract needs no proof (undersubscribed with the reserve at step 0: every counted bidder gets a lot).
 */
export type Standing = 'not-deposited' | 'not-counted' | 'failed' | 'bid' | 'unknown-bid' | 'no-proof'

export interface MyOutcome {
  standing: Standing
  /** The counted version, 1 to 3; 0 when no bid counted. */
  counted: number
  /** The record of the counted bid in this browser, if it has one. */
  version: StoredVersion | null
  /** Whether the claim needs a proof, and the step `k` it compares the bid with. */
  proofNeeded: boolean
  k: number | null
  /** `0` if the step of the bid is below `k`, `1` if equal, `2` if above. `null` when no proof is needed or the step is unknown. */
  cmp: 0 | 1 | 2 | null
  /** The class that the contract's `previewClaim` names: 0 refund, 1 full lot, 2 marginal registration. `null` when there is nothing to preview. */
  previewClass: 0 | 1 | 2 | null
  /** The amounts of the preview. For a marginal bidder it is what the settlement pays with today's counts. */
  preview: Amounts | null
  /** Registered as a marginal bidder in phase 2. */
  registered: boolean
  claimed: boolean
  /** What the claim paid, once claimed. */
  result: Amounts | null
}

/** The step of a claim in progress. */
export type ClaimStep = 'proving' | 'sending' | 'confirming'

/** What the account can do now, from the clock and the clearing. */
export type ClaimAction =
  | { kind: 'claim'; label: string; note?: string; forfeit?: string }
  | { kind: 'register'; label: string; note?: string }
  | { kind: 'settle'; label: string; note?: string }
  | { kind: 'wait'; until: bigint; text: string }
  | { kind: 'none'; text: string }

export interface UseClaim {
  /** `null` until the first read. */
  outcome: MyOutcome | null
  step: ClaimStep | null
  error: string | null
  /** Claim, or register as a marginal bidder: both are the `claim` call, with a proof when the contract needs one. */
  claim: () => Promise<void>
  /** Settle a registered marginal bidder after phase 2. */
  settle: () => Promise<void>
}

/**
 * What the claim does now and what it pays: the preview of the contract, with the time rules of the
 * phases applied on top of it. A bidder above the clearing step of a sold-out round who comes after
 * phase 1, and a marginal bidder who did not register in phase 2, only get the refund.
 */
export function resolveClaim(
  outcome: MyOutcome,
  clearing: Clearing,
  escrow: bigint,
  now: bigint,
): { cls: ClaimClass | null; amounts: Amounts | null } {
  const { previewClass, preview } = outcome
  if (previewClass === null || preview === null) return { cls: null, amounts: null }
  const refund: Amounts = { tokens: 0n, paid: 0n, refund: escrow }
  if (previewClass === 0) return { cls: 'refund', amounts: preview }
  if (previewClass === 1) {
    return clearing.outcome === Outcome.SoldOut && outcome.cmp === 2 && now > clearing.phase1End
      ? { cls: 'refund', amounts: refund }
      : { cls: 'full', amounts: preview }
  }
  return now > clearing.phase2End && !outcome.registered ? { cls: 'refund', amounts: refund } : { cls: 'marginal', amounts: preview }
}

/** What the connected account can do now. Pure: it reads the outcome of the account, the clearing and the chain time. */
export function actionOf(outcome: MyOutcome, clearing: Clearing, escrow: bigint, now: bigint): ClaimAction {
  if (outcome.standing === 'not-deposited') return { kind: 'none', text: 'This account did not deposit in this round.' }
  if (outcome.claimed) return { kind: 'none', text: 'Claimed.' }
  if (now > clearing.claimDeadline) return { kind: 'none', text: 'The claim window is closed.' }
  if (outcome.standing === 'unknown-bid') {
    return { kind: 'none', text: 'This browser does not hold the step and the salt of your counted bid, so it cannot prove the outcome.' }
  }
  const cls = resolveClaim(outcome, clearing, escrow, now).cls ?? 'refund'
  if (cls === 'full') {
    return clearing.outcome === Outcome.SoldOut
      ? {
          kind: 'claim',
          label: 'Claim now (phase 1)',
          note: 'Your price is above the clearing step. Claim before phase 1 ends: after it you only get the refund.',
        }
      : { kind: 'claim', label: 'Claim your lot' }
  }
  if (cls === 'marginal') {
    if (now <= clearing.phase1End) {
      return {
        kind: 'wait',
        until: clearing.phase1End,
        text: 'Your price is at the clearing step. You register in phase 2, which opens when phase 1 ends.',
      }
    }
    if (now <= clearing.phase2End) {
      return outcome.registered
        ? { kind: 'wait', until: clearing.phase2End, text: 'You are registered. You settle after phase 2 ends.' }
        : {
            kind: 'register',
            label: 'Register as marginal',
            note: 'Your escrow stays locked until you settle. Register before phase 2 ends, or you only get the refund.',
          }
    }
    return {
      kind: 'settle',
      label: 'Settle',
      note: 'Phase 2 is over: the contract pays your share of the lots that are left, and refunds the rest of your escrow.',
    }
  }
  const forfeit =
    clearing.outcome === Outcome.SoldOut && outcome.cmp === 2 && now > clearing.phase1End
      ? 'Phase 1 is over, so you do not get your lot. You only get the refund.'
      : clearing.outcome === Outcome.SoldOut && outcome.cmp === 1 && now > clearing.phase2End
        ? 'Phase 2 is over and you did not register, so you do not get your lot. You only get the refund.'
        : undefined
  return { kind: 'claim', label: 'Claim refund', forfeit }
}

async function readClaimed(e3Id: bigint, bidder: Address): Promise<Amounts | null> {
  const { e3Program } = getContractAddresses()
  const { logs } = await scanLogs((range) =>
    publicClient.getContractEvents({
      address: e3Program,
      abi: PrivateRoundProgram__factory.abi,
      eventName: 'Claimed',
      args: { e3Id, bidder },
      strict: true,
      ...range,
    }),
  )
  const last = logs.at(-1)
  return last ? { tokens: last.args.tokens, paid: last.args.paid, refund: last.args.refund } : null
}

/** The standing of the connected account in a decided round, and the calls that pay it. */
export function useClaim(sale: SaleState, clearing: Clearing | null, account: Address | undefined): UseClaim {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()
  const [outcome, setOutcome] = useState<MyOutcome | null>(null)
  const [step, setStep] = useState<ClaimStep | null>(null)
  const [error, setError] = useState<string | null>(null)
  const e3Id = sale.e3Id
  const escrow = sale.escrow
  const target = useRef({ e3Id, account, clearing, escrow })
  const paidResult = useRef<Amounts | null>(null)

  useEffect(() => {
    target.current = { e3Id, account, clearing, escrow }
  }, [e3Id, account, clearing, escrow])

  const refresh = useCallback(async () => {
    const { e3Id: id, account: bidder, clearing: cleared, escrow: held } = target.current
    if (!bidder || !cleared) return
    const read = { address: e3Program, abi: PrivateRoundProgram__factory.abi } as const
    const [deposited, counted, claimed, registered] = await Promise.all([
      publicClient.readContract({ ...read, functionName: 'deposited', args: [id, bidder] }),
      publicClient.readContract({ ...read, functionName: 'countedVersion', args: [id, bidder] }),
      publicClient.readContract({ ...read, functionName: 'claimed', args: [id, bidder] }),
      publicClient.readContract({ ...read, functionName: 'registered', args: [id, bidder] }),
    ])
    const countedVersion = Number(counted)
    const failedRound = cleared.outcome === Outcome.NotMet || cleared.outcome === Outcome.Aborted
    const requirement =
      deposited && !failedRound && countedVersion > 0
        ? await publicClient.readContract({ ...read, functionName: 'claimRequirement', args: [id, bidder] })
        : null
    const proofNeeded = requirement?.[0] ?? false
    const k = requirement && requirement[0] ? requirement[1] : null
    const version =
      loadVersions({ chainId: chain.id, program: e3Program, e3Id: id, account: bidder }).find(
        (entry) => entry.version === countedVersion,
      ) ?? null
    const cmp: MyOutcome['cmp'] = k === null || version === null ? null : compareBid(version.level, k)

    let standing: Standing
    if (!deposited) standing = 'not-deposited'
    else if (failedRound) standing = 'failed'
    else if (countedVersion === 0) standing = 'not-counted'
    else if (!proofNeeded) standing = 'no-proof'
    else standing = version === null ? 'unknown-bid' : 'bid'

    let previewClass: MyOutcome['previewClass'] = null
    let preview: Amounts | null = null
    if (standing === 'failed' || standing === 'not-counted') {
      // The refund of the whole escrow needs no proof, and so no preview.
      previewClass = 0
      preview = { tokens: 0n, paid: 0n, refund: held }
    } else if (standing === 'bid' || standing === 'no-proof') {
      const [cls, tokens, paid, refund] = await publicClient.readContract({
        ...read,
        functionName: 'previewClaim',
        args: [id, bidder, cmp ?? 2],
      })
      previewClass = cls as 0 | 1 | 2
      preview = { tokens, paid, refund }
    }
    const result = claimed ? (paidResult.current ?? (await readClaimed(id, bidder).catch(() => null))) : null
    if (target.current.e3Id !== id || target.current.account !== bidder) return
    setOutcome({
      standing,
      counted: countedVersion,
      version,
      proofNeeded,
      k,
      cmp,
      previewClass,
      preview,
      registered,
      claimed,
      result,
    })
  }, [e3Program])

  useEffect(() => {
    paidResult.current = null
    setOutcome(null)
    setError(null)
    if (!account || !clearing) return
    const run = () => void refresh().catch((err) => console.warn('Could not read the outcome:', err))
    run()
    const timer = setInterval(run, POLL_MS)
    return () => clearInterval(timer)
    // `clearing` is an object that the clearing hook rebuilds on each poll; its fields are what matter.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [e3Id, account, clearing?.outcome, clearing?.step, clearing?.aboveClaimed, clearing?.marginalRegistered, refresh])

  /** Send one transaction of the account, then keep the amounts that its `Claimed` event holds. */
  const send = useCallback(
    async (functionName: 'claim' | 'settleMarginal', data: `0x${string}`) => {
      if (!account || !walletClient) return
      const read = { address: e3Program, abi: PrivateRoundProgram__factory.abi } as const
      setStep('sending')
      const hash =
        functionName === 'claim'
          ? await walletClient.writeContract(
              (await publicClient.simulateContract({ ...read, functionName, args: [e3Id, account, data], account })).request,
            )
          : await walletClient.writeContract(
              (await publicClient.simulateContract({ ...read, functionName, args: [e3Id, account], account })).request,
            )
      setStep('confirming')
      const receipt = await publicClient.waitForTransactionReceipt({ hash })
      if (receipt.status !== 'success') throw new Error(`The ${functionName} transaction reverted`)
      const paid = parseEventLogs({ abi: PrivateRoundProgram__factory.abi, eventName: 'Claimed', logs: receipt.logs }).find(
        (log) => log.address.toLowerCase() === e3Program.toLowerCase() && log.args.bidder.toLowerCase() === account.toLowerCase(),
      )
      if (paid) paidResult.current = { tokens: paid.args.tokens, paid: paid.args.paid, refund: paid.args.refund }
    },
    [account, walletClient, e3Program, e3Id],
  )

  const run = useCallback(
    async (work: () => Promise<void>) => {
      if (step !== null) return
      setError(null)
      try {
        await work()
      } catch (err) {
        setError(formatError(err))
      } finally {
        setStep(null)
        void refresh().catch((err) => console.warn('Could not read the outcome:', err))
      }
    },
    [step, refresh],
  )

  const claim = useCallback(
    () =>
      run(async () => {
        if (!account || !outcome) return
        let data: `0x${string}` = '0x'
        if (outcome.proofNeeded) {
          if (!outcome.version || outcome.k === null) {
            throw new Error('This browser does not hold the step and the salt of your counted bid, so it cannot prove the outcome.')
          }
          setStep('proving')
          const read = { address: e3Program, abi: PrivateRoundProgram__factory.abi } as const
          const bidCommitment = await publicClient.readContract({
            ...read,
            functionName: 'bidCommitments',
            args: [e3Id, account, outcome.counted],
          })
          const prover = await ClaimProver.create()
          try {
            const proved = await prover.prove({
              b: outcome.version.level,
              salt: outcome.version.salt,
              bidder: account,
              e3Id,
              bidCommitment,
              k: outcome.k,
            })
            data = proved.calldata
          } finally {
            await prover.destroy()
          }
        }
        await send('claim', data)
      }),
    [run, account, outcome, e3Program, e3Id, send],
  )

  const settle = useCallback(() => run(() => send('settleMarginal', '0x')), [run, send])

  return { outcome, step, error, claim, settle }
}
