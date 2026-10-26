// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { type Address, parseEventLogs } from 'viem'
import { ClaimTree, encodeClaimData, nullifier as computeNullifier } from '@interfold/token-launch'
import { ClaimProver } from '@interfold/token-launch/prover'
import { TokenLaunchProgram__factory } from '@contract-types/factories/contracts/TokenLaunchProgram__factory'
import { type BidSecret } from '@/utils/bid-storage'
import { chain, publicClient } from '@/utils/chain'
import { loadClaims, saveClaim } from '@/utils/claim-storage'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { scanLogs } from '@/utils/logs'
import { relayClaim } from '@/utils/relayer'
import type { SaleState } from '@/utils/sale'
import type { LoggedBid } from './useBidLog'
import type { HeldSecret } from './useSecrets'

const POLL_MS = 5_000

/** What a claim pays or paid: sale-token base units, payment-token base units spent, payment-token base units refunded. */
export interface Amounts {
  tokens: bigint
  paid: bigint
  refund: bigint
}

/** `0` if the step of the bid is below `k`, `1` if equal, `2` if above. */
export type Cmp = 0 | 1 | 2

/**
 * How one secret of this browser fares in the cleared sale:
 * - `not-on-chain`: no bid on chain opens it.
 * - `dropped`: the bid did not count; `refundDropped` returns its escrow, no claim.
 * - `ready`: a counted bid that nobody claimed yet. A bid at the clearing step of a capped sale registers
 *   while the marginal window is open (`marginal.register`); after it the claim is refund-only.
 * - `claimed`: the nullifier is used.
 * - `marginal-registered`: the bid registered at the clearing step and waits for `payMarginal`.
 * - `marginal-paid`: `payMarginal` paid the registered bid.
 */
export type ClaimStatus = 'not-on-chain' | 'dropped' | 'ready' | 'claimed' | 'marginal-registered' | 'marginal-paid'

/** The marginal case: a bid at the clearing step of a capped sale. Bids fill in bid order, so the claim is public. */
export interface MarginalState {
  /** The marginal window is open: the claim registers. After it, the claim is refund-only. */
  register: boolean
  /** The most tokens this bid can get, if every earlier marginal bid leaves enough: `floor(budget * saleUnit / pStar)`. */
  maxTokens: bigint
  /** The recipient that the registration named. */
  recipient: Address | null
  /** What `payMarginal` pays now (a live estimate until the window ends), or paid. */
  amounts: Amounts | null
}

export interface ClaimRow {
  secret: BidSecret
  status: ClaimStatus
  /** The comparison of the max price step with the clearing step. Only for a counted bid. */
  cmp: Cmp | null
  /** What the claim pays, as the contract previews it. */
  preview: Amounts | null
  nullifier: `0x${string}` | null
  marginal: MarginalState | null
  /** Once claimed: where the funds went and what they were. */
  result: { recipient: Address; amounts: Amounts; txHash: `0x${string}` | null; recipientKey: `0x${string}` | null } | null
}

export type ClaimStep = 'tree' | 'proving' | 'sending' | 'confirming'

export const CLAIM_STEP_LABELS: Record<ClaimStep, string> = {
  tree: 'Building the claim tree from the bid logs…',
  proving: 'Proving your claim in the browser…',
  sending: 'Sending the claim to the relayer…',
  confirming: 'Waiting for the claim to be mined…',
}

export interface UseClaims {
  /** One row for each secret; empty until the sale is cleared. */
  rows: ClaimRow[]
  step: ClaimStep | null
  /** The index of the bid that is being claimed. */
  busyIndex: number | null
  error: string | null
  /** Prove and send the claim of `secret` to `recipient`. `recipientKey` is stored with the record when the app generated the recipient. */
  claim: (secret: BidSecret, recipient: Address, recipientKey: `0x${string}` | null) => Promise<void>
  /** Read the claims again, for example after `payMarginal`. */
  reload: () => void
}

/** Nullifiers by secret: each one needs a hash in the browser, and the claims are polled. */
const nullifiers = new Map<string, Promise<`0x${string}`>>()

function nullifierOf(secret: BidSecret): Promise<`0x${string}`> {
  const key = `${secret.saleId}:${secret.salt}`
  let value = nullifiers.get(key)
  if (!value) {
    value = computeNullifier({ salt: secret.salt, saleId: secret.saleId })
    nullifiers.set(key, value)
    value.catch(() => nullifiers.delete(key))
  }
  return value
}

const toCmp = (step: number, k: number): Cmp => (step < k ? 0 : step === k ? 1 : 2)

/** The amounts of the `Claimed` event of a nullifier, and the transaction. */
async function readClaimed(saleId: bigint, nullifier: `0x${string}`) {
  const { e3Program } = getContractAddresses()
  const { logs } = await scanLogs((range) =>
    publicClient.getContractEvents({
      address: e3Program,
      abi: TokenLaunchProgram__factory.abi,
      eventName: 'Claimed',
      args: { saleId, nullifier },
      strict: true,
      ...range,
    }),
  )
  const last = logs.at(-1)
  return last
    ? {
        recipient: last.args.recipient,
        amounts: { tokens: last.args.tokens, paid: last.args.paid, refund: last.args.refund },
        txHash: last.transactionHash,
      }
    : null
}

/** The amounts of the `MarginalPaid` event of a bid. */
async function readMarginalPaid(saleId: bigint, index: number): Promise<Amounts | null> {
  const { e3Program } = getContractAddresses()
  const { logs } = await scanLogs((range) =>
    publicClient.getContractEvents({
      address: e3Program,
      abi: TokenLaunchProgram__factory.abi,
      eventName: 'MarginalPaid',
      args: { saleId, index: BigInt(index) },
      strict: true,
      ...range,
    }),
  )
  const last = logs.at(-1)
  return last ? { tokens: last.args.tokens, paid: last.args.paid, refund: last.args.refund } : null
}

/** The claims of the secrets that this browser holds, and the action that sends one through the relayer. */
export function useClaims(sale: SaleState, held: readonly HeldSecret[], bids: readonly LoggedBid[] | null): UseClaims {
  const { e3Program } = getContractAddresses()
  const { saleId, clearing } = sale
  const budgetUnit = sale.budgetUnit
  const saleUnit = 10n ** BigInt(sale.saleToken.decimals)
  const [rows, setRows] = useState<ClaimRow[]>([])
  const [step, setStep] = useState<ClaimStep | null>(null)
  const [busyIndex, setBusyIndex] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const target = useRef({ held, clearing, saleId, budgetUnit, saleUnit })

  const refresh = useCallback(async () => {
    const { held: secrets, clearing: cleared, saleId: id, budgetUnit: unit, saleUnit: tokenUnit } = target.current
    if (!cleared) return setRows([])
    const read = { address: e3Program, abi: TokenLaunchProgram__factory.abi } as const
    const stored = loadClaims(chain.id, e3Program, id)
    const next = await Promise.all(
      secrets.map(async ({ secret, confirmed }): Promise<ClaimRow> => {
        if (!confirmed) return { secret, status: 'not-on-chain', cmp: null, preview: null, nullifier: null, marginal: null, result: null }
        if (((cleared.countedMask >> BigInt(secret.index)) & 1n) === 0n) {
          return { secret, status: 'dropped', cmp: null, preview: null, nullifier: null, marginal: null, result: null }
        }
        const cmp = toCmp(secret.step, cleared.step)
        const nullifier = await nullifierOf(secret)
        const budgetUnits = cmp === 0 ? 0 : secret.budget

        // A bid at the clearing step of a capped sale fills in bid order: its claim registers, then `payMarginal` pays.
        if (cleared.kind === 'capped' && cmp === 1) {
          const [registered, , recipient, paid] = await publicClient.readContract({
            ...read,
            functionName: 'marginalInfo',
            args: [id, BigInt(secret.index)],
          })
          const open = (await publicClient.getBlock()).timestamp <= cleared.marginalDeadline
          const maxTokens = (BigInt(secret.budget) * unit * tokenUnit) / cleared.pStar
          if (registered) {
            const [tokens, spent, refund] = await publicClient.readContract({
              ...read,
              functionName: 'previewMarginal',
              args: [id, BigInt(secret.index)],
            })
            const done = paid ? await readMarginalPaid(id, secret.index).catch(() => null) : null
            const amounts = done ?? { tokens, paid: spent, refund }
            return {
              secret,
              status: paid ? 'marginal-paid' : 'marginal-registered',
              cmp,
              preview: null,
              nullifier,
              marginal: { register: false, maxTokens, recipient, amounts },
              result: null,
            }
          }
          if (open) {
            return {
              secret,
              status: 'ready',
              cmp,
              preview: null,
              nullifier,
              marginal: { register: true, maxTokens, recipient: null, amounts: null },
              result: null,
            }
          }
        }

        const used = await publicClient.readContract({ ...read, functionName: 'nullifierUsed', args: [id, nullifier] })
        const [tokens, paid, refund] = await publicClient.readContract({
          ...read,
          functionName: 'previewClaim',
          args: [id, cmp, budgetUnits, secret.escrow],
        })
        const preview = { tokens, paid, refund }
        if (!used) return { secret, status: 'ready', cmp, preview, nullifier, marginal: null, result: null }
        const record = stored.find((entry) => entry.nullifier === nullifier)
        const event = await readClaimed(id, nullifier).catch(() => null)
        const recipient = event?.recipient ?? record?.recipient
        return {
          secret,
          status: 'claimed',
          cmp,
          preview,
          nullifier,
          marginal: null,
          result: recipient
            ? {
                recipient,
                amounts: event?.amounts ?? { tokens: record?.tokens ?? 0n, paid: record?.paid ?? 0n, refund: record?.refund ?? 0n },
                txHash: event?.txHash ?? record?.txHash ?? null,
                recipientKey: record?.recipientKey ?? null,
              }
            : null,
        }
      }),
    )
    if (target.current.saleId === id) setRows(next)
  }, [e3Program])

  useEffect(() => {
    target.current = { held, clearing, saleId, budgetUnit, saleUnit }
    const run = () => void refresh().catch((err) => console.warn('Could not read the claims:', err))
    run()
    if (!clearing) return
    const timer = setInterval(run, POLL_MS)
    return () => clearInterval(timer)
  }, [held, clearing, saleId, budgetUnit, saleUnit, refresh])

  const claim = useCallback(
    async (secret: BidSecret, recipient: Address, recipientKey: `0x${string}` | null) => {
      if (!clearing || step !== null) return
      setError(null)
      setBusyIndex(secret.index)
      let prover: ClaimProver | undefined
      try {
        setStep('tree')
        if (bids === null || bids.length !== sale.bidCount)
          throw new Error('The bid logs are not complete yet. Wait a moment and try again.')
        const tree = new ClaimTree()
        for (const bid of bids) tree.insert(BigInt(bid.bidCommitment))
        if (tree.root !== clearing.root) throw new Error('The claim tree that this page built does not match the root on chain.')
        const leaf = bids.find((bid) => bid.index === secret.index)
        if (leaf?.bidCommitment.toLowerCase() !== secret.bidCommitment.toLowerCase()) {
          throw new Error('No bid on chain opens this secret.')
        }

        // The contract fixes `reveal_index`: 1 for every claim of a capped sale while the marginal window is open. The
        // proof must use the same value, whatever the class of the bid.
        const revealIndex = clearing.kind === 'capped' && (await publicClient.getBlock()).timestamp <= clearing.marginalDeadline

        setStep('proving')
        prover = await ClaimProver.create()
        const proved = await prover.prove({
          step: secret.step,
          budget: secret.budget,
          escrowUnits: secret.escrow,
          salt: secret.salt,
          bidder: secret.bidder,
          index: secret.index,
          saleId,
          k: clearing.step,
          recipient,
          root: clearing.root,
          countedMask: clearing.countedMask,
          path: tree.path(secret.index).siblings,
          revealIndex,
        })
        const previewRead = { address: e3Program, abi: TokenLaunchProgram__factory.abi } as const
        const [tokens, paid, refund] = await publicClient.readContract({
          ...previewRead,
          functionName: 'previewClaim',
          args: [saleId, proved.cmp, proved.budgetUnits, secret.escrow],
        })
        // Keep the record, with the key of a generated recipient, before anything is sent.
        saveClaim(chain.id, e3Program, { saleId, nullifier: proved.nullifier, recipient, recipientKey, tokens, paid, refund, txHash: null })

        setStep('sending')
        const hash = await relayClaim(
          saleId,
          encodeClaimData({
            proof: proved.proof,
            nullifier: proved.nullifier,
            recipient,
            escrowUnits: secret.escrow,
            budgetUnits: proved.budgetUnits,
            cmp: proved.cmp,
            indexPlusOne: proved.indexPlusOne,
          }),
        )
        saveClaim(chain.id, e3Program, { saleId, nullifier: proved.nullifier, recipient, recipientKey, tokens, paid, refund, txHash: hash })
        setStep('confirming')
        const receipt = await publicClient.waitForTransactionReceipt({ hash })
        if (receipt.status !== 'success') throw new Error('The claim transaction reverted')
        // A registration at the clearing step pays later: it emits `MarginalRegistered`, not `Claimed`.
        const paidEvent = parseEventLogs({ abi: TokenLaunchProgram__factory.abi, eventName: 'Claimed', logs: receipt.logs }).find(
          (log) => log.address.toLowerCase() === e3Program.toLowerCase() && log.args.nullifier === proved.nullifier,
        )
        if (paidEvent) {
          const { tokens: t, paid: p, refund: r } = paidEvent.args
          saveClaim(chain.id, e3Program, {
            saleId,
            nullifier: proved.nullifier,
            recipient,
            recipientKey,
            tokens: t,
            paid: p,
            refund: r,
            txHash: hash,
          })
        }
      } catch (err) {
        setError(formatError(err))
      } finally {
        await prover?.destroy()
        setStep(null)
        setBusyIndex(null)
        void refresh().catch((err) => console.warn('Could not read the claims:', err))
      }
    },
    [clearing, step, bids, sale.bidCount, saleId, e3Program, refresh],
  )

  const reload = useCallback(() => void refresh().catch((err) => console.warn('Could not read the claims:', err)), [refresh])

  return { rows, step, busyIndex, error, claim, reload }
}
