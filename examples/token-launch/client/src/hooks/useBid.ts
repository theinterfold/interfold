// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type Address, parseSignature } from 'viem'
import { bidInputsHash, bidTypedData, encodeBidInput } from '@interfold/token-launch'
import { type BidStep, BidProver } from '@interfold/token-launch/prover'
import { TokenLaunchProgram__factory } from '@contract-types/factories/contracts/TokenLaunchProgram__factory'
import { saveSecret } from '@/utils/bid-storage'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { relayBid } from '@/utils/relayer'
import type { SaleState } from '@/utils/sale'
import { allowanceOf, approveToken, balanceOf, erc20Abi } from '@/utils/tokens'

/** Seconds a permit signature stays valid, counted from the latest block. */
const PERMIT_VALID_SECONDS = 3600n

export type StepStatus = 'pending' | 'active' | 'done' | 'error'

export interface StepRow {
  id: string
  label: string
  status: StepStatus
}

/** What the bidder picks. `tier` indexes `sale.tiers`; `budget` is in budget units, 1 to the tier amount; `step` is the max price step. */
export interface BidChoice {
  tier: number
  budget: number
  step: number
}

/** The steps of one submission, in the order they run. A relayed bid is signed and posted, a direct one is sent by the wallet. */
function planSteps(relayed: boolean, approving: boolean): { id: string; label: string }[] {
  return [
    ...(approving ? [{ id: 'approve', label: 'Approve the escrow (confirm in your wallet)' }] : []),
    { id: 'encrypt', label: 'Encrypt your bid for both rounds' },
    { id: 'encryption-proof-1', label: 'Prove the round 1 encryption' },
    { id: 'encryption-proof-2', label: 'Prove the round 2 encryption' },
    { id: 'bid-proof', label: 'Prove that the bid is valid' },
    ...(relayed
      ? [
          { id: 'sign', label: 'Sign the permit and the bid (confirm in your wallet)' },
          { id: 'send', label: 'Send the signed bid to the relayer' },
        ]
      : [{ id: 'send', label: 'Send the bid (confirm in your wallet)' }]),
    { id: 'confirm', label: 'Wait for the transaction to be mined' },
  ]
}

const stepId = (step: BidStep): string => (step.kind === 'encryption-proof' ? `encryption-proof-${step.round}` : step.kind)

export interface UseBid {
  /** The steps of the last submission; empty before the first one. */
  steps: StepRow[]
  submitting: boolean
  /** Wall-clock ms at which the last submission started, and how long it took once it is over. */
  run: { startedAt: number; elapsedMs: number | null } | null
  /** The error of the last submission. */
  error: string | null
  /** The transaction of the last bid that was mined. */
  txHash: `0x${string}` | null
  /** Prove and send a bid; `relayed` signs it and lets the server send it. */
  submit: (choice: BidChoice, relayed: boolean) => Promise<void>
}

interface Params {
  sale: SaleState
  account: Address | undefined
  /** The committee keys of round 1 and round 2. */
  keys: { round1: Uint8Array | null; round2: Uint8Array | null }
  /** Re-read the chain and the storage after a submission. */
  onSubmitted: () => void
}

/**
 * Drives the bid of the connected account: one encryption for each round and one proof in the
 * browser, then one transaction that the wallet sends or, with `relayed`, the server. The secret of the
 * bid is stored before anything is sent: it is the only way to claim.
 */
export function useBid({ sale, account, keys, onSubmitted }: Params): UseBid {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()
  const { saleId } = sale

  const [plan, setPlan] = useState<{ id: string; label: string }[]>([])
  const [statuses, setStatuses] = useState<Record<string, StepStatus>>({})
  const [run, setRun] = useState<UseBid['run']>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [txHash, setTxHash] = useState<`0x${string}` | null>(null)

  // The wallet may switch accounts while a proof runs; the proof binds the account it was made for.
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
    setPlan([])
    setStatuses({})
    setRun(null)
    setError(null)
    setTxHash(null)
  }, [account, saleId])

  /** `id` starts; the step that was running is over. */
  const advance = useCallback((id: string) => {
    setStatuses((prev) => ({
      ...Object.fromEntries(Object.entries(prev).map(([key, status]) => [key, status === 'active' ? 'done' : status])),
      [id]: 'active',
    }))
  }, [])

  const submit = useCallback(
    async ({ tier, budget, step }: BidChoice, relayed: boolean) => {
      if (!account || !walletClient || !keys.round1 || !keys.round2 || submitting) return
      const startedAt = Date.now()
      setSubmitting(true)
      setError(null)
      setTxHash(null)
      setStatuses({})
      setPlan([])
      setRun({ startedAt, elapsedMs: null })
      let prover: BidProver | undefined
      try {
        const read = { address: e3Program, abi: TokenLaunchProgram__factory.abi } as const
        const escrowUnits = sale.tiers[tier]
        const escrow = BigInt(escrowUnits) * sale.budgetUnit
        if (!Number.isInteger(budget) || budget < 1 || budget > escrowUnits)
          throw new Error(`The budget is 1 to ${escrowUnits} budget units.`)
        if (step < 0 || step >= sale.levels) throw new Error('The max price step is outside the price grid.')
        if ((await balanceOf(sale.paymentToken.address, account)) < escrow) {
          throw new Error(`This account holds less than the escrow of ${escrowUnits} budget units. Get payment tokens first.`)
        }

        // A direct bid needs an allowance: ask for it first, so that a slow proof cannot outlive a prompt.
        const approving = !relayed && (await allowanceOf(sale.paymentToken.address, account, e3Program)) < escrow
        setPlan(planSteps(relayed, approving))
        if (approving) {
          advance('approve')
          await approveToken(walletClient, sale.paymentToken.address, account, e3Program, escrow)
        }

        // The proof binds the index of the bid: the number of bids before it.
        const index = Number(await publicClient.readContract({ ...read, functionName: 'bidCount', args: [saleId], blockTag: 'pending' }))
        prover = await BidProver.create()
        const prepared = await prover.prove({
          committeeKey1: keys.round1,
          committeeKey2: keys.round2,
          step,
          budget,
          escrowUnits,
          bidder: account,
          saleId,
          index,
          levels: sale.levels,
          onProgress: (progress) => advance(stepId(progress)),
        })
        if (abandoned.current) return
        if (accountRef.current?.toLowerCase() !== account.toLowerCase()) {
          throw new Error('The connected account changed while the proof was running. Reconnect the account that bids and submit again.')
        }
        // Keep the secret before anything is sent. It is the only way to claim.
        const secret = {
          saleId,
          bidder: account,
          step,
          budget,
          escrow: escrowUnits,
          tier,
          index,
          salt: prepared.salt,
          bidCommitment: prepared.bidCommitment,
          txHash: null,
        }
        const storeKey = { chainId: chain.id, program: e3Program, saleId }
        saveSecret(storeKey, secret)

        const bid = {
          bidder: account,
          tier,
          ciphertext1: prepared.ciphertext1,
          ciphertext2: prepared.ciphertext2,
          ctCommitment1: prepared.ctCommitment1,
          ctCommitment2: prepared.ctCommitment2,
          bidCommitment: prepared.bidCommitment,
          proof: prepared.proof,
        }
        const countNow = Number(await publicClient.readContract({ ...read, functionName: 'bidCount', args: [saleId], blockTag: 'pending' }))
        if (countNow !== index) throw new Error('Another bid took your place while the proof ran. Submit again.')

        let hash: `0x${string}`
        if (relayed) {
          advance('sign')
          const token = { address: sale.paymentToken.address, abi: erc20Abi } as const
          const [name, nonce, block] = await Promise.all([
            publicClient.readContract({ ...token, functionName: 'name' }),
            publicClient.readContract({ ...token, functionName: 'nonces', args: [account] }),
            publicClient.getBlock(),
          ])
          const deadline = block.timestamp + PERMIT_VALID_SECONDS
          const permitSignature = await walletClient.signTypedData({
            account,
            domain: { name, version: '1', chainId: chain.id, verifyingContract: sale.paymentToken.address },
            types: {
              Permit: [
                { name: 'owner', type: 'address' },
                { name: 'spender', type: 'address' },
                { name: 'value', type: 'uint256' },
                { name: 'nonce', type: 'uint256' },
                { name: 'deadline', type: 'uint256' },
              ],
            },
            primaryType: 'Permit',
            message: { owner: account, spender: e3Program, value: escrow, nonce, deadline },
          })
          const { r, s, v, yParity } = parseSignature(permitSignature)
          const typedData = bidTypedData(
            chain.id,
            e3Program,
            saleId,
            account,
            tier,
            bidInputsHash(bid.ctCommitment1, bid.ctCommitment2, bid.bidCommitment, bid.ciphertext1, bid.ciphertext2),
          )
          const signature = await walletClient.signTypedData({ account, ...typedData })
          advance('send')
          hash = await relayBid(
            saleId,
            encodeBidInput({ ...bid, signature, permit: { deadline, v: Number(v ?? BigInt(27 + (yParity ?? 0))), r, s } }),
          )
        } else {
          advance('send')
          const { request } = await publicClient.simulateContract({
            ...read,
            functionName: 'publishInput',
            args: [saleId, encodeBidInput(bid)],
            account,
          })
          hash = await walletClient.writeContract(request)
        }

        saveSecret(storeKey, { ...secret, txHash: hash })
        advance('confirm')
        const receipt = await publicClient.waitForTransactionReceipt({ hash })
        if (receipt.status !== 'success') throw new Error('The publishInput transaction reverted')
        setTxHash(hash)
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
    [account, walletClient, keys, submitting, e3Program, saleId, sale, advance, onSubmitted],
  )

  const steps = plan.map(({ id, label }): StepRow => ({ id, label, status: statuses[id] ?? 'pending' }))

  return { steps, submitting, run, error, txHash, submit }
}
