// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { type AuctionType, type Role, rolesFor } from '@shared/layout'
import { InputProver, type ProveStep, encodeBidInput, newBidSecret } from '@shared/prover'
import { AuctionProgram__factory } from '@contract-types/factories/contracts/AuctionProgram__factory'
import { type StoredBid, type StoredRole, emptyRoles, hasSentRole, loadBid, saveBid, saveBidChecked } from '@/utils/bid-storage'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'

export type RowStatus = 'pending' | ProveStep | 'sending' | 'done' | 'error'

export interface Row {
  status: RowStatus
  txHash?: `0x${string}`
  error?: string
  /** Wall-clock ms at which this ciphertext started, while it is in progress or done in this session. */
  startedAt?: number
  /** How long the ciphertext took, once it is done in this session. */
  elapsedMs?: number
}

/** The `submittedRoles` bitmask when every role of the auction type is in, i.e. the bidder is linked. */
export const allRolesMask = (type: AuctionType): number => rolesFor(type).reduce((mask, role) => mask | (1 << role), 0)

export const hasRole = (mask: number, role: Role) => (mask & (1 << role)) !== 0

/** What became of a `publishInput` transaction that was sent in an earlier session. */
async function settleSent(hash: `0x${string}`): Promise<'success' | 'reverted' | 'dropped'> {
  try {
    await publicClient.getTransaction({ hash })
  } catch {
    // Not in the chain and not in the pool: it was never mined or was replaced.
    try {
      const receipt = await publicClient.getTransactionReceipt({ hash })
      return receipt.status === 'success' ? 'success' : 'reverted'
    } catch {
      return 'dropped'
    }
  }
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  return receipt.status === 'success' ? 'success' : 'reverted'
}

export interface UseBid {
  /** What this browser remembers of the account's bid in this auction. */
  stored: StoredBid | null
  /** One row for each ciphertext of the auction type, in the order of `rolesFor(type)`. */
  rows: Row[]
  submitting: boolean
  /** An error that is not tied to one ciphertext (wallet missing, secret lost). */
  error: string | null
  /** Prove and publish the roles the chain does not have yet, for a bid of `level`. */
  submit: (level: number) => Promise<void>
}

interface Params {
  e3Id: bigint
  auctionType: AuctionType
  account: `0x${string}` | undefined
  committeeKey: Uint8Array | null
  /** The roles of `account` already on chain, as read by the caller. */
  mask: number
  /** Re-read the chain after the submission moved. */
  onSubmitted: () => void
}

/**
 * Drives the bid of the connected account: one ciphertext for each role of the auction type (three,
 * or four for ratio-lane second price), each encrypted and proven in the browser, then published by
 * the wallet. A bid that was interrupted resumes with the secret kept in
 * localStorage, because the roles 0 and 1 of one bid must commit to the same level and salt.
 */
export function useBid({ e3Id, auctionType, account, committeeKey, mask, onSubmitted }: Params): UseBid {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()
  const roles = rolesFor(auctionType)

  const [stored, setStored] = useState<StoredBid | null>(null)
  const [progress, setProgress] = useState<Partial<Record<Role, Row>>>({})
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // The wallet may switch accounts while a proof is running; the proof binds the account it was made for.
  const accountRef = useRef(account)
  accountRef.current = account
  const abandoned = useRef(false)
  useEffect(() => {
    abandoned.current = false
    return () => {
      abandoned.current = true
    }
  }, [])

  const keyFor = useCallback(
    (bidder: `0x${string}`) => ({ chainId: chain.id, program: e3Program, e3Id, account: bidder }),
    [e3Id, e3Program],
  )

  useEffect(() => {
    setProgress({})
    setError(null)
    setStored(account ? loadBid(keyFor(account)) : null)
  }, [account, keyFor])

  const submit = useCallback(
    async (level: number) => {
      if (!account || !walletClient || !committeeKey || submitting) return
      setSubmitting(true)
      setError(null)
      setProgress({})
      let prover: InputProver | undefined
      let current: Role | null = null
      try {
        // Read the roles again, with the pool included: the mask the caller holds may predate a transaction
        // that is sent but not mined yet.
        const onChain = await publicClient.readContract({
          address: e3Program,
          abi: AuctionProgram__factory.abi,
          functionName: 'submittedRoles',
          args: [e3Id, account],
          blockTag: 'pending',
        })
        const key = keyFor(account)
        let bid = loadBid(key)
        if (bid && hasSentRole(bid)) {
          // A ciphertext of this bid was sent: its salt is on chain in a commitment, so keep the secret.
        } else if (onChain === 0) {
          // Nothing was sent, so the bid is free to change.
          bid = { ...newBidSecret(level), roles: emptyRoles(auctionType) }
          saveBidChecked(key, bid)
        } else if (!bid) {
          throw new Error('Part of this bid is on chain, but this browser does not hold its secret, so the rest cannot be linked to it.')
        }
        setStored(bid)

        for (const role of roles) {
          const sent: StoredRole = bid.roles[role] ?? { status: 'pending' }
          let reopened = false
          if (sent.status === 'sent' && sent.txHash !== undefined) {
            // Sent in an earlier session: wait for that transaction instead of sending the role again.
            current = role
            setProgress((prev) => ({ ...prev, [role]: { status: 'sending', txHash: sent.txHash, startedAt: Date.now() } }))
            const outcome = await settleSent(sent.txHash)
            if (abandoned.current) return
            const settled: StoredRole =
              outcome === 'success' ? { status: 'done' as const, txHash: sent.txHash } : { status: 'pending' as const }
            bid = { ...bid, roles: { ...bid.roles, [role]: settled } }
            saveBid(key, bid)
            setStored(bid)
            setProgress((prev) => ({ ...prev, [role]: settled }))
            current = null
            onSubmitted()
            if (outcome === 'success') continue
            // Reverted or never mined: the role is open again, whatever the stale mask says.
            reopened = true
          }
          if (!reopened && hasRole(onChain, role)) continue
          current = role
          prover ??= await InputProver.create()
          const startedAt = Date.now()
          const setRow = (row: Row) => setProgress((prev) => ({ ...prev, [role]: { startedAt, ...row } }))
          setRow({ status: 'encrypt' })
          const prepared = await prover.prove(role, bid, committeeKey, account, (step) => setRow({ status: step }))
          if (abandoned.current) return
          if (accountRef.current?.toLowerCase() !== account.toLowerCase()) {
            throw new Error('The connected account changed while the proof was running. Reconnect the account that bids and submit again.')
          }

          setRow({ status: 'sending' })
          const { request } = await publicClient.simulateContract({
            address: e3Program,
            abi: AuctionProgram__factory.abi,
            functionName: 'publishInput',
            args: [e3Id, encodeBidInput(prepared)],
            account,
          })
          const txHash = await walletClient.writeContract(request)
          // Remember the transaction before waiting for it: a reload now must not start a new bid.
          bid = { ...bid, roles: { ...bid.roles, [role]: { status: 'sent', txHash } } }
          saveBid(key, bid)
          setStored(bid)
          setRow({ status: 'sending', txHash })
          const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash })
          if (receipt.status !== 'success') {
            bid = { ...bid, roles: { ...bid.roles, [role]: { status: 'pending' } } }
            saveBid(key, bid)
            setStored(bid)
            throw new Error('The publishInput transaction reverted')
          }

          bid = { ...bid, roles: { ...bid.roles, [role]: { status: 'done', txHash } } }
          saveBid(key, bid)
          setStored(bid)
          setRow({ status: 'done', txHash, elapsedMs: Date.now() - startedAt })
          onSubmitted()
        }
      } catch (err) {
        if (current === null) setError(formatError(err))
        else {
          const failed = current
          setProgress((prev) => ({ ...prev, [failed]: { ...prev[failed], status: 'error', error: formatError(err) } }))
        }
      } finally {
        await prover?.destroy()
        if (!abandoned.current) setSubmitting(false)
        onSubmitted()
      }
    },
    [account, walletClient, committeeKey, submitting, e3Program, e3Id, auctionType, roles, keyFor, onSubmitted],
  )

  const rows = roles.map(
    (role): Row =>
      progress[role] ??
      (hasRole(mask, role)
        ? { status: 'done', txHash: stored?.roles[role]?.txHash }
        : stored?.roles[role]?.status === 'sent'
          ? { status: 'sending', txHash: stored.roles[role]?.txHash }
          : { status: 'pending' }),
  )

  return { stored, rows, submitting, error, submit }
}
