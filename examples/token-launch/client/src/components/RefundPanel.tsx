// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { useWalletClient } from 'wagmi'
import type { LoggedBid } from '@/hooks/useBidLog'
import type { HeldSecret } from '@/hooks/useSecrets'
import type { Settlement } from '@/hooks/useSettlement'
import { chain } from '@/utils/chain'
import { formatError } from '@/utils/error-formatting'
import { Phase, isRefundPhase } from '@/utils/phase'
import { sendIndexAction } from '@/utils/program-tx'
import { type SaleState, formatBudget } from '@/utils/sale'
import { TxLink } from './Explorer'
import Spinner from './Spinner'

interface Props {
  sale: SaleState
  account: `0x${string}` | undefined
  bids: readonly LoggedBid[] | null
  held: readonly HeldSecret[]
  settlement: Settlement | null
  onChanged: () => void
}

/**
 * Refunds of the bids that the claim does not cover. A dropped bid (it did not count in both rounds) of a
 * cleared sale and every bid of a stopped sale get their escrow back at the address of the bidder. Anyone
 * may send the transaction; the funds go to the bidder.
 */
const RefundPanel: React.FC<Props> = ({ sale, account, bids, held, settlement, onChanged }) => {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const [busy, setBusy] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [sent, setSent] = useState<{ index: number; hash: `0x${string}` } | null>(null)

  const stopped = isRefundPhase(sale.phase)
  const mask = sale.clearing?.countedMask ?? 0n
  const mine = new Set([
    ...(bids ?? []).filter((bid) => bid.bidder.toLowerCase() === account?.toLowerCase()).map((bid) => bid.index),
    ...held.filter((entry) => entry.confirmed).map((entry) => entry.secret.index),
  ])
  const refundable = (bids ?? []).filter(
    (bid) => mine.has(bid.index) && (stopped || (sale.phase === Phase.Cleared && ((mask >> BigInt(bid.index)) & 1n) === 0n)),
  )
  if (refundable.length === 0) return null

  const send = async (index: number) => {
    if (!walletClient) return
    setBusy(index)
    setError(null)
    try {
      const hash = await sendIndexAction(walletClient, stopped ? 'refundEscrow' : 'refundDropped', sale.saleId, index)
      setSent({ index, hash })
      onChanged()
    } catch (err) {
      setError(formatError(err))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className='space-y-4'>
      <h3 className='h3'>{stopped ? 'Refund your escrow' : 'Dropped bids'}</h3>
      <p className='muted text-sm'>
        {stopped
          ? 'The sale did not clear. Each bid gets its whole escrow back at its bidder address.'
          : 'These bids did not count in both rounds. Each gets its whole escrow back at its bidder address. No proof is needed.'}
      </p>
      <ul className='space-y-2'>
        {refundable.map((bid) => {
          const done = settlement?.refunded.has(bid.index) ?? false
          return (
            <li key={bid.index} className='flex flex-wrap items-center justify-between gap-3 border border-rule-strong bg-card p-3 text-sm'>
              <span>
                Bid Nº {bid.index}: {formatBudget(sale, sale.tiers[bid.tier])}
              </span>
              {done ? (
                <span className='text-accent'>
                  Refunded
                  {sent?.index === bid.index && (
                    <>
                      {' '}
                      · <TxLink hash={sent.hash} />
                    </>
                  )}
                </span>
              ) : (
                <button onClick={() => void send(bid.index)} disabled={busy !== null || !walletClient} className='btn sm'>
                  {busy === bid.index ? <Spinner size={12} /> : 'Refund escrow'}
                </button>
              )}
            </li>
          )
        })}
      </ul>
      {!walletClient && <p className='text-xs'>Connect a wallet to send the transaction.</p>}
      {error && <div className='note bad'>{error}</div>}
    </div>
  )
}

export default RefundPanel
