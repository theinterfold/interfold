// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useCallback, useEffect, useState } from 'react'
import { useWalletClient } from 'wagmi'
import { TokenLaunchProgram__factory } from '@contract-types/factories/contracts/TokenLaunchProgram__factory'
import { useChainTime } from '@/hooks/useChainTime'
import { useCreateSale } from '@/hooks/useCreateSale'
import type { Settlement } from '@/hooks/useSettlement'
import { chain, publicClient } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { formatError } from '@/utils/error-formatting'
import { Phase, formatDuration, isRefundPhase } from '@/utils/phase'
import { type SaleAction, sendSaleAction } from '@/utils/program-tx'
import { type SaleState, formatDateTime, formatPayment, formatSaleTokens } from '@/utils/sale'
import { TxLink } from './Explorer'
import Spinner from './Spinner'

const POLL_MS = 6_000

const DONE_TEXT: Partial<Record<SaleAction, string>> = {
  withdrawProceeds: 'Proceeds withdrawn.',
  withdrawUnsold: 'Unsold tokens withdrawn.',
  sweep: 'Unclaimed funds swept.',
  refundSupply: 'Supply refunded.',
  withdrawForfeited: 'Forfeited escrows withdrawn.',
}

interface Props {
  sale: SaleState
  account: `0x${string}` | undefined
  settlement: Settlement | null
  /** Re-read the sale and the settlement after a transaction. */
  onChanged: () => void
}

/** What the creator can take out of the sale in its current phase, and the buttons. */
const CreatorPanel: React.FC<Props> = ({ sale, account, settlement, onChanged }) => {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const { e3Program } = getContractAddresses()
  const now = useChainTime()
  const link = useCreateSale(account)
  const [proceeds, setProceeds] = useState<bigint | null>(null)
  const [busy, setBusy] = useState<SaleAction | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [last, setLast] = useState<{ action: SaleAction; hash: `0x${string}` } | null>(null)
  const { phase, clearing } = sale

  const refresh = useCallback(() => {
    publicClient
      .readContract({ address: e3Program, abi: TokenLaunchProgram__factory.abi, functionName: 'proceedsAvailable', args: [sale.saleId] })
      .then(setProceeds)
      .catch((err) => console.warn('Could not read the proceeds:', err))
  }, [e3Program, sale.saleId])

  useEffect(() => {
    if (phase !== Phase.Cleared) return
    refresh()
    const timer = setInterval(refresh, POLL_MS)
    return () => clearInterval(timer)
  }, [phase, refresh])

  const run = async (action: SaleAction) => {
    if (!walletClient) return
    setBusy(action)
    setError(null)
    try {
      setLast({ action, hash: await sendSaleAction(walletClient, action, sale.saleId) })
    } catch (err) {
      setError(formatError(err))
    } finally {
      setBusy(null)
      refresh()
      onChanged()
    }
  }

  const button = (action: SaleAction, label: string, disabled: boolean) => (
    <button onClick={() => void run(action)} disabled={busy !== null || !walletClient || disabled} className='btn sm'>
      {busy === action ? <Spinner size={12} /> : label}
    </button>
  )

  const unsold = clearing ? sale.supply - clearing.sold : 0n

  return (
    <div className='space-y-5'>
      {sale.roundTwoId === null && phase !== Phase.Failed && phase !== Phase.Aborted && (
        <div className='note warn space-y-3'>
          <p>
            Round 2 is not requested. Bids need both rounds. Request it now, before the bidding window starts. The request pays one more
            Interfold fee.
          </p>
          <button
            onClick={() => void link.linkRoundTwo(sale.saleId).then((ok) => ok && onChanged())}
            disabled={link.step !== 'idle'}
            className='btn sm'
          >
            {link.step === 'idle' ? 'Request round 2' : <Spinner size={12} />}
          </button>
          {link.error && <p className='text-xs text-danger'>{link.error}</p>}
        </div>
      )}

      {phase === Phase.Cleared && clearing && (
        <>
          <p className='text-sm text-ink-2'>
            You created this sale. Each claim pays you its payment. Tokens of winners who have not claimed stay in the program until they
            claim.
          </p>
          <div className='grid gap-4 sm:grid-cols-2'>
            <div className='space-y-3 border border-rule-strong bg-card p-4'>
              <p className='mono-sm muted'>Proceeds to withdraw</p>
              <p className='font-serif text-3xl'>{proceeds === null ? '…' : formatPayment(sale, proceeds)}</p>
              {button('withdrawProceeds', 'Withdraw proceeds', proceeds === null || proceeds === 0n)}
            </div>
            <div className='space-y-3 border border-rule-strong bg-card p-4'>
              <p className='mono-sm muted'>Unsold tokens</p>
              <p className='font-serif text-3xl'>{formatSaleTokens(sale, unsold)}</p>
              {button(
                'withdrawUnsold',
                settlement?.unsoldWithdrawn ? 'Withdrawn' : 'Withdraw unsold tokens',
                unsold === 0n || settlement?.unsoldWithdrawn === true,
              )}
            </div>
          </div>
          <div className='space-y-3 border border-rule-strong bg-card p-4'>
            <p className='mono-sm muted'>Unclaimed funds</p>
            {settlement?.swept ? (
              <p className='text-sm'>
                Swept: {formatSaleTokens(sale, settlement.swept.saleTokens)} and {formatPayment(sale, settlement.swept.paymentTokens)} went
                to you.
              </p>
            ) : now > clearing.claimDeadline ? (
              <p className='text-sm'>
                The claim window closed on {formatDateTime(clearing.claimDeadline)}. You can take every remaining token, every unclaimed
                escrow and the unwithdrawn proceeds, once.
              </p>
            ) : (
              <p className='text-sm text-ink-soft'>
                Bidders can claim for another {formatDuration(clearing.claimDeadline - now)} (until {formatDateTime(clearing.claimDeadline)}
                ). After that you can sweep what is left.
              </p>
            )}
            {button('sweep', 'Sweep unclaimed', settlement?.swept != null || now <= clearing.claimDeadline)}
          </div>
        </>
      )}

      {isRefundPhase(phase) && (
        <div className='space-y-3 border border-rule-strong bg-card p-4'>
          <p className='mono-sm muted'>The sale stopped</p>
          <p className='text-sm text-ink-2'>
            Take the supply back. Each bidder takes its own escrow back. If the two rounds counted different bids, you also take the escrows
            of those bids.
          </p>
          <div className='flex flex-wrap gap-3'>
            {button(
              'refundSupply',
              settlement?.supplyRefunded ? 'Supply refunded' : 'Refund the supply',
              settlement?.supplyRefunded === true,
            )}
            {phase === Phase.Aborted &&
              button(
                'withdrawForfeited',
                settlement?.forfeitedWithdrawn ? 'Forfeited withdrawn' : 'Withdraw forfeited escrows',
                settlement?.forfeitedWithdrawn === true,
              )}
          </div>
        </div>
      )}

      {error && <div className='note bad'>{error}</div>}
      {last && (
        <div className='note ok'>
          {DONE_TEXT[last.action]} Transaction <TxLink hash={last.hash} />
        </div>
      )}
    </div>
  )
}

export default CreatorPanel
