// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useState } from 'react'
import { CheckCircleIcon, CircleIcon, WarningCircleIcon } from '@phosphor-icons/react'
import { MAX_BIDDERS, MAX_BIDS_PER_BIDDER } from '@interfold/sealed-cca'
import { type StepRow, useBid } from '@/hooks/useBid'
import { type UseDeposit, useDeposit } from '@/hooks/useDeposit'
import type { Wallet } from '@/hooks/useWallet'
import { type SalePhase, type SaleState, formatPayment, formatStepPrice } from '@/utils/sale'
import { ConnectPrompt } from './ConnectPrompt'
import MintButton from './MintButton'
import { TxLink } from './Explorer'
import Spinner from './Spinner'

function formatElapsed(ms: number): string {
  const seconds = Math.floor(ms / 1000)
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`
}

/** Elapsed time since `startedAt`, ticking each second while `running`. */
function useElapsed(startedAt: number | undefined, running: boolean): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!running) return
    setNow(Date.now())
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [running])
  return startedAt === undefined ? 0 : Math.max(now - startedAt, 0)
}

const StepIcon: React.FC<{ status: StepRow['status'] }> = ({ status }) =>
  status === 'done' ? (
    <CheckCircleIcon size={16} weight='fill' className='text-brand-green' />
  ) : status === 'active' ? (
    <Spinner size={14} />
  ) : status === 'error' ? (
    <WarningCircleIcon size={16} weight='fill' className='text-negative' />
  ) : (
    <CircleIcon size={16} />
  )

const DEPOSIT_STEP_LABELS: Record<NonNullable<UseDeposit['step']>, string> = {
  approving: 'Approving the escrow…',
  signing: 'Sign the permit in your wallet…',
  sending: 'Depositing…',
  confirming: 'Waiting for the deposit to be mined…',
}

interface BidPanelProps {
  sale: SaleState
  phase: SalePhase
  wallet: Wallet
  committeeKey: Uint8Array | null
  /** How many bids the connected account has on chain, or `null` before the first read. */
  bidCount: number | null
  onSubmitted: () => void
}

const BidPanel: React.FC<BidPanelProps> = ({ sale, phase, wallet, committeeKey, bidCount, onSubmitted }) => {
  const levels = sale.prices.length
  const deposit = useDeposit({ e3Id: sale.e3Id, paymentToken: sale.paymentToken.address, escrow: sale.escrow, account: wallet.address })
  const deposited = deposit.state?.deposited === true
  const bid = useBid({
    e3Id: sale.e3Id,
    levels,
    bidderIndex: deposit.state?.deposited ? deposit.state.index : null,
    account: wallet.address,
    committeeKey,
    onSubmitted,
  })
  const [level, setLevel] = useState(0)
  const [relayed, setRelayed] = useState(false)
  const elapsed = useElapsed(bid.run?.startedAt, bid.submitting)

  const count = bidCount ?? 0
  const left = MAX_BIDS_PER_BIDDER - count
  // What this browser remembers of the bid that is on chain now.
  const current = bid.versions.find(({ version }) => version === count)
  const open = phase === 'bidding'
  const busyDeposit = deposit.step !== null
  const short = deposit.balance !== null && deposit.balance < sale.escrow

  // Why a deposit is not possible right now, if it is not.
  let depositBlocked: string | null = null
  if (phase === 'awaiting-key')
    depositBlocked = 'Bidding opens once the committee has published its key. Key generation takes several minutes.'
  else if (!open) depositBlocked = 'Bidding is closed.'
  else if (sale.bidderCount >= MAX_BIDDERS) depositBlocked = `This sale is full: ${MAX_BIDDERS} bidders have deposited.`
  else if (short) depositBlocked = `This account holds less than the escrow of ${formatPayment(sale, sale.escrow)}.`

  // Why a bid is not possible right now, if it is not.
  let bidBlocked: string | null = null
  if (!open) bidBlocked = phase === 'awaiting-key' ? 'Bidding opens once the committee has published its key.' : 'Bidding is closed.'
  else if (!deposited) bidBlocked = 'Deposit the escrow first.'
  else if (left <= 0) bidBlocked = `You have used all ${MAX_BIDS_PER_BIDDER} bids of this sale.`
  else if (committeeKey === null) bidBlocked = 'Fetching the committee key…'

  const canDeposit = wallet.ready && depositBlocked === null && !busyDeposit && deposit.state !== null
  const canSubmit = wallet.ready && bidBlocked === null && !bid.submitting && bidCount !== null

  const limitNote = (
    <p className='muted text-xs'>
      This sale takes up to {MAX_BIDDERS} bidders. {sale.bidderCount} of {MAX_BIDDERS} places are taken.
    </p>
  )

  if (!wallet.isConnected) {
    return (
      <div className='space-y-4'>
        <ConnectPrompt>Connect a wallet to bid.</ConnectPrompt>
        <p className='muted text-sm'>
          Every bid locks an escrow of {formatPayment(sale, sale.escrow)}. The sale clears at one price and refunds what the price leaves.
        </p>
        {limitNote}
      </div>
    )
  }

  return (
    <div className='space-y-8'>
      {wallet.wrongChain && <div className='note bad'>Your wallet is on another network. Switch networks to bid.</div>}

      <div className='space-y-3'>
        <p className='label !mb-0'>1. Deposit the escrow</p>
        {deposit.state === null ? (
          <div className='skeleton h-10' />
        ) : deposited ? (
          <div className='note ok'>
            Escrow of {formatPayment(sale, sale.escrow)} locked. Your place is Nº {deposit.state.deposited ? deposit.state.index : ''}.
          </div>
        ) : (
          <>
            <p className='muted text-xs'>
              Every bid locks the same escrow of <strong>{formatPayment(sale, sale.escrow)}</strong>, whatever your price. The sale uses
              what your price needs and refunds the rest. Your balance:{' '}
              {deposit.balance === null ? '…' : formatPayment(sale, deposit.balance)}.
            </p>
            {short && (
              <MintButton
                token={sale.paymentToken}
                account={wallet.address}
                amount={sale.escrow - (deposit.balance ?? 0n)}
                onMinted={deposit.refresh}
              />
            )}
            {depositBlocked && !short && <div className='note'>{depositBlocked}</div>}
            {deposit.error && <div className='note bad'>{deposit.error}</div>}
            <button onClick={() => void deposit.deposit(relayed)} disabled={!canDeposit} className='btn block'>
              {deposit.step ? (
                <>
                  <Spinner size={14} /> {DEPOSIT_STEP_LABELS[deposit.step]}
                </>
              ) : relayed ? (
                'Sign permit and deposit through relayer'
              ) : (
                'Deposit escrow'
              )}
            </button>
            {limitNote}
          </>
        )}
      </div>

      <div className='space-y-4'>
        <p className='label !mb-0'>2. Bid</p>

        {count > 0 && (
          <div className='inset ok p-4'>
            <p className='meta muted'>
              Your bid · version {count} of up to {MAX_BIDS_PER_BIDDER}
            </p>
            {current ? (
              <>
                <p className='value'>
                  {formatStepPrice(sale, current.level)} <span className='text-lg'>{sale.paymentToken.symbol}</span>
                </p>
                <p className='muted mt-1 text-xs'>
                  Highest price you pay for one {sale.saleToken.symbol}. Step {current.level} of {levels - 1}. Kept in this browser; only
                  you can see it.
                </p>
                {current.txHash !== '0x' && (
                  <p className='muted mt-1 text-xs'>
                    Transaction <TxLink hash={current.txHash} />
                  </p>
                )}
              </>
            ) : (
              <p className='muted mt-1 text-xs'>
                This account has bid {count} {count === 1 ? 'time' : 'times'} here, but this browser does not hold the price. Only the
                browser that made the bid can show it, and only it can claim a winning bid.
              </p>
            )}
          </div>
        )}

        {left > 0 && (
          <div className='space-y-3'>
            <p className='muted text-xs'>
              {count === 0 ? 'Pick the highest price you will pay for one token' : 'Pick a new highest price'}
            </p>
            <div className='grid grid-cols-4 gap-2' role='radiogroup' aria-label='Highest price'>
              {Array.from({ length: levels }, (_, l) => (
                <button
                  key={l}
                  type='button'
                  role='radio'
                  aria-checked={level === l}
                  disabled={bid.submitting}
                  onClick={() => setLevel(l)}
                  className={`opt px-2 text-center ${level === l ? 'on' : ''}`}
                >
                  {formatStepPrice(sale, l)}
                </button>
              ))}
            </div>
            <p className='muted text-xs'>
              Prices are in {sale.paymentToken.symbol} for one {sale.saleToken.symbol}. You pay the clearing price, which is never above
              your pick. Your pick never leaves this browser unencrypted: only a ciphertext and a proof are published.
              {count > 0 && ' An update replaces your bid: the latest version that is valid counts.'}
            </p>
          </div>
        )}

        {bidBlocked && <div className='note'>{bidBlocked}</div>}
        {bid.error && <div className='note bad'>{bid.error}</div>}

        {left > 0 && (
          <div className='space-y-3'>
            <label className='flex cursor-pointer items-start gap-3 text-sm'>
              <input
                type='checkbox'
                checked={relayed}
                disabled={bid.submitting || busyDeposit}
                onChange={(event) => setRelayed(event.target.checked)}
                className='mt-1'
              />
              <span>
                <span className='block font-semibold'>Send through relayer</span>
                <span className='muted block text-xs'>
                  You sign in your wallet and the server sends the transaction and pays the gas. For the deposit you sign a permit. For the
                  bid you sign the bid. The relayer cannot change either.
                </span>
              </span>
            </label>
            <button onClick={() => void bid.submit(level, relayed)} disabled={!canSubmit} className='btn accent block'>
              {bid.submitting ? (
                <>
                  <Spinner size={14} /> Proving and submitting…
                </>
              ) : count === 0 ? (
                'Submit bid'
              ) : (
                `Update bid (${left} left)`
              )}
            </button>
            <p className='muted text-xs'>Proving runs in this tab and takes a few minutes. Keep the tab open.</p>
          </div>
        )}

        {bid.steps.length > 0 && (
          <div className='space-y-3'>
            <div className='flex items-center justify-between'>
              <p className='label !mb-0'>Your submission</p>
              <p className='muted font-mono text-xs'>
                {bid.run?.elapsedMs != null ? `done in ${formatElapsed(bid.run.elapsedMs)}` : bid.submitting ? formatElapsed(elapsed) : ''}
              </p>
            </div>
            <ol className='inset space-y-1.5 p-4 text-sm'>
              {bid.steps.map((step) => (
                <li
                  key={step.id}
                  className={`flex items-center gap-2 ${step.status === 'active' ? 'font-semibold' : step.status === 'pending' ? 'text-muted' : 'text-ink'}`}
                >
                  <StepIcon status={step.status} />
                  {step.label}
                </li>
              ))}
            </ol>
          </div>
        )}
      </div>
    </div>
  )
}

export default BidPanel
