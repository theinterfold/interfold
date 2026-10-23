// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useState } from 'react'
import { CheckCircleIcon, CircleIcon, WarningCircleIcon } from '@phosphor-icons/react'
import { LEVELS, MAX_BIDDERS_BY_TYPE, ROLE_LABELS, type Role, rolesFor } from '@shared/layout'
import { allRolesMask, type Row, type RowStatus, useBid } from '@/hooks/useBid'
import type { Wallet } from '@/hooks/useWallet'
import { type AuctionPhase, type AuctionState, formatPrice } from '@/utils/auction'
import { ConnectPrompt } from './ConnectPrompt'
import { TxLink } from './Explorer'
import Spinner from './Spinner'

/** The stages of one ciphertext, in the order the browser and the wallet go through them. */
const STAGES = [
  ['encrypt', 'Encrypt the bid'],
  ['encryption-proof', 'Prove the encryption'],
  ['bid-proof', 'Prove the bid is valid'],
  ['fold-proof', 'Fold the proofs into one'],
  ['sending', 'Publish on chain (confirm in your wallet)'],
] as const satisfies readonly (readonly [RowStatus, string])[]

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

const CiphertextProgress: React.FC<{ index: number; total: number; role: Role; row: Row }> = ({ index, total, role, row }) => {
  const running = row.status !== 'pending' && row.status !== 'done' && row.status !== 'error'
  const elapsed = useElapsed(row.startedAt, running)
  const stageIndex = STAGES.findIndex(([status]) => status === row.status)

  return (
    <li className='border border-rule-strong bg-card p-4'>
      <div className='flex flex-wrap items-center justify-between gap-2'>
        <p className='text-sm font-semibold'>
          <span className='mono muted mr-2'>
            {index + 1}/{total}
          </span>
          {ROLE_LABELS[role]}
        </p>
        {row.status === 'done' ? (
          <span className='tag live'>
            <CheckCircleIcon size={12} weight='fill' /> submitted{row.elapsedMs !== undefined && ` in ${formatElapsed(row.elapsedMs)}`}
          </span>
        ) : row.status === 'error' ? (
          <span className='tag bad'>
            <WarningCircleIcon size={12} weight='fill' /> failed
          </span>
        ) : running ? (
          <span className='tag wait font-mono'>{formatElapsed(elapsed)}</span>
        ) : (
          <span className='tag muted'>waiting</span>
        )}
      </div>

      {running && (
        <ol className='mt-3 space-y-1.5 text-sm'>
          {STAGES.map(([status, label], position) => {
            const done = position < stageIndex
            const active = position === stageIndex
            return (
              <li key={status} className={`flex items-center gap-2 ${active ? 'font-semibold' : done ? 'text-ink-2' : 'text-ink-soft'}`}>
                {done ? (
                  <CheckCircleIcon size={16} weight='fill' className='text-accent' />
                ) : active ? (
                  <Spinner size={14} />
                ) : (
                  <CircleIcon size={16} />
                )}
                {label}
              </li>
            )
          })}
        </ol>
      )}
      {row.status === 'sending' && row.txHash && (
        <p className='muted mt-2 text-xs'>
          Transaction <TxLink hash={row.txHash} />
        </p>
      )}
      {row.status === 'done' && row.txHash && (
        <p className='muted mt-2 text-xs'>
          Transaction <TxLink hash={row.txHash} />
        </p>
      )}
      {row.error && <p className='note bad mt-3'>{row.error}</p>}
    </li>
  )
}

interface BidPanelProps {
  auction: AuctionState
  phase: AuctionPhase
  wallet: Wallet
  committeeKey: Uint8Array | null
  /** The roles the connected account has on chain, or `null` before the first read. */
  mask: number | null
  onSubmitted: () => void
}

const BidPanel: React.FC<BidPanelProps> = ({ auction, phase, wallet, committeeKey, mask, onSubmitted }) => {
  const bid = useBid({
    e3Id: auction.e3Id,
    auctionType: auction.auctionType,
    account: wallet.address,
    committeeKey,
    mask: mask ?? 0,
    onSubmitted,
  })
  const [level, setLevel] = useState(0)

  const roles = rolesFor(auction.auctionType)
  const maxBidders = MAX_BIDDERS_BY_TYPE[auction.auctionType]
  const submittedAny = (mask ?? 0) !== 0
  const linked = mask === allRolesMask(auction.auctionType)
  const chosen = bid.stored && submittedAny ? bid.stored.bid : level
  // Only complete bids take a place: the contract rejects every ciphertext once the places are full.
  const full = auction.linkedBidders >= maxBidders && !linked
  const secretLost = submittedAny && !bid.stored

  // Why bidding is not possible right now, if it is not.
  let blocked: string | null = null
  if (phase === 'awaiting-key') blocked = 'Bidding opens once the committee has published its key. Key generation takes several minutes.'
  else if (phase !== 'bidding') blocked = 'Bidding is closed.'
  else if (linked) blocked = `Your bid is in: all ${roles.length} ciphertexts are on chain.`
  else if (full) blocked = `This auction is full: ${maxBidders} bidders have completed their bids.`
  else if (secretLost)
    blocked = 'Part of a bid from this account is on chain, but this browser does not hold its secret, so the bid cannot be completed here.'
  else if (committeeKey === null) blocked = 'Fetching the committee key…'

  const pending = bid.rows.filter((row) => row.status !== 'done').length
  const canSubmit = wallet.ready && blocked === null && !bid.submitting && mask !== null && pending > 0
  const showProgress = bid.submitting || submittedAny || bid.rows.some((row) => row.status === 'error' || row.status === 'sending')

  if (!wallet.isConnected) {
    return (
      <div className='space-y-4'>
        <ConnectPrompt>Connect a wallet to bid.</ConnectPrompt>
        {blocked && <p className='muted text-sm'>{blocked}</p>}
      </div>
    )
  }

  return (
    <div className='space-y-6'>
      {wallet.wrongChain && <div className='note bad'>Your wallet is on another network. Switch networks to bid.</div>}

      {bid.stored && submittedAny ? (
        <div className='border border-accent bg-accent-soft p-4'>
          <p className='mono-sm muted'>Your bid</p>
          <p className='font-serif text-4xl'>{formatPrice(bid.stored.bid, auction.prices)}</p>
          <p className='muted mt-1 text-xs'>
            Level {bid.stored.bid} of {LEVELS - 1}. Kept in this browser; only you can see it.
          </p>
        </div>
      ) : (
        <div className='space-y-3'>
          <p className='label !mb-0'>Pick your bid</p>
          <div className='grid grid-cols-4 gap-2' role='radiogroup' aria-label='Bid level'>
            {Array.from({ length: LEVELS }, (_, l) => (
              <button
                key={l}
                type='button'
                role='radio'
                aria-checked={level === l}
                disabled={bid.submitting}
                onClick={() => setLevel(l)}
                className={`border px-2 py-2.5 text-center font-mono text-sm transition-colors disabled:cursor-not-allowed ${
                  level === l ? 'border-ink bg-ink text-paper' : 'border-rule-strong bg-card hover:border-ink'
                }`}
              >
                {formatPrice(l, auction.prices)}
              </button>
            ))}
          </div>
          <p className='muted text-xs'>
            The creator set the price of each of the {LEVELS} levels. Your bid never leaves this browser unencrypted: only ciphertexts and
            proofs are published. Nobody, the creator included, can read it.
          </p>
        </div>
      )}

      {blocked && <div className={`note ${linked ? 'ok' : ''}`}>{blocked}</div>}
      {bid.error && <div className='note bad'>{bid.error}</div>}

      {!linked && (
        <div className='space-y-3'>
          <button onClick={() => void bid.submit(chosen)} disabled={!canSubmit} className='btn accent lg block'>
            {bid.submitting ? (
              <>
                <Spinner size={14} /> Proving and submitting…
              </>
            ) : submittedAny ? (
              `Resume: prove and submit ${pending} more`
            ) : (
              'Encrypt, prove and submit'
            )}
          </button>
          <p className='muted text-xs'>
            Proving runs in this tab and takes a few minutes for each of the {roles.length} ciphertexts. Keep the tab open; if you leave,
            you can resume from the auction page with the same bid.
          </p>
        </div>
      )}

      {showProgress && (
        <div className='space-y-3'>
          <div className='flex items-center justify-between'>
            <p className='label !mb-0'>Your submission</p>
            <p className='muted font-mono text-xs'>
              {roles.length - pending}/{roles.length} submitted
            </p>
          </div>
          <ol className='space-y-3'>
            {roles.map((role, index) => (
              <CiphertextProgress key={role} index={index} total={roles.length} role={role} row={bid.rows[index]} />
            ))}
          </ol>
        </div>
      )}
    </div>
  )
}

export default BidPanel
