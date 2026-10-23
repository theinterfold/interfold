// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useState } from 'react'
import { CheckCircleIcon, CircleIcon, WarningCircleIcon } from '@phosphor-icons/react'
import { MAX_BIDDERS_BY_TYPE, MAX_BIDS_PER_BIDDER, MIN_BIDDERS, rolesFor } from '@shared/layout'
import { type StepRow, useBid } from '@/hooks/useBid'
import { type UseAllowlist, gateKind as gateKindOf } from '@/hooks/useAllowlist'
import type { Wallet } from '@/hooks/useWallet'
import { type AuctionPhase, type AuctionState, formatPrice } from '@/utils/auction'
import { ConnectPrompt } from './ConnectPrompt'
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
    <CheckCircleIcon size={16} weight='fill' className='text-accent' />
  ) : status === 'active' ? (
    <Spinner size={14} />
  ) : status === 'error' ? (
    <WarningCircleIcon size={16} weight='fill' className='text-danger' />
  ) : (
    <CircleIcon size={16} />
  )

interface BidPanelProps {
  auction: AuctionState
  phase: AuctionPhase
  wallet: Wallet
  committeeKey: Uint8Array | null
  /** The members of the auction's allowlist, when it has one. */
  allowlist: UseAllowlist
  /** How many bids the connected account has on chain, or `null` before the first read. */
  bidCount: number | null
  onSubmitted: () => void
}

const BidPanel: React.FC<BidPanelProps> = ({ auction, phase, wallet, committeeKey, allowlist, bidCount, onSubmitted }) => {
  const levels = auction.prices.length
  const gateKind = gateKindOf(auction.gate)
  const bid = useBid({
    e3Id: auction.e3Id,
    auctionType: auction.auctionType,
    levels,
    gateKind,
    members: allowlist.members,
    account: wallet.address,
    committeeKey,
    onSubmitted,
  })
  const [level, setLevel] = useState(0)
  const [relayed, setRelayed] = useState(false)
  const elapsed = useElapsed(bid.run?.startedAt, bid.submitting)

  const maxBidders = MAX_BIDDERS_BY_TYPE[auction.auctionType]
  const count = bidCount ?? 0
  const left = MAX_BIDS_PER_BIDDER - count
  // What this browser remembers of the bid that is on chain now.
  const current = bid.versions.find(({ version }) => version === count)
  const onList =
    allowlist.members === null || wallet.address === undefined
      ? null
      : allowlist.members.some((member) => member.toLowerCase() === wallet.address?.toLowerCase())
  const limitNote = (
    <p className='muted text-xs'>
      This auction type takes {MIN_BIDDERS} to {maxBidders} bidders. {auction.bidderCount} of {maxBidders} places are taken.
    </p>
  )

  // Why bidding is not possible right now, if it is not.
  let blocked: string | null = null
  if (phase === 'awaiting-key') blocked = 'Bidding opens once the committee has published its key. Key generation takes several minutes.'
  else if (phase !== 'bidding') blocked = 'Bidding is closed.'
  else if (gateKind === 'unknown')
    blocked = 'This auction uses a bidder gate that this app cannot build a proof for, so it cannot bid here.'
  else if (gateKind === 'allowlist' && allowlist.error) blocked = `Could not read the allowlist: ${allowlist.error}`
  else if (gateKind === 'allowlist' && allowlist.members === null) blocked = 'Reading the allowlist…'
  else if (gateKind === 'allowlist' && onList === false)
    blocked = 'This account is not on the allowlist of the auction, so the contract would reject its bid.'
  else if (left <= 0) blocked = `You have used all ${MAX_BIDS_PER_BIDDER} bids of this auction.`
  else if (count === 0 && auction.bidderCount >= maxBidders) blocked = `This auction is full: ${maxBidders} bidders have bid.`
  else if (committeeKey === null) blocked = 'Fetching the committee key…'

  const canSubmit = wallet.ready && blocked === null && !bid.submitting && bidCount !== null

  const gateNote =
    gateKind === 'allowlist' ? (
      <p className='muted text-xs'>
        Only addresses on the allowlist of the creator can bid
        {allowlist.members && ` (${allowlist.members.length} ${allowlist.members.length === 1 ? 'address' : 'addresses'})`}.
      </p>
    ) : gateKind === 'open' ? (
      <p className='muted text-xs'>Anyone can bid.</p>
    ) : null

  if (!wallet.isConnected) {
    return (
      <div className='space-y-4'>
        <ConnectPrompt>Connect a wallet to bid.</ConnectPrompt>
        {blocked && <p className='muted text-sm'>{blocked}</p>}
        {gateNote}
        {limitNote}
      </div>
    )
  }

  return (
    <div className='space-y-6'>
      {wallet.wrongChain && <div className='note bad'>Your wallet is on another network. Switch networks to bid.</div>}

      {count > 0 && (
        <div className='border border-accent bg-accent-soft p-4'>
          <p className='mono-sm muted'>
            Your bid · version {count} of up to {MAX_BIDS_PER_BIDDER}
          </p>
          {current ? (
            <>
              <p className='font-serif text-4xl'>{formatPrice(current.level, auction.prices)}</p>
              <p className='muted mt-1 text-xs'>
                Step {current.level} of {levels - 1}. Kept in this browser; only you can see it.
              </p>
              <p className='muted mt-1 text-xs'>
                Transaction <TxLink hash={current.txHash} />
              </p>
            </>
          ) : (
            <p className='muted mt-1 text-xs'>
              This account has bid {count} {count === 1 ? 'time' : 'times'} here, but this browser does not hold the level. Only the browser
              that made the bid can show it.
            </p>
          )}
        </div>
      )}

      {gateKind === 'allowlist' && onList !== null && (
        <div className={`note ${onList ? 'ok' : 'bad'}`}>
          {onList ? 'Your account is on the allowlist of this auction.' : 'Your account is not on the allowlist of this auction.'}
        </div>
      )}

      {left > 0 && (
        <div className='space-y-3'>
          <p className='label !mb-0'>{count === 0 ? 'Pick your bid' : 'Pick a new bid'}</p>
          <div className='grid grid-cols-4 gap-2' role='radiogroup' aria-label='Bid level'>
            {Array.from({ length: levels }, (_, l) => (
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
            The creator set {levels} steps and the price of each. Your bid never leaves this browser unencrypted: only ciphertexts and a
            proof are published. Nobody, the creator included, can read it.
            {count > 0 && ' An update replaces your bid: the latest version that is valid counts, and earlier versions are ignored.'}
          </p>
          {gateNote}
          {limitNote}
        </div>
      )}

      {blocked && <div className='note'>{blocked}</div>}
      {bid.error && <div className='note bad'>{bid.error}</div>}

      {left > 0 && (
        <div className='space-y-3'>
          <label className='flex cursor-pointer items-start gap-3 text-sm'>
            <input
              type='checkbox'
              checked={relayed}
              disabled={bid.submitting}
              onChange={(event) => setRelayed(event.target.checked)}
              className='mt-1'
            />
            <span>
              <span className='block font-semibold'>Send through relayer</span>
              <span className='muted block text-xs'>
                You sign the bid in your wallet and the server sends the transaction and pays the gas. The relayer cannot change the bid:
                the signature covers the bytes and the version.
              </span>
            </span>
          </label>
          <button onClick={() => void bid.submit(level, relayed)} disabled={!canSubmit} className='btn accent lg block'>
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
          <p className='muted text-xs'>
            Proving runs in this tab and takes a few minutes: {rolesFor(auction.auctionType).length} encryptions with their proofs, then{' '}
            {rolesFor(auction.auctionType).length === 4 ? 'three' : 'two'} proofs for the bid itself. Keep the tab open.
          </p>
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
          <ol className='space-y-1.5 border border-rule-strong bg-card p-4 text-sm'>
            {bid.steps.map((step) => (
              <li
                key={step.id}
                className={`flex items-center gap-2 ${step.status === 'active' ? 'font-semibold' : step.status === 'pending' ? 'text-ink-soft' : 'text-ink-2'}`}
              >
                <StepIcon status={step.status} />
                {step.label}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  )
}

export default BidPanel
