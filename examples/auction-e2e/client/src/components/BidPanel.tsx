// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { MAX_BIDDERS, MAX_BIDS_PER_BIDDER, MIN_BIDDERS, rolesFor } from '@interfold/auction-core'
import { useBid } from '@/hooks/useBid'
import { useLeaveGuard } from '@/hooks/useLeaveGuard'
import { type UseAllowlist, gateKind as gateKindOf } from '@/hooks/useAllowlist'
import type { Wallet } from '@/hooks/useWallet'
import { type AuctionPhase, type AuctionState, formatPrice, maskCount, masksComplete } from '@/utils/auction'
import { BID_PROOF_HINT, KEY_GENERATION_HINT } from '@/utils/estimates'
import { sameAddress } from '@/utils/format'
import { ConnectPrompt } from './ConnectPrompt'
import { TxLink } from './Explorer'
import Spinner from './Spinner'
import SubmissionSteps from './SubmissionSteps'
import { WrongChainNote } from './WrongChainNote'

interface BidPanelProps {
  auction: AuctionState
  phase: AuctionPhase
  wallet: Wallet
  committeeKey: Uint8Array | null
  /** Why the committee key could not be read, if it could not. */
  keyError: string | null
  /** The members of the auction's allowlist, when it has one. */
  allowlist: UseAllowlist
  /** How many bids the connected account has on chain, or `null` before the first read. */
  bidCount: number | null
  onSubmitted: () => void
}

/** What to tell a visitor when bidding is over, by phase. */
const CLOSED_NOTE: Partial<Record<AuctionPhase, string>> = {
  computing: 'Bidding is closed. The program is computing the result.',
  decrypting: 'Bidding is closed. The committee is decrypting the result.',
  complete: 'Bidding is closed. The result is ready below.',
  failed: 'Bidding is closed. The auction failed.',
}

const BidPanel: React.FC<BidPanelProps> = ({ auction, phase, wallet, committeeKey, keyError, allowlist, bidCount, onSubmitted }) => {
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
  useLeaveGuard(bid.submitting)

  const maxBidders = MAX_BIDDERS
  const count = bidCount ?? 0
  const left = MAX_BIDS_PER_BIDDER - count
  // What this browser remembers of the bid that is on chain now.
  const current = bid.versions.find(({ version }) => version === count)
  const onList =
    allowlist.members === null || wallet.address === undefined
      ? null
      : allowlist.members.some((member) => sameAddress(member, wallet.address))
  const limitNote = (
    <p className='muted text-xs'>
      This auction type takes {MIN_BIDDERS} to {maxBidders} bidders. {auction.bidderCount} of {maxBidders} places are taken.
    </p>
  )

  // Why bidding is not possible right now, if it is not.
  let blocked: string | null = null
  if (phase === 'awaiting-key')
    blocked = `Bidding opens once the committee has published its key. Key generation takes ${KEY_GENERATION_HINT}.`
  else if (phase !== 'bidding') blocked = CLOSED_NOTE[phase] ?? 'Bidding is closed.'
  else if (auction.providers.some((provider) => sameAddress(provider.address, wallet.address)))
    blocked = 'This account is a mask provider of the auction, and a mask provider cannot bid. Use another account to bid.'
  else if (!masksComplete(auction)) blocked = `Waiting for mask providers (${maskCount(auction)}/${auction.providers.length})`
  else if (gateKind === 'unknown')
    blocked = 'This auction uses a bidder gate that this app cannot build a proof for, so it cannot bid here.'
  else if (gateKind === 'allowlist' && allowlist.error) blocked = `Could not read the allowlist: ${allowlist.error}`
  else if (gateKind === 'allowlist' && allowlist.members === null) blocked = 'Reading the allowlist…'
  else if (gateKind === 'allowlist' && onList === false)
    blocked = 'This account is not on the allowlist of the auction, so the contract would reject its bid.'
  else if (left <= 0) blocked = `You have used all ${MAX_BIDS_PER_BIDDER} bids of this auction.`
  else if (count === 0 && auction.bidderCount >= maxBidders) blocked = `This auction is full: ${maxBidders} bidders have bid.`
  else if (committeeKey === null) blocked = keyError === null ? 'Fetching the committee key…' : 'Bidding needs the committee key.'

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
      {wallet.wrongChain && <WrongChainNote>Your wallet is on another network. Switch networks to bid.</WrongChainNote>}

      {count > 0 && (
        <div className='inset ok p-4'>
          <p className='meta muted'>
            Your bid · version {count} of up to {MAX_BIDS_PER_BIDDER}
          </p>
          {current ? (
            <>
              <p className='value'>{formatPrice(current.level, auction.prices)}</p>
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
                className={`opt px-2 text-center ${level === l ? 'on' : ''}`}
              >
                <span className='block text-xs text-muted'>Step {l}</span>
                {formatPrice(l, auction.prices)}
              </button>
            ))}
          </div>
          <p className='muted text-xs'>
            The creator set {levels} steps and the price of each. Your bid is encrypted in this browser. Only ciphertexts and a proof are
            published. Nobody, the creator included, can read the bid.
          </p>
          {count > 0 && (
            <div className='note warn space-y-1 text-sm'>
              <p className='font-semibold'>An update replaces your bid.</p>
              <ul className='list-disc space-y-1 pl-5'>
                <li>Only the latest valid version counts. Earlier versions are ignored.</li>
                <li>You lose your place in the queue. If the top bids tie, the bidder who bid first wins.</li>
              </ul>
            </div>
          )}
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
                You sign the bid in your wallet. The server sends the transaction and pays the gas. The relayer cannot change the bid,
                because the signature covers the bytes and the version. The relayer sees your address and the time of the bid. If the
                relayer is down, clear this box and send the bid from your wallet.
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
          <p className='muted text-sm'>
            Proving runs in this tab and takes {BID_PROOF_HINT}. It makes {rolesFor(auction.auctionType).length} encryptions with their
            proofs, then {rolesFor(auction.auctionType).length === 4 ? 'three' : 'two'} proofs for the bid itself. Keep the tab open. The
            page can stop responding for short periods. This is normal.
          </p>
        </div>
      )}

      {bid.steps.length > 0 && (
        <SubmissionSteps title='Your submission' steps={bid.steps} running={bid.submitting} run={bid.run} expected={BID_PROOF_HINT} />
      )}
    </div>
  )
}

export default BidPanel
