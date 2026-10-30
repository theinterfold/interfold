// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { LockKeyIcon, SealCheckIcon, UsersThreeIcon } from '@phosphor-icons/react'
import { useAuctions } from '@/hooks/useAuctions'
import { useChainTime } from '@/hooks/useChainTime'
import { type AuctionPhase, type AuctionState, PHASE_LABELS, phaseOf } from '@/utils/auction'
import { KEY_GENERATION_HINT } from '@/utils/estimates'
import AuctionCard, { AuctionCardSkeleton } from '@/components/AuctionCard'
import Cipher from '@/components/Cipher'

const PRINCIPLES = [
  {
    icon: LockKeyIcon,
    label: 'Sealed.',
    body: 'Every bid is encrypted in your browser to a committee key. Nobody, the creator included, can read it.',
  },
  {
    icon: UsersThreeIcon,
    label: 'Decided by a committee.',
    body: 'A program compares the encrypted bids. A threshold committee that no single party controls decrypts only the outcome.',
  },
  {
    icon: SealCheckIcon,
    label: 'Proven.',
    body: 'Each bid carries zero-knowledge proofs that it is well formed, so a bad bid cannot spoil the auction.',
  },
]

interface Group {
  /** The phase of every auction in the group. The title of the group is the label of the phase. */
  phase: AuctionPhase
  note: string
}

const GROUPS: Group[] = [
  { phase: 'bidding', note: 'The committee key is ready. Place a bid.' },
  { phase: 'awaiting-key', note: `The committee is generating the key that bids are encrypted to. This takes ${KEY_GENERATION_HINT}.` },
  { phase: 'computing', note: 'Bidding is closed. The program is comparing the encrypted bids.' },
  { phase: 'decrypting', note: 'The committee is decrypting the outcome.' },
  { phase: 'complete', note: 'Results are public.' },
  { phase: 'failed', note: 'These auctions have no result.' },
]

const AuctionGroups: React.FC<{ auctions: AuctionState[]; now: bigint }> = ({ auctions, now }) => (
  <div className='space-y-10'>
    {GROUPS.map((group) => {
      const inGroup = auctions.filter((auction) => phaseOf(auction, now) === group.phase)
      if (inGroup.length === 0) return null
      return (
        <section key={group.phase} className='space-y-4'>
          <div className='flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1'>
            <h3 className='flex items-center gap-2 text-base font-semibold'>
              {PHASE_LABELS[group.phase]} <span className='ui-count'>{inGroup.length}</span>
            </h3>
            <p className='muted text-sm'>{group.note}</p>
          </div>
          <div className='list'>
            {inGroup.map((auction) => (
              <AuctionCard key={auction.e3Id.toString()} auction={auction} now={now} />
            ))}
          </div>
        </section>
      )
    })}
  </div>
)

const Home: React.FC = () => {
  const { data: auctions, loading, error, retry } = useAuctions()
  const now = useChainTime()

  return (
    <div className='page !pt-0'>
      <section className='page-intro'>
        <h1 className='display'>
          Bid in private. <em>Reveal only the winner.</em>
        </h1>
        <p className='lede'>
          In a sealed-bid auction every bidder names a price once, in secret. Here the bids stay encrypted from the browser to the result:
          Interfold computes over the ciphertexts and a committee decrypts only who won and at what price.
        </p>
        <div className='actions'>
          <Link to='/create' className='btn'>
            Create an auction
          </Link>
          <Link to='/about' className='linkish'>
            How it works
          </Link>
        </div>
      </section>

      <section className='mb-16 grid items-start gap-6 lg:grid-cols-[1.25fr_1fr]'>
        <ul className='list'>
          {PRINCIPLES.map(({ icon: Icon, label, body }) => (
            <li key={label} className='flex items-start gap-4 p-5'>
              <Icon size={26} weight='light' className='mt-0.5 shrink-0' />
              <p>
                <span className='block font-semibold'>{label}</span> <span className='muted'>{body}</span>
              </p>
            </li>
          ))}
        </ul>
        <div className='card space-y-4'>
          <div className='flex items-center justify-between gap-3'>
            <span className='mono muted'>Your bid, encrypted</span>
            <span
              className='tag live dot'
              title='Fully homomorphic encryption: the program computes on the bids while they stay encrypted.'
            >
              Encrypted
            </span>
          </div>
          <Cipher seed={11} length={300} />
          <div className='hr-soft' />
          <p className='meta muted'>This is what the chain stores of a bid. It is all anyone sees while the auction runs.</p>
        </div>
      </section>

      <section>
        <div className='page-head'>
          <div>
            <h2>Auctions</h2>
            <p>Open an auction to bid or to read its result.</p>
          </div>
          <Link to='/create' className='btn ghost sm'>
            Create an auction
          </Link>
        </div>

        {error && (
          <div role='alert' className='note bad mb-6 flex flex-wrap items-center justify-between gap-3'>
            <span>Could not load the auctions: {error}</span>
            <button type='button' onClick={retry} className='btn ghost sm'>
              Try again
            </button>
          </div>
        )}

        {loading ? (
          <div className='space-y-3' role='status'>
            <span className='sr-only'>Loading the auctions…</span>
            <AuctionCardSkeleton />
            <AuctionCardSkeleton />
            <AuctionCardSkeleton />
          </div>
        ) : auctions.length === 0 ? (
          error ? null : (
            <div className='card flat space-y-3 text-center'>
              <p className='h3'>No auctions yet</p>
              <p className='muted'>Be the first: create one and share its link with the bidders.</p>
              <div>
                <Link to='/create' className='btn'>
                  Create an auction
                </Link>
              </div>
            </div>
          )
        ) : (
          <AuctionGroups auctions={auctions} now={now} />
        )}
      </section>
    </div>
  )
}

export default Home
