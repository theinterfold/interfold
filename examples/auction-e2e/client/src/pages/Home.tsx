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
import { type AuctionPhase, type AuctionState, phaseOf } from '@/utils/auction'
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
    label: 'Decided without trust.',
    body: 'A program compares the encrypted bids. A threshold committee that no single party controls decrypts only the outcome.',
  },
  {
    icon: SealCheckIcon,
    label: 'Proven.',
    body: 'Each bid carries zero-knowledge proofs that it is well formed, so a bad bid cannot spoil the auction.',
  },
]

interface Group {
  title: string
  note: string
  phases: AuctionPhase[]
}

const GROUPS: Group[] = [
  { title: 'Open for bids', note: 'The committee key is ready. Place a bid.', phases: ['bidding'] },
  { title: 'Waiting for keys', note: 'The committee is generating the key bids are encrypted to.', phases: ['awaiting-key'] },
  {
    title: 'Being computed',
    note: 'Bidding is closed and the outcome is being computed and decrypted.',
    phases: ['computing', 'decrypting'],
  },
  { title: 'Finished', note: 'Results are public.', phases: ['complete', 'failed'] },
]

const AuctionGroups: React.FC<{ auctions: AuctionState[]; now: bigint }> = ({ auctions, now }) => (
  <div className='space-y-12'>
    {GROUPS.map((group) => {
      const inGroup = auctions.filter((auction) => group.phases.includes(phaseOf(auction, now)))
      if (inGroup.length === 0) return null
      return (
        <section key={group.title} className='space-y-5'>
          <div className='flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1'>
            <h2 className='h2'>
              {group.title} <span className='muted font-mono text-base'>{inGroup.length}</span>
            </h2>
            <p className='muted text-sm'>{group.note}</p>
          </div>
          <div className='hr' />
          <div className='grid gap-5 md:grid-cols-2 lg:grid-cols-3'>
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
  const { data: auctions, loading, error } = useAuctions()
  const now = useChainTime()

  return (
    <>
      <section className='page'>
        <div className='grid items-start gap-10 lg:grid-cols-[1.25fr_1fr] lg:gap-16'>
          <div className='space-y-8'>
            <div className='space-y-5'>
              <p className='mono muted'>Sealed-bid auctions on Interfold</p>
              <h1 className='display'>
                Bid in private. <em>Reveal only the winner.</em>
              </h1>
              <p className='lede'>
                In a sealed-bid auction every bidder names a price once, in secret. Here the bids stay encrypted from the browser to the
                result: Interfold computes over the ciphertexts and a committee decrypts only who won and at what price.
              </p>
            </div>
            <ul className='space-y-4'>
              {PRINCIPLES.map(({ icon: Icon, label, body }) => (
                <li key={label} className='flex items-start gap-4'>
                  <Icon size={26} weight='light' className='mt-0.5 shrink-0' />
                  <p>
                    <span className='font-semibold text-accent'>{label}</span> <span className='muted'>{body}</span>
                  </p>
                </li>
              ))}
            </ul>
            <div className='flex flex-wrap items-center gap-4'>
              <Link to='/create' className='btn lg'>
                Create an auction
              </Link>
              <Link to='/about' className='linkish'>
                How it works
              </Link>
            </div>
          </div>

          <div className='card space-y-4 lg:sticky lg:top-8'>
            <div className='flex items-center justify-between gap-3'>
              <span className='mono muted'>Your bid, encrypted</span>
              <span className='tag live dot'>FHE</span>
            </div>
            <Cipher seed={11} length={300} />
            <div className='hr-soft' />
            <p className='mono-sm muted'>This is all anyone sees of a bid while the auction runs.</p>
          </div>
        </div>
      </section>

      <section className='page !pt-0'>
        <div className='mb-8 flex flex-wrap items-end justify-between gap-4'>
          <h2 className='h1'>Auctions</h2>
          <Link to='/create' className='btn ghost'>
            Create an auction
          </Link>
        </div>

        {error && <div className='note bad mb-6'>Could not load the auctions: {error}</div>}

        {loading ? (
          <div className='grid gap-5 md:grid-cols-2 lg:grid-cols-3'>
            <AuctionCardSkeleton />
            <AuctionCardSkeleton />
            <AuctionCardSkeleton />
          </div>
        ) : auctions.length === 0 ? (
          <div className='card flat space-y-3 text-center'>
            <p className='h3'>No auctions yet</p>
            <p className='muted'>Be the first: create one and share its link with the bidders.</p>
            <div>
              <Link to='/create' className='btn'>
                Create an auction
              </Link>
            </div>
          </div>
        ) : (
          <AuctionGroups auctions={auctions} now={now} />
        )}
      </section>
    </>
  )
}

export default Home
