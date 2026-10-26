// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { HandshakeIcon, LockKeyIcon, SealCheckIcon } from '@phosphor-icons/react'
import { useNegotiations } from '@/hooks/useNegotiations'
import { useChainTime } from '@/hooks/useChainTime'
import { useWallet } from '@/hooks/useWallet'
import { type NegotiationState, roleOf } from '@/utils/negotiation'
import NegotiationCard, { NegotiationCardSkeleton } from '@/components/NegotiationCard'
import Cipher from '@/components/Cipher'

/** The most negotiations of other people that the page lists. */
const RECENT_LIMIT = 12

const PRINCIPLES = [
  {
    icon: LockKeyIcon,
    label: 'Sealed.',
    body: 'The seller seals a minimum price and the buyer a maximum price, each in its own browser. Nobody can read either: not the other party, not the committee.',
  },
  {
    icon: HandshakeIcon,
    label: 'One price, or no match.',
    body: 'If the maximum is at least the minimum, both learn one agreed price between the two. Otherwise both learn only that there is no match.',
  },
  {
    icon: SealCheckIcon,
    label: 'Proven.',
    body: 'Each offer carries a zero-knowledge proof that it is well formed, so a party cannot cheat the result with a malformed offer.',
  },
]

const Group: React.FC<{ title: string; note: string; items: NegotiationState[]; now: bigint; account: string | undefined }> = ({
  title,
  note,
  items,
  now,
  account,
}) => (
  <section className='space-y-4'>
    <div className='flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1'>
      <h3 className='flex items-center gap-2 text-base font-semibold'>
        {title} <span className='ui-count'>{items.length}</span>
      </h3>
      <p className='muted text-sm'>{note}</p>
    </div>
    <div className='list'>
      {items.map((item) => (
        <NegotiationCard key={item.e3Id.toString()} negotiation={item} now={now} account={account} />
      ))}
    </div>
  </section>
)

const Home: React.FC = () => {
  const { data: negotiations, loading, error } = useNegotiations()
  const now = useChainTime()
  const { address } = useWallet()

  const mine = negotiations.filter((item) => roleOf(item, address) !== null)
  const others = negotiations.filter((item) => roleOf(item, address) === null).slice(0, RECENT_LIMIT)

  return (
    <div className='page !pt-0'>
      <section className='page-intro'>
        <h1 className='display'>
          Name your price in private. <em>Learn one price.</em>
        </h1>
        <p className='lede'>
          A seller has a private minimum price. A buyer has a private maximum price. Interfold compares them on encrypted data and a
          committee decrypts only the result: one agreed price, or no match.
        </p>
        <div className='actions'>
          <Link to='/create' className='btn'>
            Create a negotiation
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
            <span className='mono muted'>Your price, encrypted</span>
            <span className='tag live dot'>FHE</span>
          </div>
          <Cipher seed={11} length={300} />
          <div className='hr-soft' />
          <p className='meta muted'>This is all anyone sees of an offer while the negotiation runs.</p>
        </div>
      </section>

      <section className='space-y-10'>
        <div className='page-head !mb-0'>
          <div>
            <h2>Negotiations</h2>
            <p>Open a negotiation to send your offer or to read its result.</p>
          </div>
          <Link to='/create' className='btn ghost sm'>
            Create a negotiation
          </Link>
        </div>

        {error && <div className='note bad'>Could not load the negotiations: {error}</div>}

        {loading ? (
          <div className='space-y-3'>
            <NegotiationCardSkeleton />
            <NegotiationCardSkeleton />
            <NegotiationCardSkeleton />
          </div>
        ) : negotiations.length === 0 ? (
          <div className='card flat space-y-3 text-center'>
            <p className='h3'>No negotiations yet</p>
            <p className='muted'>Be the first: create one and send its link to the seller and the buyer.</p>
            <div>
              <Link to='/create' className='btn'>
                Create a negotiation
              </Link>
            </div>
          </div>
        ) : (
          <>
            {mine.length > 0 && <Group title='Yours' note='You are the seller or the buyer.' items={mine} now={now} account={address} />}
            {others.length > 0 && (
              <Group
                title={mine.length > 0 ? 'Recent' : 'Recent negotiations'}
                note='Anyone can follow a negotiation and read its result.'
                items={others}
                now={now}
                account={address}
              />
            )}
          </>
        )}
      </section>
    </div>
  )
}

export default Home
