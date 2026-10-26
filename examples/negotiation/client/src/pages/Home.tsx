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
  <section className='space-y-5'>
    <div className='flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1'>
      <h2 className='h2'>
        {title} <span className='muted font-mono text-base'>{items.length}</span>
      </h2>
      <p className='muted text-sm'>{note}</p>
    </div>
    <div className='hr' />
    <div className='grid gap-5 md:grid-cols-2 lg:grid-cols-3'>
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
    <>
      <section className='page'>
        <div className='grid items-start gap-10 lg:grid-cols-[1.25fr_1fr] lg:gap-16'>
          <div className='space-y-8'>
            <div className='space-y-5'>
              <p className='mono muted'>Sealed price negotiation on Interfold</p>
              <h1 className='display'>
                Name your price in private. <em>Learn one price.</em>
              </h1>
              <p className='lede'>
                A seller has a private minimum price. A buyer has a private maximum price. Interfold compares them on encrypted data and a
                committee decrypts only the result: one agreed price, or no match.
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
                Create a negotiation
              </Link>
              <Link to='/about' className='linkish'>
                How it works
              </Link>
            </div>
          </div>

          <div className='card space-y-4 lg:sticky lg:top-8'>
            <div className='flex items-center justify-between gap-3'>
              <span className='mono muted'>Your price, encrypted</span>
              <span className='tag live dot'>FHE</span>
            </div>
            <Cipher seed={11} length={300} />
            <div className='hr-soft' />
            <p className='mono-sm muted'>This is all anyone sees of an offer while the negotiation runs.</p>
          </div>
        </div>
      </section>

      <section className='page space-y-12 !pt-0'>
        <div className='flex flex-wrap items-end justify-between gap-4'>
          <h2 className='h1'>Negotiations</h2>
          <Link to='/create' className='btn ghost'>
            Create a negotiation
          </Link>
        </div>

        {error && <div className='note bad'>Could not load the negotiations: {error}</div>}

        {loading ? (
          <div className='grid gap-5 md:grid-cols-2 lg:grid-cols-3'>
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
    </>
  )
}

export default Home
