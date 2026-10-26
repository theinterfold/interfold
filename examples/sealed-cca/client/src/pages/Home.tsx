// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { CoinsIcon, LockKeyIcon, SealCheckIcon } from '@phosphor-icons/react'
import { useSales } from '@/hooks/useSales'
import { useChainTime } from '@/hooks/useChainTime'
import { type SalePhase, type SaleState, phaseOf } from '@/utils/sale'
import SaleCard, { SaleCardSkeleton } from '@/components/SaleCard'
import Cipher from '@/components/Cipher'

const PRINCIPLES = [
  {
    icon: LockKeyIcon,
    label: 'Sealed.',
    body: 'Each bid is your highest price, encrypted in your browser to a committee key. Nobody, the creator included, can read it.',
  },
  {
    icon: CoinsIcon,
    label: 'One price for all.',
    body: 'The sale clears once, at the lowest price where the demand fits the supply. Everyone who gets tokens pays that price.',
  },
  {
    icon: SealCheckIcon,
    label: 'Proven.',
    body: 'Each bid carries a zero-knowledge proof that it is well formed. Your claim carries a proof of your outcome, and no one else sees your price.',
  },
]

interface Group {
  title: string
  note: string
  phases: SalePhase[]
}

const GROUPS: Group[] = [
  { title: 'Open for bids', note: 'The committee key is ready. Deposit and bid.', phases: ['bidding'] },
  { title: 'Waiting for keys', note: 'The committee is generating the key bids are encrypted to.', phases: ['awaiting-key'] },
  {
    title: 'Being computed',
    note: 'Bidding is closed and the demand curve is being computed and decrypted.',
    phases: ['computing', 'decrypting'],
  },
  { title: 'Cleared', note: 'The clearing price is public. Claim tokens and refunds.', phases: ['complete', 'failed'] },
]

const SaleGroups: React.FC<{ sales: SaleState[]; now: bigint }> = ({ sales, now }) => (
  <div className='space-y-10'>
    {GROUPS.map((group) => {
      const inGroup = sales.filter((sale) => group.phases.includes(phaseOf(sale, now)))
      if (inGroup.length === 0) return null
      return (
        <section key={group.title} className='space-y-4'>
          <div className='flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1'>
            <h3 className='flex items-center gap-2 text-base font-semibold'>
              {group.title} <span className='ui-count'>{inGroup.length}</span>
            </h3>
            <p className='muted text-sm'>{group.note}</p>
          </div>
          <div className='list'>
            {inGroup.map((sale) => (
              <SaleCard key={sale.e3Id.toString()} sale={sale} now={now} />
            ))}
          </div>
        </section>
      )
    })}
  </div>
)

const Home: React.FC = () => {
  const { data: sales, loading, error } = useSales()
  const now = useChainTime()

  return (
    <div className='page !pt-0'>
      <section className='page-intro'>
        <h1 className='display'>
          Bid in private. <em>Clear at one price.</em>
        </h1>
        <p className='lede'>
          In a sealed token sale every bidder names the highest price it will pay, once, in secret, and locks a fixed escrow. Interfold adds
          the encrypted bids together and a committee decrypts only the demand curve. The sale then clears at one uniform price.
        </p>
        <div className='actions'>
          <Link to='/create' className='btn'>
            Create a sale
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
            <span className='tag live dot'>FHE</span>
          </div>
          <Cipher seed={11} length={300} />
          <div className='hr-soft' />
          <p className='meta muted'>This is all anyone sees of a bid while the sale runs.</p>
        </div>
      </section>

      <section>
        <div className='page-head'>
          <div>
            <h2>Sales</h2>
            <p>Open a sale to bid or to read its result.</p>
          </div>
          <Link to='/create' className='btn ghost sm'>
            Create a sale
          </Link>
        </div>

        {error && <div className='note bad mb-6'>Could not load the sales: {error}</div>}

        {loading ? (
          <div className='space-y-3'>
            <SaleCardSkeleton />
            <SaleCardSkeleton />
            <SaleCardSkeleton />
          </div>
        ) : sales.length === 0 ? (
          <div className='card flat space-y-3 text-center'>
            <p className='h3'>No sales yet</p>
            <p className='muted'>Be the first: create one and share its link with the bidders.</p>
            <div>
              <Link to='/create' className='btn'>
                Create a sale
              </Link>
            </div>
          </div>
        ) : (
          <SaleGroups sales={sales} now={now} />
        )}
      </section>
    </div>
  )
}

export default Home
