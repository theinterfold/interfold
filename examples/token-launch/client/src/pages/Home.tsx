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
import { Phase } from '@/utils/phase'
import type { SaleState } from '@/utils/sale'
import SaleCard, { SaleCardSkeleton } from '@/components/SaleCard'
import Cipher from '@/components/Cipher'

const PRINCIPLES = [
  {
    icon: LockKeyIcon,
    label: 'Private.',
    body: 'Each bid is a budget and a max price. The browser encrypts both. Nobody reads them, the creator included.',
  },
  {
    icon: CoinsIcon,
    label: 'One price for all.',
    body: 'The sale clears once. A short probe search reveals a few budget sums, not the full demand curve. Every winner pays the clearing price.',
  },
  {
    icon: SealCheckIcon,
    label: 'Unlinkable.',
    body: 'A claim proof shows that a counted bid exists. The tokens go to a fresh address. Nothing links that address to your bid.',
  },
]

interface Group {
  title: string
  note: string
  include: (sale: SaleState) => boolean
}

const GROUPS: Group[] = [
  {
    title: 'Open for bids',
    note: 'Both committee keys exist. Pick a tier, a budget and a max price.',
    include: (sale) => sale.phase === Phase.Bidding && sale.keysReady,
  },
  {
    title: 'Waiting for keys',
    note: 'The committee makes the keys that bids are encrypted to.',
    include: (sale) => sale.phase === Phase.Bidding && !sale.keysReady,
  },
  {
    title: 'In progress',
    note: 'Bidding is closed. The rounds reveal a few budget sums.',
    include: (sale) => sale.phase >= Phase.Round1 && sale.phase <= Phase.Clearable,
  },
  { title: 'Cleared', note: 'The clearing price is public. Claim tokens and refunds.', include: (sale) => sale.phase === Phase.Cleared },
  {
    title: 'Stopped',
    note: 'The sale did not clear. Bidders and the creator take their funds back.',
    include: (sale) => sale.phase === Phase.Aborted || sale.phase === Phase.Failed,
  },
]

const SaleGroups: React.FC<{ sales: SaleState[]; now: bigint }> = ({ sales, now }) => (
  <div className='space-y-12'>
    {GROUPS.map((group) => {
      const inGroup = sales.filter(group.include)
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
            {inGroup.map((sale) => (
              <SaleCard key={sale.saleId.toString()} sale={sale} now={now} />
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
    <>
      <section className='page'>
        <div className='grid items-start gap-10 lg:grid-cols-[1.25fr_1fr] lg:gap-16'>
          <div className='space-y-8'>
            <div className='space-y-5'>
              <p className='mono muted'>Private token launches on Interfold</p>
              <h1 className='display'>
                Bid in private. <em>Claim without a trace.</em>
              </h1>
              <p className='lede'>
                A bidder gives a private budget and a private max price. Interfold adds the encrypted bids. A committee reveals a few budget
                sums and the sale clears at one uniform price. Each bidder then claims to a fresh address.
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
                Create a sale
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
            <p className='mono-sm muted'>This is all anyone sees of a bid. The budget and the max price stay private.</p>
          </div>
        </div>
      </section>

      <section className='page !pt-0'>
        <div className='mb-8 flex flex-wrap items-end justify-between gap-4'>
          <h2 className='h1'>Sales</h2>
          <Link to='/create' className='btn ghost'>
            Create a sale
          </Link>
        </div>

        {error && <div className='note bad mb-6'>Could not load the sales: {error}</div>}

        {loading ? (
          <div className='grid gap-5 md:grid-cols-2 lg:grid-cols-3'>
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
    </>
  )
}

export default Home
