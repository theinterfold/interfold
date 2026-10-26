// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { MAX_BIDDERS } from '@interfold/private-round'
import { useSale } from '@/hooks/useSales'
import { useChainTime } from '@/hooks/useChainTime'
import { useCommitteeKey } from '@/hooks/useCommitteeKey'
import { useBidCount } from '@/hooks/useBidCount'
import { useWallet } from '@/hooks/useWallet'
import { formatDateTime, formatPayment, formatSaleTokens, formatStepPrice, lotCostAt, phaseOf, timeLeftLabel } from '@/utils/sale'
import { getContractAddresses } from '@/utils/env-config'
import BidPanel from '@/components/BidPanel'
import CreatorPanel from '@/components/CreatorPanel'
import { AddressLink } from '@/components/Explorer'
import PhaseTimeline from '@/components/PhaseTimeline'
import ResultPanel from '@/components/ResultPanel'
import Section from '@/components/Section'
import Spinner from '@/components/Spinner'
import StatusBadge from '@/components/StatusBadge'

const parseE3Id = (param: string | undefined): bigint | null => (param && /^\d+$/.test(param) ? BigInt(param) : null)

const SalePage: React.FC = () => {
  const e3Id = parseE3Id(useParams().e3Id)
  const { sale, error, refresh } = useSale(e3Id)
  const now = useChainTime()
  const wallet = useWallet()
  const { count: bidCount, refresh: refreshBidCount } = useBidCount(e3Id, wallet.address)

  const phase = sale ? phaseOf(sale, now) : null
  // The key is only needed to bid, and bidding needs it until the window closes.
  const committeeKey = useCommitteeKey(e3Id, phase === 'awaiting-key' || phase === 'bidding')

  const onSubmitted = React.useCallback(() => {
    refreshBidCount()
    void refresh()
  }, [refreshBidCount, refresh])

  if (e3Id === null) return <NotFound text='This is not a valid round id.' />
  if (sale === undefined) {
    return (
      <div className='page space-y-6'>
        {error ? (
          <div className='note bad'>Could not load the round: {error}</div>
        ) : (
          <>
            <div className='skeleton h-14 max-w-xl' />
            <div className='skeleton h-24' />
            <div className='skeleton h-64' />
          </>
        )}
      </div>
    )
  }
  if (sale === null) return <NotFound text={`There is no round Nº ${e3Id} on this deployment.`} />
  if (phase === null) return null

  const { e3Program } = getContractAddresses()
  const isCreator = wallet.address !== undefined && wallet.address.toLowerCase() === sale.creator.toLowerCase()

  return (
    <div className='page space-y-10'>
      <header className='space-y-4'>
        <Link to='/' className='linkish'>
          All rounds
        </Link>
        <div className='flex flex-wrap items-start justify-between gap-4'>
          <div className='min-w-0 space-y-3'>
            <p className='mono muted'>Round Nº {sale.e3Id.toString().padStart(3, '0')} · private round, one price for everyone</p>
            <h1 className='h1'>{sale.title}</h1>
          </div>
          <div className='flex items-center gap-3'>
            <StatusBadge phase={phase} />
            <CopyLinkButton />
          </div>
        </div>
        <p className='lede'>
          {sale.lots} lot{sale.lots === 1 ? '' : 's'} of {formatSaleTokens(sale, sale.lot)} for sale. Each bidder wants one lot and locks{' '}
          {formatPayment(sale, sale.escrow)}. If the reserve is met, the round clears at one price for everyone.
        </p>
      </header>

      <dl className='card grid grid-cols-2 gap-x-6 gap-y-5 !p-5 md:grid-cols-3 lg:grid-cols-4'>
        <Fact label='Bidders deposited'>
          <span className='font-mono text-xs'>
            {sale.bidderCount}/{MAX_BIDDERS}
          </span>
        </Fact>
        <Fact label='Lots'>
          <span className='font-mono'>
            {sale.lots} × {formatSaleTokens(sale, sale.lot)}
          </span>
        </Fact>
        <Fact label='Escrow per bidder'>{formatPayment(sale, sale.escrow)}</Fact>
        <Fact label='Reserve'>
          <span className='font-mono' title={`Step ${sale.reserveStep}`}>
            step {sale.reserveStep}: {formatStepPrice(sale, sale.reserveStep)} {sale.paymentToken.symbol}
          </span>
        </Fact>
        <Fact label='Minimum raise'>
          <span className='font-mono'>
            {sale.minLots} bidder{sale.minLots === 1 ? '' : 's'} at the reserve
          </span>
        </Fact>
        <Fact label='Time'>{timeLeftLabel(sale, phase, now)}</Fact>
        <Fact label='Bidding ends'>{formatDateTime(sale.inputWindow[1])}</Fact>
        <Fact label={`${sale.prices.length} price steps`}>
          <span className='font-mono' title={sale.prices.map((_, level) => formatStepPrice(sale, level)).join(', ')}>
            {formatStepPrice(sale, 0)} – {formatStepPrice(sale, sale.prices.length - 1)} {sale.paymentToken.symbol}
          </span>
        </Fact>
        <Fact label='One lot costs'>
          <span className='font-mono'>
            {formatPayment(sale, lotCostAt(sale, 0))} – {formatPayment(sale, lotCostAt(sale, sale.prices.length - 1))}
          </span>
        </Fact>
        <Fact label='Created by'>
          <AddressLink address={sale.creator} />
        </Fact>
        <Fact label='Sale token'>
          <AddressLink address={sale.saleToken.address} />
        </Fact>
        <Fact label='Payment token'>
          <AddressLink address={sale.paymentToken.address} />
        </Fact>
        <Fact label='Contract'>
          <AddressLink address={e3Program} />
        </Fact>
      </dl>

      {error && <div className='note bad'>Could not refresh the round: {error}</div>}

      <div className='grid items-start gap-8 lg:grid-cols-[1fr_1.25fr]'>
        <Section eyebrow='Nº 01' title='Progress'>
          <PhaseTimeline phase={phase} sale={sale} />
        </Section>
        <Section eyebrow='Nº 02' title='Your bid'>
          <BidPanel sale={sale} phase={phase} wallet={wallet} committeeKey={committeeKey} bidCount={bidCount} onSubmitted={onSubmitted} />
        </Section>
      </div>

      <Section eyebrow='Nº 03' title='Result'>
        {phase === 'complete' ? (
          <ResultPanel sale={sale} account={wallet.address} />
        ) : phase === 'failed' ? (
          <div className='note'>There is no result: the round failed.</div>
        ) : (
          <div className='note flex items-start gap-3'>
            <Spinner size={16} />
            <span>
              The result appears once the bidding window has closed, the program has combined the encrypted bids and the committee has
              decrypted the outcome. That takes a few minutes after the window closes.
            </span>
          </div>
        )}
      </Section>

      {isCreator && phase === 'complete' && (
        <Section eyebrow='Nº 04' title='Creator'>
          <CreatorPanel sale={sale} />
        </Section>
      )}
    </div>
  )
}

const Fact: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className='min-w-0'>
    <dt className='mono-sm muted'>{label}</dt>
    <dd className='mt-1 text-sm'>{children}</dd>
  </div>
)

const CopyLinkButton: React.FC = () => {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => {
        void navigator.clipboard.writeText(window.location.href).then(() => {
          setCopied(true)
          setTimeout(() => setCopied(false), 2000)
        })
      }}
      className='btn ghost sm'
    >
      {copied ? 'Link copied' : 'Copy link'}
    </button>
  )
}

const NotFound: React.FC<{ text: string }> = ({ text }) => (
  <div className='page space-y-5'>
    <div className='note'>{text}</div>
    <Link to='/' className='btn ghost'>
      Back to the rounds
    </Link>
  </div>
)

export default SalePage
