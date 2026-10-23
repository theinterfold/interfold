// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { AUCTION_TYPE_DESCRIPTIONS, AUCTION_TYPE_LABELS, MAX_BIDDERS_BY_TYPE, isRatioType } from '@interfold/auction'
import { useAuction } from '@/hooks/useAuctions'
import { useChainTime } from '@/hooks/useChainTime'
import { useCommitteeKey } from '@/hooks/useCommitteeKey'
import { useAllowlist, gateKind as gateKindOf } from '@/hooks/useAllowlist'
import { useBidCount } from '@/hooks/useBidCount'
import { useWallet } from '@/hooks/useWallet'
import { formatDateTime, phaseOf, timeLeftLabel } from '@/utils/auction'
import { loadVersions } from '@/utils/bid-storage'
import { chain } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { Pips } from '@/components/AuctionCard'
import BidPanel from '@/components/BidPanel'
import { AddressLink } from '@/components/Explorer'
import PhaseTimeline from '@/components/PhaseTimeline'
import ResultPanel from '@/components/ResultPanel'
import Section from '@/components/Section'
import Spinner from '@/components/Spinner'
import StatusBadge from '@/components/StatusBadge'

const parseE3Id = (param: string | undefined): bigint | null => (param && /^\d+$/.test(param) ? BigInt(param) : null)

const AuctionPage: React.FC = () => {
  const e3Id = parseE3Id(useParams().e3Id)
  const { auction, error, refresh } = useAuction(e3Id)
  const now = useChainTime()
  const wallet = useWallet()
  const { count: bidCount, refresh: refreshBidCount } = useBidCount(e3Id, wallet.address)

  const phase = auction ? phaseOf(auction, now) : null
  // The key is only needed to bid, and bidding needs it until the window closes.
  const committeeKey = useCommitteeKey(e3Id, phase === 'awaiting-key' || phase === 'bidding')

  const allowlist = useAllowlist(auction?.gate, e3Id)

  // The bids of this browser change only when a submission lands, which moves the bid count.
  const myVersions = useMemo(
    () =>
      e3Id === null || !wallet.address || bidCount === null
        ? []
        : loadVersions({ chainId: chain.id, program: getContractAddresses().e3Program, e3Id, account: wallet.address }),
    [e3Id, wallet.address, bidCount],
  )

  const onSubmitted = React.useCallback(() => {
    refreshBidCount()
    void refresh()
  }, [refreshBidCount, refresh])

  if (e3Id === null) return <NotFound text='This is not a valid auction id.' />
  if (auction === undefined) {
    return (
      <div className='page space-y-6'>
        {error ? (
          <div className='note bad'>Could not load the auction: {error}</div>
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
  if (auction === null) return <NotFound text={`There is no auction Nº ${e3Id} on this deployment.`} />
  if (phase === null) return null

  const { e3Program } = getContractAddresses()
  const maxBidders = MAX_BIDDERS_BY_TYPE[auction.auctionType]
  const gateKind = gateKindOf(auction.gate)

  return (
    <div className='page space-y-10'>
      <header className='space-y-4'>
        <Link to='/' className='linkish'>
          All auctions
        </Link>
        <div className='flex flex-wrap items-start justify-between gap-4'>
          <div className='min-w-0 space-y-3'>
            <p className='mono muted'>
              Auction Nº {auction.e3Id.toString().padStart(3, '0')} · {AUCTION_TYPE_LABELS[auction.auctionType]}
            </p>
            <h1 className='h1'>{auction.title}</h1>
          </div>
          <div className='flex items-center gap-3'>
            <StatusBadge phase={phase} />
            <CopyLinkButton />
          </div>
        </div>
        <p className='lede'>{AUCTION_TYPE_DESCRIPTIONS[auction.auctionType]}</p>
      </header>

      <dl className='card grid grid-cols-2 gap-x-6 gap-y-5 !p-5 md:grid-cols-3 lg:grid-cols-4'>
        <Fact label='Bidders'>
          <span className='flex items-center gap-2'>
            <Pips filled={auction.bidderCount} total={maxBidders} />
            <span className='font-mono text-xs'>
              {auction.bidderCount}/{maxBidders}
            </span>
          </span>
        </Fact>
        <Fact label='Who can bid'>
          {gateKind === 'open' ? (
            'Anyone'
          ) : gateKind === 'allowlist' ? (
            allowlist.members ? (
              `An allowlist of ${allowlist.members.length} ${allowlist.members.length === 1 ? 'address' : 'addresses'}`
            ) : (
              'An allowlist'
            )
          ) : (
            <span className='flex flex-wrap items-center gap-1'>
              A gate contract <AddressLink address={auction.gate} />
            </span>
          )}
        </Fact>
        <Fact label='Top tie'>
          {isRatioType(auction.auctionType) ? 'Random draw among the tied bidders' : 'Priority from a hash of the ciphertexts'}
        </Fact>
        <Fact label='Time'>{timeLeftLabel(auction, phase, now)}</Fact>
        <Fact label='Bidding ends'>{formatDateTime(auction.inputWindow[1])}</Fact>
        <Fact label={`${auction.prices.length} price steps`}>
          <span className='font-mono' title={auction.prices.map((price) => price.toLocaleString('en-US')).join(', ')}>
            {auction.prices[0].toLocaleString('en-US')} – {auction.prices[auction.prices.length - 1].toLocaleString('en-US')}
          </span>
        </Fact>
        <Fact label='Created by'>
          <AddressLink address={auction.creator} />
        </Fact>
        <Fact label='Contract'>
          <AddressLink address={e3Program} />
        </Fact>
      </dl>

      {error && <div className='note bad'>Could not refresh the auction: {error}</div>}

      <div className='grid items-start gap-8 lg:grid-cols-[1fr_1.25fr]'>
        <Section eyebrow='Nº 01' title='Progress'>
          <PhaseTimeline phase={phase} auction={auction} />
        </Section>
        <Section eyebrow='Nº 02' title='Your bid'>
          <BidPanel
            auction={auction}
            phase={phase}
            wallet={wallet}
            committeeKey={committeeKey}
            allowlist={allowlist}
            bidCount={bidCount}
            onSubmitted={onSubmitted}
          />
        </Section>
      </div>

      <Section eyebrow='Nº 03' title='Result'>
        {phase === 'complete' ? (
          <ResultPanel auction={auction} account={wallet.address} myVersions={myVersions} />
        ) : phase === 'failed' ? (
          <div className='note'>There is no result: the auction failed.</div>
        ) : (
          <div className='note flex items-start gap-3'>
            <Spinner size={16} />
            <span>
              The result appears once the bidding window has closed, the program has computed over the encrypted bids and the committee has
              decrypted the outcome. That takes a few minutes after the window closes.
            </span>
          </div>
        )}
      </Section>
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
      Back to the auctions
    </Link>
  </div>
)

export default AuctionPage
