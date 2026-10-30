// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useMemo, useState } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { MAX_BIDDERS } from '@interfold/auction-core'
import { designOf, hasProviders } from '@/utils/designs'
import { useAuction } from '@/hooks/useAuctions'
import { useChainTime } from '@/hooks/useChainTime'
import { useCommitteeKey } from '@/hooks/useCommitteeKey'
import { useAllowlist, gateKind as gateKindOf } from '@/hooks/useAllowlist'
import { useBidCount } from '@/hooks/useBidCount'
import { useWallet } from '@/hooks/useWallet'
import { FAILURE_TEXT, formatDateTime, formatPrice, maskCount, phaseOf, timeLeftLabel } from '@/utils/auction'
import { sameAddress, shortId } from '@/utils/format'
import { loadVersions } from '@/utils/bid-storage'
import { chain } from '@/utils/chain'
import { getContractAddresses } from '@/utils/env-config'
import { Pips } from '@/components/AuctionCard'
import BidPanel from '@/components/BidPanel'
import MaskPanel from '@/components/MaskPanel'
import CopyId from '@/components/CopyId'
import { AddressLink } from '@/components/Explorer'
import { KeyRetry } from '@/components/KeyRetry'
import { PictureControl, PictureHero, usePicture } from '@/components/AuctionPicture'
import AuctionExplainer, { explainerTitle } from '@/components/AuctionExplainer'
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
  const committee = useCommitteeKey(e3Id, phase === 'awaiting-key' || phase === 'bidding')

  const allowlist = useAllowlist(auction?.gate, e3Id)
  // A replaced picture has a new URL, so a cache cannot show the old one.
  const [pictureVersion, setPictureVersion] = useState<number | undefined>(undefined)
  const picture = usePicture(e3Id, pictureVersion)
  const location = useLocation()

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
        {error ? <div className='note bad'>Could not load the auction: {error}</div> : <AuctionSkeleton bare />}
      </div>
    )
  }
  if (auction === null) {
    return (
      <NotFound
        text={`There is no auction ${shortId(e3Id)} on this deployment.`}
        hint='Check the link. The auction may also belong to an earlier deployment of this app.'
      />
    )
  }
  if (phase === null) return <AuctionSkeleton />

  const { e3Program } = getContractAddresses()
  const isCreator = wallet.ready && sameAddress(auction.creator, wallet.address)
  // The create page navigates here with the error of a picture upload that failed after the auction was created.
  const pictureError = typeof location.state?.pictureError === 'string' ? location.state.pictureError : undefined
  const maxBidders = MAX_BIDDERS
  const gateKind = gateKindOf(auction.gate)

  return (
    <div className='page space-y-10'>
      <header className='space-y-4'>
        <nav className='breadcrumb' aria-label='Breadcrumb'>
          <Link to='/'>All auctions</Link>
          <span aria-hidden>/</span>
          <span aria-current='page'>Auction</span>
        </nav>
        <div className='flex flex-wrap items-start justify-between gap-4'>
          <div className='min-w-0 flex-1 space-y-3'>
            <div className='flex min-w-0 flex-wrap items-center gap-3'>
              <p className='mono muted'>{designOf(auction.auctionType).label}</p>
              <CopyId id={auction.e3Id} />
            </div>
            <h1 className='title'>{auction.title}</h1>
          </div>
          <div className='flex items-center gap-3'>
            <StatusBadge phase={phase} />
            <CopyLinkButton />
          </div>
        </div>
        <p className='lede'>{designOf(auction.auctionType).description}</p>
      </header>

      {picture.status !== 'loading' && (picture.status === 'present' || isCreator) && (
        <section className='space-y-3' aria-label='Picture'>
          {picture.status === 'present' && picture.url && <PictureHero url={picture.url} title={auction.title} />}
          {isCreator && wallet.address && (
            <PictureControl
              e3Id={auction.e3Id}
              account={wallet.address}
              hasPicture={picture.status === 'present'}
              initialError={pictureError}
              onUploaded={() => setPictureVersion(Date.now())}
            />
          )}
        </section>
      )}

      <dl className='card grid grid-cols-2 gap-x-6 gap-y-5 md:grid-cols-3 lg:grid-cols-4'>
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
        {hasProviders(auction.auctionType) && (
          <Fact label='Mask providers'>
            <span className='font-mono text-xs'>
              {maskCount(auction)}/{auction.providers.length} masks sent
            </span>
          </Fact>
        )}
        <Fact label='Ties'>The tied bidder who bid first wins. The tie is not revealed</Fact>
        <Fact label='Bidding'>
          {timeLeftLabel(auction, phase, now)}
          <span className='muted block text-xs font-normal'>Ends {formatDateTime(auction.inputWindow[1])}</span>
        </Fact>
        <Fact label={`${auction.prices.length} price steps`}>
          <details>
            <summary className='cursor-pointer font-mono'>
              {formatPrice(0, auction.prices)} – {formatPrice(auction.prices.length - 1, auction.prices)}
            </summary>
            <ol className='mt-1 space-y-0.5 font-mono text-xs'>
              {auction.prices.map((_, step) => (
                <li key={step}>
                  Step {step}: {formatPrice(step, auction.prices)}
                </li>
              ))}
            </ol>
          </details>
        </Fact>
        <Fact label='Created by'>
          <AddressLink address={auction.creator} />
        </Fact>
        <Fact label='Contract'>
          <AddressLink address={e3Program} />
        </Fact>
      </dl>

      {error && <div className='note bad'>Could not refresh the auction: {error}</div>}
      <KeyRetry error={committee.error} onRetry={committee.retry} />

      {hasProviders(auction.auctionType) && (
        <Section title='Mask providers'>
          <MaskPanel
            auction={auction}
            phase={phase}
            wallet={wallet}
            committeeKey={committee.key}
            keyError={committee.error}
            onSubmitted={onSubmitted}
          />
        </Section>
      )}

      <div className='grid items-start gap-8 lg:grid-cols-[1fr_1.25fr]'>
        <Section title='Progress'>
          <PhaseTimeline phase={phase} auction={auction} now={now} />
        </Section>
        <Section title='Your bid'>
          <BidPanel
            auction={auction}
            phase={phase}
            wallet={wallet}
            committeeKey={committee.key}
            keyError={committee.error}
            allowlist={allowlist}
            bidCount={bidCount}
            onSubmitted={onSubmitted}
          />
        </Section>
      </div>

      <Section title='Result'>
        {phase === 'complete' ? (
          <ResultPanel auction={auction} account={wallet.address} myVersions={myVersions} />
        ) : phase === 'failed' ? (
          <div role='alert' className='note bad'>
            There is no result: the auction failed.
            {auction.failureReason !== null && ` ${FAILURE_TEXT[auction.failureReason]}`}
          </div>
        ) : (
          <div role='status' className='note flex items-start gap-3'>
            <Spinner size={16} />
            <span>
              The result appears once the bidding window has closed, the program has computed over the encrypted bids and the committee has
              decrypted the outcome. That takes a few minutes after the window closes.
            </span>
          </div>
        )}
      </Section>

      <Section title={explainerTitle(auction.auctionType)}>
        <AuctionExplainer type={auction.auctionType} />
      </Section>
    </div>
  )
}

const Fact: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className='min-w-0'>
    <dt className='meta muted'>{label}</dt>
    <dd className='mt-1 text-sm font-medium'>{children}</dd>
  </div>
)

const CopyLinkButton: React.FC = () => {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const done = (next: 'copied' | 'failed') => {
    setState(next)
    setTimeout(() => setState('idle'), 2000)
  }
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(window.location.href).then(
          () => done('copied'),
          () => done('failed'),
        )
      }}
      className='btn ghost sm'
      aria-live='polite'
    >
      {state === 'copied' ? 'Link copied' : state === 'failed' ? 'Copy failed' : 'Copy link'}
    </button>
  )
}

const AuctionSkeleton: React.FC<{ bare?: boolean }> = ({ bare }) => {
  const body = (
    <>
      <span className='sr-only' role='status'>
        Loading the auction…
      </span>
      <div className='skeleton h-14 max-w-xl' aria-hidden />
      <div className='skeleton h-24' aria-hidden />
      <div className='skeleton h-64' aria-hidden />
    </>
  )
  return bare ? body : <div className='page space-y-6'>{body}</div>
}

const NotFound: React.FC<{ text: string; hint?: string }> = ({ text, hint }) => (
  <div className='page space-y-5'>
    <div className='note space-y-1'>
      <p>{text}</p>
      {hint && <p className='muted text-sm'>{hint}</p>}
    </div>
    <Link to='/' className='btn ghost'>
      Back to the auctions
    </Link>
  </div>
)

export default AuctionPage
