// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useCallback, useState } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { useNegotiation } from '@/hooks/useNegotiations'
import { useChainTime } from '@/hooks/useChainTime'
import { useCommitteeKey } from '@/hooks/useCommitteeKey'
import { useWallet } from '@/hooks/useWallet'
import { ROLE_NAMES, formatDateTime, formatLevel, formatPrice, phaseOf, roleOf, timeLeftLabel } from '@/utils/negotiation'
import { shortId } from '@/utils/format'
import { getContractAddresses } from '@/utils/env-config'
import CopyId from '@/components/CopyId'
import { AddressLink } from '@/components/Explorer'
import { PictureControl, PictureHero, usePicture } from '@/components/NegotiationPicture'
import OfferPanel from '@/components/OfferPanel'
import PhaseTimeline from '@/components/PhaseTimeline'
import ResultPanel from '@/components/ResultPanel'
import Section from '@/components/Section'
import StatusBadge from '@/components/StatusBadge'

const parseE3Id = (param: string | undefined): bigint | null => (param && /^\d+$/.test(param) ? BigInt(param) : null)

const NegotiationPage: React.FC = () => {
  const e3Id = parseE3Id(useParams().e3Id)
  const { negotiation, error, refresh } = useNegotiation(e3Id)
  const now = useChainTime()
  const wallet = useWallet()
  // A replaced picture has a new URL, so a cache cannot show the old one.
  const [pictureVersion, setPictureVersion] = useState<number | undefined>(undefined)
  const picture = usePicture(e3Id, pictureVersion)
  const location = useLocation()

  const phase = negotiation ? phaseOf(negotiation, now) : null
  const role = negotiation ? roleOf(negotiation, wallet.address) : null
  // The key is only needed to send an offer, and an offer needs it until the window closes.
  const needsKey =
    negotiation !== undefined &&
    negotiation !== null &&
    role !== null &&
    !negotiation.offered[ROLE_NAMES[role]] &&
    (phase === 'awaiting-key' || phase === 'offers')
  const committeeKey = useCommitteeKey(e3Id, needsKey)

  const onChanged = useCallback(() => void refresh(), [refresh])

  if (e3Id === null) return <NotFound text='This is not a valid negotiation id.' />
  if (negotiation === undefined) {
    return (
      <div className='page space-y-6'>
        {error ? (
          <div className='note bad'>Could not load the negotiation: {error}</div>
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
  if (negotiation === null) return <NotFound text={`There is no negotiation Nº ${shortId(e3Id)} on this deployment.`} />
  if (phase === null) return null

  const { e3Program } = getContractAddresses()
  const last = negotiation.levels - 1
  const isCreator = wallet.ready && wallet.address !== undefined && wallet.address.toLowerCase() === negotiation.creator.toLowerCase()
  // The create page can pass the error of a picture upload that failed after the negotiation was created.
  const pictureError = typeof location.state?.pictureError === 'string' ? location.state.pictureError : undefined

  return (
    <div className='page space-y-10'>
      <header className='space-y-4'>
        <nav className='breadcrumb' aria-label='Breadcrumb'>
          <Link to='/'>All negotiations</Link>
          <span aria-hidden>/</span>
          <span aria-current='page'>Negotiation</span>
        </nav>
        <div className='flex flex-wrap items-start justify-between gap-4'>
          <div className='min-w-0 flex-1 space-y-3'>
            <div className='flex min-w-0 flex-wrap items-center gap-3'>
              <p className='mono muted'>Sealed price negotiation</p>
              <CopyId id={negotiation.e3Id} />
            </div>
            <h1 className='title'>{negotiation.title}</h1>
          </div>
          <div className='flex items-center gap-3'>
            <StatusBadge phase={phase} />
            <CopyLinkButton />
          </div>
        </div>
        <p className='lede'>
          A seller and a buyer each send one sealed price. If the buyer&rsquo;s maximum is at least the seller&rsquo;s minimum, both learn
          one agreed price. Otherwise both learn only that there is no match.
        </p>
        {role !== null && (
          <p className='note ok'>
            You are the <strong>{ROLE_NAMES[role]}</strong> of this negotiation.
          </p>
        )}
      </header>

      {picture.status !== 'loading' && (picture.status === 'present' || isCreator) && (
        <section className='space-y-3' aria-label='Picture'>
          {picture.status === 'present' && picture.url && <PictureHero url={picture.url} title={negotiation.title} />}
          {isCreator && wallet.address && (
            <PictureControl
              e3Id={negotiation.e3Id}
              account={wallet.address}
              hasPicture={picture.status === 'present'}
              initialError={pictureError}
              onUploaded={() => setPictureVersion(Date.now())}
            />
          )}
        </section>
      )}

      <dl className='card grid grid-cols-2 gap-x-6 gap-y-5 md:grid-cols-3 lg:grid-cols-4'>
        <Fact label='Seller'>
          <AddressLink address={negotiation.seller} />
          <OfferMark sealed={negotiation.offered.seller} />
        </Fact>
        <Fact label='Buyer'>
          <AddressLink address={negotiation.buyer} />
          <OfferMark sealed={negotiation.offered.buyer} />
        </Fact>
        <Fact label='Time'>{timeLeftLabel(negotiation, phase, now)}</Fact>
        <Fact label='Offers close'>{formatDateTime(negotiation.inputWindow[1])}</Fact>
        <Fact label={`${negotiation.levels} price levels`}>
          <span
            className='font-mono'
            title={Array.from({ length: negotiation.levels }, (_, level) => formatLevel(negotiation, level)).join(', ')}
          >
            {formatLevel(negotiation, 0)} – {formatLevel(negotiation, last)}
          </span>
        </Fact>
        <Fact label='Step'>
          <span className='font-mono'>{formatPrice(negotiation, negotiation.stepPrice)}</span>
        </Fact>
        <Fact label='Created by'>
          <AddressLink address={negotiation.creator} />
        </Fact>
        <Fact label='Contract'>
          <AddressLink address={e3Program} />
        </Fact>
      </dl>

      {error && <div className='note bad'>Could not refresh the negotiation: {error}</div>}

      <div className='grid items-start gap-8 lg:grid-cols-[1fr_1.25fr]'>
        <Section eyebrow='Nº 01' title='Progress'>
          <PhaseTimeline phase={phase} negotiation={negotiation} />
        </Section>
        <Section eyebrow='Nº 02' title='Your offer'>
          <OfferPanel
            negotiation={negotiation}
            phase={phase}
            wallet={wallet}
            committeeKey={committeeKey}
            role={role}
            onSubmitted={onChanged}
          />
        </Section>
      </div>

      <Section eyebrow='Nº 03' title='Result'>
        <ResultPanel negotiation={negotiation} phase={phase} account={wallet.address} role={role} onSettled={onChanged} />
      </Section>
    </div>
  )
}

const Fact: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className='min-w-0'>
    <dt className='meta muted'>{label}</dt>
    <dd className='mt-1 space-y-1 text-sm font-medium'>{children}</dd>
  </div>
)

/** Whether a party has sent its offer. The chain shows this; the offer itself stays encrypted. */
const OfferMark: React.FC<{ sealed: boolean }> = ({ sealed }) => (
  <p className={`text-xs ${sealed ? 'text-brand-green' : 'text-muted'}`}>{sealed ? 'Offer sealed' : 'No offer yet'}</p>
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
      Back to the negotiations
    </Link>
  </div>
)

export default NegotiationPage
