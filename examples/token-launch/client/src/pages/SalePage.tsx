// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { MAX_BIDDERS } from '@interfold/token-launch'
import { useBidLog } from '@/hooks/useBidLog'
import { useChainTime } from '@/hooks/useChainTime'
import { useCommitteeKey } from '@/hooks/useCommitteeKey'
import { useSale } from '@/hooks/useSales'
import { useSecrets } from '@/hooks/useSecrets'
import { useSettlement } from '@/hooks/useSettlement'
import { useWallet } from '@/hooks/useWallet'
import { Phase, isRefundPhase } from '@/utils/phase'
import { formatBudget, formatDateTime, formatPayment, formatSaleTokens, formatStepPrice, timeLeftLabel } from '@/utils/sale'
import { getContractAddresses } from '@/utils/env-config'
import BidPanel from '@/components/BidPanel'
import ClaimPanel from '@/components/ClaimPanel'
import CreatorPanel from '@/components/CreatorPanel'
import { AddressLink } from '@/components/Explorer'
import PhaseTimeline from '@/components/PhaseTimeline'
import RefundPanel from '@/components/RefundPanel'
import ResultPanel from '@/components/ResultPanel'
import Section from '@/components/Section'
import StatusBadge from '@/components/StatusBadge'

const parseSaleId = (param: string | undefined): bigint | null => (param && /^\d+$/.test(param) ? BigInt(param) : null)

const SalePage: React.FC = () => {
  const saleId = parseSaleId(useParams().saleId)
  const { sale, error, refresh } = useSale(saleId)
  const now = useChainTime()
  const wallet = useWallet()

  const bidding = sale?.phase === Phase.Bidding
  const ended = sale !== undefined && sale !== null && sale.phase >= Phase.Cleared
  // The bids are polled while bidding runs. After it they are read once: the claim tree needs them.
  const { bids, refresh: refreshBids } = useBidLog(saleId, bidding)
  const secrets = useSecrets(saleId ?? 0n, bids)
  const reloadSecrets = secrets.reload
  const { settlement, refresh: refreshSettlement } = useSettlement(saleId ?? 0n, ended)
  // Both keys are only needed to bid, and bidding needs them until the window closes.
  const key1 = useCommitteeKey(saleId, bidding)
  const key2 = useCommitteeKey(sale?.roundTwoId ?? null, bidding)

  const onChanged = React.useCallback(() => {
    refreshBids()
    refreshSettlement()
    reloadSecrets()
    void refresh()
  }, [refreshBids, refreshSettlement, reloadSecrets, refresh])

  if (saleId === null) return <NotFound text='This is not a valid sale id.' />
  if (sale === undefined) {
    return (
      <div className='page space-y-6'>
        {error ? (
          <div className='note bad'>Could not load the sale: {error}</div>
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
  if (sale === null) return <NotFound text={`There is no sale Nº ${saleId} on this deployment.`} />

  const { e3Program } = getContractAddresses()
  const isCreator = wallet.address !== undefined && wallet.address.toLowerCase() === sale.creator.toLowerCase()
  const saleUnit = 10n ** BigInt(sale.saleToken.decimals)
  const myStep = secrets.held.find((entry) => entry.confirmed)?.secret.step ?? null
  const stopped = isRefundPhase(sale.phase)
  const showClaim = sale.phase === Phase.Cleared
  const showCreator = isCreator && (sale.phase >= Phase.Cleared || sale.roundTwoId === null)

  return (
    <div className='page space-y-10'>
      <header className='space-y-4'>
        <Link to='/' className='linkish'>
          All sales
        </Link>
        <div className='flex flex-wrap items-start justify-between gap-4'>
          <div className='min-w-0 space-y-3'>
            <p className='mono muted'>Sale Nº {sale.saleId.toString().padStart(3, '0')} · private budget and max price</p>
            <h1 className='h1'>{sale.title}</h1>
          </div>
          <div className='flex items-center gap-3'>
            <StatusBadge phase={sale.phase} waitingForKeys={!sale.keysReady} />
            <CopyLinkButton />
          </div>
        </div>
        <p className='lede'>
          {formatSaleTokens(sale, sale.supply)} for sale. A bid locks an escrow tier and keeps its budget and its max price private. The
          sale clears at one price for everyone.
        </p>
      </header>

      <dl className='card grid grid-cols-2 gap-x-6 gap-y-5 !p-5 md:grid-cols-3 lg:grid-cols-4'>
        <Fact label='Bids'>
          <span className='font-mono text-xs'>
            {sale.bidCount}/{MAX_BIDDERS}
          </span>
        </Fact>
        <Fact label='Escrow tiers'>
          <span className='font-mono text-xs'>{sale.tiers.map((units) => formatBudget(sale, units)).join(' · ')}</span>
        </Fact>
        <Fact label='Time'>{timeLeftLabel(sale, now)}</Fact>
        <Fact label='Bidding ends'>{formatDateTime(sale.inputWindow[1])}</Fact>
        <Fact label={`${sale.levels} price steps`}>
          <span className='font-mono' title={sale.prices.map((_, step) => formatStepPrice(sale, step)).join(', ')}>
            {formatStepPrice(sale, 0)} – {formatStepPrice(sale, sale.levels - 1)} {sale.paymentToken.symbol}
          </span>
        </Fact>
        <Fact label='Budget unit'>
          <span className='font-mono'>{formatPayment(sale, sale.budgetUnit)}</span>
        </Fact>
        <Fact label='Most one unit buys'>
          <span className='font-mono'>{formatSaleTokens(sale, (sale.budgetUnit * saleUnit) / sale.prices[0])}</span>
        </Fact>
        <Fact label='Least one unit buys'>
          <span className='font-mono'>{formatSaleTokens(sale, (sale.budgetUnit * saleUnit) / sale.prices[sale.levels - 1])}</span>
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
        <Fact label='E3 runs'>
          <span className='font-mono text-xs'>
            round 1: {sale.saleId.toString()} · round 2: {sale.roundTwoId === null ? 'not requested' : sale.roundTwoId.toString()}
          </span>
        </Fact>
      </dl>

      {error && <div className='note bad'>Could not refresh the sale: {error}</div>}

      <div className='grid items-start gap-8 lg:grid-cols-[1fr_1.25fr]'>
        <Section eyebrow='Nº 01' title='Progress'>
          <PhaseTimeline sale={sale} />
        </Section>
        <Section eyebrow='Nº 02' title='Your bid'>
          {sale.phase === Phase.Bidding || secrets.held.length > 0 ? (
            <BidPanel
              sale={sale}
              wallet={wallet}
              keys={{ round1: key1, round2: key2 }}
              bids={bids}
              secrets={secrets}
              now={now}
              onSubmitted={onChanged}
            />
          ) : (
            <div className='note'>Bidding is closed.</div>
          )}
        </Section>
      </div>

      <Section eyebrow='Nº 03' title='Result'>
        <ResultPanel sale={sale} myStep={myStep} onChanged={onChanged} />
      </Section>

      {(showClaim || stopped) && (
        <Section eyebrow='Nº 04' title={showClaim ? 'Claim' : 'Refunds'}>
          {showClaim && <ClaimPanel sale={sale} account={wallet.address} secrets={secrets} bids={bids} />}
          <RefundPanel sale={sale} account={wallet.address} bids={bids} held={secrets.held} settlement={settlement} onChanged={onChanged} />
          {stopped && secrets.held.length === 0 && (
            <p className='muted text-sm'>
              Connect the wallet that bid to see its refunds. Anyone can send a refund; the funds go to the bidder.
            </p>
          )}
        </Section>
      )}

      {showCreator && (
        <Section eyebrow='Nº 05' title='Creator'>
          <CreatorPanel sale={sale} account={wallet.address} settlement={settlement} onChanged={onChanged} />
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
      Back to the sales
    </Link>
  </div>
)

export default SalePage
