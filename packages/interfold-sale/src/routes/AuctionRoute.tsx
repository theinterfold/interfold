// SPDX-License-Identifier: LGPL-3.0-only

import { motion } from 'framer-motion'
import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  Coins,
  Gavel,
  LockKeyhole,
  Route as RouteIcon,
  ShieldCheck,
  Timer,
  Wallet,
} from 'lucide-react'
import { TOKEN_PHASES } from '../constants'
import { useRevealMotion } from '../hooks/useMotion'
import { blockProgress, ccaStatusIndex, predicateHookAddress, statusLine } from '../lib/auction'
import { currencyDisplay, formatAmount, formatIntegerCompact, formatTokenAmount, saleDisplayName, saleMetaLabel } from '../lib/format'
import type { AuctionConfig, AuctionStep, BidRecord, EventRow, OnchainState, SaleDeployment } from '../types'
import { BidList, DataItem, EventsView, Field, FlowRail, LockList, Metric, MiniStat, MotionCard, StatusPill } from '../components/ui'

interface AuctionRouteProps {
  deployment: SaleDeployment
  onchain?: OnchainState
  auctionConfig?: AuctionConfig
  status: string
  scheduleSteps: AuctionStep[]
  bidAmount: string
  setBidAmount(value: string): void
  maxPrice: string
  setMaxPrice(value: string): void
  selectedBidId: string
  setSelectedBidId(value: string): void
  bids: BidRecord[]
  busy?: string
  account?: string
  isCorrectNetwork: boolean
  onConnect(): void
  onSwitchNetwork(): void
  onSubmitBid(): void
  onCheckpoint(): void
  onExit(): void
  onClaim(): void
  events: EventRow[]
  onRefreshEvents(): void
}

function parseBigIntInput(value: string): bigint | undefined {
  const trimmed = value.trim()
  if (!/^\d+$/.test(trimmed)) return undefined
  return BigInt(trimmed)
}

function floorAndTick(auctionConfig?: AuctionConfig): { floor?: bigint; tick?: bigint } {
  if (!auctionConfig) return {}
  return {
    floor: BigInt(auctionConfig.floorPrice),
    tick: BigInt(auctionConfig.tickSpacing),
  }
}

function priceTicks(value: string, auctionConfig?: AuctionConfig): string {
  const price = parseBigIntInput(value)
  const { floor, tick } = floorAndTick(auctionConfig)
  if (price === undefined || floor === undefined || tick === undefined || tick === 0n || price < floor) return ''
  return ((price - floor) / tick).toString()
}

function isLimitPriceUsable(value: string, auctionConfig?: AuctionConfig): boolean {
  const price = parseBigIntInput(value)
  if (price === undefined) return false
  const { floor } = floorAndTick(auctionConfig)
  return floor === undefined || price >= floor
}

export function AuctionRoute({
  deployment,
  onchain,
  auctionConfig,
  status,
  scheduleSteps,
  bidAmount,
  setBidAmount,
  maxPrice,
  setMaxPrice,
  selectedBidId,
  setSelectedBidId,
  bids,
  busy,
  account,
  isCorrectNetwork,
  onConnect,
  onSwitchNetwork,
  onSubmitBid,
  onCheckpoint,
  onExit,
  onClaim,
  events,
  onRefreshEvents,
}: AuctionRouteProps) {
  const currency = onchain?.currencySymbol ?? currencyDisplay(auctionConfig?.currency)
  const progress = blockProgress(onchain?.blockNumber, auctionConfig)
  const title = saleDisplayName(deployment)
  const predicateEnabled = Boolean(predicateHookAddress(deployment, auctionConfig))
  const reveal = useRevealMotion()
  const revealLate = useRevealMotion(0.08)
  return (
    <motion.div className='auction-route' initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.24 }}>
      <section className='auction-hero'>
        <div className='auction-hero__intro'>
          <div className='hero-status-row'>
            <p className='eyebrow'>
              <Gavel size={14} />
              Interfold FOLD
            </p>
            <StatusPill status={status} />
          </div>
          <h1>{title}</h1>
          <p>{saleMetaLabel(deployment)}</p>
          <div className='auction-progress' aria-label='Auction progress'>
            <motion.span animate={{ width: `${progress}%` }} transition={{ duration: 0.42, ease: 'easeOut' }} />
          </div>
          <div className='auction-status-copy'>
            <strong>{statusLine(status, onchain?.blockNumber, auctionConfig)}</strong>
            <span className='mono' title={deployment.name}>
              {deployment.name.match(/(\d{8,})$/)?.[1] ? `Run ${deployment.name.match(/(\d{8,})$/)?.[1]?.slice(-6)}` : deployment.name}
            </span>
          </div>
          <div className='auction-hero__facts'>
            <MiniStat label='Sale supply' value={`${formatTokenAmount(BigInt(deployment.saleAmount))} FOLD`} />
            <MiniStat label='Raised' value={`${formatAmount(onchain?.currencyRaised, onchain?.currencyDecimals ?? 18)} ${currency}`} />
            <MiniStat
              label='Wallet currency'
              value={`${formatAmount(onchain?.currencyBalance, onchain?.currencyDecimals ?? 18)} ${currency}`}
            />
          </div>
        </div>

        <AuctionView
          deployment={deployment}
          auctionConfig={auctionConfig}
          onchain={onchain}
          status={status}
          bidAmount={bidAmount}
          setBidAmount={setBidAmount}
          maxPrice={maxPrice}
          setMaxPrice={setMaxPrice}
          selectedBidId={selectedBidId}
          setSelectedBidId={setSelectedBidId}
          bids={bids}
          busy={busy}
          account={account}
          isCorrectNetwork={isCorrectNetwork}
          onConnect={onConnect}
          onSwitchNetwork={onSwitchNetwork}
          onSubmitBid={onSubmitBid}
          onCheckpoint={onCheckpoint}
          onExit={onExit}
          onClaim={onClaim}
        />
      </section>

      <section className='auction-floor'>
        <motion.section className='auction-metrics' {...reveal}>
          <Metric label='FOLD Supply' value={formatTokenAmount(onchain?.totalFoldSupply)} note='minted total' />
          <Metric label='Wallet FOLD' value={formatTokenAmount(onchain?.foldBalance)} note={`${onchain?.lockCount ?? 0n} active locks`} />
          <Metric label='Transferable' value={formatTokenAmount(onchain?.transferableBalance)} note='after locks and bond' />
          <Metric label='Token Phase' value={TOKEN_PHASES[onchain?.phase ?? 0] ?? '-'} note='timestamp clock' />
          <Metric label='Current Block' value={onchain?.blockNumber?.toString() ?? '-'} note='CCA block clock' />
        </motion.section>

        <motion.div
          className={predicateEnabled ? 'auction-floor__grid' : 'auction-floor__grid auction-floor__grid--compact'}
          {...revealLate}
        >
          <div className='auction-floor__main'>
            <AuctionBlockPanel auctionConfig={auctionConfig} onchain={onchain} status={status} />
            <SchedulePanel auctionConfig={auctionConfig} steps={scheduleSteps} />
            <EventsView
              deployment={deployment}
              events={events.slice(0, 12)}
              onRefresh={onRefreshEvents}
              className='console-panel console-panel--events'
            />
          </div>
          <aside className='auction-floor__side'>
            {predicateEnabled && <PredicatePanel deployment={deployment} auctionConfig={auctionConfig} />}
            <WalletFoldPanel onchain={onchain} />
          </aside>
        </motion.div>
      </section>
    </motion.div>
  )
}

function AuctionBlockPanel({ auctionConfig, onchain, status }: { auctionConfig?: AuctionConfig; onchain?: OnchainState; status: string }) {
  return (
    <MotionCard className='console-panel console-panel--clock'>
      <div className='panel__head'>
        <div>
          <p className='section-kicker'>
            <Timer size={14} />
            CCA block clock
          </p>
          <h2>{status}</h2>
        </div>
      </div>
      <FlowRail
        steps={[
          { label: 'Scheduled', value: `before #${auctionConfig?.startBlock ?? '-'}` },
          { label: 'Live', value: `#${auctionConfig?.startBlock ?? '-'} - #${auctionConfig?.endBlock ?? '-'}` },
          { label: 'Settle', value: `until #${auctionConfig?.claimBlock ?? '-'}` },
          { label: 'Claim', value: `from #${auctionConfig?.claimBlock ?? '-'}` },
        ]}
        activeIndex={ccaStatusIndex(onchain?.blockNumber, auctionConfig)}
      />
      <dl className='data-list data-list--wide'>
        <DataItem label='Current block' value={onchain?.blockNumber?.toString() ?? '-'} />
        <DataItem label='Start' value={auctionConfig?.startBlock ?? '-'} />
        <DataItem label='End' value={auctionConfig?.endBlock ?? '-'} />
        <DataItem label='Claim' value={auctionConfig?.claimBlock ?? '-'} />
      </dl>
    </MotionCard>
  )
}

function WalletFoldPanel({ onchain }: { onchain?: OnchainState }) {
  return (
    <MotionCard className='console-panel console-panel--wallet'>
      <div className='panel__head'>
        <div>
          <p className='section-kicker'>
            <LockKeyhole size={14} />
            Wallet FOLD
          </p>
          <h2>Balance and locks</h2>
        </div>
      </div>
      <div className='balance-grid'>
        <MiniStat label='Balance' value={formatTokenAmount(onchain?.foldBalance)} />
        <MiniStat label='Locked' value={formatTokenAmount(onchain?.lockedBalance)} />
        <MiniStat label='Transferable' value={formatTokenAmount(onchain?.transferableBalance)} />
        <MiniStat label='Bonded' value={formatTokenAmount(onchain?.totalBonded)} />
      </div>
      <LockList locks={onchain?.locks ?? []} />
    </MotionCard>
  )
}

function SchedulePanel({ auctionConfig, steps }: { auctionConfig?: AuctionConfig; steps: AuctionStep[] }) {
  const totalBlocks = steps.reduce((sum, step) => sum + step.blockDelta, 0n)
  const totalMps = steps.reduce((sum, step) => sum + step.supply, 0n)
  return (
    <MotionCard className='console-panel console-panel--schedule'>
      <div className='panel__head'>
        <div>
          <p className='section-kicker'>
            <RouteIcon size={14} />
            Auction steps
          </p>
          <h2>{steps.length ? `${steps.length} phases` : 'No schedule'}</h2>
        </div>
      </div>
      {steps.length > 0 && (
        <>
          <div className='schedule-bars'>
            {steps.map((step) => (
              <span
                key={step.index}
                title={`Phase ${step.index}: ${step.blockDelta} blocks, ${step.mps} MPS`}
                style={{ flexGrow: Number(step.blockDelta) }}
              />
            ))}
          </div>
          <dl className='data-list data-list--wide'>
            <DataItem label='Encoded total' value={`${totalMps.toString()} MPS`} />
            <DataItem label='Block coverage' value={`${totalBlocks.toString()} blocks`} />
            <DataItem label='Auction window' value={`${auctionConfig?.startBlock ?? '-'} - ${auctionConfig?.endBlock ?? '-'}`} />
          </dl>
          <div className='schedule-list'>
            {steps.slice(0, 6).map((step) => (
              <div key={step.index} className='schedule-row'>
                <span>#{step.index}</span>
                <strong>{step.blockDelta.toString()} blocks</strong>
                <small>{step.mps.toString()} MPS</small>
              </div>
            ))}
            {steps.length > 6 && <p className='muted'>+ {steps.length - 6} more phases</p>}
          </div>
        </>
      )}
    </MotionCard>
  )
}

function PredicatePanel({ deployment, auctionConfig }: { deployment: SaleDeployment; auctionConfig?: AuctionConfig }) {
  const hook = predicateHookAddress(deployment, auctionConfig)
  if (!hook) return null
  return (
    <MotionCard className='console-panel console-panel--predicate'>
      <div className='panel__head'>
        <div>
          <p className='section-kicker'>
            <ShieldCheck size={14} />
            Predicate gate
          </p>
          <h2>Enabled</h2>
        </div>
      </div>
      <dl className='data-list data-list--wide'>
        <DataItem label='Validation hook' value={hook.slice(0, 6) + '...' + hook.slice(-4)} />
        <DataItem
          label='Registry'
          value={
            deployment.predicateRegistry ? deployment.predicateRegistry.slice(0, 6) + '...' + deployment.predicateRegistry.slice(-4) : '-'
          }
        />
        <DataItem label='Policy ID' value={deployment.predicatePolicyID ?? '-'} />
        <DataItem label='Owner binding' value={deployment.predicateRequireSenderIsOwner === false ? 'Delegated' : 'Sender = owner'} />
      </dl>
    </MotionCard>
  )
}

function LimitPriceControl({
  auctionConfig,
  value,
  setValue,
}: {
  auctionConfig?: AuctionConfig
  value: string
  setValue(value: string): void
}) {
  const { floor, tick } = floorAndTick(auctionConfig)
  const price = parseBigIntInput(value)
  const tickValue = priceTicks(value, auctionConfig)
  const belowFloor = floor !== undefined && price !== undefined && price < floor
  const offTick =
    floor !== undefined && tick !== undefined && tick > 0n && price !== undefined && price >= floor && (price - floor) % tick !== 0n

  const setTicks = (nextTicks: string) => {
    if (floor === undefined || tick === undefined) return
    const clean = nextTicks.replace(/[^\d]/g, '')
    const ticks = BigInt(clean || '0')
    setValue((floor + ticks * tick).toString())
  }

  const setPreset = (ticks: bigint) => {
    if (floor === undefined || tick === undefined) return
    setValue((floor + ticks * tick).toString())
  }

  return (
    <div className='price-picker'>
      <div className='price-picker__summary'>
        <MiniStat label='Floor' value={formatIntegerCompact(floor)} />
        <MiniStat label='Tick size' value={formatIntegerCompact(tick)} />
      </div>

      <div className='form-grid'>
        <label>
          <span>Ticks above floor</span>
          <div className='field-shell'>
            <input value={tickValue} inputMode='numeric' onChange={(event) => setTicks(event.target.value)} />
            <small>ticks</small>
          </div>
        </label>
        <Field label='Raw limit price' value={value} setValue={(next) => setValue(next.replace(/[^\d]/g, ''))} inputMode='numeric' />
      </div>

      <div className='price-presets'>
        {[0n, 1n, 5n, 10n].map((ticks) => (
          <button
            key={ticks.toString()}
            type='button'
            onClick={() => setPreset(ticks)}
            disabled={floor === undefined || tick === undefined}
          >
            {ticks === 0n ? 'At floor' : `+${ticks.toString()} ticks`}
          </button>
        ))}
      </div>

      <p className={belowFloor ? 'price-note price-note--bad' : 'price-note'}>
        {belowFloor
          ? 'Below floor'
          : offTick
            ? 'Between ticks'
            : tickValue
              ? `Floor + ${tickValue} tick${tickValue === '1' ? '' : 's'}`
              : 'Set a price level'}
      </p>
    </div>
  )
}

function AuctionView({
  deployment,
  auctionConfig,
  onchain,
  status,
  bidAmount,
  setBidAmount,
  maxPrice,
  setMaxPrice,
  selectedBidId,
  setSelectedBidId,
  bids,
  busy,
  account,
  isCorrectNetwork,
  onConnect,
  onSwitchNetwork,
  onSubmitBid,
  onCheckpoint,
  onExit,
  onClaim,
}: {
  deployment: SaleDeployment
  auctionConfig?: AuctionConfig
  onchain?: OnchainState
  status: string
  bidAmount: string
  setBidAmount(value: string): void
  maxPrice: string
  setMaxPrice(value: string): void
  selectedBidId: string
  setSelectedBidId(value: string): void
  bids: BidRecord[]
  busy?: string
  account?: string
  isCorrectNetwork: boolean
  onConnect(): void
  onSwitchNetwork(): void
  onSubmitBid(): void
  onCheckpoint(): void
  onExit(): void
  onClaim(): void
}) {
  const symbol = onchain?.currencySymbol ?? currencyDisplay(auctionConfig?.currency)
  const limitPriceOk = isLimitPriceUsable(maxPrice, auctionConfig)
  const primaryAction = !account ? onConnect : !isCorrectNetwork ? onSwitchNetwork : onSubmitBid
  const canUsePrimary = !busy && (!account || !isCorrectNetwork || (status === 'Live' && limitPriceOk))
  const buttonLabel = !account
    ? 'Connect wallet'
    : !isCorrectNetwork
      ? 'Switch network'
      : status === 'Scheduled'
        ? 'Auction not live'
        : status === 'Settling' || status === 'Claim Open'
          ? 'Bidding closed'
          : !limitPriceOk
            ? 'Set limit price'
            : busy || 'Place bid'
  const ButtonIcon = !account || !isCorrectNetwork ? Wallet : Coins
  return (
    <section className='bid-ticket panel'>
      <div className='panel__head'>
        <div>
          <p className='section-kicker'>
            <Coins size={14} />
            Bid ticket
          </p>
          <h2>{status}</h2>
        </div>
      </div>
      <div className='ticket-balance'>
        <span>Available</span>
        <strong>
          {formatAmount(onchain?.currencyBalance, onchain?.currencyDecimals ?? 18)} {symbol}
        </strong>
      </div>
      <Field label='Bid amount' value={bidAmount} setValue={setBidAmount} inputMode='decimal' suffix={symbol} />
      <LimitPriceControl auctionConfig={auctionConfig} value={maxPrice} setValue={setMaxPrice} />
      <button className='primary-button primary-button--large' type='button' disabled={!canUsePrimary} onClick={primaryAction}>
        <ButtonIcon size={16} />
        {buttonLabel}
      </button>

      <div className='divider' />
      <div className='claim-tools'>
        <Field label='Bid ID' value={selectedBidId} setValue={setSelectedBidId} inputMode='numeric' />
        <div className='claim-actions'>
          <button type='button' disabled={!selectedBidId || Boolean(busy)} onClick={onCheckpoint}>
            <Activity size={15} />
            Checkpoint
          </button>
          <button type='button' disabled={!selectedBidId || Boolean(busy)} onClick={onExit}>
            <ArrowUpRight size={15} />
            Exit
          </button>
          <button type='button' disabled={!selectedBidId || Boolean(busy)} onClick={onClaim}>
            <CheckCircle2 size={15} />
            Claim
          </button>
        </div>
      </div>
      <BidList bids={bids} selectedBidId={selectedBidId} setSelectedBidId={setSelectedBidId} chainId={deployment.chainId} />
    </section>
  )
}
