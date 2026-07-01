// SPDX-License-Identifier: LGPL-3.0-only

import type { ReactNode } from 'react'
import { motion } from 'framer-motion'
import { Activity, ExternalLink, RefreshCw, Wallet } from 'lucide-react'
import { PENDING_POLICY } from '../constants'
import { useLiftMotion } from '../hooks/useMotion'
import { bytes32Label, explorerLink, formatTokenAmount, shortAddress } from '../lib/format'
import type { BidRecord, EventRow, LockEntry, OnchainState, SaleDeployment } from '../types'

export function MotionCard({ children, className = 'panel', hover = true }: { children: ReactNode; className?: string; hover?: boolean }) {
  const lift = useLiftMotion()
  return (
    <motion.section className={className} {...(hover ? lift : {})}>
      {children}
    </motion.section>
  )
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return <span className='inline-spinner' role='status' aria-label={label} />
}

export function LoadingState({ title, detail }: { title: string; detail: string }) {
  return (
    <main className='loading-page'>
      <span className='loader-ring' />
      <h1>{title}</h1>
      <p>{detail}</p>
    </main>
  )
}

export function StatusPill({ status }: { status: string }) {
  const waiting = status === 'Scheduled' || status === 'Settling' || status === 'Loading'
  return (
    <span className={waiting ? 'status-pill status-pill--waiting' : 'status-pill'}>
      <span />
      {status}
    </span>
  )
}

export function WalletButton({
  account,
  chainId,
  targetChainId,
  onConnect,
  onSwitch,
}: {
  account?: string
  chainId?: number
  targetChainId: number
  onConnect(): Promise<void>
  onSwitch(): Promise<void>
}) {
  if (!account) {
    return (
      <button type='button' className='wallet-button' onClick={() => void onConnect()}>
        <Wallet size={15} />
        Connect
      </button>
    )
  }
  if (chainId !== targetChainId) {
    return (
      <button type='button' className='wallet-button' onClick={() => void onSwitch()}>
        <Wallet size={15} />
        Switch
      </button>
    )
  }
  return <span className='wallet-chip'>{shortAddress(account)}</span>
}

export function Metric({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div className='metric'>
      <span className='metric__label'>{label}</span>
      <strong className='metric__value'>{value}</strong>
      <span className='metric__note'>{note}</span>
    </div>
  )
}

export function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className='mini-stat'>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

export function FlowRail({ steps, activeIndex }: { steps: Array<{ label: string; value: string }>; activeIndex: number }) {
  return (
    <div className='flow-rail'>
      {steps.map((step, index) => (
        <div
          key={step.label}
          className={
            index === activeIndex ? 'flow-step flow-step--active' : index < activeIndex ? 'flow-step flow-step--done' : 'flow-step'
          }
        >
          <span />
          <strong>{step.label}</strong>
          <small>{step.value}</small>
        </div>
      ))}
    </div>
  )
}

export function LockList({ locks }: { locks: LockEntry[] }) {
  if (locks.length === 0) return <p className='muted'>No lock entries for the connected wallet.</p>
  return (
    <div className='lock-list'>
      {locks.map((entry, index) => (
        <div className='lock-row' key={`${entry.policyId}:${index}`}>
          <span>{entry.queued ? 'Queued' : 'Active'}</span>
          <strong>{bytes32Label(entry.policyId) || (entry.policyId === PENDING_POLICY ? 'PENDING' : entry.policyId)}</strong>
          <span>{formatTokenAmount(entry.amount)} FOLD</span>
        </div>
      ))}
    </div>
  )
}

export function BidList({
  bids,
  selectedBidId,
  setSelectedBidId,
  chainId,
}: {
  bids: BidRecord[]
  selectedBidId: string
  setSelectedBidId(value: string): void
  chainId: number
}) {
  if (bids.length === 0) return null
  return (
    <div className='bid-list'>
      {bids.map((bid) => (
        <button
          key={`${bid.id}:${bid.txHash}`}
          type='button'
          className={selectedBidId === bid.id ? 'bid-row bid-row--selected' : 'bid-row'}
          onClick={() => setSelectedBidId(bid.id)}
        >
          <span>#{bid.id}</span>
          <span>{bid.amount}</span>
          <a href={explorerLink(chainId, 'tx', bid.txHash)} target='_blank' rel='noreferrer' onClick={(event) => event.stopPropagation()}>
            {shortAddress(bid.txHash)}
          </a>
        </button>
      ))}
    </div>
  )
}

export function Field({
  label,
  value,
  setValue,
  inputMode,
  suffix,
}: {
  label: string
  value: string
  setValue(value: string): void
  inputMode?: 'decimal' | 'numeric' | 'text'
  suffix?: string
}) {
  return (
    <label>
      <span>{label}</span>
      <div className='field-shell'>
        <input value={value} inputMode={inputMode} onChange={(event) => setValue(event.target.value)} />
        {suffix && <small>{suffix}</small>}
      </div>
    </label>
  )
}

export function RolePill({ label, active }: { label: string; active: boolean }) {
  return <span className={active ? 'role-pill role-pill--on' : 'role-pill'}>{label}</span>
}

export function AddressRow({ label, value, chainId, tx }: { label: string; value: string; chainId: number; tx?: boolean }) {
  const href = explorerLink(chainId, tx ? 'tx' : 'address', value)
  return (
    <div className='address-row'>
      <span>{label}</span>
      {href ? (
        <a href={href} target='_blank' rel='noreferrer' className='mono'>
          {shortAddress(value)}
          <ExternalLink size={12} />
        </a>
      ) : (
        <code>{shortAddress(value)}</code>
      )}
    </div>
  )
}

export function DataItem({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </>
  )
}

export function EventsView({
  deployment,
  events,
  onRefresh,
  className = 'panel',
}: {
  deployment: SaleDeployment
  events: EventRow[]
  onRefresh(): void
  className?: string
}) {
  return (
    <MotionCard className={className}>
      <div className='panel__head'>
        <div>
          <p className='section-kicker'>
            <Activity size={14} />
            Event stream
          </p>
          <h2>FOLD and CCA activity</h2>
        </div>
        <button type='button' onClick={onRefresh}>
          <RefreshCw size={15} />
          Refresh
        </button>
      </div>
      <div className='event-list'>
        {events.length === 0 && <p className='muted'>No indexed events in the recent range.</p>}
        {events.map((event) => (
          <a
            key={event.id}
            className='event-row'
            href={explorerLink(deployment.chainId, 'tx', event.txHash)}
            target='_blank'
            rel='noreferrer'
          >
            <span className={`source-badge source-badge--${event.source.toLowerCase()}`}>{event.source}</span>
            <span>
              <strong>{event.title}</strong>
              <small>{event.detail}</small>
            </span>
            <span className='mono'>#{event.blockNumber}</span>
          </a>
        ))}
      </div>
    </MotionCard>
  )
}

export function ContractsView({ deployment, onchain }: { deployment: SaleDeployment; onchain?: OnchainState }) {
  return (
    <section className='workspace-grid'>
      <MotionCard className='panel'>
        <div className='panel__head'>
          <div>
            <p className='section-kicker'>
              <ExternalLink size={14} />
              Contracts
            </p>
            <h2>Deployment addresses</h2>
          </div>
        </div>
        <AddressRow label='FOLD' chainId={deployment.chainId} value={deployment.fold} />
        <AddressRow label='CCA auction' chainId={deployment.chainId} value={deployment.auction} />
        <AddressRow label='Foundation Safe' chainId={deployment.chainId} value={deployment.safe} />
        <AddressRow label='Sale deployer' chainId={deployment.chainId} value={deployment.saleDeployer} />
        <AddressRow label='Bonding registry' chainId={deployment.chainId} value={deployment.bondingRegistry} />
        {deployment.bondingRegistryProxyAdmin && (
          <AddressRow label='ProxyAdmin' chainId={deployment.chainId} value={deployment.bondingRegistryProxyAdmin} />
        )}
        {deployment.validationHook && <AddressRow label='Validation hook' chainId={deployment.chainId} value={deployment.validationHook} />}
        <AddressRow label='CCA factory' chainId={deployment.chainId} value={deployment.ccaFactory} />
        <AddressRow label='Deploy tx' chainId={deployment.chainId} value={deployment.txHash} tx />
      </MotionCard>
      <MotionCard className='panel'>
        <div className='panel__head'>
          <div>
            <p className='section-kicker'>
              <ExternalLink size={14} />
              Ownership
            </p>
            <h2>Who controls what</h2>
          </div>
        </div>
        <dl className='data-list data-list--wide'>
          <DataItem label='Deployer wallet' value={`${shortAddress(deployment.operator)} · gas only`} />
          <DataItem label='FOLD owner' value={shortAddress(onchain?.owner)} />
          <DataItem label='Pending FOLD owner' value={shortAddress(onchain?.pendingOwner)} />
          <DataItem label='ProxyAdmin owner' value={shortAddress(deployment.safe)} />
          <DataItem label='Validation hook owner' value={deployment.validationHook ? shortAddress(deployment.safe) : 'None'} />
          <DataItem label='Unsold tokens' value={shortAddress(deployment.auctionConfig?.tokensRecipient)} />
          <DataItem label='Funds recipient' value={shortAddress(deployment.auctionConfig?.fundsRecipient)} />
        </dl>
      </MotionCard>
    </section>
  )
}
