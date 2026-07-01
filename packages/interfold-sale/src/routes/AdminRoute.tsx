// SPDX-License-Identifier: LGPL-3.0-only

import { motion } from 'framer-motion'
import { Activity, CheckCircle2, Coins, KeyRound, Link2, LockKeyhole, ShieldCheck } from 'lucide-react'
import { TOKEN_PHASES } from '../constants'
import { useRevealMotion } from '../hooks/useMotion'
import { deploymentRunLabel, formatTokenAmount, saleDisplayName, saleMetaLabel, shortAddress } from '../lib/format'
import type { EventRow, OnchainState, Profile, SaleDeployment } from '../types'
import { ContractsView, EventsView, Field, MiniStat, MotionCard, RolePill, Spinner } from '../components/ui'

interface AdminRouteProps {
  deployment: SaleDeployment
  onchain?: OnchainState
  account?: string
  profile: Profile
  setProfile(value: Profile | ((current: Profile) => Profile)): void
  profiles: Profile[]
  saveProfile(): void
  selectProfile(profile: Profile): void
  policy: Record<string, string>
  setPolicy(value: Record<string, string> | ((current: Record<string, string>) => Record<string, string>)): void
  whitelistValue: boolean
  setWhitelistValue(value: boolean): void
  exemptValue: boolean
  setExemptValue(value: boolean): void
  busy?: string
  onCreatePolicy(): void
  onMintAllocation(): void
  onLinkClaim(): void
  onWhitelist(): void
  onClaimExempt(): void
  onAcceptOwnership(): void
  onTge(): void
  events: EventRow[]
  onRefreshEvents(): void
}

export function AdminRoute({
  deployment,
  onchain,
  account,
  profile,
  setProfile,
  profiles,
  saveProfile,
  selectProfile,
  policy,
  setPolicy,
  whitelistValue,
  setWhitelistValue,
  exemptValue,
  setExemptValue,
  busy,
  onCreatePolicy,
  onMintAllocation,
  onLinkClaim,
  onWhitelist,
  onClaimExempt,
  onAcceptOwnership,
  onTge,
  events,
  onRefreshEvents,
}: AdminRouteProps) {
  const title = saleDisplayName(deployment)
  const reveal = useRevealMotion()
  return (
    <motion.div className='admin-route' initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.22 }}>
      <section className='admin-hero'>
        <div>
          <p className='eyebrow'>
            <ShieldCheck size={14} />
            FOLD token operations
          </p>
          <h1>Admin console</h1>
          <p>
            {title} · {saleMetaLabel(deployment)}
          </p>
          <p className='raw-deployment mono' title={deployment.name}>
            {deploymentRunLabel(deployment)}
          </p>
        </div>
        <AdminStatus deployment={deployment} onchain={onchain} account={account} />
      </section>

      <motion.section className='admin-metrics' {...reveal}>
        <MiniStat label='Token phase' value={TOKEN_PHASES[onchain?.phase ?? 0] ?? '-'} />
        <MiniStat label='FOLD supply' value={formatTokenAmount(onchain?.totalFoldSupply)} />
        <MiniStat label='Wallet FOLD' value={formatTokenAmount(onchain?.foldBalance)} />
        <MiniStat label='Transferable' value={formatTokenAmount(onchain?.transferableBalance)} />
        <MiniStat label='Bonded' value={formatTokenAmount(onchain?.totalBonded)} />
      </motion.section>

      <TokenLabView
        onchain={onchain}
        account={account}
        profile={profile}
        setProfile={setProfile}
        profiles={profiles}
        saveProfile={saveProfile}
        selectProfile={selectProfile}
        policy={policy}
        setPolicy={setPolicy}
        whitelistValue={whitelistValue}
        setWhitelistValue={setWhitelistValue}
        exemptValue={exemptValue}
        setExemptValue={setExemptValue}
        busy={busy}
        onCreatePolicy={onCreatePolicy}
        onMintAllocation={onMintAllocation}
        onLinkClaim={onLinkClaim}
        onWhitelist={onWhitelist}
        onClaimExempt={onClaimExempt}
        onAcceptOwnership={onAcceptOwnership}
        onTge={onTge}
      />
      <ContractsView deployment={deployment} onchain={onchain} />
      <EventsView deployment={deployment} events={events} onRefresh={onRefreshEvents} />
    </motion.div>
  )
}

function AdminStatus({ deployment, onchain, account }: { deployment: SaleDeployment; onchain?: OnchainState; account?: string }) {
  return (
    <MotionCard className='admin-status-card'>
      <span>Foundation Safe</span>
      <strong className='mono'>{shortAddress(deployment.safe)}</strong>
      <small>{onchain?.owner?.toLowerCase() === deployment.safe.toLowerCase() ? 'Accepted owner' : 'Ownership pending'}</small>
      <div className='role-strip'>
        <RolePill label='Connected' active={Boolean(account)} />
        <RolePill label='Admin' active={Boolean(onchain?.roles.admin)} />
        <RolePill label='Minter' active={Boolean(onchain?.roles.minter)} />
        <RolePill label='Lock manager' active={Boolean(onchain?.roles.lockManager)} />
      </div>
    </MotionCard>
  )
}

function BusyIcon({ busy, label }: { busy?: string; label: string }) {
  return busy === label ? <Spinner label={label} /> : null
}

function TokenLabView({
  onchain,
  account,
  profile,
  setProfile,
  profiles,
  saveProfile,
  selectProfile,
  policy,
  setPolicy,
  whitelistValue,
  setWhitelistValue,
  exemptValue,
  setExemptValue,
  busy,
  onCreatePolicy,
  onMintAllocation,
  onLinkClaim,
  onWhitelist,
  onClaimExempt,
  onAcceptOwnership,
  onTge,
}: {
  onchain?: OnchainState
  account?: string
  profile: Profile
  setProfile(value: Profile | ((current: Profile) => Profile)): void
  profiles: Profile[]
  saveProfile(): void
  selectProfile(profile: Profile): void
  policy: Record<string, string>
  setPolicy(value: Record<string, string> | ((current: Record<string, string>) => Record<string, string>)): void
  whitelistValue: boolean
  setWhitelistValue(value: boolean): void
  exemptValue: boolean
  setExemptValue(value: boolean): void
  busy?: string
  onCreatePolicy(): void
  onMintAllocation(): void
  onLinkClaim(): void
  onWhitelist(): void
  onClaimExempt(): void
  onAcceptOwnership(): void
  onTge(): void
}) {
  const canMint = Boolean(onchain?.roles.minter)
  const canLock = Boolean(onchain?.roles.lockManager)
  const canWhitelist = Boolean(onchain?.roles.whitelist)

  return (
    <section className='admin-workspace'>
      <MotionCard className='admin-card admin-card--profile'>
        <div className='panel__head'>
          <div>
            <p className='section-kicker'>
              <KeyRound size={14} />
              Profiles
            </p>
            <h2>Claims and allocations</h2>
          </div>
          <button type='button' onClick={saveProfile}>
            <CheckCircle2 size={15} />
            Save
          </button>
        </div>
        <div className='form-grid form-grid--three'>
          <Field label='Name' value={profile.name} setValue={(value) => setProfile((current) => ({ ...current, name: value }))} />
          <Field label='Account' value={profile.account} setValue={(value) => setProfile((current) => ({ ...current, account: value }))} />
          <Field
            label='Amount'
            value={profile.amount}
            setValue={(value) => setProfile((current) => ({ ...current, amount: value }))}
            inputMode='decimal'
            suffix='FOLD'
          />
          <Field
            label='Policy ID'
            value={profile.policyId}
            setValue={(value) => setProfile((current) => ({ ...current, policyId: value }))}
          />
          <Field label='Label' value={profile.label} setValue={(value) => setProfile((current) => ({ ...current, label: value }))} />
        </div>
        <div className='button-grid'>
          <button type='button' disabled={Boolean(busy) || !canLock} onClick={onLinkClaim}>
            <BusyIcon busy={busy} label='Link claim' />
            <Link2 size={15} />
            Link claim
          </button>
          <button type='button' disabled={Boolean(busy) || !canMint} onClick={onMintAllocation}>
            <BusyIcon busy={busy} label='Mint allocation' />
            <Coins size={15} />
            Mint allocation
          </button>
        </div>
        {profiles.length > 0 && (
          <div className='profile-list'>
            {profiles.map((item) => (
              <button key={item.id} type='button' className='profile-row' onClick={() => selectProfile(item)}>
                <span>{item.name}</span>
                <span className='mono'>{shortAddress(item.account)}</span>
                <span>{item.amount} FOLD</span>
              </button>
            ))}
          </div>
        )}
      </MotionCard>

      <MotionCard className='admin-card admin-card--policy'>
        <div className='panel__head'>
          <div>
            <p className='section-kicker'>
              <LockKeyhole size={14} />
              Vesting policy
            </p>
            <h2>Write-once lock</h2>
          </div>
        </div>
        <div className='form-grid form-grid--three'>
          <Field
            label='Policy ID'
            value={policy.policyId}
            setValue={(value) => setPolicy((current) => ({ ...current, policyId: value }))}
          />
          <Field
            label='Hold until'
            value={policy.holdUntil}
            setValue={(value) => setPolicy((current) => ({ ...current, holdUntil: value }))}
            inputMode='numeric'
          />
          <label>
            <span>Anchor</span>
            <select value={policy.anchor} onChange={(event) => setPolicy((current) => ({ ...current, anchor: event.target.value }))}>
              <option value='1'>TGE</option>
              <option value='0'>Absolute</option>
            </select>
          </label>
          <Field
            label='Absolute start'
            value={policy.start}
            setValue={(value) => setPolicy((current) => ({ ...current, start: value }))}
            inputMode='numeric'
          />
          <Field
            label='Cliff seconds'
            value={policy.cliffDuration}
            setValue={(value) => setPolicy((current) => ({ ...current, cliffDuration: value }))}
            inputMode='numeric'
          />
          <Field
            label='Vest seconds'
            value={policy.vestDuration}
            setValue={(value) => setPolicy((current) => ({ ...current, vestDuration: value }))}
            inputMode='numeric'
          />
        </div>
        <button className='primary-button' type='button' disabled={Boolean(busy) || !canLock} onClick={onCreatePolicy}>
          <BusyIcon busy={busy} label='Policy' />
          <LockKeyhole size={16} />
          Create policy
        </button>
      </MotionCard>

      <MotionCard className='admin-card admin-card--controls'>
        <div className='panel__head'>
          <div>
            <p className='section-kicker'>
              <ShieldCheck size={14} />
              Transfer controls
            </p>
            <h2>Whitelist and exemptions</h2>
          </div>
        </div>
        <div className='toggle-grid'>
          <label className='toggle-row'>
            <input type='checkbox' checked={whitelistValue} onChange={(event) => setWhitelistValue(event.target.checked)} />
            <span>Transfer whitelisted</span>
          </label>
          <button type='button' disabled={Boolean(busy) || !canWhitelist} onClick={onWhitelist}>
            <BusyIcon busy={busy} label='Whitelist' />
            <ShieldCheck size={15} />
            Set whitelist
          </button>
          <label className='toggle-row'>
            <input type='checkbox' checked={exemptValue} onChange={(event) => setExemptValue(event.target.checked)} />
            <span>Claim-lock exempt</span>
          </label>
          <button type='button' disabled={Boolean(busy) || !canLock} onClick={onClaimExempt}>
            <BusyIcon busy={busy} label='Claim exemption' />
            <ShieldCheck size={15} />
            Set exemption
          </button>
        </div>
      </MotionCard>

      <MotionCard className='admin-card admin-card--launch'>
        <div className='panel__head'>
          <div>
            <p className='section-kicker'>
              <Activity size={14} />
              Launch actions
            </p>
            <h2>Ownership and TGE</h2>
          </div>
        </div>
        <div className='button-grid'>
          <button type='button' disabled={Boolean(busy)} onClick={onAcceptOwnership}>
            <BusyIcon busy={busy} label='Accept ownership' />
            <CheckCircle2 size={15} />
            Accept ownership
          </button>
          <button type='button' disabled={Boolean(busy)} onClick={onTge}>
            <BusyIcon busy={busy} label='TGE' />
            <Activity size={15} />
            Trigger TGE
          </button>
        </div>
        <p className='muted'>Connected wallet: {account ? shortAddress(account) : '-'}</p>
      </MotionCard>
    </section>
  )
}
