// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import test from 'node:test'
import { renderToStaticMarkup } from 'react-dom/server'
import type { Address } from 'viem'
import { CommitteeRewardsView, IdentityView, ManagePosition, positionActions, ticketBurnAmount, type IdentityService } from './Operator'
import { CONTRACTS, E3Stage, FEE_TOKEN } from './lib/chain'
import type { BondingConfig, OperatorStatus } from './lib/bonding'
import { claimPlan, summarizeRewards, type CommitteeSeat, type SeatStatus } from './lib/rewards'
import { buildProofBundle, dateInput, identityStatusText, parseDateInput, type OwnerAccount, type VerifierConfig } from './lib/identity'
import { pad, toHex, type Hex } from 'viem'

const OPERATOR = '0x1111111111111111111111111111111111111111' as Address
const OWNER = '0x2222222222222222222222222222222222222222' as Address
const PROPOSED = '0x3333333333333333333333333333333333333333' as Address
const OTHER = '0x4444444444444444444444444444444444444444' as Address
const UNIT = 10n ** 18n

const config: BondingConfig = {
  ciphernodeBondToken: OTHER,
  ciphernodeBondSymbol: 'FOLD',
  ciphernodeBondDecimals: 18,
  ticketToken: OTHER,
  ticketBase: OTHER,
  ticketSymbol: 'USDS',
  ticketDecimals: 18,
  requiredCiphernodeBond: 1000n * UNIT,
  ticketPrice: UNIT,
  minTicketBalance: 5n,
  exitDelay: 604_800n,
}

function position(overrides: Partial<OperatorStatus> = {}): OperatorStatus {
  return {
    bondOwner: OWNER,
    pendingBondOwner: null,
    ciphernodeBond: 1000n * UNIT,
    ticketBalance: 5n * UNIT,
    availableTickets: 5n,
    bonded: true,
    registered: true,
    active: true,
    eligible: true,
    exitInProgress: false,
    pendingTicketExit: 0n,
    pendingBondExit: 0n,
    claimableTicket: 0n,
    claimableBond: 0n,
    ...overrides,
  }
}

test('the bond owner sends every position change, and the operator key can only deregister', () => {
  const owner = positionActions(position(), OPERATOR, OWNER)
  assert.deepEqual([owner.refresh, owner.burn, owner.unbond, owner.deregister, owner.proposeOwner], [true, true, true, true, true])

  const operatorKey = positionActions(position(), OPERATOR, OPERATOR)
  assert.deepEqual([operatorKey.deregister, operatorKey.burn, operatorKey.unbond, operatorKey.proposeOwner], [true, false, false, false])

  const stranger = positionActions(position(), OPERATOR, OTHER)
  assert.deepEqual([stranger.refresh, stranger.deregister, stranger.burn], [true, false, false])
  assert.equal(positionActions(position(), OPERATOR, null).refresh, false)
})

test('an exit in progress blocks further withdrawals and deregistration', () => {
  const actions = positionActions(position({ exitInProgress: true }), OPERATOR, OWNER)
  assert.deepEqual([actions.burn, actions.unbond, actions.deregister], [false, false, false])
})

test('claims follow the claimable amounts and the bond-owner rule', () => {
  assert.equal(positionActions(position(), OPERATOR, OWNER).claimAll, false)

  const claimable = position({ claimableTicket: 3n, claimableBond: 4n })
  assert.deepEqual(
    [positionActions(claimable, OPERATOR, OWNER).claimAll, positionActions(claimable, OPERATOR, OWNER).claimTickets],
    [true, false],
  )
  assert.deepEqual(
    [positionActions(claimable, OPERATOR, OTHER).claimAll, positionActions(claimable, OPERATOR, OTHER).claimTickets],
    [false, true],
  )
  assert.equal(positionActions(position({ claimableBond: 4n }), OPERATOR, OTHER).claimTickets, false)
})

test('only the proposed wallet can accept a bond-owner transfer', () => {
  const status = position({ pendingBondOwner: PROPOSED })
  assert.equal(positionActions(status, OPERATOR, PROPOSED).acceptOwner, true)
  assert.equal(positionActions(status, OPERATOR, OWNER).acceptOwner, false)
})

test('burns a whole number of tickets that the balance covers', () => {
  assert.equal(ticketBurnAmount('2', UNIT, 5n * UNIT), 2n * UNIT)
  assert.equal(ticketBurnAmount('6', UNIT, 5n * UNIT), null)
  assert.equal(ticketBurnAmount('0', UNIT, 5n * UNIT), null)
  assert.equal(ticketBurnAmount('1.5', UNIT, 5n * UNIT), null)
})

test('shows queued and claimable exits, and nothing for an operator without a position', () => {
  const props = { config, operator: OPERATOR, wallet: OWNER, busy: null, send: () => {}, errFor: () => null }
  const html = renderToStaticMarkup(
    <ManagePosition {...props} status={position({ pendingTicketExit: 2n * UNIT, claimableTicket: 2n * UNIT })} />,
  )
  assert.match(html, /Manage the position/)
  assert.match(html, /Claim to the bond owner/)
  assert.match(html, /2 USDS/)

  const empty = position({ bondOwner: null, registered: false, ciphernodeBond: 0n, ticketBalance: 0n, availableTickets: 0n })
  assert.equal(renderToStaticMarkup(<ManagePosition {...props} status={empty} />), '')
})

test('the claim covers the claimable seats of the connected recipient, and the summary splits every amount by state', () => {
  const e3 = (sequence: bigint) => (BigInt(CONTRACTS.Interfold) << 96n) | sequence
  const seat = (sequence: bigint, recipient: Address): CommitteeSeat => ({
    e3Id: e3(sequence),
    operator: OPERATOR,
    recipient,
    refundManager: PROPOSED,
    block: 1n,
  })
  const fee = 10n ** BigInt(FEE_TOKEN.decimals)
  const seats = [8n, 7n, 6n, 5n, 4n, 3n, 2n, 1n].map((n) => seat(n, n === 3n ? OTHER : OWNER))
  const statuses = new Map<bigint, SeatStatus>([
    [e3(8n), { stage: E3Stage.Complete, state: 'onHold', amount: 6n * fee }],
    [e3(7n), { stage: E3Stage.Complete, state: 'claimed', amount: 1n * fee }],
    [e3(6n), { stage: E3Stage.Failed, state: 'claimable', amount: 4n * fee }],
    [e3(5n), { stage: E3Stage.Failed, state: 'needsProcessing', amount: null }],
    [e3(4n), { stage: E3Stage.KeyPublished, state: 'inProgress', amount: null }],
    [e3(3n), { stage: E3Stage.Complete, state: 'claimable', amount: 2n * fee }],
    [e3(2n), { stage: E3Stage.Complete, state: 'claimable', amount: 3n * fee }],
    [e3(1n), { stage: E3Stage.Complete, state: 'claimable', amount: 5n * fee }],
  ])

  // Completed E3s share one claimRewards call; each failed E3 is its own claim on the refund manager.
  assert.deepEqual(claimPlan(seats, statuses, OWNER), { rewards: [e3(2n), e3(1n)], compensation: [seats[2]] })
  assert.deepEqual(claimPlan(seats, statuses, OTHER), { rewards: [e3(3n)], compensation: [] })
  assert.deepEqual(claimPlan(seats, statuses, OPERATOR), { rewards: [], compensation: [] })
  assert.deepEqual(claimPlan(seats, statuses, null), { rewards: [], compensation: [] })

  assert.deepEqual(summarizeRewards(statuses.values()), {
    claimable: 14n * fee,
    claimableCount: 4,
    claimed: 1n * fee,
    onHold: 6n * fee,
    needsProcessing: 1,
  })

  const props = { seats, statuses, loadFailed: false, busy: null, onReload: () => {}, send: () => {}, errFor: () => null }
  const owner = renderToStaticMarkup(<CommitteeRewardsView {...props} wallet={OWNER} />)
  assert.match(owner, /<span class="mono">14<\/span>/)
  assert.match(owner, /4 rewards available/)
  assert.match(owner, /<button class="btn btn--primary">Claim rewards/)
  assert.match(owner, /2 transactions/)
  assert.match(owner, /can claim the other rewards/)
  assert.match(owner, /A failed E3 needs processing/)
  for (const label of ['On hold', 'Claimed', 'Claimable', 'Needs processing', 'In progress']) assert.match(owner, new RegExp(`>${label}<`))
  assert.match(owner, />Process</)

  // The operator key is not a recipient: it cannot claim, but it can process the failed E3.
  const operatorKey = renderToStaticMarkup(<CommitteeRewardsView {...props} wallet={OPERATOR} />)
  assert.match(operatorKey, /<button class="btn btn--primary" disabled="">Claim rewards/)
  assert.match(operatorKey, />Process</)

  const disconnected = renderToStaticMarkup(<CommitteeRewardsView {...props} wallet={null} />)
  assert.doesNotMatch(disconnected, />Process</)
  assert.match(renderToStaticMarkup(<CommitteeRewardsView {...props} statuses={null} wallet={OWNER} />), /Reading rewards/)
  assert.match(renderToStaticMarkup(<CommitteeRewardsView {...props} seats={[]} wallet={OWNER} />), /No committee has selected/)
})

// ─── Bond-owner identity ───────────────────────────────────────────────────

const DAY = 86_400n
const NOW = 1_790_000_000n
const word = (value: bigint): Hex => pad(toHex(value), { size: 32 })
const VERSION = word(0x14n << 232n)

const service: IdentityService = {
  domain: 'dashboard.theinterfold.com',
  scope: 'interfold-bond-owner',
  faceMatch: true,
  nullifierType: 0,
  proofValidity: 7n * DAY,
  maxValidity: 365n * DAY,
}

const verifier: VerifierConfig = {
  address: OTHER,
  domain: service.domain,
  scope: service.scope,
  version: VERSION,
  nullifierType: 0,
  oprfKeyHash: word(0n),
  faceMatchRequired: true,
  proofValidity: service.proofValidity,
  maxValidity: service.maxValidity,
}

const policy = { registry: PROPOSED, required: true, timepoint: NOW - 10n * DAY }

function account(overrides: Partial<OwnerAccount> = {}): OwnerAccount {
  return { now: NOW, isContract: false, identity: { identityId: word(0n), expiresAt: 0n, verifiedNow: false }, ...overrides }
}

function bundle(version: Hex = VERSION) {
  return buildProofBundle({
    success: {
      proofs: [
        {
          name: 'compare_expiry_evm',
          committedInputs: { compare_expiry_evm: { minDateTimestamp: Number(NOW + 400n * DAY), maxDateTimestamp: 0 } },
        },
        { name: 'outer_evm_count_5', proof: '0x02' },
      ],
      result: {},
    },
    params: {
      version,
      proofVerificationData: {
        vkeyHash: word(7n),
        proof: '0x1234',
        publicInputs: [word(1n), word(2n), word(NOW), word(0n), word(9n), word(0n)],
      },
      committedInputs: '0xbeef',
      serviceConfig: { validityPeriodInSeconds: 604_800, domain: service.domain, scope: service.scope, devMode: false },
    },
    owner: OWNER,
    chainId: 11_155_111,
    faceMatch: true,
  })
}

const identityProps = {
  owner: OWNER,
  policy,
  verifier,
  account: account(),
  loadFailed: false,
  service,
  validUntilInput: '2027-12-01',
  onValidUntil: () => {},
  previewFaceMatch: true,
  onPreviewFaceMatch: () => {},
  request: { phase: 'idle' } as const,
  canRegister: true,
  busy: null,
  errFor: () => null,
  onReload: () => {},
  onCreate: () => {},
  onCancel: () => {},
  onRegister: () => {},
  onDownloadProof: () => {},
  onDownloadSafe: () => {},
}

test('date fields round-trip in UTC and reject impossible dates', () => {
  assert.equal(parseDateInput('2027-12-01'), BigInt(Date.UTC(2027, 11, 1) / 1000))
  assert.equal(dateInput(parseDateInput('2027-12-01')!), '2027-12-01')
  assert.equal(parseDateInput('2026-02-31'), null)
  assert.equal(parseDateInput('01/12/2027'), null)
  assert.equal(parseDateInput('0099-01-01'), BigInt(Date.parse('0099-01-01T00:00:00Z') / 1000))
})

test('the identity panel shows the credential and offers a request', () => {
  const unverified = renderToStaticMarkup(<IdentityView {...identityProps} />)
  assert.match(unverified, /Yes, since/)
  assert.match(unverified, /Not verified/)
  assert.match(unverified, /Verify the owner/)
  assert.match(unverified, />Create ZKPassport request</)
  assert.match(unverified, /face scan/)

  const verified = account({ identity: { identityId: word(1n), expiresAt: NOW + 200n * DAY, verifiedNow: true } })
  assert.equal(
    identityStatusText(verified),
    `Verified until ${new Date(Number(NOW + 200n * DAY) * 1000).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' })}`,
  )
  const renew = renderToStaticMarkup(<IdentityView {...identityProps} account={verified} validUntilInput={dateInput(NOW + 100n * DAY)} />)
  assert.match(renew, /Renew the credential/)
  assert.match(renew, /A renewal cannot shorten the credential/)

  // A credential that ends inside the current window does not count toward request capacity.
  const short = account({ identity: { identityId: word(1n), expiresAt: NOW + 1n, verifiedNow: true } })
  assert.match(renderToStaticMarkup(<IdentityView {...identityProps} account={short} />), /does not count toward request capacity/)
  assert.match(
    renderToStaticMarkup(<IdentityView {...identityProps} validUntilInput={dateInput(NOW + 1n)} />),
    /would not count toward request/,
  )
})

test('before a deployment the panel makes a proof to download', () => {
  const preview = renderToStaticMarkup(
    <IdentityView {...identityProps} policy={null} verifier={null} account={account({ identity: null })} />,
  )
  assert.match(preview, /No identity registry on/)
  assert.match(preview, /planned settings/)
  assert.match(preview, /Require FaceMatch/)

  const ready = renderToStaticMarkup(
    <IdentityView
      {...identityProps}
      policy={null}
      verifier={null}
      account={account({ identity: null })}
      request={{ phase: 'ready', bundle: bundle() }}
    />,
  )
  assert.match(ready, /Proof ready/)
  assert.match(ready, />Download the proof \(JSON\)</)
  assert.doesNotMatch(ready, /Register the identity/)
})

test('a proof registers from the owner, or as a Safe transaction', () => {
  const ready = { phase: 'ready', bundle: bundle() } as const
  const eoa = renderToStaticMarkup(<IdentityView {...identityProps} request={ready} />)
  assert.match(eoa, /<button class="btn btn--primary">Register the identity/)
  assert.match(eoa, /Refresh the status/)

  const otherWallet = renderToStaticMarkup(<IdentityView {...identityProps} request={ready} canRegister={false} />)
  assert.match(otherWallet, /<button class="btn btn--primary" disabled="">Register the identity/)
  assert.match(otherWallet, /Connect the bond-owner wallet/)

  const safe = renderToStaticMarkup(<IdentityView {...identityProps} account={account({ isContract: true })} request={ready} />)
  assert.match(safe, />Download the Safe transaction</)
  assert.doesNotMatch(safe, /Register the identity/)
  assert.match(safe, /Safe Transaction Builder/)

  // The verifier accepts one ZKPassport version.
  const otherVersion = { phase: 'ready', bundle: bundle(word(0x15n << 232n)) } as const
  const mismatch = renderToStaticMarkup(<IdentityView {...identityProps} request={otherVersion} />)
  assert.match(mismatch, /another ZKPassport version/)
  assert.match(mismatch, /<button class="btn btn--primary" disabled="">Register the identity/)

  // A proof older than the verifier's validity window cannot register.
  const late = renderToStaticMarkup(<IdentityView {...identityProps} account={account({ now: NOW + 8n * DAY })} request={ready} />)
  assert.match(late, /too old to register/)
})

test('a registry without a verifier shows the credential but takes no registration', () => {
  const closed = renderToStaticMarkup(<IdentityView {...identityProps} verifier={null} registrationClosed />)
  assert.match(closed, /takes no registration/)
  assert.match(closed, /Not verified/)
  assert.doesNotMatch(closed, /Create ZKPassport request/)
})

test('capacity warnings apply only while the policy requires identity', () => {
  const optional = { ...policy, required: false }
  const short = account({ identity: { identityId: word(1n), expiresAt: NOW + 1n, verifiedNow: true } })
  assert.doesNotMatch(renderToStaticMarkup(<IdentityView {...identityProps} policy={optional} account={short} />), /does not count/)
  assert.doesNotMatch(
    renderToStaticMarkup(<IdentityView {...identityProps} policy={optional} validUntilInput={dateInput(NOW + 1n)} />),
    /would not count/,
  )
  // The verifier's cap counts too: a far date still ends at the maximum validity.
  const capped = renderToStaticMarkup(
    <IdentityView {...identityProps} service={{ ...service, maxValidity: 1n }} validUntilInput={dateInput(NOW + 900n * DAY)} />,
  )
  assert.match(capped, /would not count toward request/)
})

test('a proof that the verifier would reject cannot register, and an equal expiry can', () => {
  const ready = (b: ReturnType<typeof bundle>) => ({ phase: 'ready', bundle: b }) as const
  const register = /<button class="btn btn--primary">Register the identity/
  const disabled = /<button class="btn btn--primary" disabled="">Register the identity/

  // A replacement that ends exactly at the current expiry is allowed by the registry.
  const proof = bundle()
  const ends = BigInt(proof.proofDate) + service.maxValidity
  const same = account({ identity: { identityId: word(1n), expiresAt: ends, verifiedNow: true } })
  assert.match(renderToStaticMarkup(<IdentityView {...identityProps} account={same} request={ready(proof)} />), register)

  const otherOwner = { ...bundle(), owner: PROPOSED }
  const moved = renderToStaticMarkup(<IdentityView {...identityProps} request={ready(otherOwner)} />)
  assert.match(moved, /bound to another owner or network/)
  assert.match(moved, disabled)

  const salted = renderToStaticMarkup(
    <IdentityView {...identityProps} verifier={{ ...verifier, nullifierType: 1 }} request={ready(bundle())} />,
  )
  assert.match(salted, /identifier type or OPRF key differs/)
  assert.match(salted, disabled)
})
