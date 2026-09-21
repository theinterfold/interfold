// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import test from 'node:test'
import { renderToStaticMarkup } from 'react-dom/server'
import History from './History'
import Inspector from './Inspector'
import PollCard from './PollCard'
import type { HistoryEntry, Poll } from './data'
import type { InspectorDetail } from './lib/adapt'
import { E3Stage, FailureReason } from './lib/chain'
import { failureReasonLabel, failureReasonToUiIdx } from './lib/e3'
import { compactE3Id, formatE3Id, pollMetaFor } from './lib/pollMeta'

const LIVE_FAILED_E3 = 18458939420885977824981152629962741023865184457287647280899939019117062782976n

test('maps an insufficient committee failure to committee selection', () => {
  assert.equal(failureReasonLabel(FailureReason.InsufficientCommitteeMembers), 'Insufficient committee members')
  assert.equal(failureReasonToUiIdx(FailureReason.InsufficientCommitteeMembers, E3Stage.Requested), 1)
})

test('shows the E3 sequence number, not the raw 77-digit id', () => {
  // Interfold seeds its counter with its own address, so the first two E3s of a
  // deployment differ only in the final digit. Show the sequence number.
  assert.equal(compactE3Id(LIVE_FAILED_E3), 'E3-0')
  assert.equal(compactE3Id(LIVE_FAILED_E3 + 1n), 'E3-1')
  assert.equal(compactE3Id(42n), 'E3-42')
  assert.equal(pollMetaFor(LIVE_FAILED_E3).question, 'Encrypted poll E3-0')
})

test('renders a failed E3 as failed instead of complete', () => {
  const id = `E3-${LIVE_FAILED_E3}`
  const e3: InspectorDetail = {
    id,
    displayId: compactE3Id(LIVE_FAILED_E3),
    program: '0x53FC…1BA3',
    programAddr: '0x53FCdb21E73A461CfE6c64B19855204384B91BA3',
    requestedBy: '0x197be4E09614285Abb4b74b672377c404FD44d54',
    requestedByLabel: 'Requester',
    requestedTx: `0x${'1'.repeat(64)}`,
    requestedAt: 'Sep 19, 2026 · 18:31 UTC',
    requestedBlock: 26_000_000,
    currentStage: 1,
    terminalState: 'failed',
    summary: `Encrypted execution ${compactE3Id(LIVE_FAILED_E3)}`,
    committee: { size: 19, threshold: 14, selectionSeed: '0xf41f…0e8e5c', drawnAt: '—' },
    fees: { feeEscrowed: '0 USDS', committeeReward: '—', currency: 'USDS · Ethereum mainnet' },
    keygen: { scheme: 'BFV (fhe.rs)', finalizedAt: '—', publishedAt: '—', publishedTx: '—', publicKey: '—' },
    input: { openedAt: '—', closesAt: '—', inputsReceived: '—', firstBallotAt: '—', lastBallotAt: '—' },
    compute: { status: 'failed', note: 'The E3 stopped before computation completed.' },
    decryption: { status: 'failed', note: 'Threshold decryption did not start.', threshold: 10, committeeSize: 19 },
    publication: { status: 'failed', note: 'No result was published because the E3 failed.' },
    noBallots: false,
    failure: {
      reason: 'Insufficient committee members',
      failedAt: 'Sep 19, 2026 · 18:42 UTC',
      failedAtStage: 1,
      txHash: `0x${'2'.repeat(64)}`,
    },
    events: [],
  }

  const html = renderToStaticMarkup(
    <Inspector e3List={[{ id, displayId: e3.displayId, label: e3.program }]} e3={e3} selectedId={id} onSelect={() => undefined} />,
  )

  assert.match(html, />Failed</)
  assert.match(html, /Insufficient committee members/)
  assert.match(html, /E3-0/)
  assert.doesNotMatch(html, />Complete</)
})

// Every surface that shows an E3 id must show the compact form. A real id is up
// to 77 digits, which breaks the card, row, and timeline layouts.
const LONG_ID = formatE3Id(LIVE_FAILED_E3)
const SHORT_ID = compactE3Id(LIVE_FAILED_E3)

test('poll card shows the compact E3 id, with the full id in the tooltip', () => {
  const poll: Poll = {
    id: LONG_ID,
    displayId: SHORT_ID,
    question: 'Should the protocol adopt the new fee schedule?',
    context: 'An on-chain encrypted poll.',
    opened: 'Sep 19, 2026 · 18:31 UTC',
    closes: 'Sep 21, 2026 · 18:31 UTC',
    closesTs: 0,
    ballotCount: 12,
  }

  const html = renderToStaticMarkup(<PollCard poll={poll} pollState='open' currentStageIdx={3} ballotCount={12} />)

  assert.match(html, /E3-0/)
  // The full id stays reachable as a tooltip, but never as visible text.
  assert.match(html, new RegExp(`title="${LONG_ID}"`))
  assert.doesNotMatch(html, new RegExp(`>${LONG_ID}<`))
})

test('history row shows the compact E3 id, with the full id in the tooltip', () => {
  const entry: HistoryEntry = {
    id: LONG_ID,
    displayId: SHORT_ID,
    question: 'Should the protocol adopt the new fee schedule?',
    closed: 'Sep 21, 2026',
    duration: '2 days',
    ballotCount: 12,
    result: 'Approved · 62%',
  }

  const html = renderToStaticMarkup(<History entries={[entry]} />)

  assert.match(html, /E3-0/)
  assert.match(html, new RegExp(`title="${LONG_ID}"`))
  assert.doesNotMatch(html, new RegExp(`>${LONG_ID}<`))
})
