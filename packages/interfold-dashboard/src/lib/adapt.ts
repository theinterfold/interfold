// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Adapters: shape on-chain data into the prop shapes the React components expect.

import { formatUnits, keccak256, numberToHex, toHex } from 'viem'
import type { HistoryEntry, Poll } from '../data'
import type { E3FullDetails, E3Summary } from './e3'
import { decodeCrispTally, isE3Active } from './e3'
import { E3Stage } from './chain'
import { formatE3Id, isCrispProgram, pollMetaFor, programName, shortHash } from './pollMeta'

// Fee token is MockUSDC (6 decimals) on the Sepolia deployment.
const FEE_DECIMALS = 6
function fmtUsdc(v: bigint | undefined): string {
  if (v == null) return '—'
  return `${formatUnits(v, FEE_DECIMALS)} USDC`
}

export function adaptPoll(s: E3Summary): Poll {
  const meta = pollMetaFor(s.id)
  const openedTs = s.inputWindow[0]
  const closesTs = s.inputWindow[1]

  return {
    id: formatE3Id(s.id),
    question: meta.question,
    context: meta.context,
    opened: openedTs > 0n ? fmtUtc(openedTs) : '—',
    closes: closesTs > 0n ? fmtUtc(closesTs) : '—',
    closesTs: Number(closesTs),
    ballotCount: s.ballotCount,
  }
}

export function adaptHistoryEntries(list: E3Summary[], detailsCache: Map<string, E3FullDetails>): HistoryEntry[] {
  return list.map((s) => {
    const detail = detailsCache.get(s.id.toString())
    const meta = pollMetaFor(s.id)
    return {
      id: formatE3Id(s.id),
      question: meta.question,
      closed: s.inputWindow[1] > 0n ? fmtDate(s.inputWindow[1]) : 'in progress',
      duration: s.inputWindow[1] > s.inputWindow[0] && s.inputWindow[0] > 0n ? fmtDuration(s.inputWindow[1] - s.inputWindow[0]) : '—',
      ballotCount: s.ballotCount,
      result: historyResult(s, detail, meta),
    }
  })
}

// A truthful one-line status for a past poll. Prefers the decoded verdict when
// we have the result; otherwise reflects the on-chain stage (failed / expired /
// in progress / completed) rather than a blanket "Pending".
function historyResult(s: E3Summary, detail: E3FullDetails | undefined, meta: ReturnType<typeof pollMetaFor>): string {
  if (detail) {
    const tally = decodeCrispTally(detail.plaintextOutput)
    if (tally && tally.length > 0) {
      const total = tally.reduce((a, b) => a + b, 0)
      const max = Math.max(...tally)
      const pct = total > 0 ? Math.round((max / total) * 100) : 0
      const winnerLabel = meta.options[tally.indexOf(max)]?.label ?? 'Outcome'
      const verdict = /^no/i.test(winnerLabel) ? 'Declined' : /^abs/i.test(winnerLabel) ? 'Inconclusive' : 'Approved'
      return `${verdict} · ${pct}%`
    }
  }
  if (s.stage === E3Stage.Complete) return 'Completed'
  if (s.stage === E3Stage.Failed) return 'Failed'
  if (isE3Active(s.stage, s.inputWindow[1], { e3Program: s.e3Program, ballotCount: s.ballotCount })) return 'In progress'
  // Past the input window without inputs (and not flagged Complete/Failed on chain)
  // — distinguish from generic "Expired" so empty rounds are obvious in history.
  if (s.ballotCount === 0) return 'No ballots'
  return 'Expired'
}

export function adaptInspectorE3List(list: E3Summary[]) {
  return list.map((s) => ({
    id: formatE3Id(s.id),
    label: isCrispProgram(s.e3Program) ? pollMetaFor(s.id).question.slice(0, 64) : programName(s.e3Program),
  }))
}

// ─── Inspector detail shape (consumed by Inspector.tsx) ──────────────────────

export type InspectorEvent = {
  t: string
  block: number | string
  name: string
  stage: string
  tx: string // shortened for display
  txHash?: string // full hash for the explorer link ('—'/none → omitted)
}

export type InspectorDetail = {
  id: string
  program: string
  programAddr: string
  requestedBy: string
  requestedByLabel: string
  requestedTx: string
  requestedAt: string

  requestedBlock: number | null
  currentStage: number
  summary: string
  committee: { size: number; threshold: number; selectionSeed: string; drawnAt: string }
  fees: {
    feeEscrowed: string
    committeeReward: string
    currency: string
  }
  keygen: {
    scheme: string
    finalizedAt: string
    publishedAt: string
    publishedTx: string
    publicKey: string
  }
  input: {
    openedAt: string
    closesAt: string
    inputsReceived: string
    firstBallotAt: string
    lastBallotAt: string
  }
  compute: { status: string; note: string }
  decryption: { status: string; note: string; threshold: number; committeeSize: number }
  publication: { status: string; note: string; resultTx?: string }
  // True when the input window has closed without a single ballot being submitted.
  // The chain stage still reports KeyPublished (no transition is triggered without
  // inputs), so without this flag the compute/decryption sections look "in progress"
  // when in fact nothing is happening.
  noBallots: boolean
  events: InspectorEvent[]
}

const ZERO_HASH = '0x' + '0'.repeat(64)

// Encryption-scheme ids are keccak256 of a label string, so map known hashes
// back to a readable name (can't be reversed otherwise).
const KNOWN_SCHEMES: Record<string, string> = {
  [keccak256(toHex('fhe.rs:BFV'))]: 'BFV (fhe.rs)',
}
function schemeName(id: string): string {
  if (!id || id === ZERO_HASH) return '—'
  return KNOWN_SCHEMES[id.toLowerCase()] ?? shortHash(id)
}

export function adaptInspectorDetail(detail: E3FullDetails | null): InspectorDetail | null {
  if (!detail) return null
  const isCrisp = isCrispProgram(detail.e3Program)
  const meta = pollMetaFor(detail.id)
  const inputsReceived = detail.inputsTracked ? detail.ballotCount.toLocaleString() : '—'
  const sharesRequired = detail.committeeThreshold[0] || 0
  const committeeSize = detail.committeeThreshold[1] || detail.committeeMembers.length
  // Past the input window with zero ballots — see `noBallots` on InspectorDetail.
  const noBallots = detail.inputsTracked && detail.ballotCount === 0 && detail.uiStageIdx >= 4

  return {
    id: formatE3Id(detail.id),
    program: programName(detail.e3Program),
    programAddr: detail.e3Program,
    requestedBy: detail.requester,
    requestedByLabel: 'Requester',
    requestedTx: detail.requestTxHash,
    requestedAt: detail.requestedAt ? fmtUtcFromUnix(detail.requestedAt) : '—',
    requestedBlock: detail.requestEventBlock != null ? Number(detail.requestEventBlock) : null,
    currentStage: detail.uiStageIdx,
    summary: isCrisp ? meta.question : `Encrypted execution ${formatE3Id(detail.id)}`,

    committee: {
      size: committeeSize,
      threshold: sharesRequired,
      selectionSeed: detail.seed > 0n ? shortHash(numberToHex(detail.seed, { size: 32 })) : '—',
      drawnAt: detail.committeeFinalizedAt ? fmtUtcFromUnix(detail.committeeFinalizedAt) : '—',
    },

    fees: {
      feeEscrowed: fmtUsdc(detail.feeEscrowed),
      committeeReward: fmtUsdc(detail.committeeReward),
      currency: 'USDC · Sepolia',
    },

    keygen: {
      scheme: schemeName(detail.encryptionSchemeId),
      finalizedAt: detail.committeeFinalizedAt ? fmtUtcFromUnix(detail.committeeFinalizedAt) : '—',
      publishedAt: detail.committeePublishedAt ? fmtUtcFromUnix(detail.committeePublishedAt) : '—',
      publishedTx: detail.committeePublishedTx ?? '—',
      publicKey: detail.committeePublicKey && detail.committeePublicKey !== ZERO_HASH ? detail.committeePublicKey : '—',
    },

    input: {
      openedAt: detail.inputWindow[0] > 0n ? fmtUtc(detail.inputWindow[0]) : '—',
      closesAt: detail.inputWindow[1] > 0n ? fmtUtc(detail.inputWindow[1]) : '—',
      inputsReceived,
      firstBallotAt: ballotTime(detail.ballotEvents[0]),
      lastBallotAt: ballotTime(detail.ballotEvents[detail.ballotEvents.length - 1]),
    },

    compute: {
      status: noBallots ? 'idle' : detail.uiStageIdx >= 4 ? 'active' : 'pending',
      note: noBallots
        ? 'The input window closed without any ballots being submitted. There is nothing to compute over.'
        : detail.uiStageIdx < 4
          ? 'Compute begins automatically when the input window closes.'
          : "The program's FHE computation runs over the encrypted inputs, without decrypting any individual input.",
    },

    decryption: {
      status: detail.uiStageIdx >= 5 ? 'active' : 'pending',
      note:
        sharesRequired > 0
          ? `A threshold of ${sharesRequired} of ${committeeSize} committee members must each publish a partial decryption to recover the result.`
          : 'Threshold decryption begins after compute.',
      threshold: sharesRequired,
      committeeSize,
    },

    publication: {
      status: detail.resultTxHash ? 'complete' : 'pending',
      note: detail.resultTxHash
        ? 'The result has been published on-chain. Individual ballots remain encrypted.'
        : 'Final result will be written on-chain. Individual ballots remain encrypted.',
      resultTx: detail.resultTxHash,
    },

    noBallots,
    events: buildEventLog(detail),
  }
}

function ballotTime(b?: { blockNumber: bigint; timestamp?: number }): string {
  if (!b) return '—'
  return b.timestamp ? fmtClock(b.timestamp) : `block #${b.blockNumber.toString()}`
}

function buildEventLog(d: E3FullDetails): InspectorEvent[] {
  const evs: InspectorEvent[] = []
  evs.push({
    t: d.requestedAt ? fmtClock(d.requestedAt) : '—',
    block: d.requestEventBlock != null ? Number(d.requestEventBlock) : '—',
    name: 'E3Requested',
    stage: 'Requested',
    tx: shortHash(d.requestTxHash),
    txHash: d.requestTxHash,
  })
  if (d.committeeFinalizedTx) {
    evs.push({
      t: d.committeeFinalizedAt ? fmtClock(d.committeeFinalizedAt) : '—',
      block: d.committeeFinalizedBlock != null ? Number(d.committeeFinalizedBlock) : '—',
      name: 'CommitteeFinalized',
      stage: 'Committee Selected',
      tx: shortHash(d.committeeFinalizedTx),
      txHash: d.committeeFinalizedTx,
    })
  }
  if (d.committeePublishedTx) {
    evs.push({
      t: d.committeePublishedAt ? fmtClock(d.committeePublishedAt) : '—',
      block: d.committeePublishedBlock != null ? Number(d.committeePublishedBlock) : '—',
      name: 'CommitteePublished',
      stage: 'Keygen',
      tx: shortHash(d.committeePublishedTx),
      txHash: d.committeePublishedTx,
    })
  }
  d.ballotEvents.slice(0, 5).forEach((b) => {
    evs.push({
      t: b.timestamp ? fmtClock(b.timestamp) : '—',
      block: Number(b.blockNumber),
      name: 'InputPublished',
      stage: 'Input Window',
      tx: shortHash(b.txHash),
      txHash: b.txHash,
    })
  })
  if (d.ballotEvents.length > 5) {
    evs.push({
      t: '—',
      block: '—',
      name: `InputPublished (×${d.ballotEvents.length - 5} more)`,
      stage: 'Input Window',
      tx: '—',
    })
  }
  if (d.resultTxHash) {
    evs.push({
      t: d.resultAt ? fmtClock(d.resultAt) : '—',
      block: d.resultBlock != null ? Number(d.resultBlock) : '—',
      name: 'PlaintextOutputPublished',
      stage: 'Published',
      tx: shortHash(d.resultTxHash),
      txHash: d.resultTxHash,
    })
  }
  return evs
}

// ─── Time formatting ─────────────────────────────────────────────────────────

function fmtUtcFromUnix(sec: number): string {
  return fmtUtc(BigInt(sec))
}

function fmtUtc(ts: bigint): string {
  const d = new Date(Number(ts) * 1000)
  return (
    d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' }) +
    ' · ' +
    d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC', hour12: false }) +
    ' UTC'
  )
}

function fmtClock(sec: number): string {
  return (
    new Date(sec * 1000).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZone: 'UTC',
      hour12: false,
    }) + ' UTC'
  )
}

function fmtDate(ts: bigint): string {
  return new Date(Number(ts) * 1000).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' })
}

function fmtDuration(seconds: bigint): string {
  const s = Number(seconds)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.round(s / 60)} min`
  if (s < 86400) return `${Math.round(s / 3600)}h`
  return `${Math.round(s / 86400)} days`
}
