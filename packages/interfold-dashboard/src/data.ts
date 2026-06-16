// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Canonical stage definitions + display copy for the CRISP / Interfold dashboard.
// All runtime poll data comes from chain (see lib/e3.ts + lib/adapt.ts); this
// file holds only static config and the shared UI types.

export interface Stage {
  id: string
  label: string
  blurb: string
}

export const STAGES: Stage[] = [
  {
    id: 'requested',
    label: 'Requested',
    blurb: 'An E3 was requested on-chain. The network is preparing to spin up a fresh committee for this poll.',
  },
  {
    id: 'committee',
    label: 'Committee Selected',
    blurb: 'A randomly drawn committee of nodes has been assigned. Their identities are not made public.',
  },
  {
    id: 'keygen',
    label: 'Keygen',
    blurb: 'The committee collaboratively generates a shared encryption key. No single party ever holds the decryption key.',
  },
  {
    id: 'input',
    label: 'Input Window',
    blurb: "Voting is open. Ballots are encrypted on the voter's device and submitted to the network.",
  },
  {
    id: 'compute',
    label: 'Compute',
    blurb: 'The committee runs the requested FHE computation over the encrypted inputs, without ever decrypting an individual input.',
  },
  {
    id: 'decryption',
    label: 'Decryption',
    blurb: 'Only the final aggregate result is decrypted, and only by a threshold of the committee acting together.',
  },
  {
    id: 'published',
    label: 'Published',
    blurb: 'The result is written on-chain and is now public and verifiable. Individual ballots remain encrypted forever.',
  },
]

// Per-stage descriptive copy. No fabricated countdowns — live "time remaining"
// for the input window is computed from the on-chain close timestamp in PollCard.
export const STAGE_STATUS: Record<string, { label: string; sub: string }> = {
  requested: { label: 'Starting', sub: 'Committee draw begins shortly' },
  committee: { label: 'In progress', sub: 'Drawing a fresh committee' },
  keygen: { label: 'In progress', sub: 'Generating the shared key' },
  input: { label: 'Voting open', sub: "Ballots are encrypted on each voter's device" },
  compute: { label: 'In progress', sub: 'Running the FHE computation' },
  decryption: { label: 'In progress', sub: 'Threshold decrypting the aggregate' },
  published: { label: 'Result published', sub: 'On-chain · verifiable' },
}

// ─── Shared UI types ─────────────────────────────────────────────────────────

export type Poll = {
  id: string
  question: string
  context: string
  opened: string
  closes: string
  closesTs: number // unix seconds; 0 if unknown
  ballotCount: number
}

export type HistoryEntry = {
  id: string
  question: string
  closed: string
  duration: string
  ballotCount: number
  result: string
}

export type PulseData = {
  activeNow: number
  ballots24h: number
  pollsAllTime: number
}
