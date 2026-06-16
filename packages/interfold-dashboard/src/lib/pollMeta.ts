// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Off-chain poll metadata. CRISPProgram does not store the human-readable
// question or option labels on-chain — only the ballot/tally circuits and the
// encrypted votes. This map gives each E3 a friendly question/options/context.
// For unknown E3s we synthesize a generic record from the id.

import { CONTRACTS } from './chain'

export type PollMeta = {
  question: string
  context: string
  options: Array<{ id: string; label: string }>
  programLabel?: string
}

// Known E3 questions/options keyed by E3 id. CRISPProgram does not store the
// human-readable question on-chain, so real polls are added here as they launch.
// Empty by default — unknown ids fall back to a generic record.
const META: Record<string, PollMeta> = {}

export function pollMetaFor(e3Id: bigint): PollMeta {
  const m = META[e3Id.toString()]
  if (m) return m
  return {
    question: `Encrypted poll #${e3Id.toString()}`,
    context: "On-chain encrypted execution. Ballots are sealed on each voter's device; only the aggregate result is decrypted.",
    options: [
      { id: '0', label: 'Option 0' },
      { id: '1', label: 'Option 1' },
      { id: '2', label: 'Option 2' },
    ],
    programLabel: 'CRISP',
  }
}

export function formatE3Id(id: bigint): string {
  return `E3-${id.toString().padStart(4, '0')}`
}

export function shortAddr(addr: string): string {
  if (!addr || addr.length < 12) return addr
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`
}

export function shortHash(hex: string): string {
  if (!hex || hex.length < 14) return hex
  return `${hex.slice(0, 10)}…${hex.slice(-6)}`
}

// Friendly name for an E3 program contract. Known programs get a label;
// everything else falls back to a shortened address.
const KNOWN_PROGRAMS: Record<string, string> = {
  [CONTRACTS.CRISPProgram.toLowerCase()]: 'CRISP',
}

export function programName(addr: string): string {
  return KNOWN_PROGRAMS[addr?.toLowerCase()] ?? shortAddr(addr)
}

export function isCrispProgram(addr: string): boolean {
  return addr?.toLowerCase() === CONTRACTS.CRISPProgram.toLowerCase()
}
