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
    question: `Encrypted poll ${compactE3Id(e3Id)}`,
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

// E3 ids are not small sequential numbers. Interfold seeds its counter with its
// own address (`nexte3Id = uint256(uint160(address(this))) << 96`,
// Interfold.sol:268) and increments it once per request (Interfold.sol:319).
// The top 160 bits are therefore the same on every E3 of a deployment, and the
// low 96 bits are the sequence number. Show the sequence number: the full value
// is 77 digits whose leading 76 digits are identical between E3 0 and E3 1.
const E3_SEQUENCE_MASK = (1n << 96n) - 1n

/** Per-deployment sequence number of an E3: 0, 1, 2, ... */
export function e3Sequence(id: bigint): bigint {
  return id & E3_SEQUENCE_MASK
}

export function compactE3Id(id: bigint): string {
  return `E3-${e3Sequence(id)}`
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
