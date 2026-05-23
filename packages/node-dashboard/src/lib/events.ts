// SPDX-License-Identifier: LGPL-3.0-only
import type { ParsedEvent, E3Entry } from '../types'

// ── Pipeline steps ────────────────────────────────────────────────────────────
export const STEPS = [
  { id: 'requested', label: 'E3 Request' },
  { id: 'selected', label: 'Selected' },
  { id: 'keyshare', label: 'Key Share' },
  { id: 'committee', label: 'Committee' },
  { id: 'ciphertext', label: 'Ciphertext' },
  { id: 'decryption', label: 'Decryption' },
  { id: 'plaintext', label: 'Plaintext' },
  { id: 'complete', label: 'Complete' },
] as const

export const STEP_IDX: Record<string, number> = Object.fromEntries(STEPS.map((s, i) => [s.id, i]))

export const EVT_STEP: Record<string, string> = {
  E3Requested: 'requested',
  CiphernodeSelected: 'selected',
  EncryptionKeyPending: 'keyshare',
  KeyshareCreated: 'keyshare',
  EncryptionKeyReceived: 'keyshare',
  EncryptionKeyCreated: 'keyshare',
  CommitteeRequested: 'committee',
  DKGInnerProofReady: 'committee',
  PkAggregationProofPending: 'committee',
  PkAggregationProofSigned: 'committee',
  PkGenerationProofSigned: 'committee',
  PublicKeyAggregated: 'committee',
  CommitteePublished: 'committee',
  CommitteeFinalized: 'committee',
  CommitteeFinalizeRequested: 'committee',
  CiphertextOutputPublished: 'ciphertext',
  ThresholdSharePending: 'decryption',
  ThresholdShareCreated: 'decryption',
  DecryptionKeyShared: 'decryption',
  DecryptionShareProofSigned: 'decryption',
  ShareDecryptionProofPending: 'decryption',
  AggregationProofPending: 'decryption',
  AggregationProofSigned: 'decryption',
  PlaintextAggregated: 'plaintext',
  PlaintextOutputPublished: 'plaintext',
  E3RequestComplete: 'complete',
  E3Failed: 'complete',
}

export const ERR_TYPES = [
  'EnclaveError',
  'E3Failed',
  'ProofVerificationFailed',
  'SignedProofFailed',
  'ThresholdShareCollectionFailed',
  'EncryptionKeyCollectionFailed',
]

export const WARN_TYPES = ['AccusationVote', 'ProofFailureAccusation', 'CommitmentMismatch']

export const STATE_TYPES = [
  'E3Requested',
  'CiphernodeSelected',
  'CommitteePublished',
  'CommitteeFinalized',
  'CiphertextOutputPublished',
  'PlaintextOutputPublished',
  'PlaintextAggregated',
  'E3StageChanged',
  'E3RequestComplete',
]

// ── Parsing helpers ───────────────────────────────────────────────────────────

/** JSON.parse with u128 HLC timestamps wrapped in quotes to avoid precision loss */
export function safeParse(text: string): unknown {
  return JSON.parse(text.replace(/"ts"\s*:\s*(\d{20,})/g, '"ts":"$1"'))
}

/** Decode a HLC u128 (upper 64 bits = wall-clock nanos) to a locale time string */
export function hlcToTime(ts: string | number | undefined): string {
  if (!ts) return '—'
  try {
    const n = BigInt(String(ts))
    const millis = Number((n >> 64n) / 1_000_000n)
    if (millis > 0) return new Date(millis).toLocaleTimeString('en-US', { hour12: false })
  } catch {
    // fall through
  }
  return '—'
}

export function extractType(evt: ParsedEvent): string {
  if (evt.payload && typeof evt.payload === 'object') {
    return Object.keys(evt.payload)[0] ?? 'unknown'
  }
  return 'unknown'
}

export function extractE3Id(evt: ParsedEvent): string | null {
  const data = Object.values(evt.payload ?? {})[0]
  if (!data || typeof data !== 'object') return null
  const d = data as Record<string, unknown>
  const eid = d.e3_id !== undefined ? d.e3_id : d.e3Id
  if (eid == null) return null
  if (typeof eid === 'object' && eid !== null) {
    const o = eid as Record<string, unknown>
    return o.chain_id !== undefined ? `${o.chain_id}:${o.id}` : String(o.id)
  }
  return String(eid)
}

export function extractDetail(evt: ParsedEvent): string {
  const data = Object.values(evt.payload ?? {})[0]
  if (!data || typeof data !== 'object') return ''
  const d = data as Record<string, unknown>
  const parts: string[] = []
  for (const k of Object.keys(d)) {
    if (k === 'e3_id' || k === 'e3Id') continue
    const v = d[k]
    if (typeof v === 'object' && v !== null) continue
    let vs = String(v)
    if (vs.length > 46) vs = vs.slice(0, 44) + '…'
    parts.push(`${k}:${vs}`)
    if (parts.length >= 3) break
  }
  return parts.join('  ')
}

export function typeSev(type: string): 'error' | 'warn' | 'state' | '' {
  if (ERR_TYPES.includes(type)) return 'error'
  if (WARN_TYPES.includes(type)) return 'warn'
  if (STATE_TYPES.includes(type)) return 'state'
  return ''
}

// ── NDJSON response parser ────────────────────────────────────────────────────

/**
 * Parse an NDJSON events response.
 * Mutates `existingSeqs` to track seen seq numbers (dedup across calls).
 *
 * Server format per line: event JSON | {"Next":N} | "Done"
 * "Next" is only sent when events.len() == limit (>= 500); otherwise "Done".
 * read_from is inclusive so we add +1 to the cursor to skip the last seen event.
 */
export function parseNdjsonResponse(
  text: string,
  existingIds: Set<string>,
): { events: ParsedEvent[]; cursor: number | null; maxSeq: number; perAggregateMaxSeq: Map<number, number> } {
  const lines = text.trim().split('\n').filter(Boolean)
  const events: ParsedEvent[] = []
  let cursor: number | null = null
  let maxSeq = 0
  const perAggregateMaxSeq = new Map<number, number>()

  for (const line of lines) {
    let objs: unknown[]
    try {
      objs = [safeParse(line.trim())]
    } catch {
      // try splitting concatenated JSON objects on the same line
      objs = line
        .trim()
        .split(/\}\s*\{/)
        .map((f, i, a) => {
          if (a.length === 1) return f
          if (i === 0) return f + '}'
          if (i === a.length - 1) return '{' + f
          return '{' + f + '}'
        })
        .map((f) => {
          try {
            return safeParse(f)
          } catch {
            return null
          }
        })
        .filter(Boolean) as unknown[]
    }

    for (const obj of objs) {
      if (obj === 'Done') {
        cursor = null
        continue
      }
      if (obj && typeof obj === 'object') {
        const o = obj as Record<string, unknown>
        if ('Next' in o && typeof o.Next === 'number') {
          // +1: server read_from is inclusive — avoid re-fetching the last event
          cursor = (o.Next as number) + 1
          continue
        }
        if ('payload' in o && o.payload) {
          const evt = obj as ParsedEvent
          // Always update per-aggregate max seq (even for duplicate events)
          const aggId = evt.ctx?.aggregate_id
          const seq = evt.ctx?.seq
          if (aggId != null && seq != null) {
            const prev = perAggregateMaxSeq.get(aggId) ?? 0
            if (seq > prev) perAggregateMaxSeq.set(aggId, seq)
          }
          if (seq != null && seq > maxSeq) maxSeq = seq
          // Dedup by globally-unique event ID (0x-prefixed hex string)
          const id = evt.ctx?.id
          if (id != null && existingIds.has(id)) continue
          if (id != null) existingIds.add(id)
          events.push(evt)
        }
      }
    }
  }

  return { events, cursor, maxSeq, perAggregateMaxSeq }
}

// ── E3 pipeline aggregation ───────────────────────────────────────────────────

export function buildE3Map(events: ParsedEvent[]): Record<string, E3Entry> {
  const e3s: Record<string, E3Entry> = {}
  for (const evt of events) {
    const e3id = extractE3Id(evt)
    if (!e3id) continue
    const type = extractType(evt)
    const step = EVT_STEP[type]
    const ctx = evt.ctx ?? { seq: 0, ts: '', source: '' }
    const ts = hlcToTime(ctx.ts)
    const src = ctx.source ?? ''
    if (!e3s[e3id]) e3s[e3id] = { stepIdx: -1, latestTs: ts, evLog: [], error: false }
    const e = e3s[e3id]
    e.latestTs = ts
    // Add to evLog if the event maps to a known pipeline step, is a STATE_TYPE
    // (important on-chain transition), or is an error — skip internal infra events
    // like ComputeRequest that don't represent pipeline progress
    if (step || STATE_TYPES.includes(type)) {
      e.evLog.push({ type, ts, src })
      if (step) {
        const idx = STEP_IDX[step]
        if (idx !== undefined && idx > e.stepIdx) e.stepIdx = idx
      }
    }
    if (ERR_TYPES.includes(type)) {
      if (!step && !STATE_TYPES.includes(type)) e.evLog.push({ type, ts, src })
      e.error = true
    }
  }
  return e3s
}
