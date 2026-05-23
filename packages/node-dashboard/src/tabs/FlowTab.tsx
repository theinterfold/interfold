// SPDX-License-Identifier: LGPL-3.0-only
import { useState, useRef, useEffect, useMemo, useCallback } from 'react'
import type { ParsedEvent } from '../types'
import { extractE3Id, extractType, hlcToTime } from '../lib/events'
import { ACTORS, EVT_META, type ActorId } from '../lib/actorMap'

interface FlowTabProps {
  events: ParsedEvent[]
}

// ── Smart field extraction ────────────────────────────────────────────────────

const HEX_RE = /^0x[0-9a-f]{8,}$/i
const BLOB_KEYS = new Set([
  'pubkey',
  'params',
  'proof',
  'value',
  'seed',
  'error_size',
  'pk_share',
  'signed_pk_generation_proof',
  'dkg_aggregator_proof',
])

function payloadData(evt: ParsedEvent): Record<string, unknown> | null {
  const v = Object.values(evt.payload ?? {})[0]
  return v && typeof v === 'object' ? (v as Record<string, unknown>) : null
}

function extractSmartFields(evt: ParsedEvent, fields?: string[]): string {
  const d = payloadData(evt)
  if (!d) return ''

  const render = (k: string, v: unknown): string | null => {
    if (v === null || v === undefined) return null
    if (typeof v === 'object') {
      // e.g. E3id object: {chain_id:1, id:0}  →  "1:0"
      const o = v as Record<string, unknown>
      if ('chain_id' in o && 'id' in o) return `${o.chain_id}:${o.id}`
      // committee array
      if (Array.isArray(v)) return v.length > 0 ? `[${v.length} members]` : null
      return null
    }
    const s = String(v)
    if (HEX_RE.test(s)) return null // skip hex blobs
    if (s.length > 60) return null
    return s
  }

  const parts: string[] = []

  if (fields && fields.length > 0) {
    for (const k of fields) {
      const r = render(k, d[k])
      if (r !== null) parts.push(`${k}: ${r}`)
    }
  } else {
    // Auto-extract: scalars, skip known blobs
    for (const [k, v] of Object.entries(d)) {
      if (k === 'e3_id' || BLOB_KEYS.has(k)) continue
      const r = render(k, v)
      if (r !== null) {
        parts.push(`${k}: ${r}`)
        if (parts.length >= 4) break
      }
    }
  }

  return parts.join('  ·  ')
}

// ── Actor state machine ────────────────────────────────────────────────────────

const ACTOR_INIT: Record<ActorId, string> = {
  chain: 'Watching',
  sortition: 'Idle',
  node: 'Idle',
  aggregator: 'Standby',
  zk: 'Idle',
  compute: 'Idle',
  net: 'Connecting…',
}

function deriveActorStates(evList: ParsedEvent[], upTo: number): Record<ActorId, string> {
  const s = { ...ACTOR_INIT }

  for (let i = 0; i <= upTo && i < evList.length; i++) {
    const type = extractType(evList[i])
    const d = payloadData(evList[i]) ?? {}
    const pid = d.party_id !== undefined ? ` (party ${d.party_id})` : ''

    switch (type) {
      case 'E3Requested':
        s.chain = 'E3 requested'
        break
      case 'CiphernodeSelected':
        s.node = `Selected${pid}`
        s.chain = 'Committee selecting'
        break
      case 'CommitteeRequested':
        s.sortition = 'DKG in progress'
        break
      case 'CommitteeFinalizeRequested':
        s.sortition = 'Finalize requested'
        break
      case 'AggregatorChanged':
        s.aggregator = d.is_aggregator ? 'Aggregator role ✓' : 'Not aggregator'
        break
      case 'KeyshareCreated':
        s.node = `Keyshare created${pid}`
        break
      case 'EncryptionKeyPending':
        s.node = 'Collecting keys…'
        break
      case 'EncryptionKeyReceived':
        s.node = `Key received${pid}`
        break
      case 'EncryptionKeyCreated':
        s.node = 'All keys collected ✓'
        break
      case 'EncryptionKeyCollectionFailed':
        s.node = 'Key collection failed ✗'
        break
      case 'DKGInnerProofReady':
        s.zk = `DKG proof${pid} ready`
        break
      case 'DKGRecursiveAggregationComplete':
        s.zk = 'Recursive DKG done ✓'
        break
      case 'PkGenerationProofSigned':
        s.zk = `PK gen proof signed${pid}`
        break
      case 'PkAggregationProofPending':
        s.zk = 'Awaiting PK agg proof'
        break
      case 'PkAggregationProofSigned':
        s.zk = 'PK agg proof signed ✓'
        break
      case 'DkgProofSigned':
        s.zk = `DKG proof signed${pid}`
        break
      case 'PublicKeyAggregated':
        s.aggregator = 'Public key ready ✓'
        s.sortition = 'Done'
        break
      case 'CommitteePublished':
        s.chain = 'Committee published'
        break
      case 'CommitteeFinalized':
        s.chain = 'Committee finalized ✓'
        break
      case 'CiphertextOutputPublished':
        s.chain = 'Ciphertext on-chain'
        break
      case 'ComputeRequest':
        s.compute = 'FHE computing…'
        break
      case 'ComputeResponse':
        s.compute = 'Compute done ✓'
        break
      case 'ComputeRequestError':
        s.compute = 'Compute failed ✗'
        break
      case 'ThresholdSharePending':
        s.node = 'Collecting shares…'
        break
      case 'ThresholdShareCreated':
        s.node = `Threshold share created${pid}`
        break
      case 'ThresholdShareCollectionFailed':
        s.node = 'Share collection failed ✗'
        break
      case 'DecryptionKeyShared':
        s.node = `Decryption key shared${pid}`
        break
      case 'DecryptionshareCreated':
        s.node = `Decryption share created${pid}`
        break
      case 'DecryptionShareProofSigned':
        s.zk = 'Decryption proof signed'
        break
      case 'AggregationProofPending':
        s.zk = 'Awaiting aggregation proof'
        break
      case 'AggregationProofSigned':
        s.zk = 'Aggregation proof signed ✓'
        break
      case 'PlaintextAggregated':
        s.aggregator = 'Plaintext aggregated ✓'
        break
      case 'PlaintextOutputPublished':
        s.chain = 'Plaintext on-chain ✓'
        break
      case 'E3RequestComplete':
        s.chain = 'Complete ✓'
        break
      case 'E3Failed':
        s.chain = 'Failed ✗'
        break
      case 'NetReady':
        s.net = 'Ready'
        break
      case 'SyncEnded':
        s.net = 'Synced ✓'
        break
      case 'EffectsEnabled':
        s.net = 'Live mode ✓'
        break
      case 'E3StageChanged': {
        const ns = (d.new_stage as string | undefined) ?? '?'
        s.chain = `Stage → ${ns}`
        break
      }
      case 'AccusationQuorumReached':
        s.node = 'Accusation quorum ✗'
        break
      case 'CommitteeMemberExpelled':
        s.sortition = `Member expelled${pid}`
        break
      case 'SlashExecuted':
        s.chain = 'Slash executed'
        break
    }
  }

  return s
}

// ── Event type category helpers ───────────────────────────────────────────────

const ERR_TYPES_SET = new Set([
  'EnclaveError',
  'E3Failed',
  'ProofVerificationFailed',
  'SignedProofFailed',
  'ThresholdShareCollectionFailed',
  'EncryptionKeyCollectionFailed',
  'ComputeRequestError',
  'CommitmentConsistencyViolation',
])
const WARN_TYPES_SET = new Set(['AccusationVote', 'AccusationQuorumReached', 'ProofFailureAccusation', 'CommitmentConsistencyViolation'])

function evtSev(type: string): 'error' | 'warn' | '' {
  if (ERR_TYPES_SET.has(type)) return 'error'
  if (WARN_TYPES_SET.has(type)) return 'warn'
  return ''
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function FlowTab({ events }: FlowTabProps) {
  // Collect unique E3 IDs in order of first appearance
  const e3Ids = useMemo(() => {
    const seen: string[] = []
    const set = new Set<string>()
    for (const e of events) {
      const id = extractE3Id(e)
      if (id && !set.has(id)) {
        set.add(id)
        seen.push(id)
      }
    }
    return seen
  }, [events])

  const [selectedE3, setSelectedE3] = useState<string | null>(null)
  const [step, setStep] = useState(0)

  const currentE3 = selectedE3 ?? e3Ids[0] ?? null

  // Events filtered to the selected E3 (or ALL if none selected)
  const e3Events = useMemo(() => {
    if (!currentE3) return events
    return events.filter((e) => extractE3Id(e) === currentE3)
  }, [events, currentE3])

  const total = e3Events.length

  // When the selected E3 changes reset to latest step
  useEffect(() => {
    setStep(total > 0 ? total - 1 : 0)
  }, [currentE3]) // eslint-disable-line react-hooks/exhaustive-deps

  // Keep step in bounds when new events arrive for current E3
  useEffect(() => {
    setStep((s) => Math.min(s, Math.max(0, total - 1)))
  }, [total])

  const actorStates = useMemo(() => deriveActorStates(e3Events, step), [e3Events, step])

  const scrollRef = useRef<HTMLDivElement>(null)

  // Scroll current step into view
  useEffect(() => {
    const el = scrollRef.current?.querySelector(`[data-step="${step}"]`) as HTMLElement | null
    el?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [step])

  // Keyboard navigation
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        e.preventDefault()
        setStep((s) => Math.min(total - 1, s + 1))
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        e.preventDefault()
        setStep((s) => Math.max(0, s - 1))
      } else if (e.key === 'Home') {
        setStep(0)
      } else if (e.key === 'End') {
        setStep(total - 1)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [total])

  const handleE3Change = useCallback((id: string) => {
    setSelectedE3(id || null)
    setStep(0)
  }, [])

  if (e3Ids.length === 0) {
    return <div className='tab-pane empty-state'>No E3 requests observed yet.</div>
  }

  const stepPct = total > 1 ? Math.round((step / (total - 1)) * 100) : 100

  return (
    <div className='tab-pane flow-pane'>
      {/* ── Top bar ──────────────────────────────────────────────────────── */}
      <div className='flow-topbar'>
        <select className='flow-e3-select' value={currentE3 ?? ''} onChange={(e) => handleE3Change(e.target.value)}>
          {e3Ids.map((id) => (
            <option key={id} value={id}>
              E3 {id}
            </option>
          ))}
        </select>

        <div className='flow-progress-wrap'>
          <div className='flow-progress-bar'>
            <div className='flow-progress-fill' style={{ width: `${stepPct}%` }} />
          </div>
          <span className='flow-step-counter'>{total === 0 ? '—' : `${step + 1} / ${total}`}</span>
        </div>

        <div className='flow-step-btns'>
          <button className='flow-btn' onClick={() => setStep(0)} disabled={step === 0} title='Jump to first event (Home)'>
            ⏮
          </button>
          <button
            className='flow-btn'
            onClick={() => setStep((s) => Math.max(0, s - 1))}
            disabled={step === 0}
            title='Previous event (← or ↑)'
          >
            ◀ Prev
          </button>
          <button
            className='flow-btn flow-btn-primary'
            onClick={() => setStep((s) => Math.min(total - 1, s + 1))}
            disabled={step >= total - 1}
            title='Next event (→ or ↓)'
          >
            Next ▶
          </button>
          <button className='flow-btn' onClick={() => setStep(total - 1)} disabled={step >= total - 1} title='Jump to latest event (End)'>
            ⏭
          </button>
        </div>
      </div>

      {/* ── Body ─────────────────────────────────────────────────────────── */}
      <div className='flow-body'>
        {/* Actor state sidebar */}
        <div className='flow-actors'>
          <div className='flow-actors-hdr'>Actors</div>
          {ACTORS.map((actor) => (
            <div key={actor.id} className={`flow-actor-card actor-${actor.id}`}>
              <div className='flow-actor-name'>{actor.label}</div>
              <div className='flow-actor-state' title={actor.desc}>
                {actorStates[actor.id]}
              </div>
            </div>
          ))}
          <div className='flow-actors-hint'>← / → to step</div>
        </div>

        {/* Event sequence */}
        <div className='flow-events' ref={scrollRef}>
          {e3Events.map((evt, i) => {
            const type = extractType(evt)
            const meta = EVT_META[type]
            const actor = meta?.actor ?? 'node'
            const label = meta?.label ?? type
            const detail = extractSmartFields(evt, meta?.fields)
            const ts = hlcToTime(evt.ctx?.ts)
            const src = evt.ctx?.source ?? ''
            const sev = evtSev(type)
            const isCurrent = i === step
            const isPast = i < step

            return (
              <div
                key={evt.ctx?.seq ?? i}
                data-step={i}
                className={[
                  'flow-event',
                  isCurrent ? 'flow-current' : '',
                  isPast ? 'flow-past' : 'flow-future',
                  sev ? `flow-sev-${sev}` : '',
                ]
                  .filter(Boolean)
                  .join(' ')}
                onClick={() => setStep(i)}
                role='button'
                tabIndex={-1}
              >
                <span className='flow-event-seq'>{evt.ctx?.seq ?? i + 1}</span>
                <span className={`flow-event-actor actor-${actor}`}>{actor}</span>
                <div className='flow-event-body'>
                  <div className='flow-event-label'>{label}</div>
                  {detail && <div className='flow-event-detail'>{detail}</div>}
                </div>
                <div className='flow-event-meta'>
                  {ts !== '—' && <span className='flow-event-ts'>{ts}</span>}
                  {src && <span className={`flow-event-src src-${src.toLowerCase()}`}>{src}</span>}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
