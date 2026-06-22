// SPDX-License-Identifier: LGPL-3.0-only

import { useEffect, useMemo, useState } from 'react'
import { useE3Trace } from '../api'
import { absoluteTime, json, short } from '../format'
import type { E3PhaseId, E3Summary, EventView } from '../types'

const PHASES: E3PhaseId[] = [
  'request',
  'committee',
  'dkg_setup',
  'dkg_shares',
  'key_publication',
  'computation',
  'decryption',
  'settlement',
]
const COLUMN_WIDTH = 222
const NODE_WIDTH = 170
const NODE_HEIGHT = 48
const ROW_HEIGHT = 66

interface GraphNode {
  event: EventView
  x: number
  y: number
}

function eventTitle(value: string): string {
  return value.length > 24 ? `${value.slice(0, 22)}…` : value
}

function E3FlowGraph({ events, onSelect, selected }: { events: EventView[]; onSelect: (event: EventView) => void; selected?: string }) {
  const graph = useMemo(() => {
    const rows = new Map<E3PhaseId, number>()
    const nodes: GraphNode[] = events.map((event) => {
      const phase = event.phase ?? 'request'
      const row = rows.get(phase) ?? 0
      rows.set(phase, row + 1)
      return {
        event,
        x: 30 + PHASES.indexOf(phase) * COLUMN_WIDTH,
        y: 74 + row * ROW_HEIGHT,
      }
    })
    const byId = new Map(nodes.map((node) => [node.event.event_id, node]))
    const edges = nodes.flatMap((node) => {
      if (node.event.causation_id === node.event.event_id) return []
      const cause = byId.get(node.event.causation_id)
      return cause ? [{ cause, effect: node }] : []
    })
    const maxRows = Math.max(1, ...PHASES.map((phase) => rows.get(phase) ?? 0))
    return { nodes, edges, byId, height: 100 + maxRows * ROW_HEIGHT }
  }, [events])

  return (
    <div className='flow-canvas'>
      <svg width={PHASES.length * COLUMN_WIDTH + 40} height={graph.height} role='img' aria-label='Causal E3 event graph'>
        <defs>
          <marker id='flow-arrow' markerWidth='8' markerHeight='8' refX='7' refY='4' orient='auto'>
            <path d='M0,0 L8,4 L0,8 z' className='flow-arrow' />
          </marker>
        </defs>
        {PHASES.map((phase, index) => (
          <g key={phase} transform={`translate(${30 + index * COLUMN_WIDTH}, 20)`}>
            <text className='flow-phase-title'>{phase.replaceAll('_', ' ')}</text>
            <line className='flow-phase-rule' x1='0' x2={NODE_WIDTH} y1='26' y2='26' />
          </g>
        ))}
        <g className='flow-edges'>
          {graph.edges.map(({ cause, effect }) => {
            const startX = cause.x + NODE_WIDTH
            const startY = cause.y + NODE_HEIGHT / 2
            const endX = effect.x
            const endY = effect.y + NODE_HEIGHT / 2
            const bend = Math.max(25, Math.abs(endX - startX) / 2)
            const highlighted = selected === cause.event.event_id || selected === effect.event.event_id
            return (
              <path
                key={`${cause.event.event_id}-${effect.event.event_id}`}
                className={highlighted ? 'flow-edge flow-edge--selected' : 'flow-edge'}
                d={`M ${startX} ${startY} C ${startX + bend} ${startY}, ${endX - bend} ${endY}, ${endX} ${endY}`}
                markerEnd='url(#flow-arrow)'
              />
            )
          })}
        </g>
        <g className='flow-nodes'>
          {graph.nodes.map(({ event, x, y }) => (
            <g
              className={`flow-event flow-event--${event.source} flow-event--${event.severity} ${selected === event.event_id ? 'flow-event--selected' : ''}`}
              transform={`translate(${x}, ${y})`}
              key={`${event.aggregate_id}-${event.seq}`}
              role='button'
              tabIndex={0}
              onClick={() => onSelect(event)}
              onKeyDown={(keyEvent) => {
                if (keyEvent.key === 'Enter' || keyEvent.key === ' ') onSelect(event)
              }}
            >
              <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx='8' />
              <circle cx='13' cy='15' r='4' />
              <text className='flow-event__title' x='24' y='18'>
                {eventTitle(event.event_type)}
              </text>
              <text className='flow-event__meta' x='12' y='36'>
                {event.source.toUpperCase()} · #{event.seq} · {short(event.event_id, 5, 3)}
              </text>
            </g>
          ))}
        </g>
      </svg>
    </div>
  )
}

export default function FlowGraphView({
  e3s,
  selectedE3,
  onSelectE3,
  refreshKey,
}: {
  e3s: E3Summary[]
  selectedE3?: string
  onSelectE3: (id: string) => void
  refreshKey: number
}) {
  const trace = useE3Trace(selectedE3, refreshKey)
  const [selectedEvent, setSelectedEvent] = useState<EventView>()

  useEffect(() => {
    setSelectedEvent(trace.data?.events.at(-1))
  }, [selectedE3, trace.data?.events])

  const edges =
    trace.data?.events.filter((event) => trace.data?.events.some((candidate) => candidate.event_id === event.causation_id)).length ?? 0
  const roots = (trace.data?.events.length ?? 0) - edges
  const successors = selectedEvent
    ? (trace.data?.events.filter((event) => event.causation_id === selectedEvent.event_id && event.event_id !== selectedEvent.event_id) ??
      [])
    : []

  return (
    <div className='view-stack'>
      <header className='view-title flow-view-title'>
        <div>
          <span className='section-kicker'>Causal topology</span>
          <h1>E3 event flow graph</h1>
          <p>Every edge means “caused by.” Select any node to inspect its stage, source, context, successors, and failure payload.</p>
        </div>
        <label className='flow-selector'>
          <span>Computation</span>
          <select value={selectedE3 ?? ''} onChange={(event) => onSelectE3(event.target.value)}>
            {e3s.map((e3) => (
              <option value={e3.e3_id} key={e3.e3_id}>
                E3 {e3.e3_id} · {e3.status}
              </option>
            ))}
          </select>
        </label>
      </header>

      {!trace.data ? (
        <section className='panel blank-state'>
          <span className='loader-ring' />
          <h2>{trace.error ?? 'Reconstructing the causal graph…'}</h2>
        </section>
      ) : (
        <>
          <section className='graph-metrics'>
            <span>
              <strong>{trace.data.events.length}</strong> events
            </span>
            <span>
              <strong>{edges}</strong> causal edges
            </span>
            <span>
              <strong>{roots}</strong> observed roots
            </span>
            <span>
              <strong>{trace.data.error_count}</strong> failures
            </span>
          </section>
          <div className='flow-layout'>
            <section className='panel flow-graph-panel'>
              <div className='flow-legend'>
                <span>
                  <i className='legend-dot legend-dot--local' />
                  Local
                </span>
                <span>
                  <i className='legend-dot legend-dot--network' />
                  Network
                </span>
                <span>
                  <i className='legend-dot legend-dot--evm' />
                  EVM
                </span>
                <span className='flow-legend__hint'>Scroll horizontally and vertically · click a node</span>
              </div>
              <E3FlowGraph events={trace.data.events} selected={selectedEvent?.event_id} onSelect={setSelectedEvent} />
            </section>
            <aside className='panel flow-detail'>
              {selectedEvent ? (
                <>
                  <span className='section-kicker'>{selectedEvent.phase?.replaceAll('_', ' ') ?? 'unclassified'}</span>
                  <h2>{selectedEvent.event_type}</h2>
                  <p className='mono flow-detail__time'>{absoluteTime(selectedEvent.timestamp_us)}</p>
                  <dl className='flow-detail-grid'>
                    <div>
                      <dt>Event</dt>
                      <dd className='mono'>{selectedEvent.event_id}</dd>
                    </div>
                    <div>
                      <dt>Caused by</dt>
                      <dd className='mono'>{selectedEvent.causation_id}</dd>
                    </div>
                    <div>
                      <dt>Origin</dt>
                      <dd className='mono'>{selectedEvent.origin_id}</dd>
                    </div>
                    <div>
                      <dt>Observed from</dt>
                      <dd>
                        {selectedEvent.source} · {selectedEvent.producer}
                      </dd>
                    </div>
                    <div>
                      <dt>Successors</dt>
                      <dd>{successors.length || 'None observed'}</dd>
                    </div>
                  </dl>
                  {successors.length > 0 && (
                    <div className='flow-successor-list'>
                      {successors.map((event) => (
                        <button type='button' onClick={() => setSelectedEvent(event)} key={event.event_id}>
                          {event.event_type} <span className='mono'>{short(event.event_id, 5, 3)}</span>
                        </button>
                      ))}
                    </div>
                  )}
                  <div className='payload-head'>Structured payload</div>
                  <pre className='payload'>{json(selectedEvent.payload)}</pre>
                </>
              ) : (
                <div className='empty-inline'>Select an event node.</div>
              )}
            </aside>
          </div>
        </>
      )}
    </div>
  )
}
