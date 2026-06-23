// SPDX-License-Identifier: LGPL-3.0-only

import { useEffect, useMemo, useState } from 'react'
import { useE3Trace } from '../api'
import EventTimeline from '../components/EventTimeline'
import StageFlow from '../components/StageFlow'
import { compactInteger, eventTime, short } from '../format'
import type { E3PhaseId, E3Summary } from '../types'

function E3List({ e3s, selected, onSelect }: { e3s: E3Summary[]; selected?: string; onSelect: (id: string) => void }) {
  return (
    <aside className='e3-list'>
      <div className='e3-list__head'>
        <span>E3 history</span>
        <strong>{e3s.length}</strong>
      </div>
      <div className='e3-list__items'>
        {e3s.map((e3) => (
          <button
            type='button'
            key={e3.e3_id}
            className={`e3-list__item ${selected === e3.e3_id ? 'e3-list__item--selected' : ''}`}
            onClick={() => onSelect(e3.e3_id)}
          >
            <span className={`status-dot status-dot--${e3.status}`} />
            <span>
              <strong className='mono'>{e3.e3_id}</strong>
              <small>
                {e3.current_phase.replaceAll('_', ' ')} · {e3.event_count} events
              </small>
            </span>
            <span className='e3-list__time mono'>{eventTime(e3.last_seen_us)}</span>
          </button>
        ))}
        {!e3s.length && <div className='empty-inline'>No E3s have reached this node yet.</div>}
      </div>
    </aside>
  )
}

export default function E3Inspector({
  e3s,
  selected,
  onSelect,
  refreshKey,
}: {
  e3s: E3Summary[]
  selected?: string
  onSelect: (id: string) => void
  refreshKey: number
}) {
  const trace = useE3Trace(selected, refreshKey)
  const [phase, setPhase] = useState<E3PhaseId>('request')
  const [focus, setFocus] = useState<{ id: string; nonce: number }>()
  const currentPhase = trace.data?.current_phase

  // Sync phase with trace's current_phase on E3 selection change.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (currentPhase) setPhase(currentPhase)
  }, [selected, currentPhase])

  const stageEvents = useMemo(() => trace.data?.events.filter((event) => event.phase === phase) ?? [], [phase, trace.data?.events])

  useEffect(() => {
    if (!focus) return
    const frame = window.requestAnimationFrame(() => {
      const target = document.getElementById(`event-${focus.id}`)
      target?.scrollIntoView({ behavior: 'smooth', block: 'center' })
      target?.classList.add('event-card--located')
      window.setTimeout(() => target?.classList.remove('event-card--located'), 1_400)
    })
    return () => window.cancelAnimationFrame(frame)
  }, [focus, phase])

  const navigateToEvent = (id: string) => {
    const target = trace.data?.events.find((event) => event.event_id === id)
    if (!target) return
    if (target.phase) setPhase(target.phase)
    setFocus({ id, nonce: Date.now() })
  }
  return (
    <div className='inspector-layout'>
      <E3List e3s={e3s} selected={selected} onSelect={onSelect} />
      <main className='inspector-main'>
        {!selected ? (
          <div className='blank-state'>
            <span className='blank-state__glyph'>E3</span>
            <h1>No computation selected</h1>
            <p>Select an E3 to inspect its complete local flow.</p>
          </div>
        ) : trace.error && !trace.data ? (
          <div className='blank-state blank-state--error'>
            <h1>Couldn’t load this trace</h1>
            <p>{trace.error}</p>
          </div>
        ) : !trace.data ? (
          <div className='blank-state'>
            <span className='loader-ring' />
            <h1>Rebuilding the trace</h1>
            <p>Reading durable events from this node…</p>
          </div>
        ) : (
          <>
            <header className='trace-head'>
              <div>
                <span className='section-kicker'>Encrypted execution environment</span>
                <h1 className='mono'>E3 {trace.data.e3_id}</h1>
                <p>
                  Chain {trace.data.chain_id} · first observed {eventTime(trace.data.first_seen_us)} · {trace.data.event_count} events
                </p>
              </div>
              <span className={`trace-status trace-status--${trace.data.status}`}>
                <span />
                {trace.data.status}
              </span>
            </header>

            {trace.data.failure != null && (
              <div className='failure-banner'>
                <strong>Failure localized</strong>
                <code>{JSON.stringify(trace.data.failure)}</code>
              </div>
            )}
            <StageFlow phases={trace.data.phases} selected={phase} onSelect={setPhase} />

            <div className='trace-columns'>
              <section className='panel trace-events'>
                <header className='panel__head'>
                  <div>
                    <span className='section-kicker'>Selected stage</span>
                    <h2>{trace.data.phases.find((item) => item.id === phase)?.label}</h2>
                  </div>
                  <span className='panel__aside'>{stageEvents.length} events</span>
                </header>
                <div id='flow-origin-note' className='flow-note'>
                  Every row carries its durable event, cause, origin, and immediate successors. Causal links jump across stages while
                  preserving this E3 trace.
                </div>
                <EventTimeline events={stageEvents} traceEvents={trace.data.events} onNavigate={navigateToEvent} />
              </section>

              <aside className='trace-sidebar'>
                <section className='panel panel--compact'>
                  <header className='panel__head'>
                    <div>
                      <span className='section-kicker'>Participants</span>
                      <h2>Committee</h2>
                    </div>
                    <span className='panel__aside'>{trace.data.committee.length}</span>
                  </header>
                  <div className='committee-list'>
                    {trace.data.committee.map((member) => (
                      <div className={`committee-member ${member.expelled ? 'committee-member--expelled' : ''}`} key={member.address}>
                        <span className='committee-member__party mono'>P{member.party_id}</span>
                        <div>
                          <strong className='mono' title={member.address}>
                            {short(member.address, 10, 6)}
                          </strong>
                          <small title={member.score}>score {compactInteger(member.score)}</small>
                        </div>
                        {member.expelled && <span className='status-tag status-tag--failed'>Expelled</span>}
                      </div>
                    ))}
                    {!trace.data.committee.length && <div className='empty-inline'>Committee not finalized.</div>}
                  </div>
                </section>

                <section className='panel panel--compact'>
                  <header className='panel__head'>
                    <div>
                      <span className='section-kicker'>Sortition</span>
                      <h2>Tickets</h2>
                    </div>
                    <span className='panel__aside'>{trace.data.tickets.length}</span>
                  </header>
                  <div className='ticket-list'>
                    {trace.data.tickets.slice(0, 12).map((ticket) => (
                      <div key={`${ticket.node}-${ticket.ticket_id}`}>
                        <span className='mono'>#{ticket.ticket_id}</span>
                        <strong className='mono'>{short(ticket.node, 8, 5)}</strong>
                        <small>{compactInteger(ticket.score)}</small>
                      </div>
                    ))}
                    {!trace.data.tickets.length && <div className='empty-inline'>No submitted tickets observed.</div>}
                  </div>
                </section>

                <section className='panel panel--compact'>
                  <header className='panel__head'>
                    <div>
                      <span className='section-kicker'>Settlement</span>
                      <h2>Rewards</h2>
                    </div>
                    <span className='panel__aside'>{trace.data.rewards.length}</span>
                  </header>
                  <div className='reward-list'>
                    {trace.data.rewards.map((reward, index) => (
                      <div key={`${reward.account}-${index}`}>
                        <span className={`reward-state ${reward.claimed ? 'reward-state--claimed' : ''}`}>
                          {reward.claimed ? 'Claimed' : 'Credited'}
                        </span>
                        <strong className='mono' title={reward.account}>
                          {short(reward.account, 8, 5)}
                        </strong>
                        <small className='mono' title={reward.amount}>
                          {compactInteger(reward.amount)}
                        </small>
                      </div>
                    ))}
                    {!trace.data.rewards.length && <div className='empty-inline'>Rewards are recorded when the E3 settles.</div>}
                  </div>
                </section>
              </aside>
            </div>
          </>
        )}
      </main>
    </div>
  )
}
