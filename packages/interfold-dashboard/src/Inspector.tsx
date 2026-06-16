// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// E3 Inspector — deep technical record of a single E3.

import React, { useEffect, useRef, useState } from 'react'
import { STAGES } from './data'
import { CONTRACTS } from './lib/chain'
import { explorerAddress, explorerTx } from './lib/links'
import type { InspectorDetail } from './lib/adapt'
import Loader from './Loader'

export type InspectorE3List = Array<{ id: string; label: string }>

function Mono({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <span className={`mono ${className}`}>{children}</span>
}

function short(hex: string): string {
  if (!hex || hex.length < 14) return hex
  return `${hex.slice(0, 10)}…${hex.slice(-6)}`
}

// A hash/address rendered as a link out to the block explorer.
function ExplorerLink({ value, href }: { value: string; href: string }) {
  return (
    <a className='hash' href={href} target='_blank' rel='noreferrer' title={value}>
      <span className='mono'>{short(value)}</span>
      <span className='hash__icon' aria-hidden='true'>
        ↗
      </span>
    </a>
  )
}

const TxLink = ({ hash }: { hash: string }) => <ExplorerLink value={hash} href={explorerTx(hash)} />
const AddrLink = ({ address }: { address: string }) => <ExplorerLink value={address} href={explorerAddress(address)} />

function InspStatusBadge({ stageIdx, label }: { stageIdx: number; label?: string }) {
  const s = STAGES[stageIdx]
  const variant = stageIdx >= 6 ? 'published' : stageIdx === 3 ? 'open' : 'working'
  return (
    <span className={`stage-badge stage-badge--${variant}`}>
      <span className='stage-badge__dot' />
      <span>{label ?? s.label}</span>
    </span>
  )
}

function DefList({ items }: { items: Array<[React.ReactNode, React.ReactNode]> }) {
  return (
    <dl className='dl'>
      {items.map(([k, v], i) => (
        <React.Fragment key={i}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </React.Fragment>
      ))}
    </dl>
  )
}

function SectionCard({
  eyebrow,
  title,
  status,
  children,
  dense,
}: {
  eyebrow: string
  title: string
  status?: { kind: string; label: string }
  children: React.ReactNode
  dense?: boolean
}) {
  return (
    <section className={`isection ${dense ? 'isection--dense' : ''}`}>
      <header className='isection__head'>
        <div>
          <div className='isection__eyebrow'>{eyebrow}</div>
          <h3 className='isection__title'>{title}</h3>
        </div>
        {status && <span className={`isection__status isection__status--${status.kind}`}>{status.label}</span>}
      </header>
      <div className='isection__body'>{children}</div>
    </section>
  )
}

function InspectorStageStrip({ stages, currentStageIdx }: { stages: typeof STAGES; currentStageIdx: number }) {
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const [overflow, setOverflow] = useState(false)
  useEffect(() => {
    const el = wrapRef.current
    if (!el) return
    const check = () => {
      const inner = el.querySelector('.istrip') as HTMLElement | null
      if (!inner) return
      setOverflow(inner.scrollWidth - inner.clientWidth > 4 && inner.scrollLeft + inner.clientWidth < inner.scrollWidth - 4)
    }
    check()
    const ro = new ResizeObserver(check)
    ro.observe(el)
    const inner = el.querySelector('.istrip')
    inner?.addEventListener('scroll', check)
    return () => {
      ro.disconnect()
      inner?.removeEventListener('scroll', check)
    }
  }, [])
  return (
    <div className='insp-head__strip' ref={wrapRef} data-overflow={overflow ? '1' : '0'}>
      <div className='istrip' role='list'>
        {stages.map((s, i) => {
          const isLast = i === stages.length - 1
          const state = i < currentStageIdx ? 'done' : i === currentStageIdx ? (isLast ? 'done' : 'active') : 'todo'
          return (
            <React.Fragment key={s.id}>
              <div role='listitem' className={`istrip__node istrip__node--${state}`}>
                <span className='istrip__dot' />
                <span className='istrip__label'>{s.label}</span>
              </div>
              {i < stages.length - 1 && <span className={`istrip__rule ${i < currentStageIdx ? 'istrip__rule--done' : ''}`} />}
            </React.Fragment>
          )
        })}
      </div>
    </div>
  )
}

function EventLog({ events }: { events: any[] }) {
  const [filter, setFilter] = useState('all')
  const stages = ['all', ...Array.from(new Set(events.map((e) => e.stage)))]
  const filtered = filter === 'all' ? events : events.filter((e) => e.stage === filter)
  return (
    <div className='evlog-wrap'>
      <div className='evlog__filters'>
        {stages.map((s) => (
          <button key={s} type='button' className={`chip chip--sm ${filter === s ? 'chip--on' : ''}`} onClick={() => setFilter(s)}>
            {s === 'all' ? 'All events' : s}
          </button>
        ))}
        <span className='evlog__count mono'>
          {filtered.length} / {events.length}
        </span>
      </div>
      <table className='evlog'>
        <thead>
          <tr>
            <th>Time</th>
            <th>Block</th>
            <th>Event</th>
            <th>Stage</th>
            <th>Tx</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((ev, i) => (
            <tr key={i}>
              <td>
                <Mono>{ev.t}</Mono>
              </td>
              <td>
                <Mono>{typeof ev.block === 'number' ? `#${ev.block.toLocaleString()}` : ev.block}</Mono>
              </td>
              <td>
                <span className='evlog__name'>{ev.name}</span>
              </td>
              <td>
                <span className='evlog__stage'>{ev.stage}</span>
              </td>
              <td>{ev.txHash ? <TxLink hash={ev.txHash} /> : <Mono>{ev.tx}</Mono>}</td>
            </tr>
          ))}
          {filtered.length === 0 && (
            <tr>
              <td colSpan={5} className='evlog__empty'>
                No events match this filter.
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <div className='evlog__foot'>
        <span>Events stream live from the Interfold contract on Sepolia.</span>
        <a className='link-inline' href={explorerAddress(CONTRACTS.Interfold) + '#events'} target='_blank' rel='noreferrer'>
          Open in block explorer →
        </a>
      </div>
    </div>
  )
}

export default function Inspector({
  e3List,
  e3,
  selectedId,
  onSelect,
  loading,
  error,
}: {
  e3List: InspectorE3List
  e3: InspectorDetail | null
  selectedId?: string
  onSelect: (id: string) => void
  loading?: boolean
  error?: Error | null
}) {
  const list = e3List
  const setSelectedId = onSelect

  if (!e3) {
    return (
      <div className='inspector'>
        {error ? (
          <div
            style={{
              padding: '10px 14px',
              borderRadius: 8,
              fontSize: 12,
              background: '#fff1f0',
              color: '#8a1f1f',
            }}
          >
            {`Failed to load on-chain data: ${error.message}.`}
          </div>
        ) : (
          <Loader label='Loading E3 detail' sub='Reading from Sepolia…' />
        )}
      </div>
    )
  }

  // Section status derived from the E3's current UI stage index (see STAGES order).
  // The final stage (Published, index 6) is terminal: reaching it = complete.
  // When `noBallots` is set the chain stayed in KeyPublished (currentStage=4) but
  // nothing was ever submitted, so post-input sections aren't actually "in progress".
  const lastStage = STAGES.length - 1
  const stageStatus = (targetStage: number) => {
    if (e3.noBallots && targetStage >= 4) {
      return targetStage === 4 ? { kind: 'pending', label: 'No ballots' } : { kind: 'pending', label: 'Skipped' }
    }
    if (e3.currentStage > targetStage) return { kind: 'done', label: 'Done' }
    if (e3.currentStage === targetStage) {
      return targetStage >= lastStage ? { kind: 'done', label: 'Complete' } : { kind: 'live', label: 'In progress' }
    }
    return { kind: 'pending', label: 'Pending' }
  }

  return (
    <div className='inspector'>
      {(loading || error) && (
        <div
          style={{
            padding: '10px 14px',
            margin: '0 0 12px',
            borderRadius: 8,
            fontSize: 12,
            background: error ? '#fff1f0' : '#f4f6f8',
            color: error ? '#8a1f1f' : '#3a3f4a',
          }}
        >
          {error ? `Failed to load on-chain data: ${error.message}.` : 'Refreshing from Sepolia…'}
        </div>
      )}
      <section className='insp-head'>
        <div className='insp-head__row'>
          <div>
            <div className='insp-head__breadcrumb'>
              <span>Network</span>
              <span className='insp-head__crumb-sep'>/</span>
              <span>E3 inspector</span>
              <span className='insp-head__crumb-sep'>/</span>
              <Mono>{e3.id}</Mono>
            </div>
            <h1 className='insp-head__title'>{e3.summary}</h1>
            <div className='insp-head__meta'>
              <span>Program</span>
              <Mono>{e3.program}</Mono>
              <span className='insp-head__meta-sep'>·</span>
              <span>Requested by</span>
              <AddrLink address={e3.requestedBy} />
            </div>
          </div>
          <div className='insp-head__selector'>
            <label htmlFor='e3-select' className='insp-head__selector-label'>
              Inspect E3
            </label>
            <select id='e3-select' className='insp-select' value={selectedId} onChange={(e) => setSelectedId(e.target.value)}>
              {list.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.id} · {e.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <InspectorStageStrip stages={STAGES} currentStageIdx={e3.currentStage} />

        <div className='insp-stats'>
          <div className='insp-stat'>
            <div className='insp-stat__label'>Status</div>
            <div className='insp-stat__value'>
              <InspStatusBadge stageIdx={e3.currentStage} label={e3.noBallots ? 'Complete · no ballots' : undefined} />
            </div>
          </div>
          <div className='insp-stat'>
            <div className='insp-stat__label'>Committee</div>
            <div className='insp-stat__value mono'>
              {e3.committee.threshold} <span className='insp-stat__of'>of</span> {e3.committee.size}
            </div>
            <div className='insp-stat__sub'>threshold · total nodes</div>
          </div>
          <div className='insp-stat'>
            <div className='insp-stat__label'>Inputs</div>
            <div className='insp-stat__value mono'>{e3.input.inputsReceived}</div>
            <div className='insp-stat__sub'>encrypted · published</div>
          </div>
          <div className='insp-stat'>
            <div className='insp-stat__label'>Fee escrowed</div>
            <div className='insp-stat__value mono'>{e3.fees.feeEscrowed}</div>
            <div className='insp-stat__sub'>held by Interfold</div>
          </div>
        </div>
      </section>

      <SectionCard eyebrow='01 · Request & Committee' title='How this E3 came into being'>
        <div className='isection__grid'>
          <DefList
            items={[
              ['Requested at', <Mono>{e3.requestedAt}</Mono>],
              ['Request tx', <TxLink hash={e3.requestedTx} />],
              ['Block', <Mono>{e3.requestedBlock != null ? `#${e3.requestedBlock.toLocaleString()}` : '—'}</Mono>],
              ['Requested by', <AddrLink address={e3.requestedBy} />],
              ['Program', <Mono>{e3.program}</Mono>],
              ['Program address', <AddrLink address={e3.programAddr} />],
            ]}
          />
          <DefList
            items={[
              ['Committee size', <Mono>{e3.committee.size} nodes</Mono>],
              [
                'Decryption threshold',
                <Mono>
                  {e3.committee.threshold} of {e3.committee.size}
                </Mono>,
              ],
              ['Selection seed', <Mono>{e3.committee.selectionSeed}</Mono>],
              ['Drawn at', <Mono>{e3.committee.drawnAt}</Mono>],
            ]}
          />
        </div>
      </SectionCard>

      <SectionCard eyebrow='02 · Keygen' title='Distributed key generation'>
        <p className='isection__lede'>
          The committee jointly generated an encryption key. The matching <em>decryption</em> key is held in shares - never assembled, never
          written down.
        </p>
        <DefList
          items={[
            ['Encryption scheme', <Mono>{e3.keygen.scheme}</Mono>],
            ['Committee finalized', <Mono>{e3.keygen.finalizedAt}</Mono>],
            ['Public key published', <Mono>{e3.keygen.publishedAt}</Mono>],
            ['Publish tx', e3.keygen.publishedTx === '—' ? <Mono>—</Mono> : <TxLink hash={e3.keygen.publishedTx} />],
            ['Committee public key', <Mono>{e3.keygen.publicKey}</Mono>],
          ]}
        />
      </SectionCard>

      <SectionCard eyebrow='03 · Input Window' title='Encrypted inputs received'>
        <div className='isection__grid'>
          <DefList
            items={[
              ['Opened', <Mono>{e3.input.openedAt}</Mono>],
              ['Closes', <Mono>{e3.input.closesAt}</Mono>],
              ['Inputs received', <Mono>{e3.input.inputsReceived}</Mono>],
            ]}
          />
          <DefList
            items={[
              ['First input', <Mono>{e3.input.firstBallotAt}</Mono>],
              ['Last input', <Mono>{e3.input.lastBallotAt}</Mono>],
            ]}
          />
        </div>
      </SectionCard>

      <SectionCard eyebrow='04 · Compute' title='FHE computation' status={stageStatus(4)}>
        <p className='isection__lede'>{e3.compute.note}</p>
      </SectionCard>

      <SectionCard eyebrow='05 · Decryption' title='Threshold decryption' status={stageStatus(5)}>
        <p className='isection__lede'>{e3.decryption.note}</p>
        <DefList
          items={[
            [
              'Decryption threshold',
              <Mono>
                {e3.decryption.threshold} of {e3.decryption.committeeSize}
              </Mono>,
            ],
          ]}
        />
      </SectionCard>

      <SectionCard eyebrow='06 · Publication' title='Result on-chain' status={stageStatus(6)}>
        <p className='isection__lede'>{e3.publication.note}</p>
        {e3.publication.resultTx && <DefList items={[['Result tx', <TxLink hash={e3.publication.resultTx} />]]} />}
      </SectionCard>

      <SectionCard eyebrow='07 · Fees & settlement' title='Fees'>
        <div className='fees'>
          <DefList
            items={[
              ['Fee escrowed', <Mono>{e3.fees.feeEscrowed}</Mono>],
              ['Committee reward paid', <Mono>{e3.fees.committeeReward}</Mono>],
              ['Settlement', <span className='dl__muted'>{e3.fees.currency}</span>],
            ]}
          />
          <p className='isection__lede'>
            Fee escrowed is the amount currently held by the Interfold contract for this E3; it is released to the committee and any refund
            on settlement, so a completed E3 reads 0. Committee reward shows the total paid out once rewards are distributed.
          </p>
        </div>
      </SectionCard>

      <SectionCard eyebrow='08 · Event log' title='On-chain events, oldest first' dense>
        <EventLog events={e3.events} />
      </SectionCard>
    </div>
  )
}
