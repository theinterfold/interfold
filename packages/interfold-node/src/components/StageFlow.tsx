// SPDX-License-Identifier: LGPL-3.0-only

import type { E3PhaseId, PhaseView } from '../types'

export default function StageFlow({
  phases,
  selected,
  onSelect,
}: {
  phases: PhaseView[]
  selected: E3PhaseId
  onSelect: (phase: E3PhaseId) => void
}) {
  return (
    <div className='stage-flow' aria-label='E3 protocol stages'>
      {phases.map((phase, index) => (
        <div className='stage-flow__unit' key={phase.id}>
          <button
            type='button'
            className={`stage-node stage-node--${phase.state} ${selected === phase.id ? 'stage-node--selected' : ''}`}
            onClick={() => onSelect(phase.id)}
          >
            <span className='stage-node__index'>{String(index + 1).padStart(2, '0')}</span>
            <span className='stage-node__copy'>
              <strong>{phase.label}</strong>
              <span>
                {phase.event_count} events · L{phase.sources.local} N{phase.sources.net} E{phase.sources.evm}
              </span>
            </span>
            <span className='stage-node__state'>
              {phase.state === 'complete' ? '✓' : phase.state === 'failed' ? '!' : phase.state === 'active' ? '●' : '○'}
            </span>
          </button>
          {index < phases.length - 1 && (
            <span className={`stage-flow__connector ${phase.state === 'complete' ? 'stage-flow__connector--done' : ''}`} />
          )}
        </div>
      ))}
    </div>
  )
}
