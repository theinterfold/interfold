// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Live E3 timeline — the hero pipeline.

import React, { useState } from 'react'
import type { Stage } from './data'

function StageDot({ state }: { state: 'done' | 'active' | 'todo' }) {
  if (state === 'done') {
    return (
      <div className='stage-dot stage-dot--done' aria-hidden='true'>
        <svg viewBox='0 0 16 16' width='14' height='14'>
          <path
            d='M3.5 8.5 L6.8 11.5 L12.5 5'
            stroke='currentColor'
            strokeWidth='1.8'
            strokeLinecap='round'
            strokeLinejoin='round'
            fill='none'
          />
        </svg>
      </div>
    )
  }
  if (state === 'active') {
    return (
      <div className='stage-dot stage-dot--active' aria-hidden='true'>
        <span className='stage-dot__spinner' />
        <span className='stage-dot__core' />
      </div>
    )
  }
  return <div className='stage-dot stage-dot--todo' aria-hidden='true' />
}

export default function Timeline({
  stages,
  currentStageIdx,
  pollId,
  density,
  onStageClick,
}: {
  stages: Stage[]
  currentStageIdx: number
  pollId: string
  density: string
  onStageClick?: (i: number) => void
}) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null)
  const clamp = (i: number) => Math.min(Math.max(i, 0), stages.length - 1)
  const explainerIdx = clamp(hoverIdx ?? currentStageIdx)
  const explainer = stages[explainerIdx]

  return (
    <section className={`timeline timeline--${density}`}>
      <header className='timeline__head'>
        <div className='timeline__eyebrow'>
          <span className='dot-live' />
          <span>Live · {pollId}</span>
        </div>
        <h2 className='timeline__title'>Where this poll is in its lifecycle</h2>
      </header>

      <div className='timeline__track' role='list'>
        {stages.map((s, i) => {
          // The final stage (Published) is terminal — when reached it's complete, not in-progress.
          const isLast = i === stages.length - 1
          const state = i < currentStageIdx ? 'done' : i === currentStageIdx ? (isLast ? 'done' : 'active') : 'todo'
          const isClickable = !!onStageClick
          const Tag: any = isClickable ? 'button' : 'div'
          return (
            <React.Fragment key={s.id}>
              <Tag
                role={isClickable ? undefined : 'listitem'}
                type={isClickable ? 'button' : undefined}
                className={`stage stage--${state} ${isClickable ? 'stage--clickable' : ''}`}
                onMouseEnter={() => setHoverIdx(i)}
                onMouseLeave={() => setHoverIdx(null)}
                onFocus={() => setHoverIdx(i)}
                onBlur={() => setHoverIdx(null)}
                onClick={isClickable ? () => onStageClick!(i) : undefined}
                tabIndex={0}
                aria-label={`Stage ${i + 1} of ${stages.length}: ${s.label}. ${s.blurb}${isClickable ? '. Click to jump to this stage.' : ''}`}
              >
                <StageDot state={state} />
                <div className='stage__label'>{s.label}</div>
                {state === 'active' && <div className='stage__active-tag'>In progress</div>}
              </Tag>
              {i < stages.length - 1 && (
                <div className={`stage-connector ${i < currentStageIdx ? 'stage-connector--done' : ''}`} aria-hidden='true' />
              )}
            </React.Fragment>
          )
        })}
      </div>

      <div className='timeline__explainer' aria-live='polite'>
        <span className='timeline__explainer-stage'>
          {explainer.label}
          <span className='timeline__explainer-divider'>·</span>
        </span>
        <span className='timeline__explainer-text'>{explainer.blurb}</span>
      </div>
    </section>
  )
}
