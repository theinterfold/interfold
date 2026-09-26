// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { Children, CSSProperties, isValidElement, ReactElement, ReactNode, useEffect, useRef, useState } from 'react'
import { Badge } from './Badge'
import { useHydrated, useInView, useReducedMotion } from './hooks'
import classes from './ui.module.css'

type StageProps = {
  title: string
  /** The party that acts in this stage, for example `Requester` or `Ciphernodes`. */
  actor?: string
  /** An on-chain event or state that marks the stage, shown as a code badge. */
  event?: string
  /** Use `fail` for a failure path. */
  tone?: 'default' | 'fail'
  children?: ReactNode
}

/** One stage of a `Lifecycle`. The children are the stage description in Markdown. */
export function Stage(_props: StageProps): null {
  // Lifecycle reads the props and renders the stage. This component renders nothing by itself.
  return null
}

/** Lets a long CamelCase name such as `CommitteeFinalized` wrap between its words. */
const breakCamelCase = (text: string) => text.replace(/([a-z])([A-Z])/g, '$1\u200b$2')

type LifecycleProps = {
  /** Small label above the track. */
  label?: string
  /** Time that each stage stays active during autoplay, in milliseconds. */
  interval?: number
  children: ReactNode
}

/**
 * Interactive stepper for a sequence of stages. It plays automatically when it is in view, pauses on
 * hover or keyboard focus, and never plays when the reader asks for reduced motion.
 */
export function Lifecycle({ label = 'Lifecycle', interval = 6000, children }: LifecycleProps) {
  const stages = Children.toArray(children).filter(
    (child): child is ReactElement<StageProps> => isValidElement(child) && typeof (child.props as StageProps).title === 'string',
  )
  const [active, setActive] = useState(0)
  const [userPaused, setUserPaused] = useState(false)
  const [hovered, setHovered] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const inView = useInView(rootRef)
  const reduced = useReducedMotion()
  const mounted = useHydrated()

  const playing = mounted && !reduced && !userPaused && !hovered && inView && stages.length > 1

  useEffect(() => {
    if (!playing) return
    const timer = window.setTimeout(() => setActive((i) => (i + 1) % stages.length), interval)
    return () => window.clearTimeout(timer)
  }, [playing, active, interval, stages.length])

  if (stages.length === 0) return null
  const current = stages[Math.min(active, stages.length - 1)].props

  return (
    <div
      ref={rootRef}
      className={classes.lifecycle}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onFocus={() => setHovered(true)}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setHovered(false)
      }}
    >
      <div className={classes.lifecycleHeader}>
        <span className={classes.lifecycleLabel}>{label}</span>
        {mounted && !reduced && stages.length > 1 ? (
          <button type='button' className={classes.iconButton} onClick={() => setUserPaused((p) => !p)} aria-pressed={userPaused}>
            {userPaused ? '▶ Play' : '❚❚ Pause'}
          </button>
        ) : null}
      </div>
      <ol className={classes.lifecycleTrack} role='tablist' aria-label={label}>
        {stages.map((stage, index) => {
          const state = index === active ? classes.stageActive : index < active ? classes.stageDone : ''
          const fail = stage.props.tone === 'fail' ? classes.stageFail : ''
          return (
            <li key={stage.props.title} role='presentation'>
              <button
                type='button'
                role='tab'
                aria-selected={index === active}
                className={`${classes.stageButton} ${state} ${fail}`}
                onClick={() => setActive(index)}
              >
                <span className={classes.stageIndex}>{index + 1}</span>
                <span className={classes.stageTitle}>{breakCamelCase(stage.props.title)}</span>
                {index === active ? (
                  <span
                    key={`${active}-${playing}`}
                    className={`${classes.stageProgress} ${playing ? classes.stageProgressRunning : ''}`}
                    style={{ '--duration': `${interval}ms` } as CSSProperties}
                  />
                ) : null}
              </button>
            </li>
          )
        })}
      </ol>
      <div key={active} className={classes.lifecyclePanel} role='tabpanel' aria-live='polite'>
        <div className={classes.panelNumber} aria-hidden='true'>
          {String(active + 1).padStart(2, '0')}
        </div>
        <div>
          {current.actor || current.event ? (
            <div className={classes.panelMeta}>
              {current.actor ? <Badge tone={current.tone === 'fail' ? 'warning' : 'mainnet'}>{current.actor}</Badge> : null}
              {current.event ? <code>{current.event}</code> : null}
            </div>
          ) : null}
          <h4 className={classes.panelTitle}>{current.title}</h4>
          <div className={classes.panelBody}>{current.children}</div>
        </div>
      </div>
    </div>
  )
}
