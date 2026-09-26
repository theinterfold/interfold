// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { ReactNode, useEffect, useRef, useState } from 'react'
import { useInView, useReducedMotion } from './hooks'
import classes from './ui.module.css'

export type StatData = {
  /** A plain integer counts up when it enters the view. Any other value shows as it is. */
  value: string
  label: string
  hint?: ReactNode
}

function CountUp({ value }: { value: string }) {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref)
  const reduced = useReducedMotion()
  const target = /^\d{1,9}$/.test(value) ? Number(value) : null
  // The value in flight while the count runs. `null` shows the final value.
  const [counting, setCounting] = useState<string | null>(null)
  const animate = target !== null && target >= 2 && !reduced && inView

  useEffect(() => {
    if (!animate || target === null) return
    let frame = 0
    const start = performance.now()
    const duration = 900
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - progress, 3)
      setCounting(progress < 1 ? String(Math.round(eased * target)) : null)
      if (progress < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [animate, target])

  return (
    <div ref={ref} className={classes.statValue}>
      {animate && counting !== null ? counting : value}
    </div>
  )
}

/** A row of key values, for example committee sizes or timeouts. */
export function Stats({ items }: { items: StatData[] }) {
  return (
    <div className={classes.stats}>
      {items.map((item) => (
        <div key={item.label} className={classes.stat}>
          <CountUp value={item.value} />
          <div className={classes.statLabel}>{item.label}</div>
          {item.hint ? <div className={classes.statHint}>{item.hint}</div> : null}
        </div>
      ))}
    </div>
  )
}
