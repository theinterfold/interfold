// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { CSSProperties, ReactNode, useEffect, useRef, useState } from 'react'
import { useInView, useReducedMotion } from './hooks'
import classes from './ui.module.css'

/** Fades and lifts its children into place when they first scroll into view. */
export function Reveal({ children, delay = 0 }: { children: ReactNode; delay?: number }) {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref)
  return (
    <div
      ref={ref}
      className={`${classes.reveal} ${inView ? '' : classes.revealHidden}`}
      style={{ transitionDelay: `${delay}ms` } as CSSProperties}
    >
      {children}
    </div>
  )
}

const GLYPHS = '0123456789abcdef'

/**
 * Shows text that "decrypts" from random hex glyphs. The server render and screen readers get the
 * plain text. The layout does not move, because a hidden copy of the text reserves the space.
 */
export function Decrypt({ text, duration = 1400 }: { text: string; duration?: number }) {
  const reduced = useReducedMotion()
  const [shown, setShown] = useState<string | null>(null)

  useEffect(() => {
    if (reduced) return
    let frame = 0
    const start = performance.now()
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / duration)
      const settled = Math.floor(progress * text.length)
      let next = ''
      for (let i = 0; i < text.length; i++) {
        const char = text[i]
        next += i < settled || char === ' ' ? char : GLYPHS[Math.floor(Math.random() * GLYPHS.length)]
      }
      setShown(next)
      if (progress < 1) frame = requestAnimationFrame(tick)
      else setShown(null)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [text, duration, reduced])

  return (
    <span className={classes.decrypt}>
      <span className={classes.srOnly}>{text}</span>
      <span className={classes.decryptSizer} aria-hidden='true'>
        {text}
      </span>
      <span className={classes.decryptLive} aria-hidden='true'>
        {shown === null || reduced
          ? text
          : shown.split('').map((char, i) =>
              char === text[i] ? (
                <span key={i}>{char}</span>
              ) : (
                <span key={i} className={classes.decryptGlyph}>
                  {char}
                </span>
              ),
            )}
      </span>
    </span>
  )
}
