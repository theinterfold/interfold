// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { CSSProperties, ReactNode, useEffect, useRef, useState } from 'react'
import { useInView, useReducedMotion } from './hooks'
import classes from './ui.module.css'

type Phase = {
  /** Text in the center of the ring. Keep it short (one or two words). */
  core: string
  /** Caption under the ring. */
  caption: ReactNode
  /** Which nodes send particles to the center: every node, the quorum only, or none. */
  senders: 'all' | 'quorum' | 'none'
}

type ThresholdRingProps = {
  /** Committee size N. */
  n: number
  /** Threshold T. Decryption needs T + 1 shares. */
  t: number
  /** Replace the default three phases. */
  phases?: Phase[]
  variant?: 'light' | 'dark'
  /** Time for each phase, in milliseconds. */
  interval?: number
  /** Accessible description of the figure. */
  label?: string
}

const CENTER = 160
const RADIUS = 118

const defaultPhases = (quorum: number): Phase[] => [
  {
    core: 'DKG',
    senders: 'all',
    caption: (
      <>
        <strong>Key generation.</strong> The committee runs DKG and makes one shared public key.
      </>
    ),
  },
  {
    core: 'Sealed',
    senders: 'none',
    caption: (
      <>
        <strong>No single key.</strong> No member holds the full secret key.
      </>
    ),
  },
  {
    core: 'Decrypt',
    senders: 'quorum',
    caption: (
      <>
        <strong>Threshold decryption.</strong> {quorum} key shares (T + 1) decrypt the output.
      </>
    ),
  },
]

/**
 * Animated committee diagram: N ciphernodes around a shared key, with T + 1 shares for decryption.
 * The highlighted decryption set is illustrative. Pass `phases` when a page needs exact captions.
 */
export function ThresholdRing({ n, t, phases, variant = 'light', interval = 3200, label }: ThresholdRingProps) {
  const quorum = t + 1
  const steps = phases ?? defaultPhases(quorum)
  const [phase, setPhase] = useState(0)
  const rootRef = useRef<HTMLDivElement>(null)
  const inView = useInView(rootRef)
  const reduced = useReducedMotion()

  useEffect(() => {
    if (reduced || !inView || steps.length < 2) return
    const timer = window.setInterval(() => setPhase((p) => (p + 1) % steps.length), interval)
    return () => window.clearInterval(timer)
  }, [reduced, inView, interval, steps.length])

  const current = steps[phase]
  const nodes = Array.from({ length: n }, (_, i) => {
    const angle = (i / n) * Math.PI * 2 - Math.PI / 2
    return { x: CENTER + RADIUS * Math.cos(angle), y: CENTER + RADIUS * Math.sin(angle) }
  })
  // Spread the quorum around the ring so that the figure does not suggest a fixed neighborhood.
  const quorumSet = new Set(Array.from({ length: quorum }, (_, k) => Math.floor((k * n) / quorum)))
  const isSender = (i: number) => current.senders === 'all' || (current.senders === 'quorum' && quorumSet.has(i))
  const nodeRadius = n > 12 ? 7 : 10
  const description =
    label ?? `A committee of ${n} ciphernodes. Decryption needs ${quorum} key shares (threshold T = ${t}, so T + 1 = ${quorum}).`

  return (
    <div ref={rootRef} className={`${classes.ring} ${variant === 'dark' ? classes.ringDark : classes.ringLight}`}>
      <svg className={classes.ringSvg} viewBox='0 0 320 320' role='img' aria-label={description}>
        <circle className={classes.ringOrbit} cx={CENTER} cy={CENTER} r={RADIUS + 22} />
        {nodes.map((node, i) => (
          <line
            key={`spoke-${i}`}
            x1={node.x}
            y1={node.y}
            x2={CENTER}
            y2={CENTER}
            className={`${classes.ringSpoke} ${isSender(i) ? classes.ringSpokeActive : ''} ${
              current.senders === 'quorum' && !isSender(i) ? classes.ringSpokeDim : ''
            }`}
          />
        ))}
        <circle className={classes.ringCoreGlow} cx={CENTER} cy={CENTER} r={44} />
        <circle className={classes.ringCore} cx={CENTER} cy={CENTER} r={34} />
        <text className={classes.ringCoreText} x={CENTER} y={CENTER}>
          {current.core}
        </text>
        {nodes.map((node, i) => (
          <circle
            key={`node-${i}`}
            cx={node.x}
            cy={node.y}
            r={nodeRadius}
            className={`${classes.ringNode} ${isSender(i) ? classes.ringNodeActive : ''} ${
              current.senders === 'quorum' && !isSender(i) ? classes.ringNodeDim : ''
            }`}
          />
        ))}
        {!reduced
          ? nodes.map((node, i) =>
              isSender(i) ? (
                <circle
                  key={`particle-${phase}-${i}`}
                  cx={node.x}
                  cy={node.y}
                  r={3.2}
                  className={`${classes.ringParticle} ${classes.ringParticleRun}`}
                  style={
                    {
                      '--dx': `${CENTER - node.x}px`,
                      '--dy': `${CENTER - node.y}px`,
                      '--delay': `${(i % 5) * 140}ms`,
                    } as CSSProperties
                  }
                />
              ) : null,
            )
          : null}
      </svg>
      <p key={phase} className={classes.ringCaption} aria-live='polite'>
        {current.caption}
      </p>
      {steps.length > 1 ? (
        <div className={classes.ringPhases}>
          {steps.map((step, i) => (
            <button
              key={step.core}
              type='button'
              aria-label={`Show phase ${i + 1}: ${step.core}`}
              className={`${classes.ringPhaseDot} ${i === phase ? classes.ringPhaseDotActive : ''}`}
              onClick={() => setPhase(i)}
            />
          ))}
        </div>
      ) : null}
    </div>
  )
}
