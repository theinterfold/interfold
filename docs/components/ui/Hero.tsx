// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import Link from 'next/link'
import React, { ReactNode } from 'react'
import { Icon } from './Icon'
import classes from './ui.module.css'

type Action = { label: string; href: string }

type HeroProps = {
  eyebrow?: string
  title: ReactNode
  lead?: ReactNode
  primary?: Action
  secondary?: Action[]
  /** Figure on the right side, for example `<ThresholdRing variant='dark' />`. */
  visual?: ReactNode
}

/** Dark landing banner with an animated grid and a figure. */
export function Hero({ eyebrow, title, lead, primary, secondary = [], visual }: HeroProps) {
  return (
    <section className={classes.hero}>
      <div className={classes.heroGrid} aria-hidden='true' />
      <div className={`${classes.heroOrb} ${classes.heroOrbA}`} aria-hidden='true' />
      <div className={`${classes.heroOrb} ${classes.heroOrbB}`} aria-hidden='true' />
      <div>
        {eyebrow ? <span className={classes.heroEyebrow}>{eyebrow}</span> : null}
        <h1 className={classes.heroTitle}>{title}</h1>
        {lead ? <p className={classes.heroLead}>{lead}</p> : null}
        <div className={classes.heroActions}>
          {primary ? (
            <Link className={`${classes.button} ${classes.buttonPrimary}`} href={primary.href}>
              {primary.label}
              <Icon name='arrow' size={18} />
            </Link>
          ) : null}
          {secondary.map((action) => (
            <Link key={action.href} className={`${classes.button} ${classes.buttonGhost}`} href={action.href}>
              {action.label}
            </Link>
          ))}
        </div>
      </div>
      {visual ? <div className={classes.heroVisual}>{visual}</div> : null}
    </section>
  )
}

/** Accent word inside a hero title. */
export function Accent({ children }: { children: ReactNode }) {
  return <span className={classes.heroAccent}>{children}</span>
}

/** Large section heading for landing and overview pages. It is not part of the page outline. */
export function SectionHead({ kicker, title, children }: { kicker?: string; title: string; children?: ReactNode }) {
  return (
    <div className={classes.sectionHead}>
      {kicker ? <div className={classes.sectionKicker}>{kicker}</div> : null}
      <div className={classes.sectionTitle} role='heading' aria-level={2}>
        {title}
      </div>
      {children ? <div className={classes.sectionLead}>{children}</div> : null}
    </div>
  )
}
