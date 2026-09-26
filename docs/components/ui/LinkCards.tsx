// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import Link from 'next/link'
import React, { CSSProperties, MouseEvent, ReactNode } from 'react'
import { Icon, IconName } from './Icon'
import classes from './ui.module.css'

type CardsProps = {
  children: ReactNode
  /** Minimum card width before the grid wraps, in pixels. */
  min?: number
}

/** Responsive grid for `LinkCard` items. */
export function LinkCards({ children, min = 230 }: CardsProps) {
  return (
    <div className={classes.cards} style={{ '--card-min': `${min}px` } as CSSProperties}>
      {children}
    </div>
  )
}

type CardProps = {
  title: string
  href: string
  icon?: IconName
  /** Short uppercase label at the bottom of the card, for example the audience or reading time. */
  tag?: string
  children?: ReactNode
}

const trackPointer = (event: MouseEvent<HTMLElement>) => {
  const rect = event.currentTarget.getBoundingClientRect()
  event.currentTarget.style.setProperty('--mx', `${event.clientX - rect.left}px`)
  event.currentTarget.style.setProperty('--my', `${event.clientY - rect.top}px`)
}

/** A navigation card. The glow follows the pointer. External links open in a new tab. */
export function LinkCard({ title, href, icon, tag, children }: CardProps) {
  const external = /^https?:\/\//.test(href)
  const content = (
    <>
      {icon ? (
        <span className={classes.cardIcon}>
          <Icon name={icon} />
        </span>
      ) : null}
      <span className={classes.cardTitle}>
        {title}
        <span className={classes.cardArrow}>
          <Icon name='arrow' size={18} />
        </span>
      </span>
      {children ? <span className={classes.cardBody}>{children}</span> : null}
      {tag ? <span className={classes.cardTag}>{tag}</span> : null}
    </>
  )
  if (external) {
    return (
      <a className={classes.card} href={href} target='_blank' rel='noreferrer' onMouseMove={trackPointer}>
        {content}
      </a>
    )
  }
  return (
    <Link className={classes.card} href={href} onMouseMove={trackPointer}>
      {content}
    </Link>
  )
}
