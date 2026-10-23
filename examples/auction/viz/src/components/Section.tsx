// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { ReactNode } from 'react'

interface SectionProps {
  id?: string
  kicker: string
  title: string
  intro?: ReactNode
  children: ReactNode
}

export function Section({ id, kicker, title, intro, children }: SectionProps) {
  return (
    <section id={id} className='flex flex-col gap-6'>
      <div className='hr' />
      <div className='flex flex-col gap-2 pt-2'>
        <span className='mono text-accent'>{kicker}</span>
        <h2 className='h2'>{title}</h2>
        {intro !== undefined && <p className='m-0 max-w-[70ch] text-ink-2'>{intro}</p>}
      </div>
      {children}
    </section>
  )
}
