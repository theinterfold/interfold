// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'

interface SectionProps {
  eyebrow: string
  title: string
  children: React.ReactNode
}

/** A titled card: a mono eyebrow, a serif title and the content below a rule. */
const Section: React.FC<SectionProps> = ({ eyebrow, title, children }) => (
  <section className='card space-y-5 !p-5 md:!p-7'>
    <header className='space-y-2'>
      <p className='mono muted'>{eyebrow}</p>
      <h2 className='h2'>{title}</h2>
      <div className='hr' />
    </header>
    {children}
  </section>
)

export default Section
