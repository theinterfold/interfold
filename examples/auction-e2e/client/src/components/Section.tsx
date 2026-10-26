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

/** A titled panel: the title and its running number over a hairline, the content below. */
const Section: React.FC<SectionProps> = ({ eyebrow, title, children }) => (
  <section className='card'>
    <header className='panel-header'>
      <h2>{title}</h2>
      <span className='meta'>{eyebrow}</span>
    </header>
    {children}
  </section>
)

export default Section
