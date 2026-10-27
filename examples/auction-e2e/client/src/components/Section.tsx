// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'

interface SectionProps {
  title: string
  children: React.ReactNode
}

/** A titled panel: the title over a hairline, the content below. */
const Section: React.FC<SectionProps> = ({ title, children }) => (
  <section className='card'>
    <header className='panel-header'>
      <h2>{title}</h2>
    </header>
    {children}
  </section>
)

export default Section
