// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import CardContent from '@/components/Cards/CardContent'
import { EditorialShell } from '@/design/Editorial'

const SECTIONS = [
  {
    kicker: 'what is crisp?',
    body: 'CRISP (Coercion-Resistant Impartial Selection Protocol) is a secure protocol for digital decision-making, leveraging fully homomorphic encryption (FHE) and distributed threshold cryptography (DTC) to enable verifiable secret ballots. Built with Interfold, CRISP safeguards democratic systems and decision-making applications against coercion, manipulation, and other vulnerabilities.',
  },
  {
    kicker: 'why is this important?',
    body: 'Open ballots are known to produce suboptimal outcomes, exposing participants to bribery and coercion. CRISP mitigates these risks and other vulnerabilities with secret, receipt-free ballots, fostering secure and impartial decision-making environments.',
  },
  {
    kicker: 'Proof of Concept',
    body: 'This application is a Proof of Concept (PoC), demonstrating the viability of Interfold as a network and CRISP as an application for secret ballots. Future iterations of this and other applications will be progressively more complete.',
  },
]

const About: React.FC = () => {
  return (
    <EditorialShell className='flex w-full flex-1 flex-col'>
      <section className='pad-section' style={{ flex: 1 }}>
        <div className='col' style={{ gap: 28 }}>
          <h1 className='h1'>About CRISP</h1>
          <CardContent>
            {SECTIONS.map(({ kicker, body }) => (
              <div key={kicker} className='col' style={{ gap: 10 }}>
                <p className='mono muted'>{kicker}</p>
                <p className='lede' style={{ maxWidth: 'none' }}>
                  {body}
                </p>
              </div>
            ))}
          </CardContent>
        </div>
      </section>
    </EditorialShell>
  )
}

export default About
