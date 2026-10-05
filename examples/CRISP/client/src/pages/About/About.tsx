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
    body: 'CRISP (Coercion-Resistant Impartial Selection Protocol) is a protocol for digital decision-making. It uses fully homomorphic encryption (FHE) and distributed threshold cryptography (DTC) to tally encrypted ballots and publish a verifiable result. No single committee member can decrypt a ballot, but enough committee members who collude can. The public result can show how individual participants voted, for example in a small or one-sided poll.',
  },
  {
    kicker: 'why is this important?',
    body: 'Open ballots expose participants to bribery and coercion. CRISP reduces these risks with encrypted ballots and masks, which make a vote, an update, and a mask look the same on-chain. This makes a receipt of a vote less reliable, but it does not remove every risk: the CRISP server receives every ballot, and a transaction from a wallet also shows its address on-chain.',
  },
  {
    kicker: 'Proof of Concept',
    body: 'This application is a Proof of Concept (PoC), demonstrating the viability of Interfold as a network and CRISP as an application for encrypted ballots. Future iterations of this and other applications will be progressively more complete.',
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
