// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { Keyhole, ListMagnifyingGlass, ShieldCheck } from '@phosphor-icons/react'
import { EditorialShell, Cipher, MarkerUnderline } from '@/design/Editorial'

const PRINCIPLES = [
  {
    icon: Keyhole,
    label: 'Private',
    body: 'Ballots are encrypted with fully homomorphic encryption before they leave your device. No single committee member can decrypt them.',
  },
  {
    icon: ListMagnifyingGlass,
    label: 'Reliable',
    body: 'Verifiable results. The tally is computed on ciphertext and proven correct, and only the combined result is decrypted.',
  },
  {
    icon: ShieldCheck,
    label: 'Equitable',
    body: 'A threshold committee that no single party controls holds the key. Masks make votes, updates, and masks look the same on-chain, which weakens vote receipts.',
  },
]

const HeroSection: React.FC = () => {
  return (
    <EditorialShell className='flex w-full flex-1 flex-col'>
      <section className='pad-section' style={{ flex: 1 }}>
        <div className='split'>
          {/* Left — editorial copy */}
          <div className='col' style={{ gap: 36 }}>
            <div className='col' style={{ gap: 18 }}>
              <div className='mono muted'>Coercion-Resistant Impartial Selection Protocol</div>
              <h1 className='display'>
                <MarkerUnderline>Crisp</MarkerUnderline>
              </h1>
              <p className='lede' style={{ maxWidth: 'none' }}>
                Encrypted voting you can verify. Cast an encrypted vote, and a threshold committee decrypts only the final tally. The tally
                is public, so in a small or one-sided poll it can show how people voted.
              </p>
            </div>

            <ul className='col' style={{ gap: 18, listStyle: 'none', margin: 0, padding: 0 }}>
              {PRINCIPLES.map(({ icon: Icon, label, body }) => (
                <li key={label} className='row' style={{ alignItems: 'flex-start', gap: 16 }}>
                  <Icon size={28} weight='light' style={{ flexShrink: 0, marginTop: 2 }} />
                  <div>
                    <span className='accent' style={{ fontWeight: 600, marginRight: 8 }}>
                      {label}.
                    </span>
                    <span className='muted'>{body}</span>
                  </div>
                </li>
              ))}
            </ul>

            <div className='col' style={{ gap: 16 }}>
              <div className='row' style={{ gap: 10, flexWrap: 'wrap' }}>
                <span className='muted'>A simple demonstration of CRISP technology.</span>
                <a href='https://docs.theinterfold.com' target='_blank' rel='noreferrer' className='linkish'>
                  Learn more →
                </a>
              </div>
              <div>
                <Link to='/current' className='btn lg'>
                  Try the demo →
                </Link>
              </div>
            </div>
          </div>

          {/* Right — ciphertext visual */}
          <div className='split-visual'>
            <div className='card col' style={{ gap: 18 }}>
              <div className='between'>
                <span className='mono muted'>Your ballot, encrypted</span>
                <span className='tag live dot'>FHE</span>
              </div>
              <Cipher seed={7} length={320} blockSize={4} highlight />
              <div className='hr-soft' />
              <span className='mono-sm muted'>
                This is what a vote looks like on-chain: ciphertext that no single committee member can decrypt. Only the combined tally is
                decrypted.
              </span>
            </div>
          </div>
        </div>
      </section>
    </EditorialShell>
  )
}

export default HeroSection
