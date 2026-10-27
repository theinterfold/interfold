// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { WarningIcon } from '@phosphor-icons/react'
import { LEVELS, OFFER_CIPHERTEXTS } from '@interfold/negotiation'
import { GITHUB_URL } from '@/components/Footer'

const DESIGN_URL = `${GITHUB_URL}/blob/main/examples/negotiation/DESIGN.md`

const HIDDEN = [
  'The seller’s minimum price, except that it is at most the agreed price',
  'The buyer’s maximum price, except that it is at least the agreed price',
  'Both prices, if there is no match',
  'The random values that pick the agreed price: nobody knows them, not the parties, the committee or the program',
]

const REVEALED = [
  'Whether there is a match: the buyer’s maximum is at least the seller’s minimum',
  'The agreed price, if there is a match',
  'That each party sent an offer, and when',
  'The three ciphertexts of each offer, encrypted under the committee key',
]

const LIFECYCLE = [
  [
    'Create',
    `The creator picks the seller, the buyer and a grid of 2 to ${LEVELS} prices. The creator pays the Interfold fee. The price unit is only a label.`,
  ],
  [
    'Committee key',
    'A committee of ciphernodes generates a public key together. No node holds the whole secret key. This takes several minutes. Offers open when the key is published.',
  ],
  [
    'Offer',
    `Each party picks one price on the grid. The browser encrypts it as ${OFFER_CIPHERTEXTS} ciphertexts and proves that they are well formed. The proofs take several minutes. A party sends one offer and cannot change it. A relayer can send the offer for a party, and cannot change it.`,
  ],
  [
    'Compute',
    'After the window closes, the program combines the two sealed offers on ciphertexts. It never decrypts them. If one party sent no offer, the negotiation fails and nothing leaks.',
  ],
  ['Decrypt', 'The committee decrypts one ciphertext. After the decoding, it shows the match bit and the agreed price, and nothing else.'],
  [
    'Settle',
    'Anyone sends one transaction. The contract checks that the output is a valid result and stores it. Both parties read it on the page.',
  ],
] as const

const Block: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <section className='space-y-5'>
    <div className='space-y-2'>
      <h2 className='h2'>{title}</h2>
      <div className='hr' />
    </div>
    {children}
  </section>
)

const About: React.FC = () => (
  <div className='page space-y-14 !pt-0'>
    <header className='page-intro wide'>
      <h1 className='h1'>A sealed price negotiation: what stays hidden, what is revealed</h1>
      <p className='lede'>
        A seller has a private minimum price. A buyer has a private maximum price. If the maximum is at least the minimum, both learn one
        agreed price. If not, both learn only that there is no match. Interfold computes this on encrypted data.
      </p>
    </header>

    <Block title='Hidden and revealed'>
      <div className='card grid gap-6 sm:grid-cols-2'>
        <div className='space-y-2'>
          <p className='meta muted'>Hidden</p>
          <ul className='list-disc space-y-1 pl-5 text-sm'>
            {HIDDEN.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
        <div className='space-y-2'>
          <p className='meta text-brand-green'>Revealed</p>
          <ul className='list-disc space-y-1 pl-5 text-sm'>
            {REVEALED.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </div>
      <p className='prose-ed max-w-3xl'>
        What each party learns is small. Given the agreed price <em>p</em>, the seller learns that the buyer’s maximum is at least{' '}
        <em>p</em>. The buyer learns that the seller’s minimum is at most <em>p</em>. With no match, both learn only that the maximum is
        below the minimum.
      </p>
    </Block>

    <Block title='Life of a negotiation'>
      <ol className='steps'>
        {LIFECYCLE.map(([title, body], index) => (
          <li key={title} className='step done'>
            <span className='pin'>{index + 1}</span>
            <div>
              <p className='font-semibold'>{title}</p>
              <p className='text-sm text-ink'>{body}</p>
            </div>
          </li>
        ))}
      </ol>
    </Block>

    <Block title='How the price is chosen'>
      <p className='prose-ed max-w-3xl'>
        The ideal mechanism picks the agreed price uniformly from the prices that both parties accept. An encrypted program cannot do that
        exactly. It has no randomness of its own, and it cannot compare a joint secret with a private threshold at a low cost. So each party
        draws a small random share and seals it with its price. The two shares combine into a pointer that nobody knows. The program picks
        the accepted price of the least priority under that pointer. The priorities form a binary tree over the price levels.
      </p>
      <div className='card grid gap-6 sm:grid-cols-3'>
        <div className='space-y-1'>
          <p className='meta muted'>Match bit</p>
          <p className='value md'>Exact</p>
          <p className='text-sm text-ink'>There is a match if and only if the maximum is at least the minimum.</p>
        </div>
        <div className='space-y-1'>
          <p className='meta muted'>Agreed price</p>
          <p className='value md'>Almost uniform</p>
          <p className='text-sm text-ink'>
            The distance to the uniform law is at most 0.42 (total variation) over all intervals of 16 levels. The mean is 0.14.
          </p>
        </div>
        <div className='space-y-1'>
          <p className='meta muted'>Extra leak</p>
          <p className='value md'>0.12 bits</p>
          <p className='text-sm text-ink'>This is the mutual information over the ideal mechanism, with a uniform prior on both prices.</p>
        </div>
      </div>
      <p className='prose-ed max-w-3xl'>
        The law of the agreed price is not exactly uniform, and the app does not claim it is. A level in a small block of the tree wins more
        often. An interval that is a union of aligned blocks is exactly uniform. The worst interval cuts a block in a bad way. No level in
        the accepted range is ever impossible, so the output never proves that a price is excluded.{' '}
        <a href={DESIGN_URL} target='_blank' rel='noreferrer' className='linkish'>
          Read the design note
        </a>{' '}
        for the construction, the exact tables and the alternatives that were rejected.
      </p>
    </Block>

    <Block title='Proofs'>
      <div className='card flat max-w-3xl space-y-2'>
        <p className='mono muted'>Offer proof</p>
        <h3 className='h3'>The offer is well formed</h3>
        <p className='text-sm text-ink'>
          The browser proves that the {OFFER_CIPHERTEXTS} ciphertexts encrypt a valid price on the grid, a random share, and a mask. The
          mask hides the output of the combination, so the decrypted slots show only the result. The proof is bound to the committee key, to
          your role and to this negotiation, so nobody can copy it. It runs in your browser and takes several minutes. The price stays in
          this browser: keep it if you want to read it again.
        </p>
      </div>
    </Block>

    <div role='note' className='note warn flex gap-3'>
      <WarningIcon size={22} weight='fill' className='mt-0.5 shrink-0 text-warn' />
      <div className='space-y-2'>
        <p className='font-semibold'>Demo on insecure parameters</p>
        <p>
          This app runs the development preset of the encryption scheme: a tiny ring (N = 128) and a small plaintext modulus. It is fast
          enough to prove in a browser and is not secure. Use it to see how a sealed negotiation works, never for prices that matter. Prices
          are plain numbers: no token moves and no payment is made.
        </p>
      </div>
    </div>

    <div className='flex flex-wrap items-center gap-4'>
      <Link to='/create' className='btn'>
        Create a negotiation
      </Link>
      <a href={GITHUB_URL} target='_blank' rel='noreferrer' className='linkish'>
        Read the code
      </a>
    </div>
  </div>
)

export default About
