// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { WarningIcon } from '@phosphor-icons/react'
import { LEVELS, MAX_BIDDERS, MAX_BIDS_PER_BIDDER } from '@interfold/sealed-cca'
import { GITHUB_URL } from '@/components/Footer'

const HIDDEN = [
  'The highest price of each bidder',
  'Which bidders bid above or below the clearing price, until a bidder claims',
  'The size of each bid: every bid locks the same escrow',
]

const REVEALED = [
  'The demand curve: how many bidders bid at or above each price step',
  'The clearing price, and the tokens each claim buys',
  'Which addresses deposited and how many versions each sent',
  'When a bidder claims: whether its price is below, at, or above the clearing step',
]

const LIFECYCLE = [
  [
    'Create',
    `The creator picks a token, a supply, a payment token, a fixed escrow, a title, and 2 to ${LEVELS} price steps. The creator pays the Interfold fee and the program takes the supply.`,
  ],
  [
    'Committee key',
    'A committee of ciphernodes generates a public key together. No node holds the whole secret key. This takes several minutes. Bids open when the key is published.',
  ],
  [
    'Deposit',
    'A bidder locks the escrow. The contract gives the bidder a place number. One deposit, one place. The deposit is one transaction, or a signed permit that a relayer sends.',
  ],
  [
    'Bid',
    `The bidder picks the highest price it will pay. The browser encrypts it and proves that it is well formed. A bidder can update the bid up to ${MAX_BIDS_PER_BIDDER - 1} times.`,
  ],
  [
    'Compute',
    'After the window closes, the program checks each ciphertext against its commitment. It keeps the latest valid version of each bidder and adds the encrypted bids together. It never decrypts them.',
  ],
  ['Decrypt', 'The committee decrypts one ciphertext: the demand curve and the counted version of each bidder. The page decodes it.'],
  [
    'Clear and claim',
    'The contract finds the clearing price from the demand curve. Each bidder claims with a small proof of its outcome. It gets tokens and a refund. The claim window lasts 30 days from the clearing. After it, the creator sweeps every unclaimed token and escrow.',
  ],
] as const

const Block: React.FC<{ eyebrow: string; title: string; children: React.ReactNode }> = ({ eyebrow, title, children }) => (
  <section className='space-y-5'>
    <div className='space-y-2'>
      <p className='mono muted'>{eyebrow}</p>
      <h2 className='h2'>{title}</h2>
      <div className='hr' />
    </div>
    {children}
  </section>
)

const About: React.FC = () => (
  <div className='page space-y-14 !pt-0'>
    <header className='page-intro wide'>
      <h1 className='h1'>A sealed token sale: what stays hidden, what is revealed</h1>
      <p className='lede'>
        A sealed-bid sale needs bids that nobody can read until the sale is fixed. Interfold gives that with encryption that can be computed
        on, and a committee that decrypts only the demand curve.
      </p>
    </header>

    <Block eyebrow='Nº 01' title='Hidden and revealed'>
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
    </Block>

    <Block eyebrow='Nº 02' title='Life of a sale'>
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

    <Block eyebrow='Nº 03' title='How the price is set'>
      <p className='prose-ed max-w-3xl'>
        Each bidder locks the same escrow <em>E</em>. A bidder with a highest price at or above a price <em>p</em> is active at <em>p</em>{' '}
        and wants <em>E / p</em> tokens. The sale clears at the lowest price where the demand is at most the supply. If the demand at a
        price step is above the supply, and the demand just above the step is not, the sale is <strong>capped</strong> at that step: bidders
        above the step get their full tokens, and bidders at the step share what is left. If the demand falls between two steps, the sale is{' '}
        <strong>uncapped</strong>: the price lies between the two steps and the supply sells out. If the demand never reaches the supply at
        the lowest step, the sale is <strong>undersubscribed</strong>: everyone gets their full tokens at the lowest price and the creator
        takes back the rest.
      </p>
      <p className='prose-ed max-w-3xl'>
        Everyone who gets tokens pays the same price. Nobody pays more than the escrow, and nobody pays more per token than their own
        highest price. The contract refunds the rest of the escrow. Rounding never sells more than the supply.
      </p>
    </Block>

    <Block eyebrow='Nº 04' title='Proofs'>
      <div className='grid gap-5 md:grid-cols-2'>
        <div className='card flat space-y-2'>
          <p className='mono muted'>Bid proof</p>
          <h3 className='h3'>The bid is well formed</h3>
          <p className='text-sm text-ink'>
            The ciphertext holds a valid price step below the number of steps. It also holds the place number and the version of the bid.
            The proof is bound to your address and to this sale, so nobody can copy it. It runs in your browser and takes a few minutes.
          </p>
        </div>
        <div className='card flat space-y-2'>
          <p className='mono muted'>Claim proof</p>
          <h3 className='h3'>Your outcome</h3>
          <p className='text-sm text-ink'>
            After the sale clears, you prove in your browser whether your price is below, at, or above the clearing step. The contract does
            not learn more. It checks the proof against the commitment of your counted bid. The proof takes a few seconds. Keep the salt in
            this browser: without it you cannot claim a winning bid, and the contract refunds you in full as a loser.
          </p>
        </div>
      </div>
      <p className='prose-ed max-w-3xl'>
        <strong>Updates.</strong> A bidder can send up to {MAX_BIDS_PER_BIDDER} bids: the first and two updates. The program counts the
        latest version that is valid. <strong>Relayed bids.</strong> A bidder can sign a deposit permit and a bid, and let a relayer pay the
        gas. The relayer cannot change a byte of the bid.
      </p>
    </Block>

    <div role='note' className='note warn flex gap-3'>
      <WarningIcon size={22} weight='fill' className='mt-0.5 shrink-0 text-warn' />
      <div className='space-y-2'>
        <p className='font-semibold'>Demo on insecure parameters</p>
        <p>
          This app runs the development preset of the encryption scheme: a tiny ring (N = 128) and a small plaintext modulus. It is fast
          enough to prove in a browser and is not secure. Use it to see how a sealed token sale works, never for bids that matter. A sale
          takes at most {MAX_BIDDERS} bidders.
        </p>
      </div>
    </div>

    <div className='flex flex-wrap items-center gap-4'>
      <Link to='/create' className='btn'>
        Create a sale
      </Link>
      <a href={GITHUB_URL} target='_blank' rel='noreferrer' className='linkish'>
        Read the code
      </a>
    </div>
  </div>
)

export default About
