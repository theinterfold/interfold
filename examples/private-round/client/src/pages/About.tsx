// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { WarningIcon } from '@phosphor-icons/react'
import { LEVELS, MAX_BIDDERS, MAX_BIDS_PER_BIDDER, MAX_LOTS, MIN_LEVELS } from '@interfold/private-round'
import { GITHUB_URL } from '@/components/Footer'

const HIDDEN = [
  'The highest price of each bidder',
  'How many bidders accept each price step: there is no demand curve',
  'Whether a given bidder is above, at, or below the clearing step, until that bidder claims',
  'The size of each bid: every bidder wants one lot and locks the same escrow',
]

const REVEALED = [
  'Whether the reserve was met',
  'The clearing step and its price, when the round sells out',
  'How many bidders counted, and which version of each bid counted',
  'Which addresses deposited and how many versions each sent',
  'When a bidder claims: whether its price is below, at, or above the clearing step. A bidder at the step shows that it bid exactly that step when it registers. Its deposit index is public already.',
]

const LIFECYCLE = [
  [
    'Create',
    `The creator picks a token, the size of one lot, the lots for sale (1 to ${MAX_LOTS}), a payment token, a price ladder of ${MIN_LEVELS} to ${LEVELS} steps, a reserve step and a minimum raise. The creator pays the Interfold fee and the program takes the lots.`,
  ],
  [
    'Committee key',
    'A committee of ciphernodes generates a public key together. No node holds the whole secret key. This takes several minutes. Bids open when the key is published.',
  ],
  [
    'Deposit',
    'A bidder locks the escrow: the price of one lot at the highest step. The contract gives the bidder an index. One deposit, one index. The deposit is one transaction, or a signed permit that a relayer sends.',
  ],
  [
    'Bid',
    `The bidder picks the highest price it will pay for one lot. The browser encrypts the pick and a random mask, and proves that both are well formed. A bidder can update the bid up to ${MAX_BIDS_PER_BIDDER - 1} times.`,
  ],
  [
    'Compute',
    'After the window closes, the program checks each ciphertext against its commitment. It keeps the latest valid version of each bidder and combines the encrypted bids. It never decrypts them.',
  ],
  [
    'Decrypt',
    'The committee decrypts one ciphertext. It shows whether the reserve was met, the clearing step if the round sells out, and which bids counted. The page decodes it.',
  ],
  [
    'Clear',
    'Anyone sends one transaction that stores the outcome. If the reserve was not met, everyone claims a full refund with no proof, and the creator takes back the lots.',
  ],
  [
    'Phase 1: above the step',
    'In a sold-out round, bidders above the clearing step claim their lot for two days. A bidder proves, with a small proof, that its price is above the step. It gets the lot at the clearing price and the rest of its escrow back.',
  ],
  [
    'Phase 2: at the step',
    'For the next two days the bidders at the clearing step register. Each one proves that its price equals the step. Their escrow stays locked.',
  ],
  [
    'Settle',
    'After phase 2 each registered bidder settles. The lots that phase 1 left go to the first registered bidders by deposit order, one whole lot each, at the clearing price. The other registered bidders get their whole escrow back. A lot is never split. Bidders below the step claim the refund at any time. The claim window lasts 30 days from the clearing. After it, the creator sweeps what is left.',
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
  <div className='page space-y-14'>
    <header className='max-w-3xl space-y-5'>
      <p className='mono muted'>How it works</p>
      <h1 className='h1'>A private round: what stays hidden, what is revealed</h1>
      <p className='lede'>
        A private round sells a few equal lots to bidders who do not want to show their prices. Interfold gives that with encryption that
        can be computed on, and a committee that decrypts only the outcome: the reserve, and the clearing step.
      </p>
    </header>

    <Block eyebrow='Nº 01' title='Hidden and revealed'>
      <div className='card grid gap-6 sm:grid-cols-2'>
        <div className='space-y-2'>
          <p className='mono-sm muted'>Hidden</p>
          <ul className='list-disc space-y-1 pl-5 text-sm'>
            {HIDDEN.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
        <div className='space-y-2'>
          <p className='mono-sm text-accent'>Revealed</p>
          <ul className='list-disc space-y-1 pl-5 text-sm'>
            {REVEALED.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </div>
    </Block>

    <Block eyebrow='Nº 02' title='Life of a round'>
      <ol className='steps'>
        {LIFECYCLE.map(([title, body], index) => (
          <li key={title} className='step done'>
            <span className='pin'>{index + 1}</span>
            <div>
              <p className='font-semibold'>{title}</p>
              <p className='text-sm text-ink-2'>{body}</p>
            </div>
          </li>
        ))}
      </ol>
    </Block>

    <Block eyebrow='Nº 03' title='How the outcome is set'>
      <p className='prose-ed max-w-3xl'>
        The creator sells <em>K</em> lots. Each bidder wants one lot and names its highest price step <em>b</em>. The creator also sets a
        reserve step <em>r</em> and a minimum raise <em>m</em>. The round is <strong>not met</strong> if fewer than <em>m</em> bidders have{' '}
        <em>b</em> at or above <em>r</em>. Nothing sells and everyone is refunded. If the reserve is met and fewer than <em>K</em> bidders
        have <em>b</em> at or above <em>r</em>, the round is <strong>undersubscribed</strong>: every bidder at or above the reserve gets one
        lot at the reserve price. If <em>K</em> bidders or more accept the reserve, the round <strong>sells out</strong> at the highest step{' '}
        <em>l*</em> that <em>K</em> bidders still accept. Bidders above <em>l*</em> get a lot. Bidders at <em>l*</em> compete for the lots
        that are left: the first ones by deposit order get a whole lot.
      </p>
      <p className='prose-ed max-w-3xl'>
        Everyone who gets a lot pays the same price. Nobody pays more than the escrow, and nobody pays more than their own highest price.
        The contract refunds the rest of the escrow. Only the outcome and the step are public: the committee never decrypts how many bidders
        accept each step.
      </p>
    </Block>

    <Block eyebrow='Nº 04' title='The one-honest-bidder assumption'>
      <p className='prose-ed max-w-3xl'>
        Each bidder also encrypts a random <strong>mask</strong>. The program multiplies the tests of the round by the sum of the masks.
        After the decryption every test is either zero, or a random number, and a random number says nothing about the count behind it. The
        sums of the masks are uniform if at least one bidder keeps its mask secret. So the privacy of the counts needs{' '}
        <strong>one honest bidder</strong>. Your browser makes a fresh mask for every bid and does not keep it. If all the other bidders
        give their masks to one party, that party learns how many bidders accept each step. Nobody learns who bid what.
      </p>
    </Block>

    <Block eyebrow='Nº 05' title='Proofs'>
      <div className='grid gap-5 md:grid-cols-2'>
        <div className='card flat space-y-2'>
          <p className='mono muted'>Bid proof</p>
          <h3 className='h3'>The bid is well formed</h3>
          <p className='text-sm text-ink-2'>
            The bid ciphertext holds a valid price step below the number of steps, the reserve test, and the index and the version of the
            bid. The mask ciphertext is a valid encryption. The proof is bound to your address and to this round, so nobody can copy it. It
            runs in your browser and takes a few minutes.
          </p>
        </div>
        <div className='card flat space-y-2'>
          <p className='mono muted'>Claim proof</p>
          <h3 className='h3'>Your outcome</h3>
          <p className='text-sm text-ink-2'>
            After the round clears, you prove in your browser whether your price is below, at, or above the clearing step. The contract does
            not learn more. It checks the proof against the commitment of your counted bid. The proof takes a few seconds. Keep the salt in
            this browser: without it you cannot prove your outcome, and cannot claim a lot.
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
      <WarningIcon size={22} weight='fill' className='mt-0.5 shrink-0 text-warm' />
      <div className='space-y-2'>
        <p className='font-semibold'>Demo on insecure parameters</p>
        <p>
          This app runs the development preset of the encryption scheme: a tiny ring (N = 128) and a small plaintext modulus. It is fast
          enough to prove in a browser and is not secure. Use it to see how a private round works, never for bids that matter. A round takes
          at most {MAX_BIDDERS} bidders.
        </p>
      </div>
    </div>

    <div className='flex flex-wrap items-center gap-4'>
      <Link to='/create' className='btn lg'>
        Create a round
      </Link>
      <a href={GITHUB_URL} target='_blank' rel='noreferrer' className='linkish'>
        Read the code
      </a>
    </div>
  </div>
)

export default About
