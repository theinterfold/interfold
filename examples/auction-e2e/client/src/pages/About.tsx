// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import { WarningIcon } from '@phosphor-icons/react'
import {
  AUCTION_TYPES,
  AUCTION_TYPE_DESCRIPTIONS,
  AUCTION_TYPE_LABELS,
  AuctionType,
  LEVELS,
  MAX_BIDDERS_BY_TYPE,
  MAX_BIDS_PER_BIDDER,
  MIN_BIDDERS,
  PLAINTEXT_MODULUS,
} from '@shared/layout'
import { GITHUB_URL } from '@/components/Footer'

const HIDDEN_REVEALED: Record<AuctionType, { hidden: string[]; revealed: string[] }> = {
  [AuctionType.FirstPrice]: {
    hidden: ['Every losing bid', 'Who came second, and by how much'],
    revealed: ['The winner', 'The winning bid, which is the price'],
  },
  [AuctionType.SecondPrice]: {
    hidden: ['Every bid, including the winning one', 'The ranking of the losing bids'],
    revealed: ['The winner', 'The second-highest bid, which is the price'],
  },
  [AuctionType.RatioFirstPrice]: {
    hidden: ['Every bid below the top bid', 'Who came second, and by how much'],
    revealed: [
      'The winner and the top bid, which is the price',
      'If the top bids tie: every bidder that tied, and the random value that picked the winner',
    ],
  },
  [AuctionType.RatioSecondPrice]: {
    hidden: ['The winning bid, unless the top bids tie', 'The ranking of the losing bids'],
    revealed: [
      'The winner and the second-highest bid, which is the price',
      'If the top bids tie: every bidder that tied (their bid is the price), and the random value that picked the winner',
    ],
  },
}

const LIFECYCLE = [
  [
    'Create',
    'Anyone requests an auction: a title, a type, the number of price steps (2 to 16), the price of each step, who may bid (anyone, or the addresses on an allowlist) and how long bidding stays open. The creator pays the Interfold fee.',
  ],
  [
    'Committee key',
    'A committee of ciphernodes generates a public key together. No node holds the whole secret key. This takes several minutes; bids open once the key is published.',
  ],
  [
    'Bid',
    'A bidder picks one of the price steps the creator set. The browser encrypts it to the committee key, as 3 ciphertexts (4 for ratio-lane second price), proves the bid is well formed and the bidder publishes it on chain in one transaction. A bidder can update the bid twice.',
  ],
  [
    'Compute',
    'After the window closes a program checks the published bytes of each bid against its commitments and computes over the encrypted bids that pass, using the latest valid version of each bidder. It never decrypts them.',
  ],
  ['Decrypt', 'The committee decrypts one ciphertext, the outcome, and publishes it. The page decodes it in your browser.'],
] as const

const PROOFS = [
  [
    'Encryption proofs',
    'One for each ciphertext. It shows that the ciphertext is a correct encryption, under the committee key, of the plaintext the bidder committed to. This is the Interfold user-data encryption proof.',
  ],
  [
    'Bid proof',
    `One proof for the whole bid. It checks the encryption proofs and that the plaintexts are a well-formed bid: a thermometer over ${LEVELS} slots, or a random mask. The bid must be below the number of steps the creator chose, which is a public input of the proof, so nobody can bid above the top step. The two thermometers use the same step, because the proof holds the step once and builds both from it. The fourth ciphertext of ratio-lane second price is a paired mask: a random mask in which each slot of a pair holds the same value as its partner slot. This keeps the program's result readable. The proof is bound to the bidder address and to the committee key, so it cannot be copied from another bidder, and the contract verifies it before it accepts the bid.`,
  ],
  [
    'Check by the program',
    'The contract cannot read the ciphertext bytes against their commitments, but it stores both in the input tree. After the window closes, the program hashes each published ciphertext again and keeps only the bids whose bytes open their commitments. A bid that does not open is ignored whole, and the bidder falls back to its earlier valid version, if it has one.',
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
      <h1 className='h1'>What stays hidden, what is revealed, and why you can trust it</h1>
      <p className='lede'>
        A sealed-bid auction needs bids that nobody can read until the outcome is fixed. Interfold provides that with encryption that can be
        computed on, and a committee that decrypts only what the auction is meant to reveal.
      </p>
    </header>

    <Block eyebrow='Nº 01' title='Hidden and revealed'>
      <div className='grid gap-5 md:grid-cols-2'>
        {AUCTION_TYPES.map((type) => (
          <div key={type} className='card space-y-4'>
            <div className='space-y-1'>
              <h3 className='h3'>{AUCTION_TYPE_LABELS[type]}</h3>
              <p className='muted text-sm'>{AUCTION_TYPE_DESCRIPTIONS[type]}</p>
            </div>
            <div className='hr-soft' />
            <div className='grid gap-4 sm:grid-cols-2'>
              <div className='space-y-2'>
                <p className='mono-sm muted'>Hidden</p>
                <ul className='list-disc space-y-1 pl-5 text-sm'>
                  {HIDDEN_REVEALED[type].hidden.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
              <div className='space-y-2'>
                <p className='mono-sm text-accent'>Revealed</p>
                <ul className='list-disc space-y-1 pl-5 text-sm'>
                  {HIDDEN_REVEALED[type].revealed.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        ))}
      </div>
      <p className='prose-ed muted text-sm'>
        Always public, because it happens on chain: which address submitted a bid, when, how many versions it sent, and how many bidders
        took part. An auction has {MIN_BIDDERS} to {MAX_BIDDERS_BY_TYPE[AuctionType.FirstPrice]} bidders (
        {MAX_BIDDERS_BY_TYPE[AuctionType.RatioFirstPrice]} for the ratio-lane types), and a bid is one of the price steps the creator chose,
        from 2 to {LEVELS} steps. The creator sets the price of each step; the gaps between steps can be uneven.
      </p>
    </Block>

    <Block eyebrow='Nº 02' title='Life of an auction'>
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

    <Block eyebrow='Nº 03' title='The proofs of a bid'>
      <p className='prose-ed max-w-3xl'>
        A bid is three ciphertexts: two thermometers of the bid step and a random mask. Ratio-lane second price adds a fourth, the paired
        mask. The browser proves the following, which takes several minutes, and sends everything in one transaction. The contract checks
        the bid proof before it accepts the bid, and you are a bidder once the transaction is mined.
      </p>
      <div className='grid gap-5 md:grid-cols-3'>
        {PROOFS.map(([title, body], index) => (
          <div key={title} className='card flat space-y-2'>
            <p className='mono muted'>Proof {index + 1}</p>
            <h3 className='h3'>{title}</h3>
            <p className='text-sm text-ink-2'>{body}</p>
          </div>
        ))}
      </div>
    </Block>

    <Block eyebrow='Nº 04' title='Updates, relayers and who can bid'>
      <p className='prose-ed max-w-3xl'>
        <strong>Updates.</strong> A bidder can bid again, up to {MAX_BIDS_PER_BIDDER} times in all: the first bid and two updates. Each is a
        new version with new ciphertexts. The contract keeps them all and the program computes over the latest version that is valid, so an
        update replaces the earlier bid without anyone seeing either. Which addresses bid and how many versions each sent is public; the
        steps stay hidden. An update does not take another place in the auction: a place belongs to an address.
      </p>
      <p className='prose-ed max-w-3xl'>
        <strong>Relayed bids.</strong> A bidder can sign the bid in the wallet and let a relayer send the transaction, so the bidder needs
        no gas and the transaction does not come from the bidder address. The signature covers the bid commitments, a hash of every
        ciphertext and the version of the bid. The relayer cannot change a byte of the bid, and a signature stops working once the bidder
        bids again.
      </p>
      <p className='prose-ed max-w-3xl'>
        <strong>Who can bid.</strong> The creator can name a gate contract that decides which addresses may bid. This app ships an
        allowlist: the creator pastes the addresses, the contract builds a Merkle root from them, and a bidder proves membership with a
        short proof that this page builds from the public list. The list is public. Any other gate contract works on chain, but this page
        can only build the proof for the allowlist.
      </p>
    </Block>

    <Block eyebrow='Nº 05' title='Ties'>
      <p className='prose-ed max-w-3xl'>
        <strong>First-price and second-price (Vickrey).</strong> If two bidders reach the highest bid, the tie goes to the bidder with the
        higher priority. The priority comes from a hash of the published ciphertexts of all bidders. The last bidder sees the other
        ciphertexts first, and can encrypt again until the priority favours it; with updates it can try more than once. This changes the
        winner only when the top bids tie; a fair draw needs randomness that is fixed after the window closes, which these two types do not
        have.
      </p>
      <p className='prose-ed max-w-3xl'>
        <strong>Ratio-lane types.</strong> The result shows which bidders tie for the top bid, not only one winner. If more than one bidder
        tied, a random value picks the winner among them: take the value, divide it by the number of tied bidders, and the remainder is the
        place of the winner in the list of tied bidders, sorted by the order in which they bid. The value is the sum of the random masks of
        all bidders, in one extra slot. It is uniform as long as one bidder is honest, and it is fixed by the encrypted masks, so no bidder
        can predict it or try again for a better draw. The price of this rule: the tie becomes public. Everyone sees which bidders tied and
        that their bids are equal to the price. Ratio-lane types also allow {MAX_BIDDERS_BY_TYPE[AuctionType.RatioFirstPrice]} bidders, not{' '}
        {MAX_BIDDERS_BY_TYPE[AuctionType.FirstPrice]}.
      </p>
    </Block>

    <Block eyebrow='Nº 06' title='Read the result'>
      <p className='prose-ed max-w-3xl'>
        The committee publishes a vector of slots. For first-price and second-price (Vickrey) there are {LEVELS} slots per bidder, one per
        price step; an auction with fewer steps uses only the first ones. The program arranges them so that a zero slot marks the outcome:
        the winner&apos;s slot at the winning bid for a first-price auction, and the winner&apos;s slot at the second-highest bid for a
        second-price one. Every other slot holds a random value. The result page draws this grid and decodes it for you.
      </p>
      <p className='prose-ed max-w-3xl'>
        For the ratio-lane types the result is one lane of {LEVELS} slots, one per price step, and not one lane per bidder. Above the price
        every slot is zero. At the price step the slot holds the set of bidders that tied. It writes the set as a sum with a weight of 1, 2,
        4, 8 and so on for each bidder, so one number names the whole set. Ratio-lane second price reads the set from the ratio of two
        slots. Below the price every slot is random. Ratio-lane second price repeats the lanes in three copies, and the page checks that the
        copies agree. One more slot holds the random value for the tie draw. The result page draws the lane and decodes the winner for you.
      </p>
    </Block>

    <div role='note' className='note warn flex gap-3'>
      <WarningIcon size={22} weight='fill' className='mt-0.5 shrink-0 text-warm' />
      <div className='space-y-2'>
        <p className='font-semibold'>Demo on insecure parameters</p>
        <p>
          This app runs the development preset of the encryption scheme: a tiny ring (N = 128) and a plaintext modulus of{' '}
          {PLAINTEXT_MODULUS}. It is fast enough to prove in a browser and is not cryptographically secure. Use it to see how a sealed-bid
          auction works, never for bids that matter. Because of the small modulus, a slot that should hold a random value reads as zero by
          mistake with a probability of 1 in {PLAINTEXT_MODULUS}, which can make a result unreadable; the page says so when it happens.
        </p>
      </div>
    </div>

    <div className='flex flex-wrap items-center gap-4'>
      <Link to='/create' className='btn lg'>
        Create an auction
      </Link>
      <a href={GITHUB_URL} target='_blank' rel='noreferrer' className='linkish'>
        Read the code
      </a>
    </div>
  </div>
)

export default About
