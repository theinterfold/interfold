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
  AuctionType,
  DEGREE,
  LEVELS,
  MAX_BIDDERS,
  MAX_BIDS_PER_BIDDER,
  MAX_PROVIDERS,
  MIN_BIDDERS,
  MIN_LEVELS,
  PLAINTEXT_MODULUS,
  rolesFor,
} from '@interfold/auction-core'
import { designOf } from '@/utils/designs'
import { BID_PROOF_HINT, KEY_GENERATION_HINT, MASK_PROOF_HINT } from '@/utils/estimates'
import { GITHUB_URL } from '@/components/Footer'
import AuctionExplainer, { explainerTitle } from '@/components/AuctionExplainer'

/** What stays hidden in each type. What it reveals and whom it trusts come from the design of the type. */
const HIDDEN: Record<AuctionType, string[]> = {
  [AuctionType.FirstPrice]: ['Every losing bid', 'Who came second, and by how much', 'Whether the top bids tied'],
  [AuctionType.ProviderSecondPrice]: [
    'Every bid, including the winning one',
    'The ranking of the losing bids',
    'How close the losing bids were',
  ],
  [AuctionType.QnrSecondPrice]: [
    'Every bid, including the winning one',
    'The exact ranking of the losing bids. A small statistical hint about them leaks, larger on these demo parameters than on secure ones',
  ],
}

const cipherCount = (type: AuctionType) => rolesFor(type).length

const LIFECYCLE = [
  [
    'Create',
    `Anyone requests an auction: a title, a type, the number of price steps (${MIN_LEVELS} to ${LEVELS}), the price of each step, who may bid (anyone, or the addresses on an allowlist) and how long bidding stays open. The creator pays a creation fee. The fee pays for the encrypted computation of the auction (an E3).`,
  ],
  [
    'Committee key',
    `A committee of ciphernodes generates a public key together. No node holds the whole secret key. This takes ${KEY_GENERATION_HINT}. Bids open once the key is published.`,
  ],
  [
    `Mask providers (${designOf(AuctionType.ProviderSecondPrice).label} only)`,
    `The creator names 1 to ${MAX_PROVIDERS} mask providers. Each one sends one random mask, encrypted to the committee key, with a proof that no value in it is zero. This takes ${MASK_PROOF_HINT}. Bidding opens when every provider has sent its mask.`,
  ],
  [
    'Bid',
    `A bidder picks one of the price steps the creator set. The browser encrypts it to the committee key, as ${cipherCount(AuctionType.FirstPrice)} ciphertexts (${cipherCount(AuctionType.QnrSecondPrice)} for ${designOf(AuctionType.QnrSecondPrice).label}, ${cipherCount(AuctionType.ProviderSecondPrice)} for ${designOf(AuctionType.ProviderSecondPrice).label}) and proves the bid is well formed. This takes ${BID_PROOF_HINT}. The bidder publishes the bid on chain in one transaction. A bidder can update the bid ${MAX_BIDS_PER_BIDDER - 1} times.`,
  ],
  [
    'Compute',
    'After the window closes a program checks the published bytes of each bid against its commitments and computes over the encrypted bids that pass, using the latest valid version of each bidder. It never decrypts them.',
  ],
  ['Decrypt', 'The committee decrypts one ciphertext, the outcome, and publishes it. The page decodes it in your browser.'],
] as const

const ALL_TYPES = 'All types'

const PROOFS = [
  [
    'Encryption proofs',
    ALL_TYPES,
    'One for each ciphertext. It shows that the ciphertext is a correct encryption, under the committee key, of the plaintext the bidder committed to. This is the Interfold user-data encryption proof.',
  ],
  [
    'Bid proof',
    ALL_TYPES,
    `One proof for the whole bid. It checks the encryption proofs and that the plaintexts are a well-formed bid: a thermometer over ${LEVELS} slots, or a random mask. A thermometer is a row of slots that is 1 up to the bid step and 0 above it. The bid must be below the number of steps the creator chose, which is a public input of the proof, so nobody can bid above the top step. The two thermometers use the same step, because the proof holds the step once and builds both from it. The proof is bound to the bidder address and to the committee key, so nobody can copy it from another bidder. The contract verifies it before it accepts the bid.`,
  ],
  [
    'Check by the program',
    ALL_TYPES,
    'The contract cannot read the ciphertext bytes against their commitments, but it stores both in the input tree. After the window closes, the program hashes each published ciphertext again and keeps only the bids whose bytes match their commitments. The program ignores a whole bid if one ciphertext does not match. The bidder then falls back to its earlier valid version, if it has one.',
  ],
  [
    'Mask proof',
    designOf(AuctionType.ProviderSecondPrice).label,
    `One proof for each mask. It checks the encryption proof and that every one of the ${DEGREE} values in the mask is not zero. The proof is bound to the provider address and to the committee key, and the contract verifies it before it accepts the mask. A zero in the mask could hide a number that is not zero. This proof is what makes the result always readable.`,
  ],
  [
    'Shares proof',
    designOf(AuctionType.QnrSecondPrice).label,
    `One proof for the last two ciphertexts, the shares. It checks the two encryption proofs only. A share is any list of ${DEGREE} numbers between 0 and ${PLAINTEXT_MODULUS - 1}, so the proof needs no other rule, and no share that a bidder sends can make the result unreadable. The contract accepts the bid proof of this type only with the shares proof inside it.`,
  ],
] as const

const slug = (title: string) => title.toLowerCase().replace(/[^a-z0-9]+/g, '-')

const Block: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <section id={slug(title)} className='scroll-mt-24 space-y-5'>
    <div className='space-y-2'>
      <h2 className='h2'>{title}</h2>
      <div className='hr' />
    </div>
    {children}
  </section>
)

const SECTIONS = [
  'Hidden and revealed',
  'Life of an auction',
  'The proofs of a bid',
  'Updates, relayers and who can bid',
  'Ties',
  ...AUCTION_TYPES.map(explainerTitle),
  'Read the result',
] as const

const About: React.FC = () => (
  <div className='page space-y-14 !pt-0'>
    <header className='page-intro wide'>
      <h1 className='h1'>What stays hidden, and what is revealed</h1>
      <p className='lede'>
        A sealed-bid auction needs bids that nobody can read until the outcome is fixed. Interfold provides that with encryption that can be
        computed on, and a committee that decrypts only what the auction is meant to reveal.
      </p>
    </header>

    <nav aria-label='On this page' className='flex flex-wrap justify-center gap-x-6 gap-y-2 text-sm'>
      {SECTIONS.map((title) => (
        <a key={title} href={`#${slug(title)}`} className='linkish'>
          {title}
        </a>
      ))}
    </nav>

    <Block title='Hidden and revealed'>
      <div className='grid gap-5 md:grid-cols-2'>
        {AUCTION_TYPES.map((type) => (
          <div key={type} className='card space-y-4'>
            <h3 className='h3'>{designOf(type).label}</h3>
            <div className='hr-soft' />
            <div className='grid gap-4 sm:grid-cols-2'>
              <div className='space-y-2'>
                <p className='meta muted'>Hidden</p>
                <ul className='list-disc space-y-1 pl-5 text-sm'>
                  {HIDDEN[type].map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
              <div className='space-y-2'>
                <p className='meta text-brand-green'>Revealed</p>
                <p className='text-sm'>{designOf(type).reveals}</p>
              </div>
            </div>
            <div className='space-y-1'>
              <p className='meta muted'>Whom you must trust</p>
              <p className='text-sm'>{designOf(type).trust}</p>
            </div>
          </div>
        ))}
      </div>
      <p className='prose-ed muted text-sm'>
        Always public, because it happens on chain: which address submitted a bid, when, how many versions it sent, and how many bidders
        took part. An auction has {MIN_BIDDERS} to {MAX_BIDDERS} bidders, and a bid is one of the price steps the creator chose, from 2 to{' '}
        {LEVELS} steps. The creator sets the price of each step; the gaps between steps can be uneven.
      </p>
    </Block>

    <Block title='Life of an auction'>
      <ol className='steps'>
        {LIFECYCLE.map(([title, body], index) => (
          <li key={title} className='step'>
            <span className='pin'>{index + 1}</span>
            <div>
              <p className='font-semibold'>{title}</p>
              <p className='text-sm text-ink'>{body}</p>
            </div>
          </li>
        ))}
      </ol>
    </Block>

    <Block title='The proofs of a bid'>
      <p className='prose-ed max-w-3xl'>
        A {designOf(AuctionType.FirstPrice).label} bid is {cipherCount(AuctionType.FirstPrice)} ciphertexts: two thermometers of the bid
        step and a random mask that the bidder draws. A {designOf(AuctionType.ProviderSecondPrice).label} bid is{' '}
        {cipherCount(AuctionType.ProviderSecondPrice)} ciphertexts, the two thermometers, because the mask providers send the masks. A{' '}
        {designOf(AuctionType.QnrSecondPrice).label} bid is {cipherCount(AuctionType.QnrSecondPrice)} ciphertexts: the two thermometers and
        two random shares. The browser proves the following, which takes {BID_PROOF_HINT}, and sends everything in one transaction. The
        contract checks the bid proof before it accepts the bid. You are a bidder once the transaction is mined.
      </p>
      <div className='grid gap-5 md:grid-cols-2'>
        {PROOFS.map(([title, appliesTo, body]) => (
          <div key={title} className='card flat space-y-2'>
            <p className='mono muted'>Applies to: {appliesTo}</p>
            <h3 className='h3'>{title}</h3>
            <p className='text-sm text-ink'>{body}</p>
          </div>
        ))}
      </div>
    </Block>

    <Block title='Updates, relayers and who can bid'>
      <p className='prose-ed max-w-3xl'>
        <strong>Updates.</strong> A bidder can bid again, up to {MAX_BIDS_PER_BIDDER} times in all: the first bid and two updates. Each is a
        new version with new ciphertexts. The contract keeps them all and the program computes over the latest version that is valid, so an
        update replaces the earlier bid without anyone seeing either. Which addresses bid and how many versions each sent is public; the
        steps stay hidden. An update does not add a bidder, because a bidder is an address. It does lose the place in the queue: the bid
        that counts is the latest valid version, and its place is where that version was published.
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

    <Block title='Ties'>
      <p className='prose-ed max-w-3xl'>
        <strong>The first bid wins a tie.</strong> If two or more bidders reach the highest bid, the tied bidder whose counted bid was
        published first wins. The order of the bids is the order of the transactions on chain, so nobody can change it after the fact. A
        bidder that updates its bid goes to the back of the queue: the bid that counts is the latest valid version, and its place is where
        that version was published. The earlier version loses its place. If the latest version does not open its commitments, the program
        falls back to the earlier version, and that version keeps its own place.
      </p>
      <p className='prose-ed max-w-3xl'>
        <strong>Every type.</strong> The result does not show that a tie happened. It shows the winner and the price, and the winner is the
        tied bidder who bid first. No bidder can change the outcome of a tie by encrypting again, because the ciphertext bytes play no part
        in it. Every type allows {MAX_BIDDERS} bidders.
      </p>
      <p className='prose-ed max-w-3xl'>
        <strong>{designOf(AuctionType.FirstPrice).label}.</strong> The result has one lane for each bidder. A lane is a block of {LEVELS}{' '}
        slots, in the order of the bids. The bidders that bid the same top step are told apart by their lane. The first tied bidder has a
        lane that reads exactly 1, and the lanes of the later tied bidders look random.
      </p>
    </Block>

    {AUCTION_TYPES.map((type) => (
      <Block key={type} title={explainerTitle(type)}>
        <AuctionExplainer type={type} />
      </Block>
    ))}

    <Block title='Read the result'>
      <p className='prose-ed max-w-3xl'>
        The committee publishes a vector of slots: {LEVELS} slots for each bidder, one for each price step. An auction with fewer steps uses
        only the first ones. The program arranges the slots so that the outcome sits in the zero slots and the one slot. The result page
        draws the grid and decodes it for you.
      </p>
      <p className='prose-ed max-w-3xl'>
        {designOf(AuctionType.FirstPrice).label}: above the price every slot is zero. At the price step the lanes before the winner are
        exactly 0 and the lane of the winner is exactly 1. The lanes after the winner look random, and so does every slot below the price.
        The mask of the bidders makes them random, and it never touches the slots that the reading needs.
      </p>
      <p className='prose-ed max-w-3xl'>
        {designOf(AuctionType.ProviderSecondPrice).label}: every slot that is not zero is a random number between 1 and{' '}
        {PLAINTEXT_MODULUS - 1} that the mask providers made. It never reads as zero by mistake. The winner is the one bidder whose slot is
        zero at the price step.
      </p>
      <p className='prose-ed max-w-3xl'>
        {designOf(AuctionType.QnrSecondPrice).label} has the same grid. Its slots that are not zero are numbers that the shares of the
        bidders made. They never read as zero by mistake either, but they are not exactly uniform, so they carry a small hint about the
        losing bids.
      </p>
    </Block>

    <div role='note' className='note warn flex gap-3'>
      <WarningIcon size={22} weight='fill' className='mt-0.5 shrink-0 text-warn' />
      <div className='space-y-2'>
        <p className='font-semibold'>Demo on insecure parameters</p>
        <p>
          This app runs the development preset of the encryption scheme: a tiny ring (N = {DEGREE}) and a plaintext modulus of{' '}
          {PLAINTEXT_MODULUS}. It is fast enough to prove in a browser and is not cryptographically secure. Use it to see how a sealed-bid
          auction works, never for bids that matter. With a modulus this small, a random slot would read as zero by mistake with a
          probability of 1 in {PLAINTEXT_MODULUS}. All three types are built so that this cannot make a result unreadable. Second price
          without providers pays for that with a small statistical hint about the losing bids, and the small modulus makes the hint larger
          than it would be on a secure preset.
        </p>
      </div>
    </div>

    <div className='flex flex-wrap items-center gap-4'>
      <Link to='/create' className='btn'>
        Create an auction
      </Link>
      <a href={GITHUB_URL} target='_blank' rel='noreferrer' className='linkish'>
        Read the code
      </a>
    </div>
  </div>
)

export default About
