// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { AuctionType, DEGREE, MAX_BIDDERS_BY_TYPE, MAX_PROVIDERS, PLAINTEXT_MODULUS } from '@interfold/auction'
import { exampleRows } from '@/utils/explainer-example'

const Mono: React.FC<{ children: React.ReactNode }> = ({ children }) => <span className='font-mono'>{children}</span>

/** How the "Second-price, mask providers" type works, in plain words, with a worked example of 3 bidders. */
const ProviderAuctionExplainer: React.FC = () => {
  const rows = exampleRows()
  const maxBidders = MAX_BIDDERS_BY_TYPE[AuctionType.ProviderSecondPrice]
  return (
    <div className='space-y-6'>
      <div className='space-y-2'>
        <h3 className='h3'>Who sends what</h3>
        <p className='prose-ed max-w-3xl'>
          The creator names 1 to {MAX_PROVIDERS} <strong>mask providers</strong>. Before bidding opens, each provider sends{' '}
          <strong>one mask</strong>: a ciphertext that holds {DEGREE} random numbers, each between 1 and {PLAINTEXT_MODULUS - 1}, and none
          of them zero. A zero-knowledge proof shows that no number in the mask is zero. After that, each bidder sends{' '}
          <strong>two ciphertexts</strong> and no mask: <Mono>ge</Mono> marks every price step up to and including the bid, and{' '}
          <Mono>gt</Mono> marks every price step below the bid. The auction takes 2 to {maxBidders} bidders.
        </p>
      </div>

      <div className='space-y-2'>
        <h3 className='h3'>What the program computes</h3>
        <p className='prose-ed max-w-3xl'>
          Let <Mono>n</Mono> be the number of bidders, and let <Mono>l</Mono> be a price step (a level). Let <Mono>bᵢ</Mono> be the bid of
          bidder <Mono>i</Mono>, where the first bidder is bidder 0. For each bidder and each level, the program makes a number called{' '}
          <Mono>tests</Mono> out of the encrypted <Mono>ge</Mono> and <Mono>gt</Mono> rows, without decrypting them:
        </p>
        <ul className='prose-ed max-w-3xl list-disc space-y-1 pl-6'>
          <li>
            <Mono>C</Mono> is the number of bidders with a bid of at least <Mono>l</Mono>. The factor <Mono>C × (C − 1)</Mono> is zero when
            fewer than 2 bidders reach level <Mono>l</Mono>, so every level above the second-highest bid becomes zero.
          </li>
          <li>
            <Mono>beaten</Mono> counts the rivals that beat bidder <Mono>i</Mono> at level <Mono>l</Mono>: the rivals with a bid above{' '}
            <Mono>l</Mono>, plus 1 if <Mono>bᵢ</Mono> is below <Mono>l</Mono>, plus the tied bidders who bid earlier. It is zero only for
            the winner, and only at a level that the winner reaches.
          </li>
          <li>
            <Mono>tests = beaten × C × (C − 1)</Mono>. Each factor is a whole number below {PLAINTEXT_MODULUS}.
          </li>
        </ul>
        <p className='prose-ed max-w-3xl'>
          So <Mono>tests</Mono> is zero in two cases only: at a level above the second-highest bid, and for the winner at the second-highest
          bid, which is the price.
        </p>
      </div>

      <div className='space-y-3'>
        <h3 className='h3'>Why the masks are needed</h3>
        <p className='prose-ed max-w-3xl'>
          The numbers in <Mono>tests</Mono> tell more than the winner and the price. For example, they show how many bidders reach each
          level. So the program multiplies each slot of <Mono>tests</Mono> by a secret number <Mono>r</Mono>:{' '}
          <Mono>output = tests × r</Mono>, with <Mono>r = M₁ × M₂ × … × M_k</Mono>, where <Mono>M₁</Mono> to <Mono>M_k</Mono> are the masks
          of the <Mono>k</Mono> providers. A zero stays zero. Any other number becomes a number that looks random between 1 and{' '}
          {PLAINTEXT_MODULUS - 1}. If at least one provider chose its mask at random and kept it secret, the committee decrypts a pattern of
          zeros and random numbers, and the pattern shows only the winner and the price.
        </p>
      </div>

      <div className='space-y-3'>
        <h3 className='h3'>A worked example</h3>
        <p className='prose-ed max-w-3xl'>
          Three bidders bid the price steps <Mono>2</Mono>, <Mono>3</Mono> and <Mono>1</Mono>. Bidder 0 bids 2, bidder 1 bids 3 and bidder 2
          bids 1. The table shows the numbers for levels 0 to 3. Levels above 3 are all zero, like level 3.
        </p>
        <div className='overflow-x-auto'>
          <table className='w-full max-w-3xl border-collapse text-sm'>
            <thead>
              <tr className='text-left'>
                <th className='p-2'>
                  Level <Mono>l</Mono>
                </th>
                <th className='p-2'>
                  <Mono>C</Mono>
                </th>
                <th className='p-2'>
                  <Mono>C × (C − 1)</Mono>
                </th>
                <th className='p-2'>
                  <Mono>beaten</Mono> (bidders 0, 1, 2)
                </th>
                <th className='p-2'>
                  <Mono>tests</Mono> (bidders 0, 1, 2)
                </th>
                <th className='p-2'>Output after the masks</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ level, atLeast, factor, beaten, tests }) => (
                <tr key={level} style={{ borderTop: '1px solid var(--rule)' }}>
                  <td className='p-2 font-mono'>{level}</td>
                  <td className='p-2 font-mono'>{atLeast}</td>
                  <td className='p-2 font-mono'>{factor}</td>
                  <td className='p-2 font-mono'>{beaten.join(', ')}</td>
                  <td className='p-2 font-mono'>{tests.join(', ')}</td>
                  <td className='p-2 font-mono'>{tests.map((value) => (value === 0 ? '0' : '?')).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className='prose-ed max-w-3xl'>
          Read the output from the top. Level 3 is all zero, and so is every level above it: fewer than 2 bidders reach those levels. Level
          2 is the highest level with a number that is not zero, so the price is step 2, the second-highest bid. At level 2 only bidder 1
          has a zero, so <strong>bidder 1 wins at level 2</strong>. Each <Mono>?</Mono> is a random number between 1 and{' '}
          {PLAINTEXT_MODULUS - 1}: nobody can tell that bidder 0 was close and bidder 2 was far. If bidders tie, the tied bidder who bid
          first wins.
        </p>
      </div>

      <div className='space-y-2'>
        <h3 className='h3'>Why it cannot fail by chance</h3>
        <p className='prose-ed max-w-3xl'>
          The numbers are small: every factor of <Mono>tests</Mono> that is not zero is a whole number below {PLAINTEXT_MODULUS}. The number{' '}
          {PLAINTEXT_MODULUS} is prime, so the product of numbers that are not zero is never a multiple of {PLAINTEXT_MODULUS}. The proof of
          each mask shows that none of its numbers is zero. So a number of <Mono>tests</Mono> that is not zero can never become a zero in
          the output, and the result always reads.
        </p>
      </div>

      <div className='space-y-2'>
        <h3 className='h3'>Whom you must trust</h3>
        <p className='prose-ed max-w-3xl'>
          Privacy needs one honest provider: one that draws its mask at random and keeps it secret. If every provider shares its mask with
          the others, they can divide the output by <Mono>r</Mono> and read the numbers of <Mono>tests</Mono>. Those numbers show more than
          the winner and the price, for example how many bidders reach each level. The auction also needs every provider: bidding stays
          closed until all <Mono>k</Mono> masks are on chain, and the auction cannot run if one provider never sends its mask. The creator
          names the providers, and the creator can add the server of this app, itself, or other parties.
        </p>
      </div>
    </div>
  )
}

export default ProviderAuctionExplainer
