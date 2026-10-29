// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { AuctionType, DEGREE, MAX_BIDDERS_BY_TYPE, PLAINTEXT_MODULUS } from '@interfold/auction'
import { exampleRows } from '@/utils/explainer-example'

const Mono: React.FC<{ children: React.ReactNode }> = ({ children }) => <span className='font-mono'>{children}</span>

/** How the "Second-price, no providers" type works, in plain words, with a worked example of 3 bidders. */
const QnrAuctionExplainer: React.FC = () => {
  const rows = exampleRows()
  const maxBidders = MAX_BIDDERS_BY_TYPE[AuctionType.QnrSecondPrice]
  // About half of the numbers modulo the plaintext modulus are squares, so S² − 3 takes about half of the values.
  const reachable = (PLAINTEXT_MODULUS + 1) / 2
  return (
    <div className='space-y-6'>
      <div className='space-y-2'>
        <h3 className='h3'>Who sends what</h3>
        <p className='prose-ed max-w-3xl'>
          There are no mask providers and no other party: only bidders. Each bidder sends <strong>four ciphertexts</strong>. Two are the
          bid: <Mono>ge</Mono> marks every price step up to and including the bid, and <Mono>gt</Mono> marks every price step below the bid.
          Two are <strong>shares</strong>, <Mono>s₁</Mono> and <Mono>s₂</Mono>: each holds {DEGREE} random numbers between 0 and{' '}
          {PLAINTEXT_MODULUS - 1}, which the browser of the bidder draws. The auction takes 2 to {maxBidders} bidders.
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
        <h3 className='h3'>How the shares hide the numbers</h3>
        <p className='prose-ed max-w-3xl'>
          The numbers in <Mono>tests</Mono> tell more than the winner and the price. For example, they show how many bidders reach each
          level. So the program multiplies each slot of <Mono>tests</Mono> by a number <Mono>r</Mono> that nobody knows. It makes{' '}
          <Mono>r</Mono> from the shares of all the bidders. It adds the first shares of all bidders to get <Mono>S₁</Mono>, and the second
          shares to get <Mono>S₂</Mono>, and then it computes <Mono>r = (S₁² − 3) × (S₂² − 3)</Mono>, in each slot. The output is{' '}
          <Mono>tests × r</Mono>. A zero stays zero, and any other number becomes a number that looks random. If at least one bidder drew
          its shares at random and kept them secret, then <Mono>S₁</Mono> and <Mono>S₂</Mono> are random for everyone else, even if all the
          other bidders agree on their shares.
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
                <th className='p-2'>Output after the shares</th>
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
          has a zero, so <strong>bidder 1 wins at level 2</strong>. Each <Mono>?</Mono> is a number that is not zero and that hides the
          number of <Mono>tests</Mono>: nobody can tell with certainty that bidder 0 was close and bidder 2 was far. If bidders tie, the
          tied bidder who bid first wins.
        </p>
      </div>

      <div className='space-y-2'>
        <h3 className='h3'>Why it cannot fail</h3>
        <p className='prose-ed max-w-3xl'>
          The number 3 is not a square modulo {PLAINTEXT_MODULUS}: no whole number multiplied by itself leaves the remainder 3 after
          division by {PLAINTEXT_MODULUS}. So <Mono>S² − 3</Mono> is never zero, whatever <Mono>S</Mono> is, so <Mono>r</Mono> is never
          zero, whatever the bidders send. Every factor of <Mono>tests</Mono> that is not zero is a whole number below {PLAINTEXT_MODULUS},
          and {PLAINTEXT_MODULUS} is prime, so a product of numbers that are not zero is never a multiple of {PLAINTEXT_MODULUS}. A number
          of <Mono>tests</Mono> that is not zero can therefore never become a zero in the output, and the result always reads. A bidder who
          sends bad shares on purpose cannot break the auction: the bid proof checks the format of the shares only, and any shares give the
          same winner and price. In the types without a zero-failure design (first-price, second-price and the ratio types), each bidder
          draws a random mask, and the sum of the masks is zero in a slot with the probability 1 in {PLAINTEXT_MODULUS}, which can hide a
          loser and make the result unreadable.
        </p>
      </div>

      <div className='space-y-2'>
        <h3 className='h3'>The trade-off: a small hint about the losing bids</h3>
        <p className='prose-ed max-w-3xl'>
          This type needs no trusted party: nobody has to be named, and no provider can stall the auction. The price of this is that{' '}
          <Mono>r</Mono> is not exactly uniform. <Mono>S² − 3</Mono> takes only {reachable} of the {PLAINTEXT_MODULUS} possible values (a
          square is one of about half of the numbers), so some numbers appear in the output more often than others. The numbers that are not
          zero therefore leak a <strong>small statistical hint</strong> about the numbers of <Mono>tests</Mono>, and so about the losing
          bids, for example how many bidders reach a level. The zero pattern still shows the winner and the price, as in the other types.
          The hint is small for one slot, but an output holds many slots. The demo uses small, insecure parameters, with the modulus{' '}
          {PLAINTEXT_MODULUS}, and there the hint is larger than it would be on secure parameters with a much larger modulus. Choose the
          type with providers if the losing bids must stay hidden completely and you accept a trusted party.
        </p>
      </div>

      <div className='space-y-2'>
        <h3 className='h3'>Whom you must trust</h3>
        <p className='prose-ed max-w-3xl'>
          Nobody. Privacy needs one bidder who draws its shares at random and keeps them secret, and the browser of each bidder does this by
          default. The creator, the server and the committee do not choose or see the shares. The auction cannot fail and no one can stop
          it, apart from the usual rules: at least 2 bidders, and the committee that decrypts the output.
        </p>
      </div>
    </div>
  )
}

export default QnrAuctionExplainer
