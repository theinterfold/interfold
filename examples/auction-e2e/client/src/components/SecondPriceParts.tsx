// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { LEVELS, PLAINTEXT_MODULUS } from '@interfold/auction-core'
import { EXAMPLE_BIDS, EXAMPLE_PRICE, EXAMPLE_WINNER, exampleCells, exampleRows } from '@/utils/explainer-example'
import { Bullets, EXPLAINER_HEADINGS, Mono, Part, Prose } from './ExplainerParts'
import { SlotPicture } from './SlotPicture'

/** The part of "What the program computes" that the two second-price types share: `C`, `beaten` and `tests`. */
export const SecondPriceTests: React.FC = () => (
  <>
    <Prose>
      Let <Mono>l</Mono> be a price step. Let <Mono>bᵢ</Mono> be the bid of bidder <Mono>i</Mono>. The first bidder is bidder 0. For each
      bidder and each step, the program makes a number called <Mono>tests</Mono> from the encrypted <Mono>ge</Mono> and <Mono>gt</Mono>{' '}
      rows. It never decrypts them.
    </Prose>
    <Bullets>
      <li>
        <Mono>C</Mono> is the number of bidders with a bid of at least <Mono>l</Mono>. <Mono>C × (C − 1)</Mono> is zero when fewer than 2
        bidders reach step <Mono>l</Mono>. So every step above the second-highest bid becomes zero.
      </li>
      <li>
        <Mono>beaten</Mono> counts the rivals that beat bidder <Mono>i</Mono> at step <Mono>l</Mono>. These are the rivals with a bid above{' '}
        <Mono>l</Mono>, plus 1 if <Mono>bᵢ</Mono> is below <Mono>l</Mono>, plus the tied bidders who bid earlier. It is zero only for the
        winner, and only at a step that the winner reaches.
      </li>
      <li>
        <Mono>tests = beaten × C × (C − 1)</Mono>. Each factor is a whole number below {PLAINTEXT_MODULUS}.
      </li>
    </Bullets>
    <Prose>
      So <Mono>tests</Mono> is zero in two cases only. The first case is a step above the second-highest bid. The second case is the winner
      at the second-highest bid, which is the price.
    </Prose>
  </>
)

/** Why the two second-price types hide the numbers of `tests`. It is two sentences that start a paragraph. */
export const SecondPriceWhyHide: React.FC = () => (
  <>
    The numbers in <Mono>tests</Mono> tell more than the winner and the price. For example, they show how many bidders reach each step.
  </>
)

/** Why a number of `tests` that is not zero never becomes zero. It is two sentences inside a paragraph. */
export const SecondPriceNonZeroProduct: React.FC = () => (
  <>
    Every factor of <Mono>tests</Mono> that is not zero is a whole number below {PLAINTEXT_MODULUS}. The number {PLAINTEXT_MODULUS} is
    prime, so a product of numbers that are not zero is never a multiple of {PLAINTEXT_MODULUS}.
  </>
)

/** The worked example of the two second-price types: a table, then the same numbers as a picture. */
export const SecondPriceExample: React.FC<{ outputLabel: string; unknownText: React.ReactNode }> = ({ outputLabel, unknownText }) => {
  const rows = exampleRows()
  const cells = exampleCells()
  const shown = rows.length
  return (
    <Part title={EXPLAINER_HEADINGS.example}>
      <Prose>
        Three bidders bid the price steps <Mono>{EXAMPLE_BIDS[0]}</Mono>, <Mono>{EXAMPLE_BIDS[1]}</Mono> and <Mono>{EXAMPLE_BIDS[2]}</Mono>.
        The table shows steps 0 to {shown - 1}. Every step above {shown - 1} is all zero, like step {shown - 1}.
      </Prose>
      <div className='overflow-x-auto'>
        <table className='w-full max-w-3xl border-collapse text-sm'>
          <thead>
            <tr className='text-left'>
              <th className='p-2'>
                Step <Mono>l</Mono>
              </th>
              <th className='p-2'>
                <Mono>C</Mono>
              </th>
              <th className='whitespace-nowrap p-2'>
                <Mono>C × (C − 1)</Mono>
              </th>
              <th className='p-2'>
                <Mono>beaten</Mono> (bidders 0, 1, 2)
              </th>
              <th className='p-2'>
                <Mono>tests</Mono> (bidders 0, 1, 2)
              </th>
              <th className='p-2'>{outputLabel} (bidders 0, 1, 2)</th>
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
      <Prose>The same output as a picture. Each row is a bidder, and each column is a price step.</Prose>
      <SlotPicture
        axis={rows.map(({ level }) => String(level))}
        rows={EXAMPLE_BIDS.map((_, bidder) => ({
          key: String(bidder),
          winner: bidder === EXAMPLE_WINNER,
          name: (
            <>
              Bidder {bidder}
              {bidder === EXAMPLE_WINNER && <span className='tag live'>winner</span>}
            </>
          ),
          cells: cells[bidder],
        }))}
        priceStep={EXAMPLE_PRICE}
        reading='the winner’s zero at the price'
        summary={`Worked example. Bidder ${EXAMPLE_WINNER} wins at step ${EXAMPLE_PRICE}. Every other slot is a zero or a random number.`}
      />
      <Prose>
        Read the output from the top. Step {shown - 1} is all zero, and so is every step above it, because fewer than 2 bidders reach those
        steps. Step {EXAMPLE_PRICE} is the highest step with a number that is not zero, so the price is step {EXAMPLE_PRICE}: the
        second-highest bid. At step {EXAMPLE_PRICE} only bidder {EXAMPLE_WINNER} has a zero. So{' '}
        <strong>
          bidder {EXAMPLE_WINNER} wins at step {EXAMPLE_PRICE}
        </strong>
        . {unknownText}
      </Prose>
    </Part>
  )
}

/** "How the result is read" for the two second-price types. */
export const SecondPriceReading: React.FC = () => (
  <Part title={EXPLAINER_HEADINGS.reading}>
    <Bullets>
      <li>The price is the highest step where some slot is not zero.</li>
      <li>The winner is the one bidder whose slot is zero at that step.</li>
      <li>Every slot above the price is zero.</li>
      <li>Every other slot holds a number that looks random. The reader does not need it.</li>
    </Bullets>
    <Prose>
      The output has {LEVELS} slots for each bidder, one for each price step. If bidders tie, the tied bidder who bid first wins.
    </Prose>
  </Part>
)
