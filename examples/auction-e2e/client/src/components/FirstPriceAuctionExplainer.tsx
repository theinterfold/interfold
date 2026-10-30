// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { AuctionType, DEGREE, GROUPS, LEVELS, PLAINTEXT_MODULUS } from '@interfold/auction-core'
import {
  FIRST_PRICE_BIDS,
  FIRST_PRICE_LAST_TIED,
  FIRST_PRICE_PRICE,
  FIRST_PRICE_WINNER,
  firstPriceCells,
  firstPriceRows,
  type LaneSlot,
} from '@/utils/explainer-example'
import { AtAGlance, BidRows, BidderLimit, Bullets, EXPLAINER_HEADINGS, FailureScope, Mono, Part, Prose } from './ExplainerParts'
import { SlotPicture } from './SlotPicture'

/** The steps the worked example shows: 0 up to the highest bid. Every step above the highest bid is zero. */
const SHOWN_STEPS = FIRST_PRICE_PRICE + 1

const SLOT_TEXT: Record<LaneSlot, string> = { zero: '0', one: '1', random: '?' }

/** How the "First-price" type works, in plain words, with a worked example of 3 bidders and a tie. */
const FirstPriceAuctionExplainer: React.FC = () => {
  const rows = firstPriceRows(SHOWN_STEPS)
  const cells = firstPriceCells(SHOWN_STEPS)
  const price = FIRST_PRICE_PRICE
  const winner = FIRST_PRICE_WINNER
  return (
    <div className='space-y-6'>
      <AtAGlance type={AuctionType.FirstPrice}>
        The highest bid wins and pays its own bid. Each bidder hides its bid with a mask that the bidder draws. No other party is needed.
      </AtAGlance>

      <Part title={EXPLAINER_HEADINGS.sends}>
        <Prose>
          Each bidder sends <strong>three ciphertexts</strong>. Two of them hold the bid. <BidRows /> The third is a <strong>mask</strong>:{' '}
          {DEGREE} random numbers between 0 and {PLAINTEXT_MODULUS - 1}. The browser of the bidder draws the mask. There are no mask
          providers and no other party. <BidderLimit />
        </Prose>
      </Part>

      <Part title={EXPLAINER_HEADINGS.computes}>
        <Prose>
          The output has {DEGREE} slots. The program cuts them into {GROUPS} <strong>lanes</strong> of {LEVELS} slots. Lane <Mono>j</Mono>{' '}
          belongs to bidder <Mono>j</Mono>, in the order the bidders bid. Slot <Mono>l</Mono> of a lane is price step <Mono>l</Mono>. A lane
          that has no bidder stays zero.
        </Prose>
        <Prose>
          For each lane and each step, the program computes <Mono>out = ge + mask × A</Mono>. It never decrypts anything.
        </Prose>
        <Bullets>
          <li>
            <Mono>ge</Mono> is 1 if the bidder of the lane bid at least this step, and 0 if not.
          </li>
          <li>
            <Mono>A</Mono> counts the rivals that matter at this step. These are the bidders that bid above the step, plus the earlier
            bidders that bid exactly the step. <Mono>A</Mono> is a small whole number, below {PLAINTEXT_MODULUS}.
          </li>
          <li>
            <Mono>mask</Mono> is the sum of the masks of all bidders in this slot.
          </li>
        </Bullets>
        <Prose>
          When <Mono>A</Mono> is 0, the slot is just <Mono>ge</Mono>: exactly 0 or exactly 1. When <Mono>A</Mono> is 1 or more, the mask
          turns the slot into a number that looks random. The program does this with one multiplication of two ciphertexts.
        </Prose>
      </Part>

      <Part title={EXPLAINER_HEADINGS.example}>
        <Prose>
          Three bidders bid the price steps <Mono>{FIRST_PRICE_BIDS[0]}</Mono>, <Mono>{FIRST_PRICE_BIDS[1]}</Mono> and{' '}
          <Mono>{FIRST_PRICE_BIDS[2]}</Mono>. Bidders {winner} and {FIRST_PRICE_LAST_TIED} tie at the top with {price}, and bidder {winner}{' '}
          bid first. The table shows steps 0 to {SHOWN_STEPS - 1}. Every step above {SHOWN_STEPS - 1} is all zero, because nobody bid above
          it.
        </Prose>
        <div className='overflow-x-auto'>
          <table className='w-full max-w-3xl border-collapse text-sm'>
            <thead>
              <tr className='text-left'>
                <th className='p-2'>
                  Step <Mono>l</Mono>
                </th>
                <th className='p-2'>
                  <Mono>ge</Mono> (lanes 0, 1, 2)
                </th>
                <th className='p-2'>
                  <Mono>A</Mono> (lanes 0, 1, 2)
                </th>
                <th className='p-2'>Output (lanes 0, 1, 2)</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ level, lanes }) => (
                <tr key={level} style={{ borderTop: '1px solid var(--rule)' }}>
                  <td className='p-2 font-mono'>{level}</td>
                  <td className='p-2 font-mono'>{lanes.map(({ ge }) => (ge ? 1 : 0)).join(', ')}</td>
                  <td className='p-2 font-mono'>{lanes.map(({ rivals }) => rivals).join(', ')}</td>
                  <td className='p-2 font-mono'>{lanes.map(({ slot }) => SLOT_TEXT[slot]).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Prose>The same output as a picture. Each row is a lane, and each column is a price step.</Prose>
        <SlotPicture
          axis={rows.map(({ level }) => String(level))}
          rows={FIRST_PRICE_BIDS.map((_, lane) => ({
            key: String(lane),
            winner: lane === winner,
            name: (
              <>
                Lane {lane}
                {lane === winner && <span className='tag live'>winner</span>}
              </>
            ),
            cells: cells[lane],
          }))}
          priceStep={price}
          reading='the winner’s 1 at the price'
          summary={`Worked example. Lane ${winner} wins at step ${price}. Every other slot is a zero or a random number.`}
        />
        <Prose>
          Read the output from the top. Step {SHOWN_STEPS - 1} is the highest step with a slot that is not zero, so the price is step{' '}
          {price}: the winning bid. At that step, lane 0 is exactly 0 and lane {winner} is exactly 1. The first lane that is not zero is
          lane {winner}, so{' '}
          <strong>
            bidder {winner} wins at step {price}
          </strong>
          . Lane 2 also bid {price}, but it bid later. Its <Mono>A</Mono> is 1, so its slot looks random. The tie shows nowhere in the
          output, and the bidder who bid first wins.
        </Prose>
      </Part>

      <Part title={EXPLAINER_HEADINGS.reading}>
        <Bullets>
          <li>The price is the highest step where some lane is not zero.</li>
          <li>The winner is the first lane that is not zero at that step. Its slot is exactly 1.</li>
          <li>Every lane before the winner is exactly 0 at that step.</li>
          <li>Every slot above the price, and every lane without a bidder, is exactly 0.</li>
          <li>Every other slot holds a number that looks random. The reader does not need it.</li>
        </Bullets>
      </Part>

      <Part title={EXPLAINER_HEADINGS.cannotFail}>
        <Prose>
          The mask changes only the slots where <Mono>A</Mono> is 1 or more. The slots that the reader needs have <Mono>A = 0</Mono>, so the
          mask never touches them. Above the top bid, every term is 0. At the top step, a lane before the winner has <Mono>ge = 0</Mono> and{' '}
          <Mono>A = 0</Mono>, so it is exactly 0. The winner has <Mono>ge = 1</Mono> and <Mono>A = 0</Mono>, so it is exactly 1. A mask that
          is zero by chance in some slot cannot break this. The result is always readable.
        </Prose>
        <FailureScope />
      </Part>

      <Part title={EXPLAINER_HEADINGS.leaks}>
        <Prose>
          The output shows the winner and the winning bid, which is the price of a first-price auction, and nothing else. A slot with{' '}
          <Mono>A</Mono> of 1 or more holds <Mono>ge + mask × A</Mono>. If at least one bidder drew its mask at random, the sum of the masks
          is a uniform random number in every slot. <Mono>A</Mono> is not zero and is below {PLAINTEXT_MODULUS}, and {PLAINTEXT_MODULUS} is
          prime. So the slot is a uniform random number too. It tells nothing about the other bids, and nothing about the tie.
        </Prose>
      </Part>

      <Part title={EXPLAINER_HEADINGS.trust}>
        <Prose>
          Privacy needs one bidder who draws its mask at random and keeps it secret. The browser of each bidder does this by default. If all
          the bidders share their masks with one party, that party can read the numbers of <Mono>A</Mono>. These numbers show more than the
          winner and the price. The creator, the server and the committee do not choose or see the masks. A bidder who sends a bad mask on
          purpose cannot make the result unreadable.
        </Prose>
      </Part>
    </div>
  )
}

export default FirstPriceAuctionExplainer
