// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { AuctionType, DEGREE, GROUPS, LEVELS, MAX_BIDDERS_BY_TYPE, PLAINTEXT_MODULUS } from '@interfold/auction'
import { FIRST_PRICE_BIDS, firstPriceRows, type LaneSlot } from '@/utils/explainer-example'

const Mono: React.FC<{ children: React.ReactNode }> = ({ children }) => <span className='font-mono'>{children}</span>

/** The levels the worked example shows: 0 up to the highest bid. Every level above the highest bid is zero. */
const SHOWN_LEVELS = 4

const SLOT_TEXT: Record<LaneSlot, string> = { zero: '0', one: '1', random: '?' }
const SLOT_CLASS: Record<LaneSlot, string> = { zero: 'zero', one: 'read', random: 'rand' }

/** How the "First-price" type works, in plain words, with a worked example of 3 bidders and a tie. */
const FirstPriceAuctionExplainer: React.FC = () => {
  const rows = firstPriceRows(SHOWN_LEVELS)
  const maxBidders = MAX_BIDDERS_BY_TYPE[AuctionType.FirstPrice]
  const price = Math.max(...FIRST_PRICE_BIDS)
  const columns = { gridTemplateColumns: `max-content repeat(${SHOWN_LEVELS}, minmax(0, 1fr))` }
  return (
    <div className='space-y-6'>
      <div className='space-y-2'>
        <h3 className='h3'>Who sends what</h3>
        <p className='prose-ed max-w-3xl'>
          Each bidder sends <strong>three ciphertexts</strong>. <Mono>ge</Mono> marks every price step up to and including the bid, and{' '}
          <Mono>gt</Mono> marks every price step below the bid. The third is a <strong>mask</strong>: {DEGREE} random numbers between 0 and{' '}
          {PLAINTEXT_MODULUS - 1}, which the browser of the bidder draws. There are no mask providers and no other party: only bidders. The
          auction takes 2 to {maxBidders} bidders.
        </p>
      </div>

      <div className='space-y-3'>
        <h3 className='h3'>The lanes</h3>
        <p className='prose-ed max-w-3xl'>
          The output has {DEGREE} slots. The program cuts them into {GROUPS} <strong>lanes</strong> of {LEVELS} slots. Lane <Mono>j</Mono>{' '}
          belongs to bidder <Mono>j</Mono>, in the order the bidders bid. Slot <Mono>p</Mono> of a lane is the price step <Mono>p</Mono>. A
          lane that has no bidder stays zero.
        </p>
        <p className='prose-ed max-w-3xl'>
          For each lane and each price step, the program computes <Mono>out = ge + mask × A</Mono>, without decrypting anything:
        </p>
        <ul className='prose-ed max-w-3xl list-disc space-y-1 pl-6'>
          <li>
            <Mono>ge</Mono> is 1 if the bidder of the lane bid at least this step, and 0 if not.
          </li>
          <li>
            <Mono>A</Mono> counts the rivals that matter at this step: the bidders that bid above the step, plus the earlier bidders that
            bid exactly the step. <Mono>A</Mono> is a small whole number, below {PLAINTEXT_MODULUS}.
          </li>
          <li>
            <Mono>mask</Mono> is the sum of the masks of all bidders in this slot.
          </li>
        </ul>
        <p className='prose-ed max-w-3xl'>
          When <Mono>A</Mono> is 0, the slot is just <Mono>ge</Mono>: exactly 0 or exactly 1. When <Mono>A</Mono> is 1 or more, the mask
          turns the slot into a number that looks random. The program does this with one multiplication of two ciphertexts.
        </p>
      </div>

      <div className='space-y-3'>
        <h3 className='h3'>A worked example, with a tie</h3>
        <p className='prose-ed max-w-3xl'>
          Three bidders bid the price steps <Mono>2</Mono>, <Mono>3</Mono> and <Mono>3</Mono>. Bidder 0 bids 2. Bidders 1 and 2 tie at the
          top with 3, and bidder 1 bid first. The table shows levels 0 to {SHOWN_LEVELS - 1}. Every level above {SHOWN_LEVELS - 1} is all
          zero, because nobody bid above it.
        </p>
        <div className='overflow-x-auto'>
          <table className='w-full max-w-3xl border-collapse text-sm'>
            <thead>
              <tr className='text-left'>
                <th className='p-2'>
                  Level <Mono>p</Mono>
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

        <p className='prose-ed max-w-3xl'>
          The same output as a picture of the lanes. Each row is a lane, and each column is a price step.
        </p>
        <div className='overflow-x-auto pb-2'>
          <div className='slots' style={columns}>
            <span />
            {rows.map(({ level }) => (
              <span key={level} className='axis'>
                {level}
              </span>
            ))}
            {FIRST_PRICE_BIDS.map((_, lane) => (
              <React.Fragment key={lane}>
                <span className={`row-name ${lane === 1 ? 'font-semibold text-brand-green' : ''}`}>
                  Lane {lane}
                  {lane === 1 && <span className='tag live'>winner</span>}
                </span>
                {rows.map(({ level, lanes }) => (
                  <span
                    key={level}
                    className={`cell ${SLOT_CLASS[lanes[lane].slot]} ${level === price ? 'col-price' : ''}`}
                    title={`lane ${lane}, step ${level}: ${lanes[lane].slot === 'random' ? 'random-looking number' : lanes[lane].slot === 'one' ? 'exactly 1' : 'exactly 0'}`}
                  />
                ))}
              </React.Fragment>
            ))}
          </div>
        </div>
        <div className='legend'>
          <span>
            <i className='slots-swatch rand' /> A number that looks random (<Mono>?</Mono>)
          </span>
          <span>
            <i style={{ background: 'var(--paper)' }} /> Exactly 0
          </span>
          <span>
            <i style={{ background: 'var(--vote-action)', borderColor: 'var(--vote-action)' }} /> Exactly 1: the reading
          </span>
          <span>
            <i style={{ boxShadow: '0 0 0 2px var(--ink)' }} /> Price step
          </span>
        </div>

        <p className='prose-ed max-w-3xl'>
          Read the output from the top. Level {SHOWN_LEVELS - 1} is the highest level with a slot that is not zero, so the price is step{' '}
          {price}: the winning bid. At that level, lane 0 is exactly 0 and lane 1 is exactly 1. The first lane that is not zero is lane 1,
          so <strong>bidder 1 wins at step {price}</strong>. Lane 2 also bid {price}, but it bid later: its <Mono>A</Mono> is 1, so its slot
          looks random. The tie shows nowhere in the output, and the bidder who bid first wins. Every slot below the price looks random too,
          and nobody reads it.
        </p>
      </div>

      <div className='space-y-2'>
        <h3 className='h3'>How the result is read</h3>
        <ul className='prose-ed max-w-3xl list-disc space-y-1 pl-6'>
          <li>The price is the highest level where some lane is not zero.</li>
          <li>The winner is the first lane that is not zero at that level. Its slot is exactly 1.</li>
          <li>Every lane before the winner is exactly 0 at that level.</li>
          <li>Every slot above the price, and every lane without a bidder, is exactly 0.</li>
        </ul>
        <p className='prose-ed max-w-3xl'>
          The slots of the later lanes at the price, and every slot below the price, look random. The reader does not need them.
        </p>
      </div>

      <div className='space-y-2'>
        <h3 className='h3'>Why it never fails</h3>
        <p className='prose-ed max-w-3xl'>
          The mask changes only the slots where <Mono>A</Mono> is 1 or more. The slots that the reader needs have <Mono>A = 0</Mono>, so the
          mask never touches them. Above the top bid, every term is 0. At the top level, a lane before the winner has <Mono>ge = 0</Mono>{' '}
          and <Mono>A = 0</Mono>, so it is exactly 0. The winner has <Mono>ge = 1</Mono> and <Mono>A = 0</Mono>, so it is exactly 1. A mask
          that is zero by chance in some slot cannot break this. The result always reads.
        </p>
      </div>

      <div className='space-y-2'>
        <h3 className='h3'>What it leaks</h3>
        <p className='prose-ed max-w-3xl'>
          The output shows the winner and the winning bid, which is the price of a first-price auction, and nothing else. A slot with{' '}
          <Mono>A</Mono> of 1 or more holds <Mono>ge + mask × A</Mono>. If at least one bidder drew its mask at random, the sum of the masks
          is a uniform random number in every slot. <Mono>A</Mono> is not zero and is below {PLAINTEXT_MODULUS}, and {PLAINTEXT_MODULUS} is
          prime, so the slot is a uniform random number too. It tells nothing about the other bids, and nothing about the tie.
        </p>
      </div>

      <div className='space-y-2'>
        <h3 className='h3'>Whom you must trust</h3>
        <p className='prose-ed max-w-3xl'>
          Nobody. Privacy needs one bidder who draws its mask at random and keeps it secret, and the browser of each bidder does this by
          default. If all the bidders share their masks with one party, that party can read the numbers of <Mono>A</Mono>, which show more
          than the winner and the price. The creator, the server and the committee do not choose or see the masks. A bidder who sends a bad
          mask on purpose cannot make the result unreadable.
        </p>
      </div>
    </div>
  )
}

export default FirstPriceAuctionExplainer
