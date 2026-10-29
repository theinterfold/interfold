// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useState } from 'react'
import type { Address } from 'viem'
import {
  AuctionType,
  MIN_BIDDERS,
  type RegionResult,
  type SelectedBid,
  type SubmittedBid,
  decodeAuction,
  selectBids,
} from '@interfold/auction'
import { type AuctionState, formatPrice } from '@/utils/auction'
import { opensCommitment } from '@/utils/commitments'
import { readSubmittedBids } from '@/utils/auction-events'
import type { StoredVersion } from '@/utils/bid-storage'
import { formatError } from '@/utils/error-formatting'
import { AddressLink } from './Explorer'
import Spinner from './Spinner'

/** What became of one bidder's bids: the version the auction computed over, if any. */
interface BidderOutcome {
  bidder: Address
  /** The highest version the bidder submitted. */
  latest: number
  /** The version that counted: the highest one whose bytes open their commitments. `null` if none did. */
  counted: number | null
}

interface Decoded {
  /** The bids the program computed over, in bidder position order. */
  bidders: SelectedBid[]
  outcomes: BidderOutcome[]
  result: RegionResult
}

/**
 * The bids of the auction as the program reads them: the bytes of each ciphertext are hashed again and
 * must open the commitment the bidder published. The same rule as `select` in the program.
 */
async function selectCountedBids(bids: SubmittedBid[]): Promise<{ bidders: SelectedBid[]; outcomes: BidderOutcome[] }> {
  const bidders = selectBids(bids, await opensCommitment(bids.flatMap((bid) => bid.ciphertexts)))
  const outcomes = new Map<string, BidderOutcome>()
  for (const { bidder, version } of bids) {
    const key = bidder.toLowerCase()
    const known = outcomes.get(key)
    outcomes.set(key, { bidder, latest: Math.max(known?.latest ?? 0, version), counted: null })
  }
  for (const { bidder, version } of bidders) {
    const outcome = outcomes.get(bidder.toLowerCase())
    if (outcome) outcome.counted = version
  }
  return { bidders, outcomes: [...outcomes.values()] }
}

const sameAddress = (a: string, b: string | undefined) => b !== undefined && a.toLowerCase() === b.toLowerCase()

const PRICE_EXPLANATION: Record<AuctionType, string> = {
  [AuctionType.FirstPrice]:
    'First-price auction: the winner pays their own bid, which is the highest bid. The committee decrypted one lane of numbers for each bidder. The lanes show only the winner and that bid. The masks of the bidders hide every other slot, and they never touch the slots that the reading needs, so the lanes always read.',
  [AuctionType.ProviderSecondPrice]:
    'Second-price auction with mask providers: the winner pays the second-highest bid. The committee decrypted a pattern of zeros and random numbers, and the pattern shows only the winner and that price; the winning bid itself stays secret. The mask providers made the random numbers, and none of them is zero, so the pattern always reads.',
  [AuctionType.QnrSecondPrice]:
    'Second-price auction without providers: the winner pays the second-highest bid. The committee decrypted a pattern of zeros and other numbers, and the pattern shows the winner and that price; the winning bid itself stays secret. The bidders made the random shares, and the number 3 is not a square modulo 257, so the pattern always reads. The numbers that are not zero carry a small statistical hint about the losing bids.',
}

const PRICE_CAPTION: Record<AuctionType, string> = {
  [AuctionType.FirstPrice]: 'The winning bid',
  [AuctionType.ProviderSecondPrice]: 'The second-highest bid',
  [AuctionType.QnrSecondPrice]: 'The second-highest bid',
}

interface ResultPanelProps {
  auction: AuctionState
  account: `0x${string}` | undefined
  /** The bids of the connected account that this browser remembers. */
  myVersions: StoredVersion[]
}

/** Decodes the published plaintext of an auction and shows who won, at what price, and how to read it. */
const ResultPanel: React.FC<ResultPanelProps> = ({ auction, account, myVersions }) => {
  const [decoded, setDecoded] = useState<Decoded | { error: string } | null>(null)
  const plaintextOutput = auction.plaintextOutput

  useEffect(() => {
    let cancelled = false
    setDecoded(null)
    if (plaintextOutput === null) return
    readSubmittedBids(auction.e3Id)
      .then(selectCountedBids)
      .then(async ({ bidders, outcomes }) => {
        if (bidders.length < MIN_BIDDERS) {
          throw new Error(
            `Only ${bidders.length} ${bidders.length === 1 ? 'bid' : 'bids'} opened their commitments, and the auction needs ${MIN_BIDDERS}. The program had nothing to compute over.`,
          )
        }
        const result = await decodeAuction(auction.auctionType, plaintextOutput, bidders.length)
        if (!cancelled) setDecoded({ bidders, outcomes, result })
      })
      .catch((err) => {
        if (!cancelled) setDecoded({ error: formatError(err) })
      })
    return () => {
      cancelled = true
    }
  }, [auction.e3Id, auction.auctionType, plaintextOutput])

  if (decoded === null) {
    return (
      <div className='note flex items-center gap-3'>
        <Spinner size={16} /> Decoding the result in your browser…
      </div>
    )
  }
  if ('error' in decoded) return <div className='note bad'>Could not decode the result: {decoded.error}</div>

  return (
    <ResultView
      auction={auction}
      account={account}
      myVersions={myVersions}
      bidders={decoded.bidders}
      outcomes={decoded.outcomes}
      result={decoded.result}
    />
  )
}

interface ResultViewProps extends ResultPanelProps {
  bidders: SelectedBid[]
  outcomes: BidderOutcome[]
  result: RegionResult
}

/** Shows a decoded result: the winner, the price and the view that fits the result kind. */
export const ResultView: React.FC<ResultViewProps> = ({ auction, account, myVersions, bidders, outcomes, result }) => {
  const { winner, price } = result
  const winnerAddress = winner === null ? null : bidders[winner].bidder
  const youWon = winnerAddress !== null && sameAddress(winnerAddress, account)
  const mine = outcomes.find((outcome) => sameAddress(outcome.bidder, account))
  const youBid = mine?.counted != null
  // The level of the version that counted, if this browser made that bid.
  const myBid = myVersions.find(({ version }) => version === mine?.counted)?.level ?? null
  const priceLabel = price === null ? 'unreadable' : formatPrice(price, auction.prices)

  return (
    <div className='space-y-7'>
      <div className='grid gap-4 sm:grid-cols-2'>
        <div className='inset ok p-5'>
          <p className='meta muted'>Winner{youWon ? ' (you)' : ''}</p>
          <p className='mt-2 text-lg'>{winnerAddress ? <AddressLink address={winnerAddress} full /> : 'unreadable'}</p>
        </div>
        <div className='inset strong p-5'>
          <p className='meta muted'>Price</p>
          <p className='value mt-1'>{priceLabel}</p>
          <p className='muted mt-2 text-xs'>
            {PRICE_CAPTION[auction.auctionType]}
            {price !== null && `: step ${price} of ${auction.prices.length - 1}`}
          </p>
        </div>
      </div>

      {(winner === null || price === null) && (
        <div role='alert' className='note bad'>
          The result does not show a single winner. This cannot happen by chance, whatever the bidders send, so the output is not from the
          auction program.
        </div>
      )}

      {account && (
        <div className={`note ${youWon ? 'ok' : ''}`}>
          {youWon ? (
            <>
              <strong>You won.</strong> You pay {priceLabel}.
            </>
          ) : youBid ? (
            <>
              <strong>You did not win.</strong>
              {myBid !== null && ` Your bid was ${formatPrice(myBid, auction.prices)}.`}
            </>
          ) : mine ? (
            <>
              <strong>Your bid was dropped.</strong> The ciphertext bytes of {mine.latest === 1 ? 'your bid' : 'each of your bids'} did not
              open their commitments, so the program left {mine.latest === 1 ? 'it' : 'them'} out.
            </>
          ) : (
            'This account did not bid in this auction.'
          )}
        </div>
      )}

      <p className='text-sm text-ink'>{PRICE_EXPLANATION[auction.auctionType]}</p>
      <SlotGrid auction={auction} account={account} bidders={bidders} result={result} />
      <CountedBids account={account} bidders={bidders} outcomes={outcomes} />
    </div>
  )
}

/** Which version of each bidder's bid the program computed over, and the bidders that it left out. */
const CountedBids: React.FC<{ account: `0x${string}` | undefined; bidders: SelectedBid[]; outcomes: BidderOutcome[] }> = ({
  account,
  bidders,
  outcomes,
}) => {
  const dropped = outcomes.filter((outcome) => outcome.counted === null)
  return (
    <div className='space-y-3'>
      <h3 className='h3'>Which bids counted</h3>
      <p className='text-sm text-muted'>
        A bidder can update its bid, and the program computes over the latest version that is valid. The program hashes the bytes of every
        ciphertext again and checks that they open the commitment the bidder published; a bid with any ciphertext that does not open is
        ignored whole. This page repeats that check in your browser.
      </p>
      <ol className='space-y-2'>
        {bidders.map((bid) => {
          const outcome = outcomes.find((candidate) => sameAddress(candidate.bidder, bid.bidder))
          return (
            <li key={bid.bidder} className='flex flex-wrap items-center gap-2 text-sm'>
              <span className='mono muted'>{bid.position}</span>
              <AddressLink address={bid.bidder} />
              {sameAddress(bid.bidder, account) && <span className='tag muted'>you</span>}
              <span className='tag live'>version {bid.version} counted</span>
              {outcome && outcome.latest > bid.version && (
                <span className='muted text-xs'>
                  {outcome.latest === bid.version + 1
                    ? `version ${outcome.latest} did not open its commitments`
                    : `versions above ${bid.version} did not open their commitments`}
                </span>
              )}
            </li>
          )
        })}
      </ol>
      {dropped.length > 0 && (
        <>
          <h3 className='h3'>Dropped bidders</h3>
          <p className='text-sm text-muted'>
            These bidders sent bytes that do not open their commitments in any version. Nothing of their bids was used.
          </p>
          <ul className='space-y-2'>
            {dropped.map((outcome) => (
              <li key={outcome.bidder} className='flex flex-wrap items-center gap-2 text-sm'>
                <AddressLink address={outcome.bidder} />
                {sameAddress(outcome.bidder, account) && <span className='tag muted'>you</span>}
                <span className='tag bad'>dropped</span>
                <span className='muted text-xs'>
                  {outcome.latest === 1
                    ? 'bytes did not open the commitments'
                    : `none of its ${outcome.latest} versions opened the commitments`}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}

const SlotGrid: React.FC<{
  auction: AuctionState
  account: `0x${string}` | undefined
  bidders: SelectedBid[]
  result: RegionResult
}> = ({ auction, account, bidders, result }) => {
  const { price, winner, set } = result
  const firstPrice = auction.auctionType === AuctionType.FirstPrice
  const levels = auction.prices.length
  const columns = { gridTemplateColumns: `max-content repeat(${levels}, minmax(0, 1fr))` }

  return (
    <div className='space-y-4'>
      <div className='space-y-1'>
        <h3 className='h3'>How the result is read</h3>
        <p className='text-sm text-muted'>
          {firstPrice
            ? `The committee published one lane of ${levels} slots for each bidder, one slot per price step. Above the price every slot is zero. At the price step the winner’s lane is exactly 1, and every lane before it is exactly 0. The lanes after the winner, and every slot below the price, look random: the masks of the bidders hide them, and the reading does not need them.`
            : `The committee published ${levels} slots per bidder, one per price step. Slots hold a random value unless the program zeroed them. Every bidder’s slots are random up to the price. At the price step exactly one is zero, the winner’s. Above it every slot is zero.`}
        </p>
      </div>

      <div className='overflow-x-auto pb-2'>
        <div className='slots' style={columns}>
          <span />
          {Array.from({ length: levels }, (_, level) => (
            <span key={level} className='axis' title={`price ${formatPrice(level, auction.prices)}`}>
              {level}
            </span>
          ))}
          {set.map((row, position) => {
            const address = bidders[position].bidder
            const mine = sameAddress(address, account)
            return (
              <React.Fragment key={address}>
                <span className={`row-name ${position === winner ? 'font-semibold text-brand-green' : ''}`}>
                  <AddressLink address={address} />
                  {mine && <span className='tag muted'>you</span>}
                  {position === winner && <span className='tag live'>winner</span>}
                </span>
                {row.slice(0, levels).map((isSet, level) => {
                  const reading = position === winner && level === price
                  return (
                    <span
                      key={level}
                      className={`cell ${reading ? 'read' : isSet ? 'rand' : 'zero'} ${level === price ? 'col-price' : ''}`}
                      title={`step ${level}: ${reading ? (firstPrice ? 'exactly 1, the reading' : 'zero, the reading') : isSet ? 'random value' : 'zero'}`}
                    />
                  )
                })}
              </React.Fragment>
            )
          })}
        </div>
      </div>

      <div className='legend'>
        <span>
          <i className='slots-swatch rand' /> Random value
        </span>
        <span>
          <i style={{ background: 'var(--paper)' }} /> Zero
        </span>
        <span>
          <i style={{ background: 'var(--vote-action)', borderColor: 'var(--vote-action)' }} /> The reading: the winner’s{' '}
          {firstPrice ? '1' : 'zero'} at the price
        </span>
        <span>
          <i style={{ boxShadow: '0 0 0 2px var(--ink)' }} /> Price step
        </span>
      </div>
      <p className='muted text-xs'>
        If the top bids tie, the tied bidder who bid first wins. The result does not show that a tie happened. A bidder that updated its bid
        has the place of its update, so an update loses the place of the earlier bid.
      </p>
      {!result.unusedGroupsZero && (
        <p role='alert' className='note bad'>
          The slots the program must zero are not zero: this output is not from the auction program.
        </p>
      )}
    </div>
  )
}

export default ResultPanel
