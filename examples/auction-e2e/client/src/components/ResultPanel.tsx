// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useState } from 'react'
import type { Address } from 'viem'
import { AuctionType, MIN_BIDDERS, type RegionResult, type SelectedBid, type SubmittedBid, selectBids } from '@interfold/auction-core'
import { DESIGNS } from '@/utils/designs'
import { type AuctionState, formatPrice } from '@/utils/auction'
import { opensCommitment } from '@/utils/commitments'
import { readSubmittedBids } from '@/utils/auction-events'
import type { StoredVersion } from '@/utils/bid-storage'
import { formatError } from '@/utils/error-formatting'
import { sameAddress } from '@/utils/format'
import { AddressLink } from './Explorer'
import { SlotPicture } from './SlotPicture'
import Spinner from './Spinner'

/** Reading the bids scans the logs of the chain. After this many ms the page says so. The scan goes on. */
const SLOW_NOTE_MS = 60_000

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

const PRICE_EXPLANATION: Record<AuctionType, string> = {
  [AuctionType.FirstPrice]:
    'First-price auction: the winner pays their own bid, which is the highest bid. The committee decrypted one lane of slots for each bidder. The lanes show only the winner and that bid. The masks of the bidders hide every other slot. They never touch the slots that the reading needs, so the result is always readable.',
  [AuctionType.ProviderSecondPrice]:
    'Second-price auction with mask providers: the winner pays the second-highest bid. The committee decrypted a pattern of zeros and random numbers. The pattern shows only the winner and that price. The winning bid stays secret. The mask providers made the random numbers, and none of them is zero, so the result is always readable.',
  [AuctionType.QnrSecondPrice]:
    'Second-price auction without providers: the winner pays the second-highest bid. The committee decrypted a pattern of zeros and other numbers. The pattern shows the winner and that price. The winning bid stays secret. The bidders made the random shares, and the number 3 is not a square modulo 257, so the result is always readable. The numbers that are not zero carry a small statistical hint about the losing bids.',
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
  const [attempt, setAttempt] = useState(0)
  const [slow, setSlow] = useState(false)
  const plaintextOutput = auction.plaintextOutput

  useEffect(() => {
    let cancelled = false
    setDecoded(null)
    setSlow(false)
    if (plaintextOutput === null) return
    const slowTimer = setTimeout(() => setSlow(true), SLOW_NOTE_MS)
    readSubmittedBids(auction.e3Id, auction.requestedAt)
      .then(selectCountedBids)
      .then(async ({ bidders, outcomes }) => {
        if (bidders.length < MIN_BIDDERS) {
          throw new Error(
            `Only ${bidders.length} ${bidders.length === 1 ? 'bid matched' : 'bids matched'} their commitments, and the auction needs ${MIN_BIDDERS}. The program had nothing to compute over.`,
          )
        }
        const result = await DESIGNS[auction.auctionType].decodeResult(plaintextOutput, bidders.length)
        if (!cancelled) setDecoded({ bidders, outcomes, result })
      })
      .catch((err) => {
        if (!cancelled) setDecoded({ error: formatError(err) })
      })
    return () => {
      cancelled = true
      clearTimeout(slowTimer)
    }
  }, [auction.e3Id, auction.requestedAt, auction.auctionType, plaintextOutput, attempt])

  if (decoded === null) {
    return (
      <div role='status' className='note flex items-start gap-3'>
        <Spinner size={16} />
        <span>
          Reading the bids and decoding the result in your browser.
          {slow && ' This takes longer than usual. The page keeps reading, so wait here.'}
        </span>
      </div>
    )
  }
  if ('error' in decoded) {
    return (
      <div role='alert' className='note bad flex flex-wrap items-center justify-between gap-3'>
        <span>Could not decode the result: {decoded.error}</span>
        <button type='button' onClick={() => setAttempt((count) => count + 1)} className='btn ghost sm'>
          Try again
        </button>
      </div>
    )
  }

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
const ResultView: React.FC<ResultViewProps> = ({ auction, account, myVersions, bidders, outcomes, result }) => {
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
            {price !== null && `: step ${price} (the steps go from 0 to ${auction.prices.length - 1})`}
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
              <strong>Your bid was dropped.</strong> The bytes of {mine.latest === 1 ? 'your bid' : 'each of your bids'} did not match what
              you committed to, so the program left {mine.latest === 1 ? 'it' : 'them'} out.
            </>
          ) : (
            'This account did not bid in this auction.'
          )}
        </div>
      )}

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
        ciphertext again and compares the hash with the commitment the bidder published. The program ignores a whole bid if one ciphertext
        does not match. This page repeats that check in your browser.
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
                    ? `version ${outcome.latest} did not match its commitments`
                    : `versions above ${bid.version} did not match their commitments`}
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
            For these bidders, the bytes did not match what the bidder committed to in any version. The program used nothing of their bids.
          </p>
          <ul className='space-y-2'>
            {dropped.map((outcome) => (
              <li key={outcome.bidder} className='flex flex-wrap items-center gap-2 text-sm'>
                <AddressLink address={outcome.bidder} />
                {sameAddress(outcome.bidder, account) && <span className='tag muted'>you</span>}
                <span className='tag bad'>dropped</span>
                <span className='muted text-xs'>
                  {outcome.latest === 1
                    ? 'the bytes did not match the commitments'
                    : `none of its ${outcome.latest} versions matched the commitments`}
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
  const winnerAddress = winner === null ? null : bidders[winner].bidder
  const summary =
    winnerAddress !== null && price !== null
      ? `Result grid. Winner: ${winnerAddress}. Price: ${formatPrice(price, auction.prices)}, step ${price}. Every other slot is a zero or a random number.`
      : 'Result grid. The result does not show a single winner.'
  const rows = set.map((row, position) => {
    const address = bidders[position].bidder
    return {
      key: address,
      winner: position === winner,
      name: (
        <>
          <AddressLink address={address} />
          {sameAddress(address, account) && <span className='tag muted'>you</span>}
          {position === winner && <span className='tag live'>winner</span>}
        </>
      ),
      cells: row
        .slice(0, levels)
        .map((isSet, level) =>
          position === winner && level === price ? ('read' as const) : isSet ? ('rand' as const) : ('zero' as const),
        ),
    }
  })

  return (
    <div className='space-y-4'>
      <div className='space-y-1'>
        <h3 className='h3'>How the result is read</h3>
        <p className='text-sm text-muted'>
          Only the marked cell is the reading. Every other cell is a zero or a random number. The grid has one row for each bidder and one
          column for each price step.
        </p>
      </div>

      <SlotPicture
        axis={Array.from({ length: levels }, (_, level) => String(level))}
        axisTitles={Array.from({ length: levels }, (_, level) => `price ${formatPrice(level, auction.prices)}`)}
        rows={rows}
        priceStep={price}
        reading={`the winner’s ${firstPrice ? '1' : 'zero'} at the price`}
        summary={summary}
      />

      <details className='text-sm'>
        <summary className='cursor-pointer font-semibold'>How to read this</summary>
        <div className='mt-2 space-y-2 text-muted'>
          <p>{PRICE_EXPLANATION[auction.auctionType]}</p>
          <p>
            {firstPrice
              ? `The committee published one lane of ${levels} slots for each bidder, one slot per price step. Above the price every slot is zero. At the price step the winner’s lane is exactly 1, and every lane before it is exactly 0. The lanes after the winner, and every slot below the price, look random. The masks of the bidders hide them, and the reading does not need them.`
              : `The committee published ${levels} slots per bidder, one per price step. A slot holds a random value unless the program made it zero. Every bidder’s slots are random up to the price. At the price step exactly one slot is zero: the winner’s. Above the price every slot is zero.`}
          </p>
          <p>
            If the top bids tie, the tied bidder who bid first wins. The result does not show that a tie happened. A bidder that updated its
            bid has the place of its update.
          </p>
        </div>
      </details>
      {!result.unusedGroupsZero && (
        <p role='alert' className='note bad'>
          The slots the program must zero are not zero: this output is not from the auction program.
        </p>
      )}
    </div>
  )
}

export default ResultPanel
