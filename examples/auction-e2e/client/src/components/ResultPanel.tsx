// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useState } from 'react'
import { type AuctionResult, AuctionType, LEVELS, type LaneResult, type RegionResult, decodeAuction } from '@shared/layout'
import { type AuctionState, formatPrice } from '@/utils/auction'
import { type LinkedBidder, readLinkedBidders } from '@/utils/auction-events'
import { formatError } from '@/utils/error-formatting'
import { AddressLink } from './Explorer'
import Spinner from './Spinner'

interface Decoded {
  bidders: LinkedBidder[]
  result: AuctionResult
}

const sameAddress = (a: string, b: string | undefined) => b !== undefined && a.toLowerCase() === b.toLowerCase()

const PRICE_EXPLANATION: Record<AuctionType, string> = {
  [AuctionType.FirstPrice]:
    'First-price auction: the winner pays their own bid, which is the highest bid. The committee decrypted only the winner and that bid; no other bid was ever revealed.',
  [AuctionType.SecondPrice]:
    'Second-price auction: the winner pays the second-highest bid. The committee decrypted only the winner and that price; the winning bid itself stays secret.',
  [AuctionType.RatioFirstPrice]:
    'First-price auction with ratio lanes: the winner pays their own bid, which is the highest bid. The committee decrypted the highest bid and the set of bidders that tied for it. If one bidder tied, that bidder won. If more tied, a public random value picked the winner among them. No other bid was revealed.',
  [AuctionType.RatioSecondPrice]:
    'Second-price auction with ratio lanes: the winner pays the second-highest bid. The committee decrypted that price and the set of winning bidders. If the top bids tied, that set holds every tied bidder, their bids equal the price, and a public random value picked the winner among them. Without a tie the winner’s bid stays secret.',
}

const PRICE_CAPTION: Record<AuctionType, string> = {
  [AuctionType.FirstPrice]: 'The winning bid',
  [AuctionType.SecondPrice]: 'The second-highest bid',
  [AuctionType.RatioFirstPrice]: 'The winning bid',
  [AuctionType.RatioSecondPrice]: 'The second-highest bid (the top bid, if the top bids tied)',
}

interface ResultPanelProps {
  auction: AuctionState
  account: `0x${string}` | undefined
  /** The connected account's own bid level, if this browser holds it. */
  myBid: number | null
}

/** Decodes the published plaintext of an auction and shows who won, at what price, and how to read it. */
const ResultPanel: React.FC<ResultPanelProps> = ({ auction, account, myBid }) => {
  const [decoded, setDecoded] = useState<Decoded | { error: string } | null>(null)
  const plaintextOutput = auction.plaintextOutput

  useEffect(() => {
    let cancelled = false
    setDecoded(null)
    if (plaintextOutput === null) return
    readLinkedBidders(auction.e3Id)
      .then(async (bidders) => {
        const result = await decodeAuction(
          auction.auctionType,
          plaintextOutput,
          bidders.map((bidder) => bidder.geCiphertext),
        )
        if (!cancelled) setDecoded({ bidders, result })
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

  return <ResultView auction={auction} account={account} myBid={myBid} bidders={decoded.bidders} result={decoded.result} />
}

interface ResultViewProps extends ResultPanelProps {
  bidders: LinkedBidder[]
  result: AuctionResult
}

/** Shows a decoded result: the winner, the price and the view that fits the result kind. */
export const ResultView: React.FC<ResultViewProps> = ({ auction, account, myBid, bidders, result }) => {
  const { winner, price } = result
  const winnerAddress = winner === null ? null : bidders[winner].address
  const youWon = winnerAddress !== null && sameAddress(winnerAddress, account)
  const youBid = account !== undefined && bidders.some((bidder) => sameAddress(bidder.address, account))
  const priceLabel = price === null ? 'unreadable' : formatPrice(price, auction.prices)
  const tieSet = result.kind === 'lane' ? result.tieSet : []
  const inTieSet = tieSet.length > 1 && account !== undefined && tieSet.some((position) => sameAddress(bidders[position].address, account))

  return (
    <div className='space-y-7'>
      <div className='grid gap-4 sm:grid-cols-2'>
        <div className='border border-accent bg-accent-soft p-5'>
          <p className='mono-sm muted'>Winner{youWon ? ' (you)' : ''}</p>
          <p className='mt-2 text-lg'>{winnerAddress ? <AddressLink address={winnerAddress} full /> : 'unreadable'}</p>
        </div>
        <div className='border border-ink bg-card p-5'>
          <p className='mono-sm muted'>Price</p>
          <p className='mt-1 font-serif text-4xl leading-none'>{priceLabel}</p>
          <p className='muted mt-2 text-xs'>
            {PRICE_CAPTION[auction.auctionType]}
            {price !== null && `: level ${price} of ${LEVELS - 1}`}
          </p>
        </div>
      </div>

      {result.kind === 'region' ? (
        (winner === null || price === null) && (
          <div role='alert' className='note bad'>
            The result does not show a single winner. A slot that should hold a random value read as zero by mistake (about 1 in 257 per
            slot and copy on these demo parameters). Run the auction again.
          </div>
        )
      ) : (
        <LaneProblems auction={auction} result={result} />
      )}

      {account && (
        <div className={`note ${youWon ? 'ok' : ''}`}>
          {youWon ? (
            <>
              <strong>You won.</strong> You pay {priceLabel}.{inTieSet && ' You tied for the top bid and the random draw picked you.'}
            </>
          ) : youBid ? (
            <>
              <strong>You did not win.</strong>
              {inTieSet && ' You tied for the top bid and the random draw picked another bidder.'}
              {myBid !== null && ` Your bid was ${formatPrice(myBid, auction.prices)}.`}
            </>
          ) : (
            'This account did not bid in this auction.'
          )}
        </div>
      )}

      <p className='text-sm text-ink-2'>{PRICE_EXPLANATION[auction.auctionType]}</p>
      {result.kind === 'lane' ? (
        <LaneView auction={auction} account={account} bidders={bidders} result={result} />
      ) : (
        <SlotGrid auction={auction} account={account} bidders={bidders} result={result} />
      )}
    </div>
  )
}

/** The ways a ratio-lane result can fail to read: no price or tie set, or copies that disagree. */
const LaneProblems: React.FC<{ auction: AuctionState; result: LaneResult }> = ({ auction, result }) => (
  <>
    {(result.winner === null || result.price === null || result.tieSet.length === 0) && (
      <div role='alert' className='note bad'>
        The result lanes do not show a price and a set of tied bidders.{' '}
        {auction.auctionType === AuctionType.RatioSecondPrice
          ? 'A random value in a lane read as zero by mistake (about 1 in 257 per copy on these demo parameters), or the output is not from the auction program. Run the auction again.'
          : 'A lane holds a value that no set of bidders can make, so the output is not from the auction program.'}
      </div>
    )}
    {!result.copiesAgree && (
      <div role='alert' className='note bad'>
        The copies of the result disagree about the set of tied bidders. The output is not from the auction program, so do not rely on this
        winner.
      </div>
    )}
    {result.tieSet.length > 1 && result.random === null && (
      <div role='alert' className='note bad'>
        More than one bidder tied for the top bid, but the random lane is unreadable, so the draw cannot be checked.
      </div>
    )}
  </>
)

const LaneView: React.FC<{
  auction: AuctionState
  account: `0x${string}` | undefined
  bidders: LinkedBidder[]
  result: LaneResult
}> = ({ auction, account, bidders, result }) => {
  const { price, winner, tieSet, random, lanes, copies } = result
  const columns = { gridTemplateColumns: `max-content repeat(${LEVELS}, minmax(0, 1fr))` }
  const drawn = random !== null && tieSet.length > 1 ? random % tieSet.length : null

  return (
    <div className='space-y-6'>
      <div className='space-y-1'>
        <h3 className='h3'>How the result is read</h3>
        <p className='text-sm text-ink-soft'>
          The committee published one lane of {LEVELS} slots, one per price level, and not one row per bidder. Above the price every slot is
          zero. At the price level the slot holds the set of bidders that tied for the top bid. Below it every slot is random.
          {copies > 1 && ` The program repeats the lane in ${copies} copies. The page reads each copy and checks that they agree.`}
        </p>
      </div>

      <div className='overflow-x-auto pb-2'>
        <div className='slots' style={columns}>
          <span />
          {Array.from({ length: LEVELS }, (_, level) => (
            <span key={level} className='axis' title={`price ${formatPrice(level, auction.prices)}`}>
              {level}
            </span>
          ))}
          <span className='row-name'>Result lane</span>
          {lanes.map((lane, level) => (
            <span
              key={level}
              className={`cell ${lane === 'random' ? 'rand' : lane === 'result' ? 'read' : 'zero'} ${level === price ? 'col-price' : ''}`}
              title={`level ${level}: ${lane === 'random' ? 'random value' : lane === 'result' ? 'the set of tied bidders' : 'zero'}`}
            />
          ))}
        </div>
      </div>

      <div className='legend'>
        <span>
          <i className='slots-swatch rand' /> Random value
        </span>
        <span>
          <i style={{ background: 'var(--card)' }} /> Zero
        </span>
        <span>
          <i style={{ background: 'var(--accent)', borderColor: 'var(--accent)' }} /> The set of tied bidders, at the price
        </span>
        <span>
          <i style={{ boxShadow: '0 0 0 2px var(--warm)' }} /> Price level
        </span>
      </div>

      {tieSet.length > 0 && (
        <div className='space-y-3'>
          <h3 className='h3'>{tieSet.length > 1 ? `${tieSet.length} bidders tied for the top bid` : 'No tie'}</h3>
          {tieSet.length > 1 ? (
            <>
              <p className='text-sm text-ink-soft'>
                A tie makes the set of tied bidders public: all of them bid the price. A random value, published in one extra slot, picks
                the winner. It is the sum of the random masks of all bidders, so it is uniform if one bidder is honest, and nobody could
                predict it or try again. The winner is the tied bidder at the place (value mod {tieSet.length}) in the list below, which is
                in the order the bidders bid.
              </p>
              {random !== null && drawn !== null && (
                <p className='font-mono text-sm'>
                  random value {random} mod {tieSet.length} = {drawn}, so the winner is tied bidder {drawn}
                </p>
              )}
              <ol className='space-y-2'>
                {tieSet.map((position, place) => {
                  const address = bidders[position].address
                  return (
                    <li key={address} className='flex flex-wrap items-center gap-2 text-sm'>
                      <span className='mono muted'>{place}</span>
                      <AddressLink address={address} />
                      {sameAddress(address, account) && <span className='tag muted'>you</span>}
                      {position === winner && <span className='tag live'>winner</span>}
                    </li>
                  )
                })}
              </ol>
            </>
          ) : (
            <p className='text-sm text-ink-soft'>
              One bidder holds the top bid, so that bidder won and no random draw was needed.{' '}
              {auction.auctionType === AuctionType.RatioSecondPrice
                ? 'The winning bid stays secret: only the second-highest bid, the price, is public.'
                : 'The winning bid is the price.'}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

const SlotGrid: React.FC<{
  auction: AuctionState
  account: `0x${string}` | undefined
  bidders: LinkedBidder[]
  result: RegionResult
}> = ({ auction, account, bidders, result }) => {
  const { price, winner, set } = result
  const firstPrice = auction.auctionType === AuctionType.FirstPrice
  const columns = { gridTemplateColumns: `max-content repeat(${LEVELS}, minmax(0, 1fr))` }

  return (
    <div className='space-y-4'>
      <div className='space-y-1'>
        <h3 className='h3'>How the result is read</h3>
        <p className='text-sm text-ink-soft'>
          The committee published {LEVELS} slots per bidder, one per price level. Slots hold a random value unless the program zeroed them.{' '}
          {firstPrice
            ? 'Exactly one slot is zero: the winner’s, at the winning bid.'
            : 'Every bidder’s slots are random up to the price. At the price level exactly one is zero, the winner’s. Above it every slot is zero.'}
        </p>
      </div>

      <div className='overflow-x-auto pb-2'>
        <div className='slots' style={columns}>
          <span />
          {Array.from({ length: LEVELS }, (_, level) => (
            <span key={level} className='axis' title={`price ${formatPrice(level, auction.prices)}`}>
              {level}
            </span>
          ))}
          {set.map((row, position) => {
            const address = bidders[position].address
            const mine = sameAddress(address, account)
            return (
              <React.Fragment key={address}>
                <span className={`row-name ${position === winner ? 'font-semibold text-accent' : ''}`}>
                  <AddressLink address={address} />
                  {mine && <span className='tag muted'>you</span>}
                  {position === winner && <span className='tag live'>winner</span>}
                </span>
                {row.map((isSet, level) => {
                  const reading = !isSet && position === winner && level === price
                  return (
                    <span
                      key={level}
                      className={`cell ${isSet ? 'rand' : reading ? 'read' : 'zero'} ${level === price ? 'col-price' : ''}`}
                      title={`level ${level}: ${isSet ? 'random value' : 'zero'}`}
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
          <i style={{ background: 'var(--card)' }} /> Zero
        </span>
        <span>
          <i style={{ background: 'var(--accent)', borderColor: 'var(--accent)' }} /> The reading: the winner’s zero at the price
        </span>
        <span>
          <i style={{ boxShadow: '0 0 0 2px var(--warm)' }} /> Price level
        </span>
      </div>
      <p className='muted text-xs'>
        The tie priority of each bidder comes from the published ciphertexts. It matters only when the top bids tie. The last bidder can see
        the earlier ciphertexts and could re-encrypt to improve its priority, so a tie is not a fair draw.
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
