// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { AuctionType, DEGREE, PLAINTEXT_MODULUS } from '@interfold/auction-core'
import { AtAGlance, BidRows, BidderLimit, EXPLAINER_HEADINGS, FailureScope, Mono, Part, Prose } from './ExplainerParts'
import { SecondPriceExample, SecondPriceNonZeroProduct, SecondPriceReading, SecondPriceTests, SecondPriceWhyHide } from './SecondPriceParts'

/** How the "Second-price, no providers" type works, in plain words, with a worked example of 3 bidders. */
const QnrAuctionExplainer: React.FC = () => {
  // About half of the numbers modulo the plaintext modulus are squares, so S² − 3 takes about half of the values.
  const reachable = (PLAINTEXT_MODULUS + 1) / 2
  return (
    <div className='space-y-6'>
      <AtAGlance type={AuctionType.QnrSecondPrice}>
        The highest bid wins and pays the second-highest bid. The bidders hide the losing bids with random shares. No mask provider and no
        trusted party is needed.
      </AtAGlance>

      <Part title={EXPLAINER_HEADINGS.sends}>
        <Prose>
          There are no mask providers and no other party: only bidders. Each bidder sends <strong>four ciphertexts</strong>. Two of them
          hold the bid. <BidRows />
        </Prose>
        <Prose>
          The other two are <strong>shares</strong>, <Mono>s₁</Mono> and <Mono>s₂</Mono>. Each share holds {DEGREE} random numbers between 0
          and {PLAINTEXT_MODULUS - 1}. The browser of the bidder draws them. <BidderLimit />
        </Prose>
      </Part>

      <Part title={EXPLAINER_HEADINGS.computes}>
        <SecondPriceTests />
        <Prose>
          <SecondPriceWhyHide /> So the program multiplies each slot of <Mono>tests</Mono> by a number <Mono>r</Mono> that nobody knows. It
          adds the first shares of all bidders to get <Mono>S₁</Mono>, and the second shares to get <Mono>S₂</Mono>. Then it computes{' '}
          <Mono>r = (S₁² − 3) × (S₂² − 3)</Mono>, in each slot. The output is <Mono>tests × r</Mono>. A zero stays zero. Any other number
          becomes a number that looks random. If at least one bidder drew its shares at random and kept them secret, <Mono>S₁</Mono> and{' '}
          <Mono>S₂</Mono> are random for everyone else. This holds even if all the other bidders agree on their shares.
        </Prose>
      </Part>

      <SecondPriceExample
        outputLabel='Output after the shares'
        unknownText={
          <>
            Each <Mono>?</Mono> is a number that is not zero. It hides the number of <Mono>tests</Mono>. Nobody can tell with certainty that
            bidder 0 was close and bidder 2 was far.
          </>
        }
      />

      <SecondPriceReading />

      <Part title={EXPLAINER_HEADINGS.cannotFail}>
        <Prose>
          The number 3 is not a square modulo {PLAINTEXT_MODULUS}. No whole number multiplied by itself leaves the remainder 3 after
          division by {PLAINTEXT_MODULUS}. So <Mono>S² − 3</Mono> is never zero, whatever <Mono>S</Mono> is. So <Mono>r</Mono> is never
          zero, whatever the bidders send.
        </Prose>
        <Prose>
          <SecondPriceNonZeroProduct /> A number of <Mono>tests</Mono> that is not zero can therefore never become a zero in the output. The
          result is always readable. A bidder who sends bad shares on purpose cannot break this, because any shares give the same winner and
          price.
        </Prose>
        <FailureScope />
      </Part>

      <Part title={EXPLAINER_HEADINGS.leaks}>
        <Prose>
          This type needs no trusted party, but <Mono>r</Mono> is not exactly uniform. <Mono>S² − 3</Mono> takes only {reachable} of the{' '}
          {PLAINTEXT_MODULUS} possible values, because a square is one of about half of the numbers. So some numbers appear in the output
          more often than others. The numbers that are not zero therefore leak a <strong>small statistical hint</strong> about the numbers
          of <Mono>tests</Mono>, and so about the losing bids. For example, the hint relates to how many bidders reach a step.
        </Prose>
        <Prose>
          The zero pattern still shows only the winner and the price. The hint is small for one slot, but an output holds many slots. The
          demo uses small, insecure parameters, with the modulus {PLAINTEXT_MODULUS}. There the hint is larger than on secure parameters.
          Choose the type with providers if the losing bids must stay completely hidden and you accept a trusted party.
        </Prose>
      </Part>

      <Part title={EXPLAINER_HEADINGS.trust}>
        <Prose>
          Privacy needs one bidder who draws its shares at random and keeps them secret. The browser of each bidder does this by default.
          The creator, the server and the committee do not choose or see the shares. No party can stop the auction, apart from the usual
          rules: at least 2 bidders, and the committee that decrypts the output.
        </Prose>
      </Part>
    </div>
  )
}

export default QnrAuctionExplainer
