// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { AuctionType, DEGREE, MAX_PROVIDERS, PLAINTEXT_MODULUS } from '@interfold/auction-core'
import { AtAGlance, BidRows, BidderLimit, EXPLAINER_HEADINGS, FailureScope, Mono, Part, Prose } from './ExplainerParts'
import { SecondPriceExample, SecondPriceNonZeroProduct, SecondPriceReading, SecondPriceTests, SecondPriceWhyHide } from './SecondPriceParts'

/** How the "Second-price, mask providers" type works, in plain words, with a worked example of 3 bidders. */
const ProviderAuctionExplainer: React.FC = () => (
  <div className='space-y-6'>
    <AtAGlance type={AuctionType.ProviderSecondPrice}>
      The highest bid wins and pays the second-highest bid. Mask providers hide the losing bids. Each provider sends one random mask before
      bidding opens.
    </AtAGlance>

    <Part title={EXPLAINER_HEADINGS.sends}>
      <Prose>
        The creator names 1 to {MAX_PROVIDERS} <strong>mask providers</strong>. Before bidding opens, each provider sends{' '}
        <strong>one mask</strong>. The mask is a ciphertext that holds {DEGREE} random numbers, each between 1 and {PLAINTEXT_MODULUS - 1}.
        A zero-knowledge proof shows that no number in the mask is zero.
      </Prose>
      <Prose>
        After that, each bidder sends <strong>two ciphertexts</strong> and no mask. <BidRows /> <BidderLimit />
      </Prose>
    </Part>

    <Part title={EXPLAINER_HEADINGS.computes}>
      <SecondPriceTests />
      <Prose>
        <SecondPriceWhyHide /> So the program multiplies each slot of <Mono>tests</Mono> by a secret number <Mono>r</Mono>. The output is{' '}
        <Mono>tests × r</Mono>, where <Mono>r = M₁ × M₂ × … × M_k</Mono>. <Mono>M₁</Mono> to <Mono>M_k</Mono> are the masks of the{' '}
        <Mono>k</Mono> providers. A zero stays zero. Any other number becomes a number that looks random, between 1 and{' '}
        {PLAINTEXT_MODULUS - 1}.
      </Prose>
    </Part>

    <SecondPriceExample
      outputLabel='Output after the masks'
      unknownText={
        <>
          Each <Mono>?</Mono> is a random number between 1 and {PLAINTEXT_MODULUS - 1}. Nobody can tell that bidder 0 was close and bidder 2
          was far.
        </>
      }
    />

    <SecondPriceReading />

    <Part title={EXPLAINER_HEADINGS.cannotFail}>
      <Prose>
        <SecondPriceNonZeroProduct /> The proof of each mask shows that none of its numbers is zero. So a number of <Mono>tests</Mono> that
        is not zero can never become a zero in the output. The result is always readable.
      </Prose>
      <FailureScope />
    </Part>

    <Part title={EXPLAINER_HEADINGS.leaks}>
      <Prose>
        If at least one provider chose its mask at random and kept it secret, the committee decrypts a pattern of zeros and random numbers.
        The pattern shows only the winner and the price. If every provider shares its mask with the others, they can divide the output by{' '}
        <Mono>r</Mono> and read the numbers of <Mono>tests</Mono>. These numbers show more than the winner and the price. For example, they
        show how many bidders reach each step.
      </Prose>
    </Part>

    <Part title={EXPLAINER_HEADINGS.trust}>
      <Prose>
        Privacy needs one honest provider: one that draws its mask at random and keeps it secret. The auction also needs every provider.
        Bidding stays closed until all <Mono>k</Mono> masks are on chain. The auction cannot run if one provider never sends its mask. The
        creator names the providers. The creator can add the server of this app, itself, or other parties.
      </Prose>
    </Part>
  </div>
)

export default ProviderAuctionExplainer
