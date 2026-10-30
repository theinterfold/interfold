// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { AuctionType } from '@interfold/auction-core'
import { designOf } from '@/utils/designs'
import FirstPriceAuctionExplainer from './FirstPriceAuctionExplainer'
import ProviderAuctionExplainer from './ProviderAuctionExplainer'
import QnrAuctionExplainer from './QnrAuctionExplainer'

const EXPLAINERS: Record<AuctionType, React.FC> = {
  [AuctionType.FirstPrice]: FirstPriceAuctionExplainer,
  [AuctionType.ProviderSecondPrice]: ProviderAuctionExplainer,
  [AuctionType.QnrSecondPrice]: QnrAuctionExplainer,
}

/** The title of the explainer of `type`, from the label of its design. */
export const explainerTitle = (type: AuctionType): string => `${designOf(type).label}: how it works`

/** The explainer of the design of `type`. All three share the same headings, terms and legend. */
const AuctionExplainer: React.FC<{ type: AuctionType }> = ({ type }) => {
  const Explainer = EXPLAINERS[type]
  return <Explainer />
}

export default AuctionExplainer
