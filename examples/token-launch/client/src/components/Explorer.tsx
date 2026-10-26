// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { addressExplorerUrl, txExplorerUrl } from '@/utils/chain'
import { shorten } from '@/utils/error-formatting'

interface AddressLinkProps {
  address: string
  /** Show the whole address instead of the shortened form. */
  full?: boolean
}

/** An address, linked to the block explorer where the chain has one. */
export const AddressLink: React.FC<AddressLinkProps> = ({ address, full }) => {
  const url = addressExplorerUrl(address)
  const text = full ? address : shorten(address, 8, 6)
  return url ? (
    <a href={url} target='_blank' rel='noreferrer' title={address} className='addr break-all'>
      {text}
    </a>
  ) : (
    <span title={address} className='addr break-all'>
      {text}
    </span>
  )
}

/** A transaction hash, linked to the block explorer where the chain has one. */
export const TxLink: React.FC<{ hash: string }> = ({ hash }) => {
  const url = txExplorerUrl(hash)
  const text = shorten(hash, 10, 8)
  return url ? (
    <a href={url} target='_blank' rel='noreferrer' title={hash} className='addr'>
      {text}
    </a>
  ) : (
    <span title={hash} className='addr'>
      {text}
    </span>
  )
}
