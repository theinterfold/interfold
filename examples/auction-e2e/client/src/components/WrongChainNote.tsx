// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { useSwitchChain } from 'wagmi'
import { chain } from '@/utils/chain'

/** A note for a wallet on another network, with a button that asks the wallet to switch. */
export const WrongChainNote: React.FC<{ children?: React.ReactNode }> = ({ children = 'Your wallet is on another network.' }) => {
  const { switchChain, isPending } = useSwitchChain()
  return (
    <div className='note bad flex flex-wrap items-center justify-between gap-3'>
      <span>{children}</span>
      <button type='button' onClick={() => switchChain({ chainId: chain.id })} disabled={isPending} className='btn sm'>
        Switch to {chain.name}
      </button>
    </div>
  )
}
