// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { ConnectKitButton } from 'connectkit'
import { useAccount, useSwitchChain, useConfig } from 'wagmi'
import { CaretDownIcon } from '@phosphor-icons/react'

const NetworkSwitchButton: React.FC = () => {
  const { isConnected, chain } = useAccount()
  const config = useConfig()
  const { switchChain, isPending } = useSwitchChain()

  // Only show if connected and there are multiple chains
  if (!isConnected || config.chains.length <= 1) {
    return null
  }

  const handleNetworkSwitch = (chainId: number) => {
    if (chainId !== chain?.id) {
      switchChain({ chainId })
    }
  }

  return (
    <div className='relative'>
      <select
        value={chain?.id || ''}
        onChange={(e) => handleNetworkSwitch(Number(e.target.value))}
        disabled={isPending}
        className='appearance-none rounded-lg bg-white px-3 py-2 pr-8 text-sm font-medium text-gray-900 hover:bg-gray-50 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50'
      >
        {config.chains.map((supportedChain) => (
          <option key={supportedChain.id} value={supportedChain.id}>
            {supportedChain.name}
          </option>
        ))}
      </select>
      <CaretDownIcon className='pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 transform text-slate-500' />
    </div>
  )
}

const Navbar: React.FC = () => {
  return (
    <nav className='w-full border-b border-slate-200 bg-white/80 px-6 backdrop-blur-sm lg:px-9'>
      <div className='mx-auto max-w-screen-xl'>
        <div className='flex h-20 items-center justify-between'>
          <h1 className='text-2xl font-bold text-slate-800'>Interfold E3</h1>
          <div className='flex items-center gap-3'>
            <NetworkSwitchButton />
            <ConnectKitButton />
          </div>
        </div>
      </div>
    </nav>
  )
}

export default Navbar
