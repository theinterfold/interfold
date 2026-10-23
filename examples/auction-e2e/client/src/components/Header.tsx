// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useRef } from 'react'
import { Link, NavLink } from 'react-router-dom'
import { useSwitchChain } from 'wagmi'
import { ConnectKitButton } from 'connectkit'
import { useWallet } from '@/hooks/useWallet'
import { chain } from '@/utils/chain'

const navClass = ({ isActive }: { isActive: boolean }) => (isActive ? 'active' : '')

/** The chain the app is configured for, and a prompt when the wallet is on another one. */
const NetworkBadge: React.FC = () => {
  const { wrongChain } = useWallet()
  const { switchChain, isPending } = useSwitchChain()

  if (wrongChain) {
    return (
      <button onClick={() => switchChain({ chainId: chain.id })} disabled={isPending} className='tag bad cursor-pointer'>
        Wrong network: switch to {chain.name}
      </button>
    )
  }
  return <span className='tag dot muted !border-ink !text-ink'>{chain.name}</span>
}

/** Asks the wallet to move to the app's chain once per connection. */
function useSwitchToAppChain() {
  const { address, wrongChain } = useWallet()
  const { switchChain } = useSwitchChain()
  const asked = useRef<string | null>(null)

  useEffect(() => {
    if (!address || !wrongChain || asked.current === address) return
    asked.current = address
    switchChain({ chainId: chain.id })
  }, [address, wrongChain, switchChain])
}

const WalletButton: React.FC = () => (
  <ConnectKitButton.Custom>
    {({ isConnected, isConnecting, show, truncatedAddress }) =>
      isConnected ? (
        <button onClick={show} className='wallet'>
          <span className='blockie' />
          {truncatedAddress}
        </button>
      ) : (
        <button onClick={show} className='btn sm'>
          {isConnecting ? 'Connecting…' : 'Connect wallet'}
        </button>
      )
    }
  </ConnectKitButton.Custom>
)

const Header: React.FC = () => {
  useSwitchToAppChain()
  return (
    <header className='topbar'>
      <Link to='/' className='brand'>
        <span className='glyph' />
        Sealed-Bid Auctions
      </Link>
      <nav className='topnav'>
        <NavLink to='/' end className={navClass}>
          Auctions
        </NavLink>
        <NavLink to='/create' className={navClass}>
          Create
        </NavLink>
        <NavLink to='/about' className={navClass}>
          How it works
        </NavLink>
      </nav>
      <div className='topbar-right'>
        <NetworkBadge />
        <WalletButton />
      </div>
    </header>
  )
}

export default Header
