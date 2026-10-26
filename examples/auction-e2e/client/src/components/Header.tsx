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
import { WalletIcon } from '@phosphor-icons/react'
import { InterfoldSymbol, Wordmark } from '@/components/Brand'

const navClass = ({ isActive }: { isActive: boolean }) => `site-header-link${isActive ? ' is-active' : ''}`

/** The strip under the header: the chain the app is configured for, and a prompt when the wallet is on another one. */
const NetworkStrip: React.FC = () => {
  const { wrongChain } = useWallet()
  const { switchChain, isPending } = useSwitchChain()

  return (
    <div className='faucet-strip'>
      <div className='site-header-grid faucet-strip-content'>
        <p>
          <span className='faucet-strip-network'>{chain.name} testnet</span>
          {wrongChain ? 'Your wallet is on another network.' : 'Demo on insecure parameters: do not bid anything that matters.'}
        </p>
        {wrongChain && (
          <button onClick={() => switchChain({ chainId: chain.id })} disabled={isPending} className='btn sm'>
            Switch to {chain.name}
          </button>
        )}
      </div>
    </div>
  )
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
          <WalletIcon size={16} aria-hidden />
          <span className='wallet-address'>{truncatedAddress}</span>
        </button>
      ) : (
        <button onClick={show} className='wallet'>
          <WalletIcon size={16} aria-hidden />
          <span className='max-sm:sr-only'>{isConnecting ? 'Connecting…' : 'Connect wallet'}</span>
        </button>
      )
    }
  </ConnectKitButton.Custom>
)

const Header: React.FC = () => {
  useSwitchToAppChain()
  return (
    <>
      <header className='site-header-chrome'>
        <div className='site-header-grid'>
          <Link to='/' className='site-header-brand' aria-label='Interfold Auctions: home'>
            <Wordmark />
            <span className='site-header-product'>Auctions</span>
          </Link>
          <Link to='/' aria-hidden tabIndex={-1} className='site-header-symbol'>
            <InterfoldSymbol />
          </Link>
          <div className='site-header-right'>
            <nav className='site-header-navigation' aria-label='Main'>
              <ul className='site-header-links'>
                <li>
                  <NavLink to='/' end className={navClass}>
                    Auctions
                  </NavLink>
                </li>
                <li>
                  <NavLink to='/create' className={navClass}>
                    Create
                  </NavLink>
                </li>
                <li>
                  <NavLink to='/about' className={navClass}>
                    How it works
                  </NavLink>
                </li>
              </ul>
            </nav>
            <div className='site-header-action'>
              <WalletButton />
            </div>
          </div>
        </div>
      </header>
      <NetworkStrip />
    </>
  )
}

export default Header
