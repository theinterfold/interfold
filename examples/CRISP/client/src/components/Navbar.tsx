// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { Link } from 'react-router-dom'
import NavMenu from '@/components/NavMenu'
import { ConnectKitButton } from 'connectkit'
import useToken from '@/hooks/generic/useMintToken'

const PAGES = [
  {
    label: 'Live Poll',
    path: '/current',
  },
  {
    label: 'About',
    path: '/about',
  },
  {
    label: 'All Polls',
    path: '/all',
  },
]

const Navbar: React.FC = () => {
  const { mintTokens, isMinting } = useToken()

  return (
    <div className='crisp-editorial' data-palette='interfold' data-mode='light' data-density='comfortable'>
      <header className='topbar'>
        <Link to={'/'} className='brand' style={{ cursor: 'pointer' }}>
          <span className='glyph' />
          <span style={{ fontWeight: 500 }}>Crisp</span>
        </Link>

        <nav className='topnav max-md:hidden'>
          {PAGES.map(({ label, path }) => (
            <Link key={label} to={path}>
              {label}
            </Link>
          ))}
        </nav>

        <div className='topbar-right'>
          <button disabled={isMinting} onClick={mintTokens} className='pill-mint max-md:hidden'>
            + Mint test tokens
          </button>
          <ConnectKitButton />
          <NavMenu />
        </div>
      </header>
    </div>
  )
}

export default Navbar
