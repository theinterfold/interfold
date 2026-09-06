// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Link, NavLink } from 'react-router-dom'

import { WalletButton } from './WalletButton'

export const APP_NAME = 'Treasury'
export const APP_KICKER = 'Private treasury risk · threshold CKKS'

const PAGES = [
  { label: 'Rounds', path: '/rounds' },
  { label: 'How it works', path: '/' },
]

export const Navbar = () => (
  <header className="topbar">
    <Link to="/" className="brand" style={{ cursor: 'pointer' }}>
      <span className="glyph" />
      <span style={{ fontWeight: 500 }}>{APP_NAME}</span>
      <span className="brand-mono" style={{ marginLeft: 10 }}>
        {APP_KICKER}
      </span>
    </Link>
    <nav className="topnav">
      {PAGES.map(({ label, path }) => (
        <NavLink key={label} to={path} end={path === '/'} className={({ isActive }) => (isActive ? 'active' : '')}>
          {label}
        </NavLink>
      ))}
    </nav>
    <div className="topbar-right">
      <WalletButton />
    </div>
  </header>
)
