// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Link, NavLink } from 'react-router-dom'
import { useHealth } from '@/hooks/useRounds'

export const APP_NAME = 'Salary'
export const APP_KICKER = 'Private salary survey · threshold CKKS'

const PAGES = [
  { label: 'Rounds', path: '/rounds' },
  { label: 'How it works', path: '/' },
]

const Navbar = () => {
  const health = useHealth()
  const up = health.isSuccess
  return (
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
        <span className="row" style={{ gap: 8 }} title={up ? 'server up' : 'server unreachable'}>
          <span className={`health-dot ${up ? 'ok' : 'bad'}`} />
          <span className="mono-sm muted">{up ? 'server up' : 'server unreachable'}</span>
        </span>
      </div>
    </header>
  )
}

export default Navbar
