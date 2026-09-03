// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { NavLink } from 'react-router-dom'
import { useHealth } from '@/hooks/useRounds'

const Navbar = () => {
  const health = useHealth()
  return (
    <nav className="nav">
      <NavLink to="/" className="brand">
        🔐 CKKS Salary Survey
      </NavLink>
      <div className="links">
        <NavLink to="/">How it works</NavLink>
        <NavLink to="/rounds">Rounds</NavLink>
        <span className={health.isSuccess ? 'dot ok' : 'dot bad'} title={health.isSuccess ? 'server up' : 'server unreachable'} />
      </div>
    </nav>
  )
}

export default Navbar
