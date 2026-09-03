// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { NavLink } from 'react-router-dom'

import { WalletButton } from './WalletButton'

export const Navbar = () => (
  <nav>
    <NavLink to="/" end>CKKS Auction</NavLink>
    <NavLink to="/rounds">Rounds</NavLink>
    <span className="spacer" />
    <WalletButton />
  </nav>
)
