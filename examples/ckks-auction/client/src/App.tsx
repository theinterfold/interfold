// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Route, Routes } from 'react-router-dom'
import { EditorialShell } from '@interfold/ckks-editorial'

import { Navbar } from './components/Navbar'
import { Footer } from './components/Footer'
import { Home } from './pages/Home'
import { Rounds } from './pages/Rounds'
import { Round } from './pages/Round'
import { Probe } from './pages/Probe'

/** Palette per app (see @interfold/ckks-editorial README): auction = ink. */
export const PALETTE = 'ink'

export default function App() {
  return (
    <EditorialShell palette={PALETTE} className="app-shell">
      <Navbar />
      <main className="app-main">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/rounds" element={<Rounds />} />
          <Route path="/rounds/:id" element={<Round />} />
          <Route path="/probe" element={<Probe />} />
        </Routes>
      </main>
      <Footer />
    </EditorialShell>
  )
}
