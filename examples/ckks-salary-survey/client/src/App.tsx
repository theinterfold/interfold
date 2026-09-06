// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Routes, Route, Navigate } from 'react-router-dom'
import { EditorialShell } from '@interfold/ckks-editorial'
import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'
import Home from '@/pages/Home/Home'
import Rounds from '@/pages/Rounds/Rounds'
import RoundPage from '@/pages/Round/Round'

/** Palette per app (see @interfold/ckks-editorial README): salary = moss. */
export const PALETTE = 'moss'

const App = () => (
  <EditorialShell palette={PALETTE} className="app-shell">
    <Navbar />
    <main className="app-main">
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/rounds" element={<Rounds />} />
        <Route path="/rounds/:e3Id" element={<RoundPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </main>
    <Footer />
  </EditorialShell>
)

export default App
