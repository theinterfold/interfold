// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Route, Routes } from 'react-router-dom'

import { Navbar } from './components/Navbar'
import { Home } from './pages/Home'
import { Rounds } from './pages/Rounds'
import { Round } from './pages/Round'
import { Probe } from './pages/Probe'

export default function App() {
  return (
    <div className="app">
      <Navbar />
      <main>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/rounds" element={<Rounds />} />
          <Route path="/rounds/:id" element={<Round />} />
          <Route path="/probe" element={<Probe />} />
        </Routes>
      </main>
      <footer>CKKS sealed-bid auction on Interfold · bids are encrypted and proven in this browser; only ±1 comparison signs are ever decrypted.</footer>
    </div>
  )
}
