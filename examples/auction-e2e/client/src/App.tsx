// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import Footer from '@/components/Footer'
import Header from '@/components/Header'
import About from '@/pages/About'
import AuctionPage from '@/pages/AuctionPage'
import CreateAuction from '@/pages/CreateAuction'
import Home from '@/pages/Home'

/** A route change starts at the top of the page, as a link to a new page does. */
const ScrollToTop: React.FC = () => {
  const { pathname } = useLocation()
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [pathname])
  return null
}

const App: React.FC = () => (
  <>
    <ScrollToTop />
    <Header />
    <main className='flex flex-1 flex-col'>
      <Routes>
        <Route path='/' element={<Home />} />
        <Route path='/create' element={<CreateAuction />} />
        <Route path='/about' element={<About />} />
        <Route path='/auction/:e3Id' element={<AuctionPage />} />
        <Route path='*' element={<Navigate to='/' replace />} />
      </Routes>
    </main>
    <Footer />
  </>
)

export default App
