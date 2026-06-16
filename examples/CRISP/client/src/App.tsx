// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { Fragment, useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'
import { useSwitchChain } from 'wagmi'
//Pages
import Landing from '@/pages/Landing/Landing'
import DailyPoll from '@/pages/DailyPoll/DailyPoll'
import AllPolls from '@/pages/AllPolls/AllPolls'
import About from '@/pages/About/About'
import PollResult from '@/pages/PollResult/PollResult'
import RoundPoll from '@/pages/RoundPoll'
import useScrollToTop from '@/hooks/generic/useScrollToTop'
import { useVoteManagementContext } from '@/context/voteManagement'
import { useNotificationAlertContext } from '@/context/NotificationAlert'
import { handleGenericError } from '@/utils/handle-generic-error'
import { getChain } from './utils/methods'

const App: React.FC = () => {
  useScrollToTop()
  const { initialLoad } = useVoteManagementContext()
  const { switchChain } = useSwitchChain()
  const { showToast } = useNotificationAlertContext()

  useEffect(() => {
    ;(async () => {
      try {
        await initialLoad()

        const chain = getChain()
        switchChain({ chainId: chain.id })
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error)
        handleGenericError('App initial load', error instanceof Error ? error : new Error(errorMessage))
        showToast({
          type: 'danger',
          message: 'Failed to initialize application. Please refresh the page.',
          persistent: true,
        })
      }
    })()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <Fragment>
      <div className='flex min-h-screen flex-col'>
        <Navbar />
        <div className='flex flex-1 flex-col'>
          <Routes>
            <Route path='/' element={<Landing />} />
            <Route path='/about' element={<About />} />
            <Route path='/current' element={<DailyPoll />} />
            <Route path='/round/:roundId' element={<RoundPoll />} />
            <Route path='/all' element={<AllPolls />} />
            <Route path='/historic' element={<Navigate to='/all' replace />} />
            <Route path='/result/:roundId/:type?' element={<PollResult />} />
            <Route path='*' element={<Navigate to='/' replace />} />
          </Routes>
        </div>
        <Footer />
      </div>
    </Fragment>
  )
}

export default App
