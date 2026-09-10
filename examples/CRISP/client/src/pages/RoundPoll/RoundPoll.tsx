// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { Fragment, useEffect, useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import DailyPollSection from '@/pages/Landing/components/DailyPoll'
import { useVoteManagementContext } from '@/context/voteManagement'
import { convertTimestampToDate } from '@/utils/methods'
import LoadingAnimation from '@/components/LoadingAnimation'

const RoundPoll: React.FC = () => {
  const { roundId } = useParams<{ roundId: string }>()
  const navigate = useNavigate()
  const { roundState, getRoundStateLite, isLoading, currentRoundId } = useVoteManagementContext()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const isValidRoundId = roundId !== undefined && /^\d+$/.test(roundId)

  // If this is the current round, redirect to /current
  useEffect(() => {
    if (isValidRoundId && currentRoundId !== null && roundId === currentRoundId) {
      navigate('/current', { replace: true })
    }
  }, [isValidRoundId, roundId, currentRoundId, navigate])

  // Load the specific round
  useEffect(() => {
    let cancelled = false
    const loadRound = async () => {
      if (isValidRoundId && roundId !== undefined) {
        setLoading(true)
        setError(null)
        try {
          await getRoundStateLite(roundId)
        } catch {
          if (!cancelled) setError('Could not load this round. Refresh the page to retry.')
        } finally {
          if (!cancelled) setLoading(false)
        }
      }
    }
    void loadRound()
    return () => {
      cancelled = true
    }
  }, [isValidRoundId, roundId, getRoundStateLite])

  const endTime = useMemo(() => (roundState ? convertTimestampToDate(roundState.end_time) : null), [roundState])

  const title = `Round #${roundId}`

  if (error) return <p role='alert'>{error}</p>

  if (loading || isLoading) {
    return (
      <div className='flex flex-1 items-center justify-center'>
        <LoadingAnimation isLoading />
      </div>
    )
  }

  return (
    <Fragment>
      <DailyPollSection loading={false} endTime={endTime} title={title} />
    </Fragment>
  )
}

export default RoundPoll
