// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useState } from 'react'
import { usePublicClient } from 'wagmi'
import { subscribeEstimatedChainTime } from '@/utils/estimated-chain-clock'

interface CountdownTimerProps {
  endTime: Date
}

type RemainingTime = {
  days: string
  hours: string
  minutes: string
  seconds: string
}

const CountdownTimer: React.FC<CountdownTimerProps> = ({ endTime }) => {
  const client = usePublicClient()
  const [remainingTime, setRemainingTime] = useState<RemainingTime | null>(null)
  const endTimeMs = endTime.getTime()

  useEffect(
    () =>
      subscribeEstimatedChainTime(client, (estimatedNowMs) => {
        const difference = Math.max(0, endTimeMs - estimatedNowMs)
        setRemainingTime({
          days: Math.floor(difference / 86_400_000).toString(),
          hours: Math.floor((difference / 3_600_000) % 24).toString(),
          minutes: Math.floor((difference / 60_000) % 60).toString(),
          seconds: Math.floor((difference / 1_000) % 60).toString(),
        })
      }),
    [endTimeMs, client],
  )

  return (
    <div className='flex flex-col items-center justify-center space-y-2'>
      <p className='text-base font-bold uppercase text-slate-600/50' title='Estimated time. The chain determines when voting ends.'>
        Poll ends in:
      </p>

      {remainingTime && (
        <div className='flex space-x-6'>
          <p className='text-2xl font-bold text-slate-600'>
            {remainingTime.days}
            <span className=' text-slate-600/50'>d</span>
          </p>
          <p className='text-2xl font-bold text-slate-600'>
            {remainingTime.hours}
            <span className=' text-slate-600/50'>h</span>
          </p>
          <p className='text-2xl font-bold text-slate-600'>
            {remainingTime.minutes}
            <span className=' text-slate-600/50'>m</span>
          </p>
          <p className='text-2xl font-bold text-slate-600'>
            {remainingTime.seconds}
            <span className=' text-slate-600/50'>s</span>
          </p>
        </div>
      )}
    </div>
  )
}

export default CountdownTimer
