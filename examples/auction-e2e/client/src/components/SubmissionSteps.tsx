// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useState } from 'react'
import { CheckCircleIcon, CircleIcon, WarningCircleIcon } from '@phosphor-icons/react'
import type { StepRow } from '@/hooks/useBid'
import Spinner from './Spinner'

function formatElapsed(ms: number): string {
  const seconds = Math.floor(ms / 1000)
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`
}

/** Elapsed time since `startedAt`, ticking each second while `running`. */
function useElapsed(startedAt: number | undefined, running: boolean): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!running) return
    setNow(Date.now())
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [running])
  return startedAt === undefined ? 0 : Math.max(now - startedAt, 0)
}

const StepIcon: React.FC<{ status: StepRow['status'] }> = ({ status }) =>
  status === 'done' ? (
    <CheckCircleIcon size={16} weight='fill' className='text-brand-green' />
  ) : status === 'active' ? (
    <Spinner size={14} />
  ) : status === 'error' ? (
    <WarningCircleIcon size={16} weight='fill' className='text-negative' />
  ) : (
    <CircleIcon size={16} />
  )

interface SubmissionStepsProps {
  title: string
  steps: StepRow[]
  /** Whether a submission is running now. */
  running: boolean
  /** Wall-clock ms at which the last submission started, and how long it took once it is over. */
  run: { startedAt: number; elapsedMs: number | null } | null
}

/** The steps of one submission (a bid or a mask) with their status and the time it takes. */
const SubmissionSteps: React.FC<SubmissionStepsProps> = ({ title, steps, running, run }) => {
  const elapsed = useElapsed(run?.startedAt, running)
  return (
    <div className='space-y-3'>
      <div className='flex items-center justify-between'>
        <p className='label !mb-0'>{title}</p>
        <p className='muted font-mono text-xs'>
          {run?.elapsedMs != null ? `done in ${formatElapsed(run.elapsedMs)}` : running ? formatElapsed(elapsed) : ''}
        </p>
      </div>
      <ol className='inset space-y-1.5 p-4 text-sm'>
        {steps.map((step) => (
          <li
            key={step.id}
            className={`flex items-center gap-2 ${step.status === 'active' ? 'font-semibold' : step.status === 'pending' ? 'text-muted' : 'text-ink'}`}
          >
            <StepIcon status={step.status} />
            {step.label}
          </li>
        ))}
      </ol>
    </div>
  )
}

export default SubmissionSteps
