// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import PollCard from '@/components/Cards/PollCard'
import { PollResult } from '@/model/poll.model'
import { useVoteManagementContext } from '@/context/voteManagement'
import { Link } from 'react-router-dom'
import { EditorialShell } from '@/design/Editorial'

type PastPollSectionProps = {
  customLabel?: string
  useFullHeight?: boolean
  limit?: number
}

const PastPollSection: React.FC<PastPollSectionProps> = ({ customLabel = 'Past polls', useFullHeight = true, limit }) => {
  const { pastPolls } = useVoteManagementContext()
  const pollsToShow = limit ? pastPolls.slice(0, limit) : pastPolls

  return (
    <EditorialShell className={`flex w-full flex-col ${useFullHeight ? 'min-h-screen' : ''}`}>
      <section className='pad-section col' style={{ gap: 28, alignItems: 'center', width: '100%' }}>
        <h2 className='h2'>{customLabel}</h2>
        <div className='row' style={{ flexWrap: 'wrap', justifyContent: 'center', gap: 24, width: '100%' }}>
          {pollsToShow.map((poll: PollResult) => (
            <PollCard key={poll.roundId} {...poll} />
          ))}
        </div>
        <Link to='/all' className='btn ghost'>
          View all polls →
        </Link>
      </section>
    </EditorialShell>
  )
}

export default PastPollSection
