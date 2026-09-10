// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useEffect, useMemo } from 'react'
import PollCard from '@/components/Cards/PollCard'
import { PollResult } from '@/model/poll.model'
import LoadingAnimation from '@/components/LoadingAnimation'
import { useVoteManagementContext } from '@/context/voteManagement'
import { EditorialShell } from '@/design/Editorial'
import { convertPollData } from '@/utils/methods'
import { useInterfoldServer } from '@/hooks/interfold/useInterfoldServer'
import { useArchivePolls } from '@/hooks/voting/useArchivePolls'

const AllPolls: React.FC = () => {
  const { setPastPolls } = useVoteManagementContext()
  const { getArchivePage } = useInterfoldServer()
  const { items, hasMore, isLoading, error, loadMore } = useArchivePolls(getArchivePage)
  const visiblePolls = useMemo(() => convertPollData(items), [items])

  useEffect(() => {
    setPastPolls(visiblePolls)
  }, [visiblePolls, setPastPolls])

  useEffect(() => {
    const handleScroll = () => {
      const { scrollTop, clientHeight, scrollHeight } = document.documentElement
      if (scrollTop + clientHeight >= scrollHeight - 100 && hasMore && !isLoading && !error) void loadMore()
    }
    window.addEventListener('scroll', handleScroll, { passive: true })
    return () => window.removeEventListener('scroll', handleScroll)
  }, [hasMore, isLoading, error, loadMore])

  return (
    <EditorialShell className='flex w-full flex-1 flex-col'>
      <section className='pad-section col' style={{ flex: 1, gap: 28 }}>
        <div className='col' style={{ gap: 12 }}>
          <div className='mono muted'>Archive</div>
          <h1 className='h1'>All polls</h1>
        </div>
        {isLoading && (
          <div className='flex justify-center'>
            <LoadingAnimation isLoading={isLoading} />
          </div>
        )}
        {!visiblePolls.length && !isLoading && !error && !hasMore && <p className='lede'>There are no polls yet.</p>}
        {visiblePolls.length > 0 && (
          <div className='grid w-full grid-cols-1 gap-8 sm:grid-cols-2 md:grid-cols-3'>
            {visiblePolls.map((pollResult: PollResult, index: number) => {
              return (
                <div
                  data-test-id={`poll-${pollResult.roundId}-${index}`}
                  className='flex items-start justify-center'
                  key={`${pollResult.roundId}-${index}`}
                >
                  <PollCard {...pollResult} />
                </div>
              )
            })}
          </div>
        )}
        {error && <p role='alert'>{error}</p>}
        {hasMore && !isLoading && (
          <button type='button' className='mono' onClick={() => void loadMore()}>
            {error ? 'Try again' : 'Load more polls'}
          </button>
        )}
      </section>
    </EditorialShell>
  )
}

export default AllPolls
