// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useCallback, useEffect, useMemo, useState } from 'react'
import PollCard from '@/components/Cards/PollCard'
import { PollResult } from '@/model/poll.model'
import LoadingAnimation from '@/components/LoadingAnimation'
import { useVoteManagementContext } from '@/context/voteManagement'
import { EditorialShell } from '@/design/Editorial'
import { debounce } from '@/utils/methods'

const AllPolls: React.FC = () => {
  const { votingRound, pastPolls, getPastPolls, isLoading } = useVoteManagementContext()
  const [visiblePolls, setVisiblePolls] = useState<PollResult[]>([])
  const [page, setPage] = useState<number>(0)
  const [loadingMore, setLoadingMore] = useState<boolean>(false)

  const loadMorePolls = useCallback(() => {
    if (loadingMore || isLoading) return
    setLoadingMore(true)
    setTimeout(() => {
      setPage((prevPage) => prevPage + 1)
      window.scrollTo({
        top: document.documentElement.scrollTop - 150,
        behavior: 'smooth',
      })
      setLoadingMore(false)
    }, 1000)
  }, [loadingMore, isLoading])

  useEffect(() => {
    if (votingRound && votingRound?.pk_bytes) {
      const fetchPastPolls = async () => {
        await getPastPolls()
      }
      fetchPastPolls()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [votingRound])

  useEffect(() => {
    setVisiblePolls(pastPolls.slice(0, 12))
  }, [pastPolls])

  useEffect(() => {
    const newVisiblePolls = pastPolls.slice(0, (page + 1) * 12)
    setVisiblePolls(newVisiblePolls)
  }, [page, pastPolls])

  const handleScroll = useMemo(
    () =>
      debounce(() => {
        const { scrollTop, clientHeight, scrollHeight } = document.documentElement
        if (scrollTop + clientHeight >= scrollHeight && !loadingMore && pastPolls.length > visiblePolls.length) {
          loadMorePolls()
        }
      }, 200),
    [loadMorePolls, loadingMore, pastPolls.length, visiblePolls.length],
  )

  useEffect(() => {
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [handleScroll])

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
        {!pastPolls.length && !isLoading && <p className='lede'>There are no polls yet.</p>}
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
        {loadingMore && (
          <div className='flex w-full items-center justify-center'>
            <LoadingAnimation isLoading={loadingMore} />
          </div>
        )}
      </section>
    </EditorialShell>
  )
}

export default AllPolls
