// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { Fragment, useEffect, useMemo } from 'react'
import CardContent from '@/components/Cards/CardContent'
import VotesBadge from '@/components/VotesBadge'
import PollCardResult from '@/components/Cards/PollCardResult'
import { convertPollData, convertVoteStateLite, formatDate, markWinner } from '@/utils/methods'
import PastPollSection from '@/pages/Landing/components/PastPoll'
import { useParams } from 'react-router-dom'
import LoadingAnimation from '@/components/LoadingAnimation'
import { useVoteManagementContext } from '@/context/voteManagement'
import { EditorialShell } from '@/design/Editorial'
import CountdownTimer from '@/components/CountdownTime'
import ConfirmVote from '../DailyPoll/components/ConfirmVote'

const PollResult: React.FC = () => {
  const params = useParams()
  const { roundId, type } = params
  const { pastPolls, getWebResultByRound, pollResult, setPollResult } = useVoteManagementContext()
  const { roundEndDate, txUrl, roundState } = useVoteManagementContext()

  const activeTotalCount = type === 'confirmation' ? roundState?.vote_count : pollResult?.totalVotes

  // Right after voting the tally is not published yet, so the live round state
  // is rendered instead of the fetched result.
  const confirmationPoll = useMemo(() => {
    if (type !== 'confirmation' || !roundState || !activeTotalCount) return null
    return convertVoteStateLite(roundState)
  }, [type, roundState, activeTotalCount])

  const displayedPoll = confirmationPoll ?? pollResult
  const loading = !displayedPoll

  useEffect(() => {
    if (pollResult || confirmationPoll || !roundId) return

    const fetchPoll = async () => {
      const fetched = await getWebResultByRound(roundId)
      if (fetched) {
        setPollResult(convertPollData([fetched])[0])
      }
    }
    fetchPoll()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pastPolls, roundId, confirmationPoll, pollResult])

  return (
    <EditorialShell className='flex w-full flex-1 flex-col'>
      <section className='pad-section col' style={{ flex: 1, alignItems: 'center', gap: 36 }}>
        {loading && (
          <div className='flex items-center justify-center'>
            <LoadingAnimation isLoading={loading} />
          </div>
        )}
        {displayedPoll && (
          <Fragment>
            <div className='col' style={{ alignItems: 'center', gap: 24, width: '100%' }}>
              <div className='col' style={{ alignItems: 'center', gap: 8, textAlign: 'center' }}>
                <p className='mono muted'>Poll {displayedPoll.roundId}</p>
                <h1 className='h1'>{type === 'confirmation' ? 'Thanks for voting!' : 'Poll Results'}</h1>
                {type !== 'confirmation' && <p className='cap'>{formatDate(displayedPoll.date)}</p>}
              </div>
              {type === 'confirmation' && roundEndDate && (
                <div className='col' style={{ alignItems: 'center', gap: 6 }}>
                  <div className='cap'>Closes in</div>
                  <CountdownTimer endTime={roundEndDate} />
                </div>
              )}
              <VotesBadge totalVotes={activeTotalCount ?? 0} />
              <PollCardResult
                results={markWinner(displayedPoll.options)}
                totalVotes={displayedPoll.totalVotes}
                isResult
                isActive={type === 'confirmation' ? true : false}
              />
            </div>

            {type === 'confirmation' && <ConfirmVote confirmationUrl={txUrl} />}
            {type !== 'confirmation' && (
              <CardContent>
                <div className='col' style={{ gap: 10 }}>
                  <p className='mono muted'>HOW WAS THIS RESULT MADE?</p>
                  <p className='lede' style={{ maxWidth: 'none' }}>
                    Each voter's browser encrypted their ballot, and a zero-knowledge proof (ZKP) showed that the ballot was valid. The
                    committee tallied the ballots with Fully Homomorphic Encryption (FHE). It used threshold cryptography to decrypt only
                    the combined result, and no single committee member can decrypt a ballot. The result above is public. In a small or
                    one-sided poll, it can show how individual participants voted.
                  </p>
                </div>
                <div className='col' style={{ gap: 10 }}>
                  <p className='mono muted'>WHAT ARE THE LIMITS?</p>
                  <p className='lede' style={{ maxWidth: 'none' }}>
                    Privacy depends on the committee threshold: enough committee members who collude can decrypt ballots. The CRISP server
                    receives every ballot, and a transaction that a voter's wallet sends also shows the voter's address on-chain. Masks make
                    a vote, an update, and a mask look the same on-chain, which makes a receipt of a vote less reliable when these
                    conditions hold.
                  </p>
                </div>
              </CardContent>
            )}
            {pastPolls.length > 0 && <PastPollSection customLabel='Past polls' useFullHeight={false} limit={3} />}
          </Fragment>
        )}
      </section>
    </EditorialShell>
  )
}

export default PollResult
