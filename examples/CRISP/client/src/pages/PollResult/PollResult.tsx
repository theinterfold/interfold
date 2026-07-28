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
      const fetched = await getWebResultByRound(parseInt(roundId))
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

            {type === 'confirmation' && txUrl && <ConfirmVote confirmationUrl={txUrl} />}
            {type !== 'confirmation' && (
              <CardContent>
                <div className='col' style={{ gap: 10 }}>
                  <p className='mono muted'>WHAT JUST HAPPENED?</p>
                  <p className='lede' style={{ maxWidth: 'none' }}>
                    After casting your vote, CRISP securely processed your selection using a blend of Fully Homomorphic Encryption (FHE),
                    threshold cryptography, and zero-knowledge proofs (ZKPs), without revealing your identity or choice. Your vote was
                    encrypted and anonymously aggregated with others, ensuring the integrity of the voting process while strictly
                    maintaining confidentiality. The protocol's advanced cryptographic techniques guarantee that your vote contributes to
                    the final outcome without any risk of privacy breaches or undue influence.
                  </p>
                </div>
                <div className='col' style={{ gap: 10 }}>
                  <p className='mono muted'>WHAT DOES THIS MEAN?</p>
                  <p className='lede' style={{ maxWidth: 'none' }}>
                    Your participation has directly contributed to a transparent and fair decision-making process, showcasing the power of
                    privacy-preserving technology in governance and beyond. The use of CRISP in this vote represents a significant step
                    towards secure, anonymous, and tamper-proof digital elections and polls. This innovation ensures that every vote counts
                    equally while safeguarding against the risks of fraud and coercion, enhancing the reliability and trustworthiness of
                    digital decision-making platforms.
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
