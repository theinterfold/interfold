// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Poll } from '@/model/poll.model'

import { useVoteManagementContext } from '@/context/voteManagement'
import LoadingAnimation from '@/components/LoadingAnimation'
import CountdownTimer from '@/components/CountdownTime'
import { useModal } from 'connectkit'
import { useVoteCasting } from '@/hooks/voting/useVoteCasting'
import VotingStepIndicator from '@/components/VotingStepIndicator'
import { usePublicClient } from 'wagmi'
import { EditorialShell, Cipher } from '@/design/Editorial'

type DailyPollSectionProps = {
  loading?: boolean
  endTime: Date | null
  title?: string
}

const FaceoffSlot: React.FC<{
  poll?: Poll
  side: 'A' | 'B'
  disabled: boolean
  onSelect: (poll: Poll) => void
}> = ({ poll, side, disabled, onSelect }) => {
  if (!poll) return <div className='faceoff-slot' />
  return (
    <button
      type='button'
      data-test-id={`poll-button-${poll.value}`}
      className={`faceoff-slot ${poll.checked ? 'selected' : ''}`}
      disabled={disabled}
      onClick={() => onSelect(poll)}
    >
      <span className='mono muted faceoff-corner'>{side}</span>
      <span className='faceoff-emoji'>{poll.label}</span>
      {poll.checked && <span className='tag live dot faceoff-pick'>Picked</span>}
    </button>
  )
}

const DailyPollSection: React.FC<DailyPollSectionProps> = ({ loading, endTime, title = 'The Faceoff' }) => {
  const {
    user,
    pollOptions,
    setPollOptions,
    roundState,
    hasVotedInCurrentRound,
    voteStatusLoading,
    isLoading,
    getWebResultByRound,
    displayedRoundIsFallback,
  } = useVoteManagementContext()
  const navigate = useNavigate()
  const client = usePublicClient()
  const [isEnded, setIsEnded] = useState(false)
  const [tallyReady, setTallyReady] = useState(false)
  const [pollSelected, setPollSelected] = useState<Poll | null>(null)
  const [noPollSelected, setNoPollSelected] = useState<boolean>(true)
  const { setOpen } = useModal()
  const { castVoteWithProof, isVoting: isCastingVote, isMasking, votingStep, lastActiveStep, stepMessage } = useVoteCasting()

  // Derived and selection state are round-local. Tracking the round id lets us
  // clear them when the round changes so a new active poll doesn't inherit the
  // previous round's results state or vote selection.
  const trackedRoundId = useRef(roundState?.id)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      if (!client || !roundState) return

      if (trackedRoundId.current !== roundState.id) {
        trackedRoundId.current = roundState.id
        setTallyReady(false)
        setIsEnded(false)
        setPollSelected(null)
        setNoPollSelected(true)
      }

      try {
        const block = await client.getBlock()
        if (!cancelled) {
          setIsEnded(block.timestamp > roundState.end_time)
        }
      } catch {
        // Transient RPC failure — leave isEnded untouched and retry on the next run.
      }
    })()

    return () => {
      cancelled = true
    }
  }, [roundState, client])

  // Keep a stable reference so the polling effect below isn't torn down
  // and rebuilt every time the parent context re-renders (which otherwise
  // produced an eager `check()` call per rebuild and stacked requests).
  const getWebResultByRoundRef = useRef(getWebResultByRound)
  useEffect(() => {
    getWebResultByRoundRef.current = getWebResultByRound
  }, [getWebResultByRound])

  // Once the poll is over, poll the backend until the FHE tally is published.
  // FHE decryption takes minutes, so poll slowly with exponential backoff and
  // skip ticks while the tab is hidden to avoid bombarding the server.
  useEffect(() => {
    if (!isEnded || !roundState || tallyReady) return

    const BASE_DELAY_MS = 30_000
    const MAX_DELAY_MS = 5 * 60_000

    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | null = null
    let delay = BASE_DELAY_MS

    const tick = async () => {
      if (cancelled) return

      if (typeof document !== 'undefined' && document.hidden) {
        timer = setTimeout(tick, BASE_DELAY_MS)
        return
      }

      try {
        const result = await getWebResultByRoundRef.current(roundState.id)
        if (cancelled) return
        if (result && Array.isArray(result.tally) && result.tally.length > 0) {
          setTallyReady(true)
          return
        }
        delay = Math.min(delay * 2, MAX_DELAY_MS)
      } catch {
        delay = Math.min(delay * 2, MAX_DELAY_MS)
      }

      timer = setTimeout(tick, delay)
    }

    timer = setTimeout(tick, BASE_DELAY_MS)
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [isEnded, roundState, tallyReady])

  const handleChecked = (selectedPoll: Poll) => {
    const isAlreadySelected = pollSelected?.value === selectedPoll.value

    setPollOptions((prevOptions) =>
      prevOptions.map((option) => ({
        ...option,
        checked: option.value === selectedPoll.value ? !isAlreadySelected : false,
      })),
    )

    if (isAlreadySelected) {
      setPollSelected(null)
      setNoPollSelected(true)
    } else {
      setPollSelected(selectedPoll)
      setNoPollSelected(false)
    }
  }

  const castVote = async (isMasking: boolean) => {
    if (!user) {
      setOpen(true)
      return
    }

    await castVoteWithProof(pollSelected, isMasking)
  }

  const busy = isCastingVote || isMasking
  const optionA = pollOptions[0]
  const optionB = pollOptions[1]
  const hasPoll = Boolean(roundState && optionA?.label && optionB?.label)
  const slotDisabled = busy || isEnded || Boolean(loading)

  return (
    <EditorialShell className='flex w-full flex-1 flex-col'>
      <section className='pad-section' style={{ flex: 1 }}>
        <div className='split'>
          {/* Left — context + actions */}
          <div className='col' style={{ gap: 28 }}>
            <div className='col' style={{ gap: 12 }}>
              <div className='mono muted'>{title}</div>
              {hasPoll && <h1 className='h1'>Choose your favorite</h1>}
              {!roundState && !isLoading && <p className='lede'>No active poll found. Check back when the next round opens.</p>}
              {displayedRoundIsFallback && (
                <p className='cap muted'>Showing the latest completed poll — the current round is still being tallied under encryption.</p>
              )}
            </div>

            {roundState && (
              <div className='row' style={{ gap: 10, flexWrap: 'wrap' }}>
                {!isEnded && <span className='tag dot live'>Live</span>}
                {isEnded && tallyReady && <span className='tag dot closed'>Closed</span>}
                {isEnded && !tallyReady && <span className='tag dot tally'>Over · Tallying…</span>}
                <span className='tag'>
                  {roundState.vote_count} {roundState.vote_count === 1 ? 'vote' : 'votes'}
                </span>
                {hasVotedInCurrentRound && <span className='tag tally'>You voted</span>}
                {voteStatusLoading && <span className='tag closed'>Checking…</span>}
              </div>
            )}

            {endTime && !isEnded && !busy && (
              <div className='col' style={{ gap: 6 }}>
                <div className='cap'>Closes in</div>
                <CountdownTimer endTime={endTime} />
              </div>
            )}

            {busy && <VotingStepIndicator step={votingStep} message={stepMessage} lastActiveStep={lastActiveStep} />}
            {isLoading && !roundState && !busy && <LoadingAnimation isLoading />}

            {/* Active poll — voting actions */}
            {roundState && !isEnded && (
              <div className='col' style={{ gap: 14 }}>
                {noPollSelected && (
                  <div className='cap muted'>
                    {hasVotedInCurrentRound ? 'Select an option to update your vote' : 'Select your favorite'}
                  </div>
                )}
                <div className='row' style={{ gap: 12, flexWrap: 'wrap' }}>
                  <button className='btn lg' disabled={noPollSelected || loading || busy} onClick={() => castVote(false)}>
                    {isCastingVote ? 'Processing…' : hasVotedInCurrentRound ? 'Update vote →' : 'Cast →'}
                  </button>
                  <button className='btn ghost lg' disabled={loading || busy} onClick={() => castVote(true)}>
                    {isMasking ? 'Masking…' : 'Mask vote'}
                  </button>
                </div>
              </div>
            )}

            {/* Poll over — tallying / results, no more voting */}
            {roundState && isEnded && (
              <div className='col' style={{ gap: 14 }}>
                {tallyReady ? (
                  <>
                    <div className='cap muted'>The threshold committee has decrypted the result.</div>
                    <div>
                      <button className='btn lg' onClick={() => navigate(`/result/${roundState.id}`)}>
                        View results →
                      </button>
                    </div>
                  </>
                ) : (
                  <div className='cap muted'>
                    Voting is closed. Ballots are being tallied under encryption — results will appear here once the committee publishes the
                    decrypted tally.
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Right — faceoff + ciphertext */}
          {hasPoll && (
            <div className='split-visual col' style={{ gap: 18 }}>
              <div className='faceoff' style={{ maxWidth: 'none' }}>
                <FaceoffSlot poll={optionA} side='A' disabled={slotDisabled} onSelect={handleChecked} />
                <div className='faceoff-vs'>
                  <span className='mono'>vs</span>
                </div>
                <FaceoffSlot poll={optionB} side='B' disabled={slotDisabled} onSelect={handleChecked} />
              </div>

              <div className='card'>
                <div className='mono muted' style={{ marginBottom: 10 }}>
                  {busy ? 'Encrypting your ballot…' : 'Your ballot will be encrypted before it leaves this page'}
                </div>
                <Cipher seed={roundState ? roundState.vote_count + 3 : 11} length={160} blockSize={4} highlight />
              </div>
            </div>
          )}
        </div>
      </section>
    </EditorialShell>
  )
}

export default DailyPollSection
