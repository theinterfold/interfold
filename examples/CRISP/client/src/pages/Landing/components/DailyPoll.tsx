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
import { useVoteCasting, type SubmissionCheckStatus, type MaskTarget } from '@/hooks/voting/useVoteCasting'
import { useRegistration } from '@/hooks/voting/useRegistration'
import VotingStepIndicator from '@/components/VotingStepIndicator'
import { usePublicClient } from 'wagmi'
import { EditorialShell, Cipher } from '@/design/Editorial'
import type { InputExclusionReason } from '@crisp-e3/sdk'

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

const EXCLUSION_REASONS: Record<InputExclusionReason, string> = {
  earlier_sibling: 'A ballot or mask for your slot was committed before it and took its place.',
  stale_parent: 'It was built on an old state of your slot.',
  unusable: 'Its published data does not match its commitment.',
}

const MASK_EXCLUSION_REASONS: Record<InputExclusionReason, string> = {
  earlier_sibling: 'An entry for the same slot was committed before it and took its place.',
  stale_parent: 'It was built on an old state of the slot.',
  unusable: 'Its published data does not match its commitment.',
}

/// The frame that the vote note and the mask note share: the stage, whether checks continue, and
/// the link to the confirmation page once the input is in the slot and published.
const StatusCard: React.FC<{
  testId: string
  title: string
  body: string
  status: SubmissionCheckStatus
  onViewConfirmation: () => void
}> = ({ testId, title, body, status, onViewConfirmation }) => (
  <div className='card col' data-test-id={testId} style={{ gap: 8 }}>
    <div className='mono muted'>{title}</div>
    <p className='muted' style={{ margin: 0, lineHeight: 1.5 }}>
      {body}
    </p>
    {status.checking && (
      <p className='mono-sm muted' style={{ margin: 0 }}>
        This page checks the status again automatically.
      </p>
    )}
    {!status.checking && status.stage !== 'counted' && status.stage !== 'excluded' && status.stage !== 'failed' && (
      <p className='mono-sm muted' style={{ margin: 0 }}>
        Status checks stopped. Reload this page to check again.
      </p>
    )}
    {status.stage === 'counted' && (
      <div>
        <button className='btn sm ghost' onClick={onViewConfirmation}>
          View confirmation →
        </button>
      </div>
    )}
  </div>
)

/// What the voter sees about their last vote after it leaves this page. A committed vote counts
/// only when it is selected for the slot and its data is published, so the note follows each
/// stage instead of treating the commitment as the end.
const BallotStatusNote: React.FC<{ status: SubmissionCheckStatus; votingOpen: boolean; onViewConfirmation: () => void }> = ({
  status,
  votingOpen,
  onViewConfirmation,
}) => {
  let title: string
  let body: string
  switch (status.stage) {
    case 'awaiting_commitment':
      title = 'Not committed yet'
      body = 'Your last ballot is not on-chain yet. Your next Cast or Mask action continues that ballot first.'
      break
    case 'selection_pending':
      title = 'Committed · waiting for selection'
      body =
        'Your ballot is on-chain, but it is not counted yet. A ballot or mask for your slot that was committed earlier can still take its place.'
      break
    case 'availability_pending':
      title = 'Selected · waiting for publication'
      body = 'Your ballot holds your slot. It is counted when its encrypted data is published. This can take some hours.'
      break
    case 'counted':
      title = 'Counted'
      body = 'Your ballot is selected and published. It is counted in the tally.'
      break
    case 'excluded':
      title = 'Not counted'
      body = `Your ballot is not counted. ${status.reason ? EXCLUSION_REASONS[status.reason] : ''} ${
        status.retryOffered && votingOpen
          ? 'Select an option and press Cast again. The new ballot builds on the current state of your slot.'
          : 'Voting is closed, so you cannot cast it again.'
      }`
      break
    case 'failed':
      title = 'Not committed'
      body = `The server could not commit your ballot, so it is not counted. ${votingOpen ? 'You can cast it again.' : 'Voting is closed.'}`
      break
  }

  return <StatusCard testId='ballot-status' title={title} body={body} status={status} onViewConfirmation={onViewConfirmation} />
}

/// What the voter sees about their last mask. A mask follows the same stages as a vote, but it has
/// no retry: a mask that did not take the slot has no effect.
const MaskStatusNote: React.FC<{ status: SubmissionCheckStatus; onViewConfirmation: () => void }> = ({ status, onViewConfirmation }) => {
  let title: string
  let body: string
  switch (status.stage) {
    case 'awaiting_commitment':
      title = 'Mask not committed yet'
      body = 'Your last mask is not on-chain yet. Your next Cast or Mask action continues that mask first.'
      break
    case 'selection_pending':
      title = 'Mask committed · waiting for selection'
      body =
        'Your mask is on-chain, but it is not in the slot yet. An entry for the same slot that was committed earlier can still take its place.'
      break
    case 'availability_pending':
      title = 'Mask in the slot · waiting for publication'
      body = 'Your mask holds the slot. Its encrypted data is not published yet. This can take some hours.'
      break
    case 'counted':
      title = 'Mask in the slot'
      body = 'Your mask is selected and published.'
      break
    case 'excluded':
      title = 'Mask not taken'
      body = `Your mask did not take the slot, so it has no effect. ${status.reason ? MASK_EXCLUSION_REASONS[status.reason] : ''}`
      break
    case 'failed':
      title = 'Mask not committed'
      body = 'The server could not commit your mask.'
      break
  }

  return <StatusCard testId='mask-status' title={title} body={body} status={status} onViewConfirmation={onViewConfirmation} />
}

const DailyPollSection: React.FC<DailyPollSectionProps> = ({ loading, endTime, title = 'The Faceoff' }) => {
  const {
    user,
    pollOptions,
    setPollOptions,
    roundState,
    hasVotedInCurrentRound,
    isLoading,
    getWebResultByRound,
    displayedRoundIsFallback,
    currentRoundId,
    setTxUrl,
    setTxRoute,
  } = useVoteManagementContext()
  const { canRegister, isRegistered, isRegistering, register } = useRegistration()
  const navigate = useNavigate()
  const client = usePublicClient()
  const [isEnded, setIsEnded] = useState(false)
  const [tallyReady, setTallyReady] = useState(false)
  const [pollSelected, setPollSelected] = useState<Poll | null>(null)
  const [noPollSelected, setNoPollSelected] = useState<boolean>(true)
  const { setOpen } = useModal()
  const {
    castVoteWithProof,
    isVoting: isCastingVote,
    isMasking,
    votingStep,
    lastActiveStep,
    stepMessage,
    ballotStatus,
    maskStatus,
  } = useVoteCasting()

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
  //
  // The first check runs immediately: a page opened (or a round entered) after the tally is
  // already published must flip to results at once, not after the first delay. Same for a tab
  // coming back to the foreground — by then the backoff can have grown to minutes, which showed
  // a stale "Tallying…" long after the result existed, so becoming visible also checks at once.
  useEffect(() => {
    if (!isEnded || !roundState || tallyReady) return

    const BASE_DELAY_MS = 30_000
    const MAX_DELAY_MS = 5 * 60_000

    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | null = null
    let delay = BASE_DELAY_MS
    // Single-flight: `tick` is async, and while a request is pending `timer` is null, so a
    // visibility change during that window would otherwise start a second concurrent polling
    // chain — each one rescheduling itself, multiplying load and leaking timers past unmount.
    let running = false

    const tick = async () => {
      if (cancelled || running) return

      if (typeof document !== 'undefined' && document.hidden) {
        timer = setTimeout(tick, BASE_DELAY_MS)
        return
      }

      running = true
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
      } finally {
        running = false
      }

      timer = setTimeout(tick, delay)
    }

    const tickNow = () => {
      if (timer) clearTimeout(timer)
      timer = null
      // A foreground check is a fresh look, not a continuation of the backoff that grew while
      // nothing was watching.
      delay = BASE_DELAY_MS
      void tick()
    }

    const onVisibilityChange = () => {
      if (typeof document !== 'undefined' && !document.hidden) tickNow()
    }

    tickNow()
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', onVisibilityChange)
    }

    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
      if (typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', onVisibilityChange)
      }
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

  const castVote = async (isMasking: boolean, maskTarget: MaskTarget = 'random') => {
    if (!user) {
      setOpen(true)
      return
    }

    await castVoteWithProof(pollSelected, isMasking, maskTarget)
  }

  const busy = isCastingVote || isMasking
  const optionA = pollOptions[0]
  const optionB = pollOptions[1]
  const hasPoll = Boolean(roundState && optionA?.label && optionB?.label)
  const slotDisabled = busy || isEnded || Boolean(loading)
  // The regular cast flow builds a new proof against the slot's current head, so it is the retry.
  const retryExcluded = ballotStatus?.stage === 'excluded' && ballotStatus.retryOffered
  // A committed ballot that is not excluded is replaced by the next vote, as a counted one is.
  const ballotSubmitted =
    hasVotedInCurrentRound ||
    ballotStatus?.stage === 'selection_pending' ||
    ballotStatus?.stage === 'availability_pending' ||
    ballotStatus?.stage === 'counted'
  // The confirmation page describes the transaction, and the route, of the input it opens for.
  const viewConfirmation = (status: SubmissionCheckStatus, roundId: string) => {
    setTxUrl(status.txUrl)
    setTxRoute(status.route)
    navigate(`/result/${roundId}/confirmation`)
  }

  return (
    <EditorialShell className='flex w-full flex-1 flex-col'>
      <section className='pad-section' style={{ flex: 1 }}>
        <div className='split'>
          {/* Left — context + actions */}
          <div className='col' style={{ gap: 28 }}>
            <div className='col' style={{ gap: 12 }}>
              <div className='mono muted'>{title}</div>
              {hasPoll && <h1 className='h1'>Choose your favorite</h1>}
              {!roundState && !isLoading && currentRoundId && (
                <p className='lede'>Round #{currentRoundId} is preparing its encryption key. Voting will open when the key is available.</p>
              )}
              {!roundState && !isLoading && !currentRoundId && (
                <p className='lede'>No active poll found. Check back when the next round opens.</p>
              )}
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
                {canRegister && isRegistered === true && <span className='tag live'>Registered</span>}
              </div>
            )}

            {endTime && !isEnded && !busy && (
              <div className='col' style={{ gap: 6 }}>
                <div className='cap'>Closes in</div>
                <CountdownTimer endTime={endTime} />
              </div>
            )}

            {busy && <VotingStepIndicator step={votingStep} message={stepMessage} lastActiveStep={lastActiveStep} />}
            {roundState && ballotStatus && !busy && (
              <BallotStatusNote
                status={ballotStatus}
                votingOpen={!isEnded}
                onViewConfirmation={() => viewConfirmation(ballotStatus, roundState.id)}
              />
            )}
            {roundState && maskStatus && !busy && (
              <MaskStatusNote status={maskStatus} onViewConfirmation={() => viewConfirmation(maskStatus, roundState.id)} />
            )}
            {isLoading && !roundState && !busy && <LoadingAnimation isLoading />}

            {/* Open registration — an ONCHAIN round backed by a SelfRegistry admits voters
                during the input window, so the register action lives beside the vote. */}
            {roundState && !isEnded && canRegister && user && isRegistered === false && (
              <div className='col' style={{ gap: 8 }}>
                <div className='cap muted'>This poll has open registration — register once, then vote.</div>
                <div>
                  <button className='btn lg' disabled={isRegistering || busy} onClick={() => register()}>
                    {isRegistering ? 'Registering…' : 'Register to vote →'}
                  </button>
                </div>
              </div>
            )}

            {/* Active poll — voting actions */}
            {roundState && !isEnded && (
              <div className='col' style={{ gap: 14 }}>
                {/* Shown before every submission: the server picks the wallet or the relay route
                    only after the ballot is built. */}
                <div className='card col' data-test-id='privacy-notice' style={{ gap: 8 }}>
                  <div className='mono muted'>Before you vote</div>
                  <ul className='col muted' style={{ gap: 6, margin: 0, paddingLeft: 18, listStyle: 'disc', lineHeight: 1.5 }}>
                    <li>Your browser encrypts your ballot. No single committee member can decrypt it.</li>
                    <li>
                      The committee decrypts only the combined result, and the result is public. In a small or one-sided poll, the result
                      can show how individual participants voted.
                    </li>
                    <li>Privacy depends on the committee threshold. Enough committee members who collude can decrypt ballots.</li>
                    <li>
                      The CRISP server receives every ballot, so it sees your request. If your wallet sends the transaction, your address is
                      also visible on-chain.
                    </li>
                    <li>
                      Masks make a vote, an update, and a mask look the same on-chain. This makes a receipt of your vote less reliable, but
                      only when the conditions above hold.
                    </li>
                  </ul>
                </div>
                {noPollSelected && (
                  <div className='cap muted'>{ballotSubmitted ? 'Select an option to update your vote' : 'Select your favorite'}</div>
                )}
                <div className='row' style={{ gap: 12, flexWrap: 'wrap' }}>
                  <button
                    className='btn lg'
                    disabled={noPollSelected || loading || busy || (canRegister && isRegistered === false)}
                    onClick={() => castVote(false)}
                  >
                    {isCastingVote ? 'Processing…' : retryExcluded ? 'Cast again →' : ballotSubmitted ? 'Update vote →' : 'Cast →'}
                  </button>
                  <button className='btn ghost lg' disabled={loading || busy} onClick={() => castVote(true, 'random')}>
                    {isMasking ? 'Masking…' : 'Mask a voter'}
                  </button>
                  {/* Self-masks are what make your own later activity ambiguous: an observer
                      seeing your address write to your slot again cannot tell an update from a
                      mask — but only if masking yourself is something voters actually do. */}
                  <button className='btn ghost lg' disabled={loading || busy} onClick={() => castVote(true, 'self')}>
                    {isMasking ? 'Masking…' : 'Mask my slot'}
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
