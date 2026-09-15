// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { createGenericContext } from '@/utils/create-generic-context'
import { VoteManagementContextType, VoteManagementProviderProps } from '@/context/voteManagement'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useAccount, useChainId } from 'wagmi'
import { VoteStateLite, VotingRound } from '@/model/vote.model'
import { useInterfoldServer } from '@/hooks/interfold/useInterfoldServer'
import { convertPollData, convertTimestampToDate } from '@/utils/methods'
import { Poll, PollResult } from '@/model/poll.model'
import { generatePoll } from '@/utils/generate-random-poll'
import { handleGenericError } from '@/utils/handle-generic-error'

const [useVoteManagementContext, VoteManagementContextProvider] = createGenericContext<VoteManagementContextType>()

/// "Did I vote in this round" is a fact only this client holds. The server cannot answer it — a
/// mask is indistinguishable from a vote by design, so all it can report is slot activity, which
/// says "someone wrote to your slot", not "you voted". Kept in localStorage so it survives a
/// reload, keyed per chain, round and address: switching wallets must not leak one account's
/// state into another's, and a round id can repeat across chains — deterministic deployments give
/// two networks the same Interfold address, and round ids are derived from it.
const getVoteCacheKey = (chainId: number, roundId: string, address: string): string => {
  return `crisp-voted-${chainId}-${roundId}-${address.toLowerCase()}`
}

const nowInSeconds = (): number => Math.floor(Date.now() / 1000)
const ROUND_POLL_INITIAL_MS = 10_000
const ROUND_POLL_MAX_MS = 60_000

const VoteManagementProvider = ({ children }: VoteManagementProviderProps) => {
  /**
   * Wagmi Account State
   **/
  const { address, isConnected } = useAccount()
  const chainId = useChainId()

  /**
   * Voting Management States
   **/
  const [roundState, setRoundState] = useState<VoteStateLite | null>(null)
  const [votingRound, setVotingRound] = useState<VotingRound | null>(null)
  const [roundEndDate, setRoundEndDate] = useState<Date | null>(null)
  const [pollOptions, setPollOptions] = useState<Poll[]>([])
  const [pastPolls, setPastPolls] = useState<PollResult[]>([])
  const [txUrl, setTxUrl] = useState<string | undefined>(undefined)
  const [pollResult, setPollResult] = useState<PollResult | null>(null)
  const [currentRoundId, setCurrentRoundId] = useState<string | null>(null)
  const [pendingCurrentRoundId, setPendingCurrentRoundId] = useState<string | null>(null)
  const [displayedRoundIsFallback, setDisplayedRoundIsFallback] = useState<boolean>(false)
  const [hasVotedInCurrentRound, setHasVotedInCurrentRound] = useState<boolean>(false)

  /**
   * The connected wallet is the source of truth for the user, so it is derived
   * rather than mirrored into state.
   **/
  const user = useMemo(() => (isConnected && address ? { address } : null), [isConnected, address])
  const userAddress = user?.address

  /**
   * Voting Management Methods
   **/
  const {
    isLoading: interfoldLoading,
    getRoundStateLite: getRoundStateLiteRequest,
    getWebResultByRound,
    getWebResult,
    getCurrentRound,
    broadcastVote,
    getVoteAvailability,
  } = useInterfoldServer()

  /// Purely local — see the note on `getVoteCacheKey`. Async only to keep the signature the
  /// consumers already use.
  const checkVoteStatus = useCallback(
    async (roundId: string, userAddress: string): Promise<boolean> => {
      if (!userAddress || roundId === null || roundId === undefined) return false

      try {
        return localStorage.getItem(getVoteCacheKey(chainId, roundId, userAddress)) === 'true'
      } catch {
        // Storage can be unavailable (private browsing); treat as "not voted".
        return false
      }
    },
    [chainId],
  )

  const markVotedInRound = useCallback(
    (roundId: string) => {
      if (!userAddress) return

      try {
        localStorage.setItem(getVoteCacheKey(chainId, roundId, userAddress), 'true')
      } catch {
        // Best effort: without storage the flag only lives until the next reload.
      }

      setHasVotedInCurrentRound((prevHasVoted) => {
        return roundId === currentRoundId ? true : prevHasVoted
      })
    },
    [chainId, userAddress, currentRoundId],
  )

  const applyRoundState = useCallback((fetchedRoundState: VoteStateLite) => {
    if (fetchedRoundState.committee_public_key.length === 1 && fetchedRoundState.committee_public_key[0] === 0) {
      handleGenericError('getRoundStateLite', {
        message: 'Interfold server failed generating the necessary pk bytes',
        name: 'getRoundStateLite',
      })
    }

    const startBlockNumber = Number(fetchedRoundState.start_block)
    setRoundState({ ...fetchedRoundState, start_block: startBlockNumber })
    setVotingRound({ round_id: fetchedRoundState.id, pk_bytes: fetchedRoundState.committee_public_key })
    setPollOptions(generatePoll({ round_id: fetchedRoundState.id, emojis: fetchedRoundState.emojis }))
    setRoundEndDate(convertTimestampToDate(fetchedRoundState.end_time))
  }, [])

  const initialLoad = async () => {
    const currentRound = await getCurrentRound()
    if (!currentRound) return

    // If the current round has ended without a published tally, the page would
    // otherwise sit forever in "Over · Tallying…". Fall back to the latest past
    // round that does have a tally so the user sees something useful.
    const fetched = await getRoundStateLiteRequest(currentRound.id)
    const confirmedRound = await getCurrentRound()
    if (!confirmedRound || confirmedRound.id !== currentRound.id) {
      return
    }
    setCurrentRoundId(currentRound.id)
    if (!fetched) {
      setPendingCurrentRoundId(currentRound.id)
      return
    }
    setPendingCurrentRoundId(null)

    const ended = Number(fetched.end_time) <= nowInSeconds()
    let fallbackRoundId: string | null = null

    if (ended) {
      const currentResult = await getWebResultByRound(currentRound.id)
      const currentHasTally = !!(currentResult && Array.isArray(currentResult.tally) && currentResult.tally.length > 0)
      if (!currentHasTally) {
        const all = await getWebResult()
        const latestWithTally = (all ?? [])
          .filter((r) => Array.isArray(r.tally) && r.tally.length > 0)
          .sort((a, b) => {
            const aId = BigInt(a.round_id)
            const bId = BigInt(b.round_id)
            return aId === bId ? 0 : aId < bId ? 1 : -1
          })[0]
        if (latestWithTally && latestWithTally.round_id !== currentRound.id) {
          fallbackRoundId = latestWithTally.round_id
        }
      }
    }

    setDisplayedRoundIsFallback(fallbackRoundId !== null)
    if (fallbackRoundId) {
      await getRoundStateLite(fallbackRoundId)
    } else {
      applyRoundState(fetched)
    }
  }

  const getRoundStateLite = async (roundId: string) => {
    const fetchedRoundState = await getRoundStateLiteRequest(roundId)

    if (fetchedRoundState) {
      applyRoundState(fetchedRoundState)
    }
  }

  const getRoundStateLiteRequestRef = useRef(getRoundStateLiteRequest)
  useEffect(() => {
    getRoundStateLiteRequestRef.current = getRoundStateLiteRequest
  }, [getRoundStateLiteRequest])

  const getCurrentRoundRef = useRef(getCurrentRound)
  useEffect(() => {
    getCurrentRoundRef.current = getCurrentRound
  }, [getCurrentRound])

  useEffect(() => {
    if (currentRoundId !== null) return

    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | null = null
    let delay = ROUND_POLL_INITIAL_MS

    function schedule(wait = delay) {
      if (cancelled || document.hidden) return
      timer = setTimeout(() => {
        timer = null
        void poll()
      }, wait)
    }

    async function poll() {
      if (cancelled) return

      const currentRound = await getCurrentRoundRef.current()
      if (cancelled) return

      if (currentRound) {
        const fetched = await getRoundStateLiteRequestRef.current(currentRound.id)
        if (cancelled) return

        // The current-round pointer can change while its state is in flight. Confirm it again
        // before committing either value, or this effect stops polling on a stale round.
        const confirmedRound = await getCurrentRoundRef.current()
        if (cancelled) return
        if (!confirmedRound || confirmedRound.id !== currentRound.id) {
          schedule(1_000)
          return
        }

        // Fetch the state before storing the round ID. Storing the ID reruns this
        // effect and cancels the current request. If we store it first, a round
        // that becomes active after page load can discard its successful state
        // response and leave the page in the preparing state permanently.
        setCurrentRoundId(currentRound.id)
        setDisplayedRoundIsFallback(false)

        if (fetched) {
          applyRoundState(fetched)
          setPendingCurrentRoundId(null)
        } else {
          setPendingCurrentRoundId(currentRound.id)
        }
        return
      }

      delay = Math.min(delay * 2, ROUND_POLL_MAX_MS)
      schedule()
    }

    function resumeWhenVisible() {
      if (!document.hidden && !cancelled && !timer) {
        delay = ROUND_POLL_INITIAL_MS
        void poll()
      }
    }
    document.addEventListener('visibilitychange', resumeWhenVisible)
    schedule()
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
      document.removeEventListener('visibilitychange', resumeWhenVisible)
    }
  }, [currentRoundId, applyRoundState])

  useEffect(() => {
    if (!pendingCurrentRoundId) return
    const pendingRoundId = pendingCurrentRoundId

    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | null = null
    let delay = ROUND_POLL_INITIAL_MS

    function schedule() {
      if (cancelled || document.hidden) return
      timer = setTimeout(() => {
        timer = null
        void poll()
      }, delay)
    }

    async function poll() {
      if (cancelled) return

      const currentRound = await getCurrentRoundRef.current()
      if (cancelled) return
      if (currentRound && currentRound.id !== pendingRoundId) {
        // A newer round replaced the one whose key we were waiting for. Reset discovery instead
        // of keeping the page attached to an old round that may never become readable.
        setPendingCurrentRoundId(null)
        setCurrentRoundId(null)
        return
      }

      const fetched = await getRoundStateLiteRequestRef.current(pendingRoundId)
      if (cancelled) return
      if (fetched) {
        const confirmedRound = await getCurrentRoundRef.current()
        if (cancelled) return
        if (!confirmedRound) {
          delay = Math.min(delay * 2, ROUND_POLL_MAX_MS)
          schedule()
          return
        }
        if (confirmedRound.id !== pendingRoundId) {
          setPendingCurrentRoundId(null)
          setCurrentRoundId(null)
          return
        }
        applyRoundState(fetched)
        setPendingCurrentRoundId(null)
        return
      }

      delay = Math.min(delay * 2, ROUND_POLL_MAX_MS)
      schedule()
    }

    function resumeWhenVisible() {
      if (!document.hidden && !cancelled && !timer) {
        delay = ROUND_POLL_INITIAL_MS
        void poll()
      }
    }
    document.addEventListener('visibilitychange', resumeWhenVisible)
    schedule()
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
      document.removeEventListener('visibilitychange', resumeWhenVisible)
    }
  }, [pendingCurrentRoundId, applyRoundState])

  const getPastPolls = async () => {
    try {
      const result = await getWebResult()
      if (result) {
        const convertedPolls = convertPollData(result)
        setPastPolls(convertedPolls)
      }
    } catch (error) {
      handleGenericError('getPastPolls', error as Error)
    }
  }

  useEffect(() => {
    let cancelled = false
    const checkStatus = async () => {
      if (userAddress && currentRoundId !== null) {
        const hasVoted = await checkVoteStatus(currentRoundId, userAddress)
        if (!cancelled) {
          setHasVotedInCurrentRound(hasVoted)
        }
      } else {
        setHasVotedInCurrentRound(false)
      }
    }
    checkStatus()
    return () => {
      cancelled = true
    }
  }, [userAddress, currentRoundId, checkVoteStatus])

  return (
    <VoteManagementContextProvider
      value={{
        isLoading: interfoldLoading,
        user,
        votingRound,
        roundEndDate,
        pollOptions,
        roundState,
        pastPolls,
        txUrl,
        pollResult,
        currentRoundId,
        displayedRoundIsFallback,
        hasVotedInCurrentRound,
        setPollResult,
        getWebResultByRound,
        setTxUrl,
        getWebResult,
        setPastPolls,
        getPastPolls,
        getRoundStateLite,
        setPollOptions,
        initialLoad,
        broadcastVote,
        getVoteAvailability,
        setVotingRound,
        checkVoteStatus,
        markVotedInRound,
      }}
    >
      {children}
    </VoteManagementContextProvider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export { useVoteManagementContext, VoteManagementProvider }
