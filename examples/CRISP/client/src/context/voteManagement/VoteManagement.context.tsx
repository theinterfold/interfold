// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { createGenericContext } from '@/utils/create-generic-context'
import { VoteManagementContextType, VoteManagementProviderProps, VoteStatus } from '@/context/voteManagement'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useAccount } from 'wagmi'
import { VoteStateLite, VotingRound } from '@/model/vote.model'
import { useInterfoldServer } from '@/hooks/interfold/useInterfoldServer'
import { convertPollData, convertTimestampToDate } from '@/utils/methods'
import { Poll, PollResult } from '@/model/poll.model'
import { generatePoll } from '@/utils/generate-random-poll'
import { handleGenericError } from '@/utils/handle-generic-error'

const [useVoteManagementContext, VoteManagementContextProvider] = createGenericContext<VoteManagementContextType>()

const generateSessionId = (): string => {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`
}

const getVoteCacheKey = (sessionId: string, roundId: number, address: string): string => {
  return `crisp-vote-status-${sessionId}-${roundId}-${address.toLowerCase()}`
}

const VOTE_CACHE_DURATION = 5 * 60 * 1000

const VoteManagementProvider = ({ children }: VoteManagementProviderProps) => {
  /**
   * Wagmi Account State
   **/
  const { address, isConnected } = useAccount()

  /**
   * Session ID for cache uniqueness (regenerated on page load)
   **/
  const sessionId = useMemo(() => generateSessionId(), [])

  /**
   * Voting Management States
   **/
  const [user, setUser] = useState<{ address: string } | null>(null)
  const [roundState, setRoundState] = useState<VoteStateLite | null>(null)
  const [votingRound, setVotingRound] = useState<VotingRound | null>(null)
  const [roundEndDate, setRoundEndDate] = useState<Date | null>(null)
  const [isLoading, setIsLoading] = useState<boolean>(false)
  const [pollOptions, setPollOptions] = useState<Poll[]>([])
  const [pastPolls, setPastPolls] = useState<PollResult[]>([])
  const [txUrl, setTxUrl] = useState<string | undefined>(undefined)
  const [pollResult, setPollResult] = useState<PollResult | null>(null)
  const [currentRoundId, setCurrentRoundId] = useState<number | null>(null)
  const [displayedRoundIsFallback, setDisplayedRoundIsFallback] = useState<boolean>(false)
  const [hasVotedInCurrentRound, setHasVotedInCurrentRound] = useState<boolean>(false)
  const [voteStatusLoading, setVoteStatusLoading] = useState<boolean>(false)
  const voteStatusCache = useRef<Map<string, VoteStatus>>(new Map())

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
    getVoteStatus,
  } = useInterfoldServer()

  const checkVoteStatus = useCallback(
    async (roundId: number, userAddress: string, forceRefresh: boolean = false): Promise<boolean> => {
      if (!userAddress || roundId === null || roundId === undefined) return false

      const cacheKey = getVoteCacheKey(sessionId, roundId, userAddress)

      if (!forceRefresh) {
        const cached = voteStatusCache.current.get(cacheKey)
        if (cached && Date.now() - cached.lastChecked < VOTE_CACHE_DURATION) {
          return cached.hasVoted
        }
      }

      setVoteStatusLoading(true)
      try {
        const response = await getVoteStatus({ round_id: roundId, address: userAddress })
        if (response) {
          const status: VoteStatus = {
            hasVoted: response.has_voted,
            roundId: roundId,
            lastChecked: Date.now(),
          }
          voteStatusCache.current.set(cacheKey, status)
          return response.has_voted
        }
        return false
      } catch (error) {
        console.error('Error checking vote status:', error)
        return false
      } finally {
        setVoteStatusLoading(false)
      }
    },
    [sessionId, getVoteStatus],
  )

  const markVotedInRound = useCallback(
    (roundId: number) => {
      if (!user?.address) return

      const cacheKey = getVoteCacheKey(sessionId, roundId, user.address)
      const status: VoteStatus = {
        hasVoted: true,
        roundId: roundId,
        lastChecked: Date.now(),
      }
      voteStatusCache.current.set(cacheKey, status)

      setHasVotedInCurrentRound((prevHasVoted) => {
        return roundId === currentRoundId ? true : prevHasVoted
      })
    },
    [sessionId, user?.address, currentRoundId],
  )

  const initialLoad = async () => {
    const currentRound = await getCurrentRound()
    if (!currentRound) return
    setCurrentRoundId(currentRound.id)

    // If the current round has ended without a published tally, the page would
    // otherwise sit forever in "Over · Tallying…". Fall back to the latest past
    // round that does have a tally so the user sees something useful.
    const fetched = await getRoundStateLiteRequest(currentRound.id)
    if (!fetched) return

    const nowSec = Math.floor(Date.now() / 1000)
    const ended = Number(fetched.end_time) <= nowSec
    let fallbackRoundId: number | null = null

    if (ended) {
      const currentResult = await getWebResultByRound(currentRound.id)
      const currentHasTally = !!(currentResult && Array.isArray(currentResult.tally) && currentResult.tally.length > 0)
      if (!currentHasTally) {
        const all = await getWebResult()
        const latestWithTally = (all ?? [])
          .filter((r) => Array.isArray(r.tally) && r.tally.length > 0)
          .sort((a, b) => b.round_id - a.round_id)[0]
        if (latestWithTally && latestWithTally.round_id !== currentRound.id) {
          fallbackRoundId = latestWithTally.round_id
        }
      }
    }

    setDisplayedRoundIsFallback(fallbackRoundId !== null)
    await getRoundStateLite(fallbackRoundId ?? currentRound.id)
  }

  const getRoundStateLite = async (roundCount: number) => {
    const fetchedRoundState = await getRoundStateLiteRequest(roundCount)

    if (fetchedRoundState?.committee_public_key.length === 1 && fetchedRoundState.committee_public_key[0] === 0) {
      handleGenericError('getRoundStateLite', {
        message: 'Interfold server failed generating the necessary pk bytes',
        name: 'getRoundStateLite',
      })
    }
    if (fetchedRoundState) {
      const startBlockNumber = Number(fetchedRoundState.start_block)
      setRoundState({ ...fetchedRoundState, start_block: startBlockNumber })
      setVotingRound({ round_id: fetchedRoundState.id, pk_bytes: fetchedRoundState.committee_public_key })
      setPollOptions(generatePoll({ round_id: fetchedRoundState.id, emojis: fetchedRoundState.emojis }))
      setRoundEndDate(convertTimestampToDate(fetchedRoundState.end_time))
      setCurrentRoundId(fetchedRoundState.id)
    }
  }

  const getPastPolls = async () => {
    try {
      const result = await getWebResult()
      if (result) {
        const convertedPolls = convertPollData(result)
        setPastPolls(convertedPolls)
      }
    } catch (error) {
      handleGenericError('getPastPolls', error as Error)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    if (interfoldLoading) {
      return setIsLoading(true)
    }
    setIsLoading(false)
  }, [interfoldLoading])

  useEffect(() => {
    if (isConnected && address) {
      setUser({ address })
    } else {
      setUser(null)
      setHasVotedInCurrentRound(false)
      voteStatusCache.current.clear()
    }
  }, [isConnected, address])

  useEffect(() => {
    let cancelled = false
    const checkStatus = async () => {
      if (user?.address && currentRoundId !== null && currentRoundId >= 0) {
        const hasVoted = await checkVoteStatus(currentRoundId, user.address)
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
  }, [user?.address, currentRoundId, checkVoteStatus])

  return (
    <VoteManagementContextProvider
      value={{
        isLoading,
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
        voteStatusLoading,
        sessionId,
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
        setVotingRound,
        setUser,
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
