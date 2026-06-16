// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type React from 'react'
import { ReactNode } from 'react'
import { BroadcastVoteRequest, BroadcastVoteResponse, VotingRound, VoteStateLite } from '@/model/vote.model'
import { Poll, PollRequestResult, PollResult } from '@/model/poll.model'

export type VoteStatus = {
  hasVoted: boolean
  roundId: number
  lastChecked: number
}

export type VoteManagementContextType = {
  isLoading: boolean
  user: { address: string } | null
  votingRound: VotingRound | null
  roundEndDate: Date | null
  pollOptions: Poll[]
  roundState: VoteStateLite | null
  pastPolls: PollResult[]
  txUrl: string | undefined
  pollResult: PollResult | null
  currentRoundId: number | null
  displayedRoundIsFallback: boolean
  hasVotedInCurrentRound: boolean
  voteStatusLoading: boolean
  sessionId: string
  setPollResult: React.Dispatch<React.SetStateAction<PollResult | null>>
  getWebResultByRound: (round_id: number) => Promise<PollRequestResult | undefined>
  setTxUrl: React.Dispatch<React.SetStateAction<string | undefined>>
  setPollOptions: React.Dispatch<React.SetStateAction<Poll[]>>
  initialLoad: () => Promise<void>
  getPastPolls: () => Promise<void>
  setVotingRound: React.Dispatch<React.SetStateAction<VotingRound | null>>
  setUser: React.Dispatch<React.SetStateAction<{ address: string } | null>>
  broadcastVote: (vote: BroadcastVoteRequest) => Promise<BroadcastVoteResponse | undefined>
  getRoundStateLite: (roundCount: number) => Promise<void>
  setPastPolls: React.Dispatch<React.SetStateAction<PollResult[]>>
  getWebResult: () => Promise<PollRequestResult[] | undefined>
  checkVoteStatus: (roundId: number, address: string, forceRefresh?: boolean) => Promise<boolean>
  markVotedInRound: (roundId: number) => void
}

export type VoteManagementProviderProps = {
  children: ReactNode
}
