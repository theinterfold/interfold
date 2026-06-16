// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { handleGenericError } from '@/utils/handle-generic-error'
import {
  BroadcastVoteRequest,
  BroadcastVoteResponse,
  CurrentRound,
  EligibleVoter,
  VoteStateLite,
  VoteStatusRequest,
  VoteStatusResponse,
} from '@/model/vote.model'
import { useApi } from '../generic/useFetchApi'
import { PollRequestResult } from '@/model/poll.model'
import { ROUND_REQUESTERS } from '@/utils/constants'

const INTERFOLD_API = import.meta.env.VITE_INTERFOLD_API

if (!INTERFOLD_API) handleGenericError('useInterfoldServer', { name: 'INTERFOLD_API', message: 'Missing env VITE_INTERFOLD_API' })

const InterfoldEndpoints = {
  GetCurrentRound: `${INTERFOLD_API}/rounds/current`,
  GetRoundStateLite: `${INTERFOLD_API}/state/lite`,
  GetWebResult: `${INTERFOLD_API}/state/result`,
  GetWebAllResult: `${INTERFOLD_API}/state/all`,
  BroadcastVote: `${INTERFOLD_API}/voting/broadcast`,
  GetVoteStatus: `${INTERFOLD_API}/voting/status`,
  GetEligibleVoters: `${INTERFOLD_API}/state/eligible-addresses`,
  GetMerkleLeaves: `${INTERFOLD_API}/state/token-holders`,
} as const

export const useInterfoldServer = () => {
  const { GetCurrentRound, GetWebAllResult, BroadcastVote, GetRoundStateLite, GetWebResult, GetVoteStatus } = InterfoldEndpoints
  const { fetchData, isLoading } = useApi()
  const getCurrentRound = () => fetchData<CurrentRound, { requesters: string[] }>(GetCurrentRound, 'post', { requesters: ROUND_REQUESTERS })
  const getRoundStateLite = (round_id: number) => fetchData<VoteStateLite, { round_id: number }>(GetRoundStateLite, 'post', { round_id })
  const broadcastVote = (vote: BroadcastVoteRequest) => fetchData<BroadcastVoteResponse, BroadcastVoteRequest>(BroadcastVote, 'post', vote)
  const getWebResult = () =>
    fetchData<PollRequestResult[], { requesters: string[] }>(GetWebAllResult, 'post', { requesters: ROUND_REQUESTERS })
  const getWebResultByRound = (round_id: number) => fetchData<PollRequestResult, { round_id: number }>(GetWebResult, 'post', { round_id })
  const getVoteStatus = (request: VoteStatusRequest) => fetchData<VoteStatusResponse, VoteStatusRequest>(GetVoteStatus, 'post', request)
  const getEligibleVoters = (round_id: number) =>
    fetchData<EligibleVoter[], { round_id: number }>(InterfoldEndpoints.GetEligibleVoters, 'post', { round_id })
  const getMerkleLeaves = (round_id: number) =>
    fetchData<string[], { round_id: number }>(InterfoldEndpoints.GetMerkleLeaves, 'post', { round_id })

  return {
    isLoading,
    getWebResultByRound,
    getWebResult,
    getCurrentRound,
    getRoundStateLite,
    broadcastVote,
    getVoteStatus,
    getEligibleVoters,
    getMerkleLeaves,
  }
}
