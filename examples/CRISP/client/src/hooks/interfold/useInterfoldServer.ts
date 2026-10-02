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
import axios from 'axios'

const INTERFOLD_API = import.meta.env.VITE_INTERFOLD_API

if (!INTERFOLD_API) handleGenericError('useInterfoldServer', { name: 'INTERFOLD_API', message: 'Missing env VITE_INTERFOLD_API' })

/// Bounds one job status read. The server bounds its own chain reconciliation for a status
/// request to 15 seconds, so a healthy answer arrives well inside this. A stuck request must not
/// hold the caller: the commitment wait polls with it.
const STATUS_READ_TIMEOUT_MS = 30_000

/// Bounds one ballot broadcast. The server can run a job step, such as a relayed commitment, before
/// it answers, and that step continues when this request stops waiting. A ballot without an answer
/// stays saved, and the next action sends it again.
const BROADCAST_TIMEOUT_MS = 120_000

const InterfoldEndpoints = {
  GetCurrentRound: `${INTERFOLD_API}/rounds/current`,
  GetRoundStateLite: `${INTERFOLD_API}/state/lite`,
  GetWebResult: `${INTERFOLD_API}/state/result`,
  GetWebAllResult: `${INTERFOLD_API}/state/all`,
  BroadcastVote: `${INTERFOLD_API}/voting/broadcast`,
  GetVoteAvailability: `${INTERFOLD_API}/voting/availability`,
  GetVoteStatus: `${INTERFOLD_API}/voting/status`,
  GetEligibleVoters: `${INTERFOLD_API}/state/eligible-addresses`,
  GetMerkleLeaves: `${INTERFOLD_API}/state/token-holders`,
} as const

export const useInterfoldServer = () => {
  const { GetCurrentRound, GetWebAllResult, BroadcastVote, GetVoteAvailability, GetRoundStateLite, GetWebResult, GetVoteStatus } =
    InterfoldEndpoints
  const { fetchData, isLoading } = useApi()
  const getCurrentRound = () =>
    fetchData<CurrentRound, { requesters: string[] }>(GetCurrentRound, 'post', { requesters: ROUND_REQUESTERS }, { suppressNotFound: true })
  const getRoundStateLite = (round_id: string) =>
    fetchData<VoteStateLite, { round_id: string }>(GetRoundStateLite, 'post', { round_id }, { suppressNotFound: true })
  const getVoteAvailability = async (jobId: string): Promise<BroadcastVoteResponse | null | undefined> => {
    const url = `${GetVoteAvailability}/${encodeURIComponent(jobId)}`
    try {
      return (await axios.get<BroadcastVoteResponse>(url, { timeout: STATUS_READ_TIMEOUT_MS })).data
    } catch (error) {
      // A server replacement can legitimately lose its local job database. Tell the caller this
      // job is gone so it can clear localStorage and submit again. Other failures are transient.
      if (axios.isAxiosError(error) && error.response?.status === 404) return null
      handleGenericError(`API Error - ${url}`, error as Error)
      return undefined
    }
  }
  const broadcastVote = async (
    vote: BroadcastVoteRequest,
    onJobCreated?: (jobId: string) => void,
  ): Promise<BroadcastVoteResponse | undefined> => {
    try {
      const { data } = await axios.post<BroadcastVoteResponse>(BroadcastVote, vote, { timeout: BROADCAST_TIMEOUT_MS })
      if (data.job_id) onJobCreated?.(data.job_id)
      return data
    } catch (error) {
      // A 400 answer with the failed_broadcast status refuses this ballot, and the same bytes get
      // the same answer. After any other failure the server can still hold the ballot.
      const answer = axios.isAxiosError<BroadcastVoteResponse>(error) ? error.response : undefined
      if (answer?.status === 400 && answer.data?.status === 'failed_broadcast') return answer.data
      handleGenericError(`API Error - ${BroadcastVote}`, error as Error)
      return undefined
    }
  }
  const getWebResult = () =>
    fetchData<PollRequestResult[], { requesters: string[] }>(GetWebAllResult, 'post', { requesters: ROUND_REQUESTERS })
  const getWebResultByRound = (round_id: string) => fetchData<PollRequestResult, { round_id: string }>(GetWebResult, 'post', { round_id })
  const getVoteStatus = (request: VoteStatusRequest) => fetchData<VoteStatusResponse, VoteStatusRequest>(GetVoteStatus, 'post', request)
  const getEligibleVoters = (round_id: string) =>
    fetchData<EligibleVoter[], { round_id: string }>(InterfoldEndpoints.GetEligibleVoters, 'post', { round_id })
  const getMerkleLeaves = (round_id: string) =>
    fetchData<string[], { round_id: string }>(InterfoldEndpoints.GetMerkleLeaves, 'post', { round_id })

  return {
    isLoading,
    getWebResultByRound,
    getWebResult,
    getCurrentRound,
    getRoundStateLite,
    broadcastVote,
    getVoteAvailability,
    getVoteStatus,
    getEligibleVoters,
    getMerkleLeaves,
  }
}
