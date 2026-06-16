// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { PollOption, PollRequestResult, PollResult } from '@/model/poll.model'
import { VoteStateLite } from '@/model/vote.model'
import { Chain, sepolia, anvil } from 'viem/chains'

export const markWinner = (options: PollOption[]) => {
  const highestVoteCount = Math.max(...options.map((o) => o.votes))
  return options.map((option) => ({
    ...option,
    checked: option.votes === highestVoteCount,
  }))
}

export const convertTimestampToDate = (timestamp: number, secondsToAdd: number = 0): Date => {
  const date = new Date(timestamp * 1000)
  date.setSeconds(date.getSeconds() + secondsToAdd)
  return date
}

export const getChain = (): Chain => {
  const chainId = Number.parseInt(String(import.meta.env.VITE_CHAIN_ID ?? ''), 10)
  if (chainId === anvil.id) return anvil
  if (chainId === sepolia.id) return sepolia
  return import.meta.env.DEV ? anvil : sepolia
}

export const formatDate = (isoDateString: string): string => {
  const date = new Date(isoDateString)

  const dateFormatter = new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })

  const timeFormatter = new Intl.DateTimeFormat('en-US', {
    hour: 'numeric',
    minute: 'numeric',
    hour12: true,
  })

  return `${dateFormatter.format(date)} - ${timeFormatter.format(date)}`
}

export const convertPollData = (request: PollRequestResult[]): PollResult[] => {
  const pollResults = request.map((poll) => {
    const totalVotes = poll.total_votes
    const options: PollOption[] = [
      {
        value: 0,
        votes: Number.parseInt(String(poll.tally[0] ?? '0'), 10) || 0,
        label: poll.option_1_emoji,
        checked: false,
      },
      {
        value: 1,
        votes: Number.parseInt(String(poll.tally[1] ?? '0'), 10) || 0,
        label: poll.option_2_emoji,
        checked: false,
      },
    ]

    const date = new Date(poll.end_time * 1000).toISOString()

    return {
      endTime: poll.end_time,
      roundId: poll.round_id,
      totalVotes: totalVotes,
      date: date,
      options: options,
    }
  })

  pollResults.sort((a, b) => b.endTime - a.endTime)

  return pollResults
}

export const convertVoteStateLite = (voteState: VoteStateLite): PollResult => {
  const endTime = voteState.end_time
  const date = new Date(endTime * 1000).toISOString()

  const options: PollOption[] = [
    {
      value: 0,
      votes: 0,
      label: voteState.emojis[0],
      checked: false,
    },
    {
      value: 1,
      votes: 0,
      label: voteState.emojis[1],
      checked: false,
    },
  ]

  return {
    roundId: voteState.id,
    totalVotes: voteState.vote_count,
    date: date,
    options: options,
    endTime: endTime,
  }
}

export const debounce = <T extends (...args: any[]) => void>(func: T, wait: number) => {
  let timeout: ReturnType<typeof setTimeout>
  return (...args: Parameters<T>) => {
    clearTimeout(timeout)
    timeout = setTimeout(() => func(...args), wait)
  }
}
