// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

export interface PollOption {
  value: number
  votes: number
  label: string // emoji
  checked?: boolean
}

export interface PollResult {
  roundId: string
  totalVotes: number
  date: string
  options: PollOption[]
  endTime: number
}

export interface PollRequestResult {
  round_id: string
  tally: number[]
  option_1_emoji: string
  option_2_emoji: string
  end_time: number
  total_votes: number
}

export interface Poll {
  value: number
  checked: boolean
  label: string
}

export interface PollEmoji {
  round_id: string
  emojis: [string, string]
}
