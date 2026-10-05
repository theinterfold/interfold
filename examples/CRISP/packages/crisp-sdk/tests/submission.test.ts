// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it } from 'vitest'

import { getSubmissionStage } from '../src/submission'
import type { InputSelectionResponse, InputSelectionStatus, SubmissionStatus, VoteResponseStatus } from '../src/types'

const DEADLINE = 1_000

const selection = (status: InputSelectionStatus): InputSelectionResponse => ({
  status,
  index: status === 'not_indexed' ? null : 3,
  head_index: 3,
  reason: status === 'excluded' ? 'earlier_sibling' : null,
})

describe('getSubmissionStage', () => {
  it.each<[string, VoteResponseStatus | null, InputSelectionStatus | null, SubmissionStatus]>([
    ['a failed job beats a selection', 'failed_broadcast', 'selected', { stage: 'failed', retryOffered: false }],
    ['an exclusion beats a published ciphertext', 'success', 'excluded', { stage: 'excluded', retryOffered: true }],
    ['a selected, published ballot counts', 'success', 'selected', { stage: 'counted', retryOffered: false }],
    [
      'a selected ballot waits for its ciphertext',
      'pending_availability',
      'selected',
      { stage: 'availability_pending', retryOffered: false },
    ],
    [
      'a ballot the wallet must still send is not committed',
      'ready_for_commitment',
      null,
      { stage: 'awaiting_commitment', retryOffered: false },
    ],
    [
      'a committed ballot the server has not indexed waits for selection',
      'pending_availability',
      'not_indexed',
      { stage: 'selection_pending', retryOffered: false },
    ],
  ])('%s', (_, availability, selectionStatus, expected) => {
    expect(
      getSubmissionStage({
        availability,
        selection: selectionStatus === null ? null : selection(selectionStatus),
        now: DEADLINE - 1,
        commitmentDeadline: DEADLINE,
      }),
    ).toEqual(expected)
  })

  it('offers no retry for an excluded ballot once the commitment deadline is reached', () => {
    expect(
      getSubmissionStage({
        availability: 'pending_availability',
        selection: selection('excluded'),
        now: DEADLINE,
        commitmentDeadline: DEADLINE,
      }),
    ).toEqual({ stage: 'excluded', retryOffered: false })
  })
})
