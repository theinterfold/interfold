// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { SubmissionStageInputs, SubmissionStatus } from './types'

/**
 * Combine the availability job and the selection answer for one ballot into the stage a voter
 * sees.
 *
 * A committed ballot counts only when the Secure Process selects it for its slot and its
 * ciphertext is published. An earlier entry that names the same parent takes the slot first, so a
 * commitment alone does not make a ballot count. The rules apply in this order:
 *
 * 1. A failed job is `failed`.
 * 2. An excluded ballot is `excluded`, whatever the job reports.
 * 3. A selected ballot is `counted` when the job reports `success`, else `availability_pending`.
 * 4. A job that is not committed yet is `awaiting_commitment`.
 * 5. Any other ballot is `selection_pending`.
 *
 * A retry is offered only for an excluded ballot before the commitment deadline, because
 * `CRISPProgram` rejects a commitment at or after the deadline.
 * @param inputs The job status, the selection answer, the time, and the deadline.
 * @returns The stage and whether a retry is offered.
 */
export const getSubmissionStage = ({ availability, selection, now, commitmentDeadline }: SubmissionStageInputs): SubmissionStatus => {
  if (availability === 'failed_broadcast') return { stage: 'failed', retryOffered: false }
  if (selection?.status === 'excluded') return { stage: 'excluded', retryOffered: now < commitmentDeadline }
  if (selection?.status === 'selected') {
    return { stage: availability === 'success' ? 'counted' : 'availability_pending', retryOffered: false }
  }
  if (availability === 'pending_commitment' || availability === 'ready_for_commitment') {
    return { stage: 'awaiting_commitment', retryOffered: false }
  }
  return { stage: 'selection_pending', retryOffered: false }
}
