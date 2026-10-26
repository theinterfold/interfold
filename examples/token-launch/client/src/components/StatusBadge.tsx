// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { PHASE_LABELS, Phase } from '@/utils/phase'

const TONES: Record<Phase, string> = {
  [Phase.None]: 'muted',
  [Phase.Bidding]: 'live dot',
  [Phase.Round1]: 'muted',
  [Phase.Probing]: 'muted',
  [Phase.Round2]: 'muted',
  [Phase.Clearable]: 'wait',
  [Phase.Cleared]: 'done',
  [Phase.Aborted]: 'bad',
  [Phase.Failed]: 'bad',
}

/** `waiting` marks a sale in the bidding phase whose keys are not ready: bids are not open yet. */
const StatusBadge: React.FC<{ phase: Phase; waitingForKeys?: boolean }> = ({ phase, waitingForKeys }) =>
  waitingForKeys && phase === Phase.Bidding ? (
    <span className='tag wait'>Waiting for keys</span>
  ) : (
    <span className={`tag ${TONES[phase]}`}>{PHASE_LABELS[phase]}</span>
  )

export default StatusBadge
