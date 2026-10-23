// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { type AuctionPhase, PHASE_LABELS } from '@/utils/auction'

const TONES: Record<AuctionPhase, string> = {
  'awaiting-key': 'wait',
  bidding: 'live dot',
  computing: 'muted',
  decrypting: 'muted',
  complete: 'done',
  failed: 'bad',
}

const StatusBadge: React.FC<{ phase: AuctionPhase }> = ({ phase }) => <span className={`tag ${TONES[phase]}`}>{PHASE_LABELS[phase]}</span>

export default StatusBadge
